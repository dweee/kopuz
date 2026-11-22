#!/usr/bin/env python3
"""Publish selected built outputs and runtime closures to the one private cache."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


class PublicationFailure(RuntimeError):
    def __init__(self, category, returncode=1):
        super().__init__(category)
        self.category = category
        self.returncode = returncode if returncode > 0 else 1


def failure_category(diagnostic):
    # Only these fixed labels reach logs. Never echo client output: it can
    # contain bearer credentials or presigned object URLs.
    for category, pattern, retry in [
        ('authentication-rejected', r'Unauthorized|Forbidden|AccessDenied|invalid.*token|HTTP[^\n]*40[13]', False),
        ('tls-validation', r'certificate|UnknownIssuer|TLS.*validation', False),
        ('integrity-mismatch', r'hash mismatch|checksum mismatch|integrity[^\n]*(failed|mismatch)', False),
        ('local-store-path', r'path[^\n]*(does not exist|not valid)|invalid store path', False),
        ('service-unavailable', r'InternalServerError|InternalError|ServiceUnavailable|HTTP[^\n]*50[0234]', True),
        ('transport', r'timed out|timeout was reached|connection (pool |)(reset|refused|closed|aborted|error)|network (is |)unreachable|could not (connect|resolve)|failed to (connect|resolve)|tcp connect error|temporary failure|unexpected EOF|dns error|SSL connect error|TLS connect error|bad record mac|SSL_read', True),
    ]:
        if re.search(pattern, diagnostic, re.I):
            return category, retry
    return 'publisher-rejected', False


def store_output_path(value):
    """Follow CI result aliases, stopping before a store output's own symlink."""
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    for _ in range(64):
        # Resolving this leaf would replace a symlink output's NAR identity
        # with its target. Resolve only outer aliases and their parents.
        if re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+', str(path)):
            if str(path).endswith('.drv'):
                break
            return str(path)
        if Path('/nix/store') == path or Path('/nix/store') in path.parents:
            break
        path = path.parent.resolve() / path.name
        if Path('/nix/store') in path.parents:
            continue
        if not path.is_symlink():
            break
        target = path.readlink()
        path = target if target.is_absolute() else path.parent / target
    raise ValueError('Expected built output paths')


PIN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}')
STORE = re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+')


def client_command(directory):
    """The installed client, the fixed server and one publisher credential."""
    binary=Path(os.environ['NIKS3_BIN'])
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary,os.X_OK):
        raise ValueError('Missing installed Niks3 client')
    server=os.environ.get('NIKS3_SERVER','https://niks3.monke.fail')
    if server!='https://niks3.monke.fail':
        raise ValueError('Unexpected destination')
    token_file=os.environ.get('NIKS3_AUTH_TOKEN_FILE')
    token=os.environ.get('NIKS3_WRITE_TOKEN')
    if token:
        if not re.fullmatch(r'[A-Za-z0-9_-]{48,128}',token):
            raise ValueError('Invalid independent publisher credential')
        path=Path(directory)/'token'
        path.write_text(token); path.chmod(0o600); token_file=str(path)
    if os.environ.get('GITHUB_SERVER_URL') == 'https://github.com':
        if token or token_file or os.environ.get('NIKS3_READ_NETRC') or (os.environ.get('NIKS3_NETRC_FILE') and os.environ.get('NIKS3_READ_AUTH') != 'github-oidc'):
            raise ValueError('GitHub requires OIDC without private credentials')
        if os.environ.get('GITHUB_EVENT_NAME') not in {'push','workflow_dispatch','schedule','repository_dispatch'}:
            raise ValueError('Untrusted publication event')
        auth=['--auth-token-script', str(Path(__file__).with_name('niks3-oidc-token.py'))]
    else:
        if not token_file or not Path(token_file).is_file():
            raise ValueError('Missing independent publisher credential file')
        auth=['--auth-token-path',token_file]
    return str(binary), server, auth


def child_environment():
    return {k:v for k,v in os.environ.items() if k not in {'NIKS3_WRITE_TOKEN','NIKS3_READ_NETRC',
                                                    'SOURCE_TOKEN','CHANNEL_TOKEN','GH_TOKEN','GITHUB_TOKEN','STATUS_TOKEN'}}


def attempt(command, deadline, label):
    """Run one client command, retrying only transient service and network failures."""
    for number in range(5):
        remaining=deadline-time.monotonic()
        if remaining<=0:
            raise subprocess.TimeoutExpired('private publisher',0)
        result=subprocess.run(command,env=child_environment(),timeout=remaining,capture_output=True,text=True)
        if result.returncode==0:
            return
        category, transient = failure_category(result.stderr+result.stdout)
        if number==4 or not transient or result.returncode in (124,137):
            raise PublicationFailure(category, result.returncode)
        delay=10*2**number
        if time.monotonic()+delay>=deadline:
            raise subprocess.TimeoutExpired('private publisher',remaining)
        print('Temporary private cache '+label+' failure; category='+category+'; retrying.',file=sys.stderr)
        subprocess.run(['sleep',str(delay)],check=True)


def create_pins(selection):
    """Upsert named pins on already published closures. Pins are never deleted."""
    pins=json.loads(selection.read_text())
    if (not isinstance(pins,dict) or not pins or len(pins)>32
            or any(not isinstance(n,str) or not PIN.fullmatch(n) for n in pins)
            or any(not isinstance(p,str) or not STORE.fullmatch(p) or p.endswith('.drv') for p in pins.values())):
        raise ValueError('Invalid pin selection')
    started=time.monotonic()
    deadline=started+int(os.environ.get('CI_NIKS3_DEADLINE_SECONDS','3600'))
    with tempfile.TemporaryDirectory(prefix='niks3-pins-',dir=os.environ.get('RUNNER_TEMP')) as directory:
        binary, server, auth = client_command(directory)
        for name, path in sorted(pins.items()):
            attempt([binary,'pins','create','--server-url',server,*auth,name,path],deadline,'pin')
    print('Pinned '+str(len(pins))+' retained release closures in private Niks3.',file=sys.stderr)


def publish(outputs, pin=None):
    paths=list(dict.fromkeys(store_output_path(p) for p in outputs.read_text().splitlines()))
    if not paths or any(not re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+',p)
                        or p.endswith('.drv') for p in paths):
        raise ValueError('Expected built output paths')
    if pin is not None and (not PIN.fullmatch(pin) or len(paths)!=1):
        raise ValueError('A pin names exactly one published closure')
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='niks3-publication-',dir=os.environ.get('RUNNER_TEMP')) as directory:
        binary, server, auth = client_command(directory)
        deadline=started+int(os.environ.get('CI_NIKS3_DEADLINE_SECONDS','3600'))
        attempt([binary,'push','--server-url',server,*auth,
                 '--verify-s3-integrity','--max-concurrent-uploads','4',
                 *(['--pin',pin] if pin else []),*paths],deadline,'upload')

    if os.environ.get('GITHUB_STEP_SUMMARY'):
        # A daemon hook can inherit a stale per-step summary path. Once the
        # client has succeeded, optional reporting must not relabel that
        # verified publication as an upload failure.
        try:
            with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as output:
                output.write(f'Published {len(paths)} output roots and their runtime closures to private Niks3 in {time.monotonic()-started:.0f}s.\n')
        except OSError:
            print('Private cache publication succeeded; optional step summary unavailable.',file=sys.stderr)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--outputs',type=Path,default=Path('outputs.txt'))
    parser.add_argument('--pin',help='Pin the single published closure under this name')
    parser.add_argument('--pins',type=Path,help='JSON object of pin name to already published store path')
    args=parser.parse_args()
    try:
        if args.pins:
            create_pins(args.pins)
        else:
            publish(args.outputs, args.pin)
    except (PublicationFailure,ValueError,OSError,KeyError,subprocess.SubprocessError) as error:
        print('Private Niks3 publication failed; this build is not successfully cached.',file=sys.stderr)
        category = (error.category if isinstance(error, PublicationFailure) else
                    'upload-deadline' if isinstance(error, subprocess.TimeoutExpired) else
                    'local-io' if isinstance(error, OSError) else 'configuration-invalid')
        print('Private upload failure category: '+category, file=sys.stderr)
        if isinstance(error,subprocess.TimeoutExpired) or getattr(error,'returncode',None) in (124,137):
            print('Private upload exceeded its '+os.environ.get('CI_NIKS3_DEADLINE_SECONDS','3600')+'-second deadline.',file=sys.stderr)
        sys.exit(error.returncode if isinstance(error,(PublicationFailure,subprocess.CalledProcessError)) and error.returncode>0 else 1)
