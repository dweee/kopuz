#!/usr/bin/env python3
"""Configure job-local private Niks3 reads and an optional independent writer."""
import argparse
from datetime import datetime
import importlib.util
import netrc
import os
from pathlib import Path
import re
import shutil
import sys
import subprocess
import time

KEY = 'niks3.monke.fail-1:q13GqiZgAxx7SyoLZInXoJjviZMOdNpfG03xs0VUD2M='


def auth_directory():
    return Path(os.environ.get('NIX_JOB_CREDENTIALS', os.environ['RUNNER_TEMP']))/'flakey-niks3-auth'


def oidc_reader():
    spec = importlib.util.spec_from_file_location('niks3_oidc', Path(__file__).with_name('niks3-oidc-token.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # A different audience selects a read-only server provider. A package build
    # that can read this netrc cannot turn its JWT into a cache upload grant.
    value = module.token(audience='https://niks3.monke.fail/read')
    expiry = datetime.fromisoformat(value['expires_at'].replace('Z', '+00:00')).timestamp()
    if expiry <= time.time()+30:
        raise ValueError('OIDC credential expires too soon')
    return 'machine niks3.monke.fail login oidc password ' + value['token'], expiry


def write_reader(path, raw):
    temporary = path.with_name('netrc.next')
    fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(raw+'\n')
    os.replace(temporary, path)


def refresh_oidc():
    directory = auth_directory()
    # GitHub tokens are short lived. Refresh the protected netrc during long
    # builds, and stop promptly when cleanup removes the job-local directory.
    expiry = float((directory/'expires-at').read_text())
    while directory.is_dir():
        deadline = time.time()+max(1, min(120, (expiry-time.time())/2))
        while time.time() < deadline:
            time.sleep(max(0, min(10, deadline-time.time())))
            if not directory.is_dir():
                return
        while directory.is_dir():
            try:
                raw, replacement_expiry = oidc_reader()
                write_reader(directory/'netrc', raw)
                expiry = replacement_expiry
                break
            except (OSError, ValueError, KeyError):
                if not directory.is_dir():
                    return
                if time.time() >= expiry:
                    (directory/'netrc').unlink(missing_ok=True)
                    raise ValueError('OIDC reader expired before refresh succeeded')
                time.sleep(min(5, expiry-time.time()))


def configure(oidc=False):
    os.umask(0o077)
    directory = auth_directory()
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink():
        raise ValueError('Unexpected authentication directory')
    if oidc and any(os.environ.get(k) for k in ('NIKS3_READ_NETRC', 'NIKS3_WRITE_TOKEN', 'NIKS3_AUTH_TOKEN_FILE')):
        raise ValueError('GitHub OIDC reader cannot use static fleet credentials')
    if oidc:
        raw, expiry = oidc_reader()
    else:
        raw = os.environ.get('NIKS3_READ_NETRC', '')
    if not raw or len(raw)>16384:
        raise ValueError('Missing private read credential')
    # netrc's parser has a file-only API. Never put the credential in argv.
    path = directory/'netrc'
    write_reader(path, raw)
    if oidc:
        (directory/'expires-at').write_text(str(expiry))
    parsed = netrc.netrc(str(path))
    if set(parsed.hosts) != {'niks3.monke.fail'} or parsed.macros:
        raise ValueError('Credential may only name the Niks3 origin')
    user, _, password = parsed.authenticators('niks3.monke.fail')
    if not user or not password or any(c.isspace() for c in user+password):
        raise ValueError('Invalid read credential')
    config = directory/'nix.conf'
    read_url = 'https://niks3.monke.fail' + ('/oidc' if oidc else '')
    config.write_text('experimental-features = nix-command flakes\naccept-flake-config = false\n'
                     'extra-substituters = '+read_url+'\n'
                     # Large Niks3 NARs repeatedly failed with HTTP/2 stream framing errors.
                     'http2 = false\nalways-allow-substitutes = true\nextra-trusted-public-keys = '+KEY+'\n'
                     'netrc-file = '+str(path)+'\n')
    values={'NIKS3_NETRC_FILE':str(path), 'NIKS3_READ_URL':read_url}
    if oidc:
        values['NIKS3_READ_AUTH'] = 'github-oidc'
    previous = os.environ.get('NIX_USER_CONF_FILES', str(Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home()/'.config')))/'nix/nix.conf'))
    configs=[p for p in previous.split(':') if p and p != str(config)]
    values['NIX_USER_CONF_FILES']=':'.join([*configs,str(config)])
    token=os.environ.get('NIKS3_WRITE_TOKEN')
    if token:
        if not re.fullmatch(r'[A-Za-z0-9_-]{48,128}',token):
            raise ValueError('Invalid independent write credential')
        token_path=directory/'write-token'
        fd=os.open(token_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as output:
            output.write(token)
        values['NIKS3_AUTH_TOKEN_FILE']=str(token_path)
    if 'GITHUB_ENV' in os.environ:
        with open(os.environ['GITHUB_ENV'],'a') as output:
            for key,value in values.items():
                if '\n' in value or '\r' in value:
                    raise ValueError('Invalid environment path')
                output.write(key+'='+value+'\n')
    if oidc:
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--refresh-oidc'],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    print('Configured job-local private Niks3 authentication; credentials withheld.')


def cleanup():
    directory=auth_directory()
    if directory.is_symlink():
        raise ValueError('Unexpected authentication directory')
    shutil.rmtree(directory,ignore_errors=True)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cleanup',action='store_true')
    parser.add_argument('--oidc',action='store_true')
    parser.add_argument('--refresh-oidc',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    try:
        if args.cleanup:
            cleanup()
        elif args.refresh_oidc:
            refresh_oidc()
        else:
            configure(args.oidc)
    except (OSError,ValueError,KeyError,netrc.NetrcParseError):
        print('Niks3 authentication configuration failed; credentials withheld.',file=sys.stderr)
        sys.exit(1)
