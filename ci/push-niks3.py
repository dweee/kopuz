#!/usr/bin/env python3
"""Publish selected built outputs and runtime closures to the one private cache."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def publish(outputs):
    binary=Path(os.environ['NIKS3_BIN'])
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary,os.X_OK):
        raise ValueError('Missing installed Niks3 client')
    server=os.environ.get('NIKS3_SERVER','https://niks3.monke.fail')
    if server!='https://niks3.monke.fail':
        raise ValueError('Unexpected destination')
    paths=list(dict.fromkeys(str(Path(p).resolve()) for p in outputs.read_text().splitlines()))
    if not paths or any(not re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+',p)
                        or p.endswith('.drv') for p in paths):
        raise ValueError('Expected built output paths')
    child={k:v for k,v in os.environ.items() if k not in {'NIKS3_WRITE_TOKEN','NIKS3_READ_NETRC','ATTIC_TOKEN','FLAKEY_ATTIC_TOKEN'}}
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='niks3-publication-',dir=os.environ.get('RUNNER_TEMP')) as directory:
        token_file=os.environ.get('NIKS3_AUTH_TOKEN_FILE')
        token=os.environ.get('NIKS3_WRITE_TOKEN')
        if token:
            if not re.fullmatch(r'[A-Za-z0-9_-]{48,128}',token):
                raise ValueError('Invalid independent publisher credential')
            path=Path(directory)/'token'
            path.write_text(token); path.chmod(0o600); token_file=str(path)
        if os.environ.get('GITHUB_SERVER_URL') == 'https://github.com':
            if token or token_file or os.environ.get('NIKS3_READ_NETRC') or os.environ.get('NIKS3_NETRC_FILE'):
                raise ValueError('GitHub requires OIDC without private credentials')
            if os.environ.get('GITHUB_EVENT_NAME') not in {'push','workflow_dispatch','schedule'}:
                raise ValueError('Untrusted publication event')
            auth=['--auth-token-script', str(Path(__file__).with_name('niks3-oidc-token.py'))]
        else:
            if not token_file or not Path(token_file).is_file():
                raise ValueError('Missing independent publisher credential file')
            auth=['--auth-token-path',token_file]
        deadline=started+int(os.environ.get('CI_NIKS3_DEADLINE_SECONDS','3600'))
        for attempt in range(5):
            remaining=deadline-time.monotonic()
            if remaining<=0:
                raise subprocess.TimeoutExpired('private publisher',0)
            result=subprocess.run([str(binary),'push','--server-url',server,*auth,
                        '--verify-s3-integrity','--max-concurrent-uploads','4',*paths],
                       env=child,timeout=remaining,capture_output=True,text=True)
            if result.returncode==0:
                break
            transient=re.search(r'(?i)InternalServerError|HTTP[^\n]*50[234]|Connection pool timed out|Connection timed out|connection reset|unexpected EOF|temporary failure',result.stderr+result.stdout)
            if attempt==4 or not transient or result.returncode in (124,137):
                raise subprocess.CalledProcessError(result.returncode,'private publisher')
            delay=10*2**attempt
            if time.monotonic()+delay>=deadline:
                raise subprocess.TimeoutExpired('private publisher',remaining)
            print('Temporary private cache upload failure; retrying.',file=sys.stderr)
            subprocess.run(['sleep',str(delay)],check=True)

    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as output:
            output.write(f'Published {len(paths)} output roots and their runtime closures to private Niks3 in {time.monotonic()-started:.0f}s.\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--outputs',type=Path,default=Path('outputs.txt'))
    args=parser.parse_args()
    try:
        publish(args.outputs)
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as error:
        print('Private Niks3 publication failed; this build is not successfully cached.',file=sys.stderr)
        if isinstance(error,subprocess.TimeoutExpired) or getattr(error,'returncode',None) in (124,137):
            print('Private upload exceeded its '+os.environ.get('CI_NIKS3_DEADLINE_SECONDS','3600')+'-second deadline.',file=sys.stderr)
        sys.exit(error.returncode if isinstance(error,subprocess.CalledProcessError) and error.returncode>0 else 1)
