#!/usr/bin/env python3
"""Configure job-local private Niks3 reads and an optional independent writer."""
import argparse
import netrc
import os
from pathlib import Path
import re
import shutil
import sys

KEY = 'niks3.monke.fail-1:q13GqiZgAxx7SyoLZInXoJjviZMOdNpfG03xs0VUD2M='


def auth_directory():
    return Path(os.environ.get('NIX_JOB_CREDENTIALS', os.environ['RUNNER_TEMP']))/'flakey-niks3-auth'


def configure():
    os.umask(0o077)
    directory = auth_directory()
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink():
        raise ValueError('Unexpected authentication directory')
    raw = os.environ.get('NIKS3_READ_NETRC', '')
    if not raw or len(raw)>16384:
        raise ValueError('Missing private read credential')
    # netrc's parser has a file-only API. Never put the credential in argv.
    path = directory/'netrc'
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'w') as output:
        output.write(raw+'\n')
    parsed = netrc.netrc(str(path))
    if set(parsed.hosts) != {'niks3.monke.fail'} or parsed.macros:
        raise ValueError('Credential may only name the Niks3 origin')
    user, _, password = parsed.authenticators('niks3.monke.fail')
    if not user or not password or any(c.isspace() for c in user+password):
        raise ValueError('Invalid read credential')
    config = directory/'nix.conf'
    config.write_text('experimental-features = nix-command flakes\naccept-flake-config = false\n'
                     'extra-substituters = https://niks3.monke.fail\n'
                     # Large Niks3 NARs repeatedly failed with HTTP/2 stream framing errors.
                     'http2 = false\nalways-allow-substitutes = true\nextra-trusted-public-keys = '+KEY+'\n'
                     'netrc-file = '+str(path)+'\n')
    values={'NIKS3_NETRC_FILE':str(path)}
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
    print('Configured job-local private Niks3 authentication; credentials withheld.')


def cleanup():
    directory=auth_directory()
    if directory.is_symlink():
        raise ValueError('Unexpected authentication directory')
    shutil.rmtree(directory,ignore_errors=True)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cleanup',action='store_true')
    args=parser.parse_args()
    try:
        cleanup() if args.cleanup else configure()
    except (OSError,ValueError,KeyError,netrc.NetrcParseError):
        print('Niks3 authentication configuration failed; credentials withheld.',file=sys.stderr)
        sys.exit(1)
