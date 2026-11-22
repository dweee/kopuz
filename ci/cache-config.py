#!/usr/bin/env python3
"""Render the reviewed public cache policy; private Niks3 is appended by its reader."""
import json
import re
from pathlib import Path

POLICY = json.loads(Path(__file__).with_name('caches.json').read_text())
PUBLIC = [url for url in POLICY['substituters'] if url != 'https://niks3.monke.fail']
KEYS = POLICY['trusted-public-keys']
# Only explicitly paired endpoints can exempt an output from retention.
# The Determinate installer serves a subset of FlakeHub-signed paths.
PUBLIC_CACHE_KEYS = {
    'https://cache.nixos.org/': 'cache.nixos.org-1',
    'https://cache.numtide.com': 'niks3.numtide.com-1',
    'https://nix-community.cachix.org': 'nix-community.cachix.org-1',
    'https://cache.lix.systems': 'cache.lix.systems',
    'https://install.determinate.systems': 'cache.flakehub.com-3',
    'https://ai.cachix.org': 'ai.cachix.org-1',
    'https://codex-desktop-linux.cachix.org': 'codex-desktop-linux.cachix.org-1',
    'https://nix-on-droid.cachix.org': 'nix-on-droid.cachix.org-1',
    'https://virby-nix-darwin.cachix.org': 'virby-nix-darwin.cachix.org-1',
    'https://cache.nixos-cuda.org': 'cache.nixos-cuda.org',
    'https://cache.flox.dev': 'flox-cache-public-1',
}
KEYS_BY_NAME = {key.split(':', 1)[0]: key for key in KEYS}
PUBLIC_CACHES = {
    url: KEYS_BY_NAME[name] for url, name in PUBLIC_CACHE_KEYS.items()
    if url in PUBLIC and name in KEYS_BY_NAME
}


def nix_config():
    return ('extra-substituters = ' + ' '.join(PUBLIC) + '\n'
            + 'extra-trusted-public-keys = ' + ' '.join(KEYS) + '\n'
            + 'connect-timeout = 20\n')

if __name__ == '__main__':
    print(nix_config(), end='')


CACHE_LINE = re.compile(r'^(?:extra-)?(?:substituters|trusted-substituters|trusted-public-keys)\s*=')

def transform(value):
    """Preserve unrelated expressions; cache expressions need an owning-repo repair."""
    if not isinstance(value, str):
        raise ValueError('dynamic cache configuration')
    lines = value.splitlines()
    if any('${{' in line and (CACHE_LINE.match(line.strip()) or '=' not in line)
           for line in lines):
        raise ValueError('dynamic cache configuration')
    return without_cache(value).rstrip()+'\n'+nix_config()


def without_cache(value):
    return '\n'.join(line for line in value.splitlines() if not CACHE_LINE.match(line.strip())
                     and not line.startswith('connect-timeout ='))


def nix_job(steps):
    return isinstance(steps, list) and any(
        'nix' in str(step.get('uses', '')).split('@', 1)[0].lower()
        or re.search(r'\bnix(?:-shell|-store|-build|-instantiate|-env)?\s', str(step.get('run', '')))
        for step in steps if isinstance(step, dict))


def installer_field(step):
    action = str(step.get('uses', '')).split('@', 1)[0]
    return ('nix_conf' if action == 'nixbuild/nix-quick-install-action' else
            'extra-conf' if action in {'DeterminateSystems/determinate-nix-action',
                                      'DeterminateSystems/nix-installer-action'} else None)
