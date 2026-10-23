#!/usr/bin/env python3
"""Resolve tracked input branches, pin exact revisions, and leave a review diff.

The tracking inventory is separate from exact flake.nix/flake.lock pins. Lock
files are written exclusively by Nix. No merge, promotion or deployment.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=3600)
    if result.returncode:
        raise RuntimeError('Input resolution or validation failed: ' + args[0])
    return result.stdout.strip()


def pin_url(locked):
    if locked['type'] == 'github':
        return 'github:' + locked['owner'] + '/' + locked['repo'] + '/' + locked['rev']
    if locked['type'] == 'git':
        from urllib.parse import urlencode
        options = {k: ('1' if locked[k] is True else '0' if locked[k] is False else locked[k])
                   for k in ['ref', 'rev', 'submodules'] if k in locked}
        return 'git+' + locked['url'] + '?' + urlencode(options)
    return None


def url_match(text, name):
    # Only the declared input's first URL, never an arbitrary matching revision.
    pattern = r'\b' + re.escape(name) + r'(?:\.url\s*=|\s*=\s*\{[^{}]*?\burl\s*=)\s*"([^"\n]+)"'
    matches = list(re.finditer(pattern, text))
    if len(matches) != 1:
        raise ValueError('Expected exactly one input URL: ' + name)
    return matches[0]


def root_node(lock, name):
    key = lock['nodes'][lock['root']]['inputs'][name]
    if not isinstance(key, str):
        raise ValueError('Cannot update a follows edge directly')
    return lock['nodes'][key]


def update():
    config = json.loads((ROOT / 'ci/tracking-inputs.json').read_text())
    if config['version'] != 1:
        raise ValueError('Unknown tracking inventory')
    if run('git', 'status', '--porcelain', '--untracked-files=no'):
        raise ValueError('Input updates require a clean checkout')
    lockfile = ROOT / 'flake.lock'
    before = json.loads(lockfile.read_text())
    declared = before['nodes'][before['root']]['inputs']
    required = {name for name, key in declared.items() if isinstance(key, str)
                and before['nodes'][key].get('original', {}).get('type') != 'path'}
    if set(config['inputs']) != required:
        raise ValueError('Tracking inventory must cover every nonlocal direct input')
    overrides = {name: rule['source'] for name, rule in config['inputs'].items()}
    # A catalog's tested cache evidence is only valid for its own locked inputs.
    # Follow that exact nixpkgs/darwin tuple instead of retargeting its recipes.
    alignment = config.get('alignWith')
    if alignment:
        catalog = json.loads(run('nix', 'flake', 'metadata', '--json', '--refresh',
                                 '--option', 'accept-flake-config', 'false',
                                 '--no-write-lock-file', overrides[alignment['input']]))
        catalog_lock = json.loads((Path(catalog['path']) / 'flake.lock').read_text())
        for name in alignment['inputs']:
            overrides[name] = pin_url(root_node(catalog_lock, name)['locked'])
            if not overrides[name]:
                raise ValueError('Unsupported aligned input')
    args = ['nix', 'flake', 'lock', '--refresh', '--option', 'accept-flake-config', 'false']
    for name, source in sorted(overrides.items()):
        args += ['--override-input', name, source]
    run(*args)
    after = json.loads(lockfile.read_text())
    flake = ROOT / 'flake.nix'
    text = flake.read_text()
    for name in sorted(overrides):
        locked = root_node(after, name)['locked']
        url = pin_url(locked)
        if url is not None:
            match = url_match(text, name)
            text = text[:match.start(1)] + url + text[match.end(1):]
    flake.write_text(text)
    # Synchronize original metadata with the exact declarations using Nix, not a
    # JSON patch. Follows edges and all transitive locks remain Nix-owned.
    run('nix', 'flake', 'lock', '--option', 'accept-flake-config', 'false')
    ownership = ROOT / 'nix/forks.json'
    if ownership.exists():
        records = json.loads(ownership.read_text())
        for name, record in records.items():
            if name in overrides:
                record['revision'] = root_node(after, name)['locked']['rev']
        ownership.write_text(json.dumps(records, indent=2)+'\n')
    if alignment:
        run(sys.executable, 'scripts/check-dave-packages-pin.py')
    run('nix', 'flake', 'check', '--no-build', '--option', 'accept-flake-config', 'false',
        '--no-write-lock-file', '--no-update-lock-file')
    changed = [name for name in overrides
               if root_node(before, name)['locked'] != root_node(after, name)['locked']]
    print('Resolved all tracked inputs; ' + str(len(changed)) + ' direct inputs changed')
    return changed


if __name__ == '__main__':
    try:
        update()
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError):
        print('Input update failed; no update branch should be published.', file=sys.stderr)
        sys.exit(1)
