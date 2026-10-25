#!/usr/bin/env python3
"""Resolve tracked input branches, pin exact revisions, and leave a review diff.

The tracking inventory is separate from exact flake.nix/flake.lock pins. Lock
files are written exclusively by Nix. No merge, promotion or deployment.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('channel_diagnostics', ROOT / 'ci/release-channel.py')
channel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(channel)
ACTIVE_PHASE = 'startup'


def phase(label):
    global ACTIVE_PHASE
    if not re.fullmatch(r'[a-z-]+', label):
        raise ValueError('Invalid updater phase')
    ACTIVE_PHASE = label
    print('Input update phase: ' + label, flush=True)


def run(*args):
    try:
        result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=3600)
    except subprocess.TimeoutExpired:
        raise channel.CommandFailure('command deadline exceeded') from None
    if result.returncode:
        kind = channel.failure_category((result.stderr or '') + '\n' + (result.stdout or ''))
        raise channel.CommandFailure(kind + ' (exit ' + str(result.returncode) + ')')
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
    # Nix identifiers include hyphens and apostrophes; a regex word boundary
    # would also match nixpkgs inside pumpkin-nixpkgs.
    pattern = r"(?<![A-Za-z0-9_'-])" + re.escape(name) + r'(?:\.url\s*=|\s*=\s*\{[^{}]*?\burl\s*=)\s*"([^"\n]+)"'
    matches = list(re.finditer(pattern, text))
    if len(matches) != 1:
        raise ValueError('Expected exactly one input URL: ' + name)
    return matches[0]


def root_node(lock, name):
    key = lock['nodes'][lock['root']]['inputs'][name]
    if not isinstance(key, str):
        raise ValueError('Cannot update a follows edge directly')
    return lock['nodes'][key]


def instantiation_expression(system):
    # `flake check --no-build` evaluates read-only, so an import-from-derivation
    # source absent from a fresh runner store is "not valid". Instantiating this
    # system's packages and checks first realises only those IFD inputs. An empty
    # flake fragment would select the default package, so load the whole flake.
    if not re.fullmatch(r'[a-z0-9_]+-[a-z0-9_]+', system):
        raise ValueError('Unexpected builder system')
    # The same Git view `nix flake check .` evaluates, including any declared
    # self.submodules setting.
    return ('let f = builtins.getFlake ' + json.dumps('git+file://' + str(ROOT)) + '; '
            'drvs = output: builtins.mapAttrs (_: p: p.drvPath) ((f.${output} or {}).' + system + ' or {}); '
            'in { packages = drvs "packages"; checks = drvs "checks"; }')


def update():
    phase('inspect-tracking-inventory')
    config = json.loads((ROOT / 'ci/tracking-inputs.json').read_text())
    if config['version'] != 1:
        raise ValueError('Unknown tracking inventory')
    phase('check-clean-checkout')
    if run('git', 'status', '--porcelain', '--untracked-files=no'):
        raise ValueError('Input updates require a clean checkout')
    phase('inspect-locked-inputs')
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
        phase('align-catalog-inputs')
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
    phase('lock-moving-inputs')
    run(*args)
    after = json.loads(lockfile.read_text())
    flake = ROOT / 'flake.nix'
    phase('pin-exact-declarations')
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
    phase('synchronize-lock-metadata')
    run('nix', 'flake', 'lock', '--option', 'accept-flake-config', 'false')
    ownership = ROOT / 'nix/forks.json'
    if ownership.exists():
        phase('align-fork-inventory')
        records = json.loads(ownership.read_text())
        for name, record in records.items():
            if name in overrides:
                record['revision'] = root_node(after, name)['locked']['rev']
        ownership.write_text(json.dumps(records, indent=2)+'\n')
    if alignment:
        phase('validate-catalog-alignment')
        run(sys.executable, 'scripts/check-dave-packages-pin.py')
    phase('instantiate-import-from-derivation')
    run('nix', 'eval', '--impure', '--json', '--option', 'accept-flake-config', 'false',
        '--expr', instantiation_expression(run('nix', 'eval', '--impure', '--raw', '--expr', 'builtins.currentSystem')))
    phase('validate-candidate')
    run('nix', 'flake', 'check', '--no-build', '--option', 'accept-flake-config', 'false',
        '--no-write-lock-file', '--no-update-lock-file')
    changed = [name for name in overrides
               if root_node(before, name)['locked'] != root_node(after, name)['locked']]
    print('Resolved all tracked inputs; ' + str(len(changed)) + ' direct inputs changed')
    return changed


def main():
    try:
        update()
    except Exception as error:
        if isinstance(error, channel.CommandFailure):
            detail = str(error)
        else:
            detail = channel.failure_category(str(error))
            if detail == 'command-failed':
                detail = 'validation-failed'
        print('Input update failed during ' + ACTIVE_PHASE + ': ' + detail +
              '; no update branch should be published.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
