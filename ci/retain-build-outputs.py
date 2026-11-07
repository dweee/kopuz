#!/usr/bin/env python3
"""Retain public completed graph outputs as data, without a publisher credential."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


channel = load('release-channel')
public = load('public-closure')
WRITERS = {'ATTIC_TOKEN', 'FLAKEY_ATTIC_TOKEN', 'NIKS3_WRITE_TOKEN', 'NIKS3_AUTH_TOKEN_FILE'}


def build_environment(environ):
    if any(environ.get(name) for name in WRITERS):
        raise ValueError('Build retention must not receive publisher credentials')
    denied = WRITERS | {'GH_TOKEN', 'GITHUB_TOKEN', 'CHANNEL_TOKEN', 'SOURCE_TOKEN',
                       'SSH_AUTH_SOCK', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL'}
    env = {key: value for key, value in environ.items() if key not in denied}
    env['NIX_CONFIG'] = env.get('NIX_CONFIG', '') + '\naccept-flake-config = false\n'
    return env


class Collector:
    def __init__(self, targets, manifest, env):
        self.manifest = Path(manifest)
        self.manifest.unlink(missing_ok=True)
        self.env = build_environment(env)
        self.candidates = set()
        if not targets:
            raise ValueError('Missing selected build graph')
        for target in targets:
            # Guard the recursive source graph before any selected build runs.
            with channel.build_environment(self.env):
                public.derivation(target)
            self.candidates.update(channel.derivation_output_paths(target, self.env))

    def retain(self, successful_roots=()):
        roots = set(successful_roots)
        if not roots <= self.candidates:
            raise ValueError('Build roots differ from selected graph')
        paths = sorted(roots | set(channel.completed_build_outputs(self.candidates, self.env)))
        if not paths:
            return
        # Keep the transfer's manifest and byte bounds, and guard all runtime
        # dependencies before an artifact can exist. Never inventory the store.
        if len(paths) > 1024:
            raise ValueError('Completed build manifest exceeds transfer limit')
        with channel.build_environment(self.env):
            public.runtime(paths)
        self.manifest.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', dir=self.manifest.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write('\n'.join(paths) + '\n')
        try:
            os.replace(temporary, self.manifest)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', action='append', required=True)
    parser.add_argument('--manifest', type=Path, default=Path('cache-outputs.txt'))
    parser.add_argument('--script', type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if args.script is not None:
        if command or not args.script.is_file():
            raise ValueError('Expected one reviewed build script')
        command = ['bash', '-eu', '-o', 'pipefail', str(args.script)]
    elif command[:2] != ['nix', 'build'] or any(not any(ref in command for ref in (target, target+'^out', target+'^*')) for target in args.target):
        raise ValueError('Expected selected Nix build command')
    targets = [str(Path.cwd()) + target[1:] if target.startswith('.#') else target for target in args.target]
    collector = Collector(targets, args.manifest, os.environ)
    roots = []
    try:
        result = subprocess.run(command, env=collector.env,
                                stdout=None if args.script is not None else subprocess.PIPE, text=True)
        if args.script is None and result.returncode == 0:
            paths = result.stdout.splitlines()
            if not paths or any(not channel.STORE.fullmatch(path) or path.endswith('.drv') for path in paths):
                raise ValueError('Missing selected build outputs')
            roots = paths
            sys.stdout.write(result.stdout)
        return result.returncode
    finally:
        collector.retain(roots)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        print('Completed build retention failed; no cache success is granted.', file=sys.stderr)
        sys.exit(1)
