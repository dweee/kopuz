#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


u = load('update-inputs')
m = load('update-monitor')


class Updates(unittest.TestCase):
    def test_urls_pin_git_revision_and_preserve_ref(self):
        self.assertEqual(u.pin_url({'type': 'git', 'url': 'https://git.monke.fail/d/tool',
                                   'ref': 'tested', 'rev': 'a'*40}),
                         'git+https://git.monke.fail/d/tool?ref=tested&rev='+'a'*40)

    def test_submodule_boolean_uses_nix_url_syntax(self):
        self.assertIn('submodules=1', u.pin_url({'type':'git','url':'https://github.com/o/r','rev':'a'*40,'submodules':True}))

    def test_exact_declaration_only(self):
        text = 'inputs = { tool = { # note\n url = "old"; inputs.nixpkgs.follows = "nixpkgs"; }; tool-src.url = "other"; };'
        match = u.url_match(text, 'tool')
        self.assertEqual(text[match.start(1):match.end(1)], 'old')

    def test_duplicate_declaration_rejected(self):
        with self.assertRaises(ValueError): u.url_match('tool.url = "a"; tool.url = "b";', 'tool')

    def test_follows_cannot_be_updated_as_a_source(self):
        with self.assertRaises(ValueError):
            u.root_node({'root': 'root', 'nodes': {'root': {'inputs': {'tool': ['another']}}}}, 'tool')

    def test_json_release_file_is_discovered(self):
        self.assertEqual(m.discover('{"url":"https://github.com/owner/repo/releases/download/v1.2/a.tar.gz"}'),
                         [('owner/repo', 'v1.2')])

    def test_nix_version_interpolation_is_resolved(self):
        text = 'version = "1.2"; src = fetchFromGitHub { owner = "o"; repo = "r"; rev = "v${version}"; hash = "sha256-x"; };'
        self.assertEqual(m.discover(text), [('o/r', 'v1.2')])

    def test_unknown_interpolation_is_not_invented(self):
        text = 'url = "https://github.com/o/r/releases/download/${tag}/archive.tar.gz";'
        self.assertEqual(m.discover(text), [('o/r', '${tag}')])

    def test_small_raw_file_pin_discovery(self):
        text = 'url = "https://raw.githubusercontent.com/o/r/main/file.yaml"; hash = "sha256-AAAA=";'
        self.assertEqual(m.raw_file_pins(text), [('https://raw.githubusercontent.com/o/r/main/file.yaml', 'sha256-AAAA=')])

    def test_archives_are_not_mistaken_for_flat_text_hashes(self):
        text = 'url = "https://raw.githubusercontent.com/o/r/main/file.tar.gz"; hash = "sha256-AAAA=";'
        self.assertEqual(m.raw_file_pins(text), [])

    def test_file_hash_reader_rejects_credentialed_and_unreviewed_hosts(self):
        for url in ['https://example.invalid/a.yaml', 'https://token@raw.githubusercontent.com/o/r/a.yaml']:
            with self.subTest(url=url), self.assertRaises(ValueError): m.file_hash(url)


@unittest.skipUnless(shutil.which('nix'), 'Nix required for lock updater fixture')
class RealInputMovement(unittest.TestCase):
    def test_branch_movement_is_written_by_nix_as_an_exact_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependency, consumer = root/'dep', root/'consumer'
            def run(path, *args):
                return subprocess.check_output(args, cwd=path, stderr=subprocess.PIPE, text=True).strip()
            for path in [dependency, consumer]:
                path.mkdir()
                run(path, 'git', 'init', '-b', 'main')
                run(path, 'git', 'config', 'user.name', 'Fixture')
                run(path, 'git', 'config', 'user.email', 'fixture@example.invalid')
            (dependency/'source.txt').write_text('old')
            run(dependency, 'git', 'add', 'source.txt')
            run(dependency, 'git', 'commit', '-m', 'Fixture old source')
            old = run(dependency, 'git', 'rev-parse', 'HEAD')
            source = 'git+' + dependency.as_uri()
            (consumer/'flake.nix').write_text('{ inputs.dep = { url = "'+source+'?rev='+old+'"; flake = false; }; outputs = {self, dep}: {}; }')
            (consumer/'ci').mkdir()
            (consumer/'ci/tracking-inputs.json').write_text(json.dumps({'version':1,'inputs':{'dep':{'source':source+'?ref=main'}}}))
            run(consumer, 'git', 'add', 'flake.nix', 'ci/tracking-inputs.json')
            run(consumer, 'nix', 'flake', 'lock')
            run(consumer, 'git', 'add', 'flake.lock')
            run(consumer, 'git', 'commit', '-m', 'Fixture consumer')
            (dependency/'source.txt').write_text('new')
            run(dependency, 'git', 'commit', '-am', 'Fixture new source')
            new = run(dependency, 'git', 'rev-parse', 'HEAD')
            with patch.object(u, 'ROOT', consumer):
                self.assertEqual(u.update(), ['dep'])
            self.assertIn('rev='+new, (consumer/'flake.nix').read_text())
            locked = u.root_node(json.loads((consumer/'flake.lock').read_text()), 'dep')
            self.assertEqual(locked['locked']['rev'], new)
            self.assertEqual(locked['original']['rev'], new)


if __name__ == '__main__': unittest.main()
