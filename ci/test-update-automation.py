#!/usr/bin/env python3
import importlib.util
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


u = load('update-inputs')
m = load('update-monitor')
a = load('automation-forge')


class Updates(unittest.TestCase):
    def test_renamed_repository_redirect_keeps_auth_on_the_same_api_host(self):
        source = 'https://api.github.com/repos/old/name/releases/latest'
        target = 'https://api.github.com/repositories/123/releases/latest'
        opener = Mock()
        opener.open.side_effect = [HTTPError(source, 301, 'Moved', {'Location': target}, None),
                                   io.BytesIO(b'{"tag_name":"v2"}')]
        with patch('urllib.request.build_opener', return_value=opener), patch.dict(m.os.environ, {'GH_TOKEN':'fixture'}):
            self.assertEqual(m.fetch(source), {'tag_name':'v2'})
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual([r.full_url for r in requests], [source, target])
        self.assertEqual([r.get_header('Authorization') for r in requests], ['Bearer fixture']*2)

    def test_redirects_cannot_send_api_credentials_to_other_origins(self):
        source = 'https://api.github.com/repos/old/name/releases/latest'
        for target in ['https://example.invalid/release', 'https://git.monke.fail/api/v1/release',
                       'http://api.github.com/release', 'https://user@api.github.com/release',
                       'https://api.github.com:444/release']:
            with self.subTest(target=target):
                opener = Mock()
                opener.open.side_effect = HTTPError(source, 302, 'Moved', {'Location':target}, None)
                with patch('urllib.request.build_opener', return_value=opener), self.assertRaises(ValueError):
                    m.fetch(source)
                self.assertEqual(opener.open.call_count, 1)

    def test_api_redirect_loop_is_bounded(self):
        source = 'https://api.github.com/repos/old/name/releases/latest'
        opener = Mock()
        opener.open.side_effect = HTTPError(source, 301, 'Moved', {'Location':source}, None)
        with patch('urllib.request.build_opener', return_value=opener), self.assertRaises(ValueError):
            m.fetch(source)
        self.assertEqual(opener.open.call_count, 4)

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




class FailureDiagnostics(unittest.TestCase):
    def test_input_failure_classifies_subprocess_error_without_output_or_arguments(self):
        secret = 'fixture-sensitive-auth-value'
        result = subprocess.CompletedProcess(['nix', secret], 9, stdout='',
            stderr='HTTP 401 at https://'+secret+'@example.invalid/private/path')
        output, error = io.StringIO(), io.StringIO()
        def update():
            u.phase('lock-moving-inputs')
            u.run('nix', secret)
        with patch.object(u, 'update', side_effect=update), patch.object(u.subprocess, 'run', return_value=result), redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(u.main(), 1)
        self.assertIn('lock-moving-inputs: authorization (exit 9)', error.getvalue())
        self.assertNotIn(secret, output.getvalue()+error.getvalue())
        self.assertNotIn('/private/path', output.getvalue()+error.getvalue())

    def test_input_timeout_does_not_print_the_command(self):
        secret = 'fixture-private-command-argument'
        def update():
            u.phase('validate-candidate')
            u.run('nix', secret)
        output, error = io.StringIO(), io.StringIO()
        with patch.object(u, 'update', side_effect=update), patch.object(u.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['nix',secret],1)), redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(u.main(), 1)
        self.assertIn('validate-candidate: command deadline exceeded', error.getvalue())
        self.assertNotIn(secret, output.getvalue()+error.getvalue())

    def test_publication_reports_http_permission_failure_without_credentialed_url(self):
        secret = 'fixture-sensitive-writer-value'
        def publish(rules):
            a.phase('create-input-pr')
            raise HTTPError('https://'+secret+'@example.invalid',403,secret,None,None)
        output, error = io.StringIO(), io.StringIO()
        with patch.object(a, 'inputs', side_effect=publish), patch.object(sys, 'argv', ['automation-forge.py','inputs']), redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(a.main(), 1)
        self.assertIn('create-input-pr: authorization (HTTP 403)', error.getvalue())
        self.assertNotIn(secret, output.getvalue()+error.getvalue())

    def test_unexpected_publication_error_hides_private_exception_text(self):
        secret = '/private/fixture-sensitive-file'
        def report(rules):
            a.phase('read-monitor-report')
            raise TypeError(secret)
        output, error = io.StringIO(), io.StringIO()
        with patch.object(a, 'report', side_effect=report), patch.object(sys, 'argv', ['automation-forge.py','report']), redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(a.main(), 1)
        self.assertIn('read-monitor-report: validation-failed', error.getvalue())
        self.assertNotIn(secret, output.getvalue()+error.getvalue())


class ImportFromDerivation(unittest.TestCase):
    def test_instantiation_loads_whole_flake_for_the_builder_system(self):
        with patch.object(u, 'ROOT', Path('/work/repo')):
            expression = u.instantiation_expression('x86_64-linux')
        # An empty flake fragment would select only the default package.
        self.assertIn('builtins.getFlake "git+file:///work/repo"', expression)
        self.assertIn('.x86_64-linux or {}', expression)
        self.assertIn('drvs "packages"', expression)
        self.assertIn('drvs "checks"', expression)

    def test_unexpected_system_is_not_interpolated(self):
        with self.assertRaises(ValueError):
            u.instantiation_expression('x86_64-linux; builtins.exec')

    @unittest.skipUnless(shutil.which('nix'), 'Nix required for instantiation fixture')
    def test_expression_evaluates_flakes_without_packages_or_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=root, check=True)
            (root/'flake.nix').write_text('{ outputs = {self}: {}; }')
            subprocess.run(['git', 'add', 'flake.nix'], cwd=root, check=True)
            with patch.object(u, 'ROOT', root):
                expression = u.instantiation_expression('x86_64-linux')
            value = subprocess.run(['nix', 'eval', '--impure', '--json', '--expr', expression],
                                   cwd=root, text=True, capture_output=True, check=True).stdout
            self.assertEqual(json.loads(value), {'packages': {}, 'checks': {}})


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
