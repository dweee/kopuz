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
    def test_updater_failure_detail_redacts_credentials(self):
        text = 'noise\nerror: unable to download https://u:p@api.github.com/x: HTTP error 403 ghp_abcDEF123 secret-tok'
        detail = u.safe_detail(text, 'secret-tok')
        self.assertIn('HTTP error 403', detail)
        for leaked in ['u:p', 'ghp_', 'secret-tok', 'noise']:
            self.assertNotIn(leaked, detail)

    def test_updater_gives_nix_the_github_token_through_the_environment_only(self):
        done = subprocess.CompletedProcess([], 0, 'ok', '')
        with patch.object(u.subprocess, 'run', return_value=done) as run, patch.dict(u.os.environ, {'GH_TOKEN': 'tok'}):
            u.run('nix', 'flake', 'lock')
        self.assertIn('access-tokens = github.com=tok', run.call_args.kwargs['env']['NIX_CONFIG'])
        self.assertNotIn('tok', run.call_args.args)

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

    def test_input_names_are_not_suffixes_of_other_nix_identifiers(self):
        for prefix in ['pumpkin-', 'other_', "other'", 'other']:
            for declaration in ['nixpkgs.url = "other";', 'nixpkgs = { url = "other"; };']:
                with self.subTest(prefix=prefix, declaration=declaration):
                    text = 'inputs = { nixpkgs.url = "selected"; ' + prefix + declaration + ' };'
                    self.assertEqual(u.url_match(text, 'nixpkgs').group(1), 'selected')
                    with self.assertRaises(ValueError):
                        u.url_match(prefix + declaration, 'nixpkgs')

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


class ApiRetries(unittest.TestCase):
    rules = {'forge': 'forgejo'}

    def test_get_retries_transport_failures_then_succeeds(self):
        calls = [TimeoutError('timed out'), HTTPError('u', 503, 'x', None, None), {'ok': True}]
        def once(*args):
            value = calls.pop(0)
            if isinstance(value, Exception): raise value
            return value
        with patch.object(a, 'api_once', side_effect=once), patch.object(a.time, 'sleep') as sleep:
            self.assertEqual(a.api(self.rules, 'GET', '/x'), {'ok': True})
        self.assertEqual([c.args[0] for c in sleep.call_args_list], list(a.API_RETRY_DELAYS))

    def test_retries_are_bounded(self):
        with patch.object(a, 'api_once', side_effect=TimeoutError('timed out')) as once, patch.object(a.time, 'sleep'):
            with self.assertRaises(TimeoutError): a.api(self.rules, 'GET', '/x')
        self.assertEqual(once.call_count, 1 + len(a.API_RETRY_DELAYS))

    def test_writes_and_client_errors_are_never_retried(self):
        for method, error in [('POST', TimeoutError('t')), ('PATCH', HTTPError('u', 503, 'x', None, None)),
                              ('GET', HTTPError('u', 403, 'x', None, None)), ('GET', HTTPError('u', 404, 'x', None, None)),
                              ('GET', ValueError('API redirect refused'))]:
            with patch.object(a, 'api_once', side_effect=error) as once, patch.object(a.time, 'sleep'):
                with self.assertRaises(type(error)): a.api(self.rules, method, '/x')
            self.assertEqual(once.call_count, 1, (method, error))


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


class CatalogAlignment(unittest.TestCase):
    def test_alignment_reads_the_catalog_lock_from_metadata_not_the_store_path(self):
        pin = {'type': 'github', 'owner': 'o', 'repo': 'r', 'rev': 'a'*40}
        catalog = {'path': '/nonexistent/lazy-tree', 'locks': {'root': 'root', 'nodes': {
            'root': {'inputs': {'nixpkgs': 'nixpkgs_2'}}, 'nixpkgs_2': {'locked': pin}}}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'ci').mkdir()
            (root/'ci/tracking-inputs.json').write_text(json.dumps({'version': 1, 'inputs': {
                'catalog': {'source': 'github:o/catalog/tested'}, 'nixpkgs': {'source': 'github:o/nixpkgs'}},
                'alignWith': {'input': 'catalog', 'inputs': ['nixpkgs']}}))
            (root/'flake.lock').write_text(json.dumps({'root': 'root', 'version': 7, 'nodes': {
                'root': {'inputs': {'catalog': 'catalog', 'nixpkgs': 'nixpkgs'}},
                'catalog': {'original': {'type': 'github'}}, 'nixpkgs': {'original': {'type': 'github'}}}}))
            calls = []
            def fake_run(*args):
                calls.append(args)
                if args[:3] == ('nix', 'flake', 'metadata'):
                    return json.dumps(catalog)
                if args[:3] == ('nix', 'flake', 'lock'):
                    raise u.channel.CommandFailure('stop after alignment')
                return ''
            with patch.object(u, 'ROOT', root), patch.object(u, 'run', fake_run):
                with self.assertRaisesRegex(u.channel.CommandFailure, 'stop after alignment'):
                    u.update()
            lock = next(c for c in calls if c[:3] == ('nix', 'flake', 'lock'))
            self.assertEqual(lock[lock.index('nixpkgs') + 1], 'github:o/r/' + 'a'*40)


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
            (consumer/'flake.nix').write_text('{ inputs.dep = { url = "'+source+'?rev='+old+'"; flake = false; }; inputs.other-dep = { url = "'+source+'?rev='+old+'"; flake = false; }; outputs = {self, dep, other-dep}: {}; }')
            (consumer/'ci').mkdir()
            (consumer/'ci/tracking-inputs.json').write_text(json.dumps({'version':1,'inputs':{'dep':{'source':source+'?ref=main'}, 'other-dep':{'source':source+'?rev='+old}}}))
            run(consumer, 'git', 'add', 'flake.nix', 'ci/tracking-inputs.json')
            run(consumer, 'nix', 'flake', 'lock')
            run(consumer, 'git', 'add', 'flake.lock')
            run(consumer, 'git', 'commit', '-m', 'Fixture consumer')
            (dependency/'source.txt').write_text('new')
            run(dependency, 'git', 'commit', '-am', 'Fixture new source')
            new = run(dependency, 'git', 'rev-parse', 'HEAD')
            with patch.object(u, 'ROOT', consumer):
                self.assertEqual(u.update(), ['dep'])
            updated = (consumer/'flake.nix').read_text()
            self.assertIn('rev='+new, u.url_match(updated, 'dep').group(1))
            self.assertIn('rev='+old, u.url_match(updated, 'other-dep').group(1))
            self.assertEqual(u.root_node(json.loads((consumer/'flake.lock').read_text()), 'other-dep')['locked']['rev'], old)
            locked = u.root_node(json.loads((consumer/'flake.lock').read_text()), 'dep')
            self.assertEqual(locked['locked']['rev'], new)
            self.assertEqual(locked['original']['rev'], new)



def git(cwd, *args):
    return subprocess.run(['git', *args], cwd=cwd, text=True, capture_output=True, check=True,
                          env=dict(a.os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.invalid',
                                   GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.invalid')).stdout.strip()


class FakeForge:
    """The few Forgejo/GitHub API calls the input publisher makes, with call records."""
    def __init__(self, repository='o/r'):
        self.repository, self.prs, self.calls, self.status, self.merge_error = repository, [], [], 'success', None
        self.changed_heads = {}

    def pr(self, number, ref, files=('flake.lock',), sha=None):
        value = {'number': number, 'body': a.INPUT_MARKER, 'base': {'ref': 'main'}, 'files': list(files),
                 'head': {'ref': ref, 'sha': sha or format(number, '040x'), 'repo': {'full_name': self.repository}}}
        self.prs.append(value)
        return value

    def __call__(self, rules, method, endpoint, data=None):
        self.calls.append((method, endpoint, data))
        prefix = '/repos/' + self.repository
        if method == 'GET' and endpoint == '/user':
            return {'login': 'flakey-updater'}
        if method == 'GET' and endpoint.startswith(prefix + '/pulls?'):
            for pr in self.prs:
                if pr['head']['ref'] == a.INPUT_BRANCH:
                    try:
                        pr['head']['sha'] = git(Path(rules['remote']), 'rev-parse', 'refs/heads/' + a.INPUT_BRANCH)
                    except subprocess.CalledProcessError:
                        pass
            page = int(endpoint.rsplit('page=', 1)[1])
            return [p for p in self.prs if p.get('state') != 'closed'][(page-1)*100:page*100]
        if method == 'POST' and endpoint == prefix + '/pulls':
            return self.pr(100 + len(self.prs), data['head'])
        if method == 'GET' and endpoint.startswith(prefix + '/commits/'):
            return {'state': self.status}
        if method == 'POST' and endpoint.endswith('/merge'):
            if self.merge_error:
                raise HTTPError('u', self.merge_error, 'm', None, None)
            return None
        if method == 'GET' and endpoint.endswith('/files?limit=100&per_page=100'):
            number = int(endpoint.split('/pulls/')[1].split('/')[0])
            return [f if isinstance(f, dict) else {'filename': f}
                    for p in self.prs if p['number'] == number for f in p['files']]
        if method == 'GET' and '/contents/' in endpoint:
            path, revision = endpoint.split('/contents/', 1)[1].split('?ref=', 1)
            try:
                return {'type': 'file', 'sha': git(a.channel.ROOT, 'rev-parse', revision + ':' + path)}
            except subprocess.CalledProcessError:
                raise HTTPError('u', 404, 'missing', None, None)
        if method == 'GET' and endpoint.startswith(prefix + '/pulls/'):
            number = int(endpoint.rsplit('/', 1)[1])
            pr = json.loads(json.dumps(next(p for p in self.prs if p['number'] == number)))
            pr.setdefault('state', 'open')
            if pr['head']['ref'] == a.INPUT_BRANCH:
                pr['head']['sha'] = git(Path(rules['remote']), 'rev-parse', 'refs/heads/' + a.INPUT_BRANCH)
            if number in self.changed_heads:
                pr['head']['sha'] = self.changed_heads[number]
            return pr
        if method == 'PATCH':
            number = int(endpoint.rsplit('/', 1)[1])
            next(p for p in self.prs if p['number'] == number)['state'] = data['state']
            return None
        if method == 'GET' and '/actions/workflows/' in endpoint:
            return {'workflow_runs': []}
        if method == 'POST' and endpoint.endswith('/dispatches'):
            return None
        raise AssertionError('unexpected API call ' + method + ' ' + endpoint)

    def made(self, method, suffix):
        return [c for c in self.calls if c[0] == method and c[1].endswith(suffix)]


class InputUpdatePR(unittest.TestCase):
    """One update branch and PR per repository, moved forward in place without force."""
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.origin, self.work = root / 'origin.git', root / 'work'
        git(root, 'init', '-q', '--bare', '-b', 'main', str(self.origin))
        git(root, 'clone', '-q', str(self.origin), str(self.work))
        (self.work / 'flake.nix').write_text('{ }\n')
        (self.work / 'flake.lock').write_text('{"pin": 0}\n')
        (self.work / 'README').write_text('fixture\n')
        git(self.work, 'add', '-A')
        git(self.work, 'commit', '-qm', 'base')
        git(self.work, 'push', '-q', 'origin', 'HEAD:refs/heads/main')
        self.forge = FakeForge()
        self.rules = {'forge': 'forgejo', 'repository': 'o/r', 'branch': 'main', 'remote': str(self.origin)}

    def land_on_main(self, name, text):
        git(self.work, 'fetch', '-q', 'origin', 'main')
        git(self.work, 'reset', '-q', '--hard', 'FETCH_HEAD')
        (self.work / name).write_text(text)
        git(self.work, 'commit', '-qam', 'landed ' + name)
        git(self.work, 'push', '-q', 'origin', 'HEAD:refs/heads/main')

    def publish(self, pin, **rules):
        """Resolve new pins on the current main, as the scheduled job does, and publish them."""
        git(self.work, 'fetch', '-q', 'origin', 'main')
        git(self.work, 'reset', '-q', '--hard', 'FETCH_HEAD')
        (self.work / 'flake.lock').write_text('{"pin": ' + str(pin) + '}\n')
        output = io.StringIO()
        with patch.object(a, 'api', self.forge), patch.object(a.channel, 'ROOT', self.work), \
                patch.dict(a.os.environ, {'AUTOMATION_TOKEN': 'fixture-token'}), redirect_stdout(output):
            a.inputs(dict(self.rules, **rules))
        return output.getvalue()

    def branch(self):
        return git(self.origin, 'rev-parse', 'refs/heads/' + a.INPUT_BRANCH)

    def proposal(self, revision):
        main = git(self.origin, 'rev-parse', 'refs/heads/main')
        return (git(self.origin, 'diff', '--name-only', main, revision),
                git(self.origin, 'show', revision + ':flake.lock'))

    def test_first_run_opens_one_pr_that_merges_itself_when_green(self):
        self.publish(1)
        self.assertEqual(self.proposal(self.branch()), ('flake.lock', '{"pin": 1}'))
        created = self.forge.made('POST', '/pulls')
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0][2]['head'], a.INPUT_BRANCH)
        self.assertEqual(self.forge.made('POST', '/merge')[0][2],
                         {'Do': 'squash', 'merge_when_checks_succeed': True, 'delete_branch_after_merge': True})

    def test_new_pins_update_the_same_pr_on_the_moved_main_without_force(self):
        self.publish(1)
        first = self.branch()
        self.land_on_main('README', 'moved\n')
        self.publish(2)
        second = self.branch()
        self.assertEqual(len(self.forge.made('POST', '/pulls')), 1)
        # A fast-forward of the old branch head, so a plain push succeeded.
        git(self.origin, 'merge-base', '--is-ancestor', first, second)
        self.assertEqual(self.proposal(second), ('flake.lock', '{"pin": 2}'))
        self.assertEqual(git(self.origin, 'show', second + ':README'), 'moved')

    def test_unchanged_pins_push_nothing(self):
        self.publish(1)
        first = self.branch()
        output = self.publish(1)
        self.assertIn('already proposes these pins', output)
        self.assertEqual(self.branch(), first)
        self.assertEqual(len(self.forge.made('POST', '/pulls')), 1)

    def test_running_checks_are_not_restarted_until_they_have_waited_too_long(self):
        self.publish(1)
        first = self.branch()
        self.forge.status = 'pending'
        self.assertIn('to finish its checks', self.publish(2))
        self.assertEqual(self.branch(), first)
        later = a.time.time() + a.PENDING_GRACE_SECONDS + 60
        with patch.object(a.time, 'time', return_value=later):
            self.publish(2)
        self.assertNotEqual(self.branch(), first)
        self.assertEqual(self.proposal(self.branch()), ('flake.lock', '{"pin": 2}'))

    def test_a_merged_and_deleted_branch_starts_a_fresh_pr_from_main(self):
        self.publish(1)
        self.forge.prs[0]['state'] = 'closed'
        git(self.origin, 'update-ref', '-d', 'refs/heads/' + a.INPUT_BRANCH)
        self.land_on_main('flake.lock', '{"pin": 1}\n')
        self.publish(2)
        main = git(self.origin, 'rev-parse', 'refs/heads/main')
        self.assertEqual(git(self.origin, 'rev-parse', self.branch() + '^@'), main)
        self.assertEqual(len(self.forge.made('POST', '/pulls')), 2)

    def test_legacy_input_only_prs_are_preserved_without_matching_pins(self):
        base = git(self.work, 'rev-parse', 'HEAD')
        pins_only = self.forge.pr(7, a.LEGACY_INPUT_PREFIX + 'a'*16, sha=base)
        fixed = self.forge.pr(8, a.LEGACY_INPUT_PREFIX + 'b'*16, files=('flake.lock', 'pkgs/fix.nix'))
        self.publish(1)
        self.assertNotIn('state', pins_only)
        self.assertNotIn('state', fixed)

    def test_equivalent_legacy_pins_can_close_after_fresh_head_verification(self):
        self.publish(1)
        old = self.forge.pr(7, a.LEGACY_INPUT_PREFIX + 'a'*16, sha=self.branch())
        self.publish(1)
        self.assertEqual(old.get('state'), 'closed')

    def test_missing_old_contents_and_changed_heads_are_preserved(self):
        self.publish(1)
        missing = self.forge.pr(7, a.LEGACY_INPUT_PREFIX + 'a'*16)
        changed = self.forge.pr(8, a.LEGACY_INPUT_PREFIX + 'b'*16, sha=self.branch())
        self.forge.changed_heads[8] = 'f'*40
        self.publish(1)
        self.assertNotIn('state', missing)
        self.assertNotIn('state', changed)

    def test_all_open_pr_pages_are_read_before_creating_a_pr(self):
        self.publish(1)
        current = self.forge.prs.pop()
        for number in range(200, 300):
            self.forge.pr(number, 'feature/' + str(number))
        self.forge.prs.append(current)
        self.publish(2)
        self.assertEqual(len(self.forge.made('POST', '/pulls')), 1)
        self.assertTrue(any('page=2' in call[1] for call in self.forge.calls))

    def test_flake_url_only_changes_are_recognized_without_masking_code_or_whitespace(self):
        text = '{ inputs.dep.url = "github:o/dep/old"; outputs = _: { value = 1; }; }\n'
        (self.work / 'flake.nix').write_text(text)
        (self.work / 'ci').mkdir()
        (self.work / 'ci/tracking-inputs.json').write_text('{"inputs":{"dep":{}}}')
        git(self.work, 'add', 'flake.nix', 'ci/tracking-inputs.json')
        git(self.work, 'commit', '-qm', 'tracked input fixture')
        base = git(self.work, 'rev-parse', 'HEAD')
        for change, expected in [(text.replace('/old', '/new'), True),
                                 (text.replace('value = 1', 'value = 2'), False),
                                 (text + '\n', False),
                                 (text.replace('/old', '/${revision}'), False),
                                 (text.replace('/old', '/\\${revision}'), False)]:
            (self.work / 'flake.nix').write_text(change)
            git(self.work, 'commit', '-qam', 'candidate change')
            head = git(self.work, 'rev-parse', 'HEAD')
            with patch.object(a.channel, 'ROOT', self.work):
                self.assertEqual(a.input_branch_is_pin_only(base, head), expected)

    def test_legacy_rename_does_not_hide_an_unproved_source_deletion(self):
        self.publish(1)
        old = self.forge.pr(7, a.LEGACY_INPUT_PREFIX + 'a'*16, sha=self.branch(),
                            files=({'filename': 'flake.lock', 'previous_filename': 'settings.json',
                                    'status': 'renamed'},))
        self.publish(1)
        self.assertNotIn('state', old)

    def test_changed_replacement_head_cannot_authorize_legacy_closure(self):
        self.publish(1)
        current = self.forge.prs[0]
        head = self.branch()
        old = self.forge.pr(7, a.LEGACY_INPUT_PREFIX + 'a'*16, sha=head)
        self.forge.changed_heads[current['number']] = 'f'*40
        with patch.object(a, 'api', self.forge), patch.object(a.channel, 'ROOT', self.work):
            a.consolidate_input_prs(self.rules, '/repos/o/r', [old], current, head)
        self.assertNotIn('state', old)

    def test_manual_source_edits_on_the_update_branch_are_not_removed(self):
        for filename, text in [('README', 'manual fix'), ('flake.nix', '{ outputs = _: {}; }')]:
            with self.subTest(filename=filename):
                self.publish(1)
                head = self.branch()
                git(self.work, 'checkout', '-q', '--detach', head)
                (self.work / filename).write_text(text)
                git(self.work, 'commit', '-qam', 'manual source fix')
                fixed = git(self.work, 'rev-parse', 'HEAD')
                git(self.work, 'push', '-q', 'origin', 'HEAD:refs/heads/' + a.INPUT_BRANCH)
                with self.assertRaisesRegex(ValueError, 'additional or unverified edits'):
                    self.publish(2)
                self.assertEqual(self.branch(), fixed)
                # A separate fixture is needed for the next manual edit case.
                git(self.origin, 'update-ref', '-d', 'refs/heads/' + a.INPUT_BRANCH)
                self.forge.prs.clear()

    def test_merge_scheduling_tolerates_already_scheduled_and_disallowed(self):
        self.forge.merge_error = 409
        self.publish(1)
        self.forge.merge_error = 405
        self.assertIn('awaits review', self.publish(2))

    def test_auto_merge_can_be_disabled_and_github_dispatches_checks_for_the_new_head(self):
        self.publish(1, inputAutoMerge=False)
        self.assertEqual(self.forge.made('POST', '/merge'), [])
        self.forge = FakeForge()
        with patch.object(a, 'attribution', return_value=''):
            self.publish(2, forge='github')
        self.assertEqual(self.forge.made('POST', '/merge'), [])
        runs = [c for c in self.forge.calls if '/actions/workflows/pr-checks.yml/runs?head_sha=' + self.branch() in c[1]]
        self.assertEqual(len(runs), 1)
        self.assertEqual(self.forge.made('POST', '/dispatches')[0][2], {'ref': a.INPUT_BRANCH})


if __name__ == '__main__': unittest.main()
