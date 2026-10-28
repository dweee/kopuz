#!/usr/bin/env python3
import importlib.util
import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import shutil
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('channel', Path(__file__).with_name('release-channel.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
A = '/nix/store/' + 'a'*32 + '-root'
B = '/nix/store/' + 'b'*32 + '-dependency'
ENTRY = {'narHash': 'sha256-'+'A'*43+'=', 'narSize': 12, 'references': []}


class Gates(unittest.TestCase):
    def test_metadata_mismatch_reports_fields_and_digests_without_paths(self):
        path = '/nix/store/' + 'a'*32 + '-fixture-secret'
        actual = dict(ENTRY, narSize=13, references=[B])
        output = io.StringIO()
        with patch.object(c, 'info', return_value={path:actual}), contextlib.redirect_stdout(output):
            with self.assertRaises(ValueError): c.verify([path], {path:ENTRY}, {})
        report = json.loads(output.getvalue().split(': ', 1)[1])
        self.assertEqual(report['fields'], ['narSize', 'references'])
        self.assertEqual(report['action'], 'rejected')
        self.assertTrue(report['root'])
        self.assertEqual(report['origin'], 'attic')
        self.assertEqual(report['expectedMetadataDigest'], c.digest(ENTRY))
        self.assertNotEqual(report['expectedMetadataDigest'], report['actualMetadataDigest'])
        self.assertNotIn('/nix/store', output.getvalue())
        self.assertNotIn('fixture-secret', output.getvalue())

    def test_command_failure_does_not_echo_secrets_or_store_paths(self):
        diagnostic = 'HTTP error 403 at /nix/store/' + 'a'*32 + '-private with token fixture-secret'
        result = subprocess.CompletedProcess(['nix'], 1, stdout='', stderr=diagnostic)
        with patch.object(c.subprocess, 'run', return_value=result):
            with self.assertRaises(c.CommandFailure) as raised: c.run('nix', 'eval')
        self.assertEqual(str(raised.exception), 'authorization (exit 1)')
        self.assertNotIn('fixture-secret', str(raised.exception))
        self.assertNotIn('/nix/store', str(raised.exception))

    def test_command_failure_detail_is_redacted(self):
        diagnostic = ('building\nerror: unable to download \'https://user:fixture-secret@host/x\': '
                      'HTTP error 503 for /nix/store/' + 'a'*32 + '-private ghp_abc123')
        result = subprocess.CompletedProcess(['nix'], 1, stdout='', stderr=diagnostic)
        with patch.object(c.subprocess, 'run', return_value=result):
            with self.assertRaises(c.CommandFailure) as raised: c.run('nix', 'build')
        text = str(raised.exception)
        self.assertTrue(text.startswith('transport (exit 1): error: unable to download'))
        for leak in ['fixture-secret', '/nix/store', 'ghp_abc123', 'private']:
            self.assertNotIn(leak, text)

    def test_fixed_diagnostic_categories_cover_cache_and_source_failures(self):
        self.assertEqual(c.failure_category('hash mismatch in fixed-output derivation'), 'source-hash-mismatch')
        self.assertEqual(c.failure_category('NAR hash mismatch'), 'cache-integrity')
        self.assertEqual(c.failure_category('path lacks a signature by a trusted key'), 'cache-signature')
        self.assertEqual(c.failure_category('HTTP/2 framing error'), 'transport')
        self.assertEqual(c.failure_category('attribute xyz missing'), 'evaluation')

    def test_truncated_nar_blocks_release(self):
        with patch.object(c, 'info', return_value={A: ENTRY}), patch.object(c, 'run', side_effect=RuntimeError('truncated')):
            with self.assertRaises(RuntimeError): c.verify([A], {A: ENTRY}, {})

    def test_reference_mismatch_blocks_before_download(self):
        with patch.object(c, 'info', return_value={A: dict(ENTRY, references=[A])}), patch.object(c, 'run') as run:
            with self.assertRaises(ValueError): c.verify([A], {A: ENTRY}, {})
            run.assert_not_called()

    def test_nonreproducible_rebuild_adopts_signed_cached_realisation(self):
        cached = dict(ENTRY, narHash='sha256-'+'B'*43+'=', narSize=13)
        output = io.StringIO()
        with patch.object(c, 'info', return_value={A: cached}), patch.object(c, 'run', return_value='') as run, contextlib.redirect_stdout(output):
            proof = c.verify([A], {A: ENTRY}, {})
        # The proof covers the cached metadata that a later audit reads remotely.
        self.assertEqual(proof, c.digest({'roots': [A], 'metadata': {A: cached}}))
        # The adopted NAR is still read and signature-checked, never skipped.
        self.assertEqual(run.call_count, 1)
        self.assertNotIn('--no-contents', run.call_args.args)
        report = json.loads(output.getvalue().splitlines()[0].split(': ', 1)[1])
        self.assertEqual(report['action'], 'adopted')
        self.assertEqual(report['fields'], ['narHash', 'narSize'])
        self.assertEqual(report['expectedMetadataDigest'], c.digest(ENTRY))
        self.assertEqual(report['actualMetadataDigest'], c.digest(cached))
        self.assertIn('Adopted 1 existing signed cache realisation', output.getvalue())
        self.assertNotIn('/nix/store', output.getvalue())

    def test_upstream_mismatch_is_never_adopted(self):
        root = dict(ENTRY, references=[B])
        def info(paths, env, origin):
            if paths == [B]:
                return {} if origin == c.CACHE else {B: dict(ENTRY, narSize=99)}
            return {A: root}
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', return_value=''):
            with self.assertRaises(ValueError): c.verify([A], {A: root, B: ENTRY}, {})

    def test_adopted_realisation_changed_during_read_blocks(self):
        cached = dict(ENTRY, narHash='sha256-'+'B'*43+'=')
        with patch.object(c, 'info', side_effect=[{A: cached}, {A: ENTRY}]), patch.object(c, 'run', return_value=''):
            with self.assertRaises(ValueError): c.verify([A], {A: ENTRY}, {})

    def test_metadata_retracted_after_read_blocks(self):
        with patch.object(c, 'info', side_effect=[{A: ENTRY}, {}]), patch.object(c, 'run'):
            with self.assertRaises(ValueError): c.verify([A], {A: ENTRY}, {})

    def test_roots_cannot_fall_back_to_upstream(self):
        with patch.object(c, 'info', return_value={}) as info, patch.object(c, 'run'):
            with self.assertRaises(ValueError): c.verify([A], {A: ENTRY}, {})
            self.assertEqual(info.call_args.args[2], c.CACHE)
            self.assertEqual(info.call_count, 1)

    def test_dependency_can_use_reviewed_upstream(self):
        root = dict(ENTRY, references=[B])
        calls = []
        def info(paths, env, origin):
            calls.append((paths, origin))
            return {} if paths == [B] and origin == c.CACHE else {p: root if p == A else ENTRY for p in paths}
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', return_value='') as run:
            self.assertRegex(c.verify([A], {A: root, B: ENTRY}, {}), r'^[a-f0-9]{64}$')
            self.assertTrue(any(origin == c.UPSTREAM for _, origin in calls))
            for call in run.call_args_list:
                self.assertIn('verify', call.args)
                self.assertIn('--sigs-needed', call.args)
                self.assertNotIn('--no-contents', call.args)

    def test_incomplete_transitive_closure_blocks(self):
        with self.assertRaises(ValueError): c.verify([A], {A: dict(ENTRY, references=[B])}, {})

    def test_no_outputs_cannot_be_green(self):
        with self.assertRaises(ValueError): c.verify([], {}, {})

    def test_missing_platform_proof_blocks_promotion(self):
        with patch.object(c, 'policy', return_value={'targets': {'aarch64-linux': []}}):
            with self.assertRaises(ValueError): c.promote('tested', 'a'*40, {})

    def test_build_environment_has_no_writer_credentials(self):
        with patch.dict(c.os.environ, {'ATTIC_TOKEN': 'fixture', 'CHANNEL_TOKEN': 'fixture'}):
            with c.build_environment({'PATH': '/bin'}):
                self.assertNotIn('ATTIC_TOKEN', c.os.environ)
                self.assertNotIn('CHANNEL_TOKEN', c.os.environ)
            self.assertEqual(c.os.environ['ATTIC_TOKEN'], 'fixture')

    def test_unreviewed_forge_is_rejected(self):
        rules = {'targets': {'aarch64-linux': []}, 'repository': 'd/example', 'remote': 'https://other.invalid/a.git'}
        with patch.object(c, 'policy', return_value=rules):
            with self.assertRaises(ValueError): c.promote('tested', 'a'*40, {'aarch64-linux': 'a'*64})

    def test_native_mismatch_cannot_build(self):
        with patch.object(c, 'policy', return_value={}), patch.object(c, 'source', return_value='a'*40), patch.object(c, 'run', return_value='x86_64-linux'):
            with self.assertRaises(ValueError): c.build('aarch64-linux')

    def test_cache_audit_requires_original_build_proof(self):
        rules = {'targets': {'aarch64-linux': []}}
        record = {'commit':'a'*40, 'policy':c.digest(rules), 'activationAuthorized':False,
                  'proofs':{'aarch64-linux':'b'*64}}
        output = io.StringIO()
        with patch.object(c, 'evaluated_roots', return_value=[A]), patch.object(c, 'remote_closure', return_value={A:ENTRY}), patch.object(c, 'verify', return_value='c'*64), contextlib.redirect_stdout(output):
            with self.assertRaises(ValueError): c.audit(rules,'a'*40,'aarch64-linux',record,{})
        line = next(line for line in output.getvalue().splitlines() if line.startswith('Retained proof mismatch: '))
        report = json.loads(line.split(': ', 1)[1])
        self.assertEqual(report['commit'], 'a'*40)
        self.assertEqual(report['system'], 'aarch64-linux')
        self.assertEqual(report['expectedProof'], 'b'*64)
        self.assertNotEqual(report['expectedProof'], report['actualProof'])
        self.assertEqual(report['rootCount'], 1)
        self.assertEqual(report['closurePathCount'], 1)
        self.assertEqual(report['rootsDigest'], c.digest([A]))
        self.assertNotIn('/nix/store', output.getvalue())

    def test_cache_audit_evaluation_disables_builders(self):
        rules = {'targets': {'aarch64-linux':[{'attribute':'packages.aarch64-linux.example'}]}}
        with patch.object(c, 'run', return_value=json.dumps([A])) as run:
            c.evaluated_roots(rules,'aarch64-linux',flake='git+file:///fixture')
            args = run.call_args.args
            self.assertEqual(args[:2], ('nix','eval'))
            self.assertIn('max-jobs',args)
            self.assertIn('0',args)
            self.assertIn('builders',args)
            self.assertNotIn('build',args)

    def test_missing_remote_root_cannot_trigger_source_build(self):
        with patch.object(c, 'info', return_value={}), patch.object(c, 'run') as run:
            with self.assertRaises(ValueError): c.remote_closure([A], {})
            run.assert_not_called()


class ReaderLifecycle(unittest.TestCase):
    def test_cli_cleanup_needs_no_token_and_preserves_existing_nix_config(self):
        helper = Path(__file__).with_name('configure-attic-read.py')
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)/'home'
            temporary = Path(directory)/'job'
            temporary.mkdir()
            config = home/'.config/nix/nix.conf'
            config.parent.mkdir(parents=True)
            config.write_text('sandbox = false\n')
            env = dict(os.environ, HOME=str(home), RUNNER_TEMP=str(temporary), ATTIC_TOKEN='fixture-token')
            subprocess.run([sys.executable, str(helper)], env=env, capture_output=True, check=True)
            credential = temporary/'flakey-attic.netrc'
            self.assertTrue(credential.exists())
            self.assertEqual(credential.stat().st_mode & 0o777, 0o600)
            env.pop('ATTIC_TOKEN')
            for _ in range(2):
                subprocess.run([sys.executable, str(helper), '--cleanup'], env=env, capture_output=True, check=True)
            self.assertFalse(credential.exists())
            self.assertEqual(config.read_text().strip(), 'sandbox = false')


PUBLIC = 'https://attic.monke.fail'
INTERNAL = 'http://172.29.0.1:8080'
TAILNET = 'http://icicle.eel-ling.ts.net:8080'
HELPER = Path(__file__).with_name('configure-attic-read.py')
configure_spec = importlib.util.spec_from_file_location('configure_attic_read', HELPER)
reader = importlib.util.module_from_spec(configure_spec)
configure_spec.loader.exec_module(reader)
REJECTED = ['http://attic.monke.fail', 'https://attic.example', 'http://172.29.0.1', 'http://172.29.0.1:8081',
            'https://172.29.0.1:8080', 'http://127.0.0.1:8080', 'http://172.29.0.1:8080/other',
            'http://172.29.0.1:8080@attic.monke.fail', 'attic.monke.fail',
            'https://icicle.eel-ling.ts.net:8080', 'http://icicle.eel-ling.ts.net', 'http://icicle.eel-ling.ts.net:8081',
            'http://icicle.eel-ling.ts.net:8080/other', 'http://other.eel-ling.ts.net:8080', 'http://100.126.145.24:8080',
            'http://icicle.eel-ling.ts.net.evil.example:8080']


class AtticServer(unittest.TestCase):
    def load(self, **env):
        scrubbed = {k: v for k, v in os.environ.items() if k != 'ATTIC_SERVER'}
        with patch.dict(os.environ, dict(scrubbed, **env), clear=True):
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        return module

    def test_public_cache_is_the_default(self):
        for env in [{}, {'ATTIC_SERVER': ''}, {'ATTIC_SERVER': ' '}, {'ATTIC_SERVER': PUBLIC}, {'ATTIC_SERVER': PUBLIC + '/'}]:
            with self.subTest(env=env):
                module = self.load(**env)
                self.assertEqual(module.CACHE, PUBLIC + '/flakey')
                self.assertEqual(module.PUBLIC_CACHE, PUBLIC + '/flakey')

    def test_internal_and_tailnet_servers_select_their_cache(self):
        for server in [INTERNAL, TAILNET]:
            for value in [server, server + '/']:
                with self.subTest(value=value):
                    module = self.load(ATTIC_SERVER=value)
                    self.assertEqual(module.CACHE, server + '/flakey')
                    self.assertEqual(module.PUBLIC_CACHE, PUBLIC + '/flakey')

    def test_only_reviewed_origins_are_accepted(self):
        for value in REJECTED:
            with self.subTest(value=value):
                with self.assertRaises(ValueError): c.attic_server({'ATTIC_SERVER': value})
                with self.assertRaises(SystemExit) as stop: self.load(ATTIC_SERVER=value)
                self.assertNotIn(value, str(stop.exception))

    def test_reader_helper_agrees_with_the_release_tool(self):
        for value in [None, '', PUBLIC, PUBLIC + '/', INTERNAL, INTERNAL + '/', TAILNET, TAILNET + '/'] + REJECTED:
            with self.subTest(value=value):
                env = {} if value is None else {'ATTIC_SERVER': value}
                with patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != 'ATTIC_SERVER'}, clear=True):
                    os.environ.update(env)
                    try: expected = c.attic_server()
                    except ValueError: expected = ValueError
                    try: actual = reader.attic_server()
                    except ValueError: actual = ValueError
                self.assertEqual(actual, expected)

    def audit_proof(self, cache):
        rules = {'targets': {'aarch64-linux': []}}
        with patch.object(c, 'CACHE', cache), patch.object(c, 'info', return_value={A: ENTRY}) as info, \
                patch.object(c, 'run', return_value='') as run, patch.object(c, 'evaluated_roots', return_value=[A]), \
                patch.object(c, 'remote_closure', return_value={A: ENTRY}):
            closure = c.verify([A], {A: ENTRY}, {})
            proof = c.digest({'commit': 'a'*40, 'policy': c.digest(rules), 'system': 'aarch64-linux', 'closure': closure})
            record = {'commit': 'a'*40, 'policy': c.digest(rules), 'activationAuthorized': False,
                      'proofs': {'aarch64-linux': proof}}
            audited = c.audit(rules, 'a'*40, 'aarch64-linux', record, {})
        self.assertEqual(run.call_args.args[run.call_args.args.index('--store') + 1], cache)
        self.assertEqual({call.args[2] for call in info.call_args_list}, {cache})
        return closure, proof, audited

    def test_proofs_are_identical_whichever_transport_read_the_cache(self):
        public = self.audit_proof(PUBLIC + '/flakey')
        # A record written through one transport is accepted through the others.
        for server in [INTERNAL, TAILNET]:
            other = self.audit_proof(server + '/flakey')
            self.assertEqual(public[:2], other[:2])
            self.assertEqual(public[2], other[2])
            self.assertNotIn('attic', json.dumps(other[2]))
            self.assertNotIn('172.29', json.dumps(other[2]))
            self.assertNotIn('ts.net', json.dumps(other[2]))

    def test_diagnostics_never_carry_the_transport(self):
        cached = dict(ENTRY, narSize=99)
        for cache in [PUBLIC + '/flakey', INTERNAL + '/flakey', TAILNET + '/flakey']:
            output = io.StringIO()
            with patch.object(c, 'CACHE', cache), patch.object(c, 'info', return_value={A: cached}), \
                    patch.object(c, 'run', return_value=''), contextlib.redirect_stdout(output):
                c.verify([A], {A: ENTRY}, {})
            self.assertNotIn('172.29', output.getvalue())
            self.assertNotIn('ts.net', output.getvalue())
            self.assertNotIn('monke.fail', output.getvalue())
            self.assertEqual(json.loads(output.getvalue().splitlines()[0].split(': ', 1)[1])['origin'], 'attic')


class ReaderEndpoint(unittest.TestCase):
    def configure(self, **extra):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)/'home'
            temporary = Path(directory)/'job'
            temporary.mkdir()
            config = home/'.config/nix/nix.conf'
            config.parent.mkdir(parents=True)
            config.write_text('sandbox = false\n')
            env = {k: v for k, v in os.environ.items() if k != 'ATTIC_SERVER'}
            env.update(HOME=str(home), RUNNER_TEMP=str(temporary), ATTIC_TOKEN='fixture-token', **extra)
            result = subprocess.run([sys.executable, str(HELPER)], env=env, capture_output=True, text=True)
            netrc = temporary/'flakey-attic.netrc'
            return (result, netrc.read_text() if netrc.exists() else None, config.read_text(),
                    oct(netrc.stat().st_mode & 0o777) if netrc.exists() else None)

    def test_public_server_is_unchanged(self):
        result, netrc, config, mode = self.configure()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(netrc, 'machine attic.monke.fail login ci password fixture-token\n')
        self.assertEqual(mode, '0o600')
        self.assertIn('extra-substituters = https://attic.monke.fail/flakey\n', config)
        self.assertIn('extra-trusted-public-keys = ' + c.KEY + '\n', config)
        self.assertNotIn('172.29', config)

    def test_internal_server_scopes_the_credential_to_that_host_only(self):
        result, netrc, config, mode = self.configure(ATTIC_SERVER=INTERNAL)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(netrc, 'machine 172.29.0.1 login ci password fixture-token\n')
        self.assertEqual(mode, '0o600')
        self.assertIn('extra-substituters = http://172.29.0.1:8080/flakey\n', config)
        # Same keys: the internal endpoint serves the same signed cache.
        self.assertIn('extra-trusted-public-keys = ' + c.KEY + '\n', config)
        self.assertNotIn('attic.monke.fail', netrc + config)
        self.assertNotIn('ts.net', netrc + config)
        self.assertNotIn('fixture-token', config + result.stdout + result.stderr)

    def test_tailnet_server_scopes_the_credential_to_its_host_only(self):
        result, netrc, config, mode = self.configure(ATTIC_SERVER=TAILNET)
        self.assertEqual(result.returncode, 0)
        # Host only, as netrc matches: no port, scheme or other origin.
        self.assertEqual(netrc, 'machine icicle.eel-ling.ts.net login ci password fixture-token\n')
        self.assertEqual(mode, '0o600')
        self.assertIn('extra-substituters = http://icicle.eel-ling.ts.net:8080/flakey\n', config)
        self.assertIn('extra-trusted-public-keys = ' + c.KEY + '\n', config)
        self.assertNotIn('attic.monke.fail', netrc + config)
        self.assertNotIn('172.29', netrc + config)
        self.assertNotIn('fixture-token', config + result.stdout + result.stderr)

    def test_unreviewed_server_writes_no_credential_and_no_config(self):
        for value in REJECTED:
            with self.subTest(value=value):
                result, netrc, config, _ = self.configure(ATTIC_SERVER=value)
                self.assertEqual(result.returncode, 1)
                self.assertIsNone(netrc)
                self.assertEqual(config, 'sandbox = false\n')
                self.assertNotIn('fixture-token', result.stdout + result.stderr)

    def test_cleanup_still_removes_the_internal_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)/'home'
            temporary = Path(directory)/'job'
            temporary.mkdir()
            env = dict(os.environ, HOME=str(home), RUNNER_TEMP=str(temporary), ATTIC_TOKEN='fixture-token', ATTIC_SERVER=INTERNAL)
            subprocess.run([sys.executable, str(HELPER)], env=env, capture_output=True, check=True)
            subprocess.run([sys.executable, str(HELPER), '--cleanup'], env=env, capture_output=True, check=True)
            self.assertFalse((temporary/'flakey-attic.netrc').exists())
            self.assertNotIn('172.29', (home/'.config/nix/nix.conf').read_text())


@unittest.skipUnless(shutil.which('nix'), 'Nix required for signed cache fixture')
class RealCache(unittest.TestCase):
    def test_local_output_cannot_hide_corrupt_missing_or_unsigned_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root/'artifact'
            artifact.write_text('Release channel NAR fixture; no compiler or production credential\n')
            path = c.run('nix', 'store', 'add-path', str(artifact))
            c.run('nix-store', '--generate-binary-cache-key', 'channel-fixture', str(root/'secret'), str(root/'public'))
            c.run('nix', 'store', 'sign', '--key-file', str(root/'secret'), path)
            cache = (root/'cache').as_uri()
            c.run('nix', 'copy', '--to', cache, path)
            narinfo = next((root/'cache').glob('*.narinfo'))
            signed = '\n'.join(line for line in narinfo.read_text().splitlines() if not line.startswith('CA:'))+'\n'
            narinfo.write_text(signed)
            expected = c.info([path], dict(c.os.environ))
            with patch.object(c, 'CACHE', cache), patch.object(c, 'KEY', (root/'public').read_text().strip()):
                closure = c.verify([path], expected, dict(c.os.environ))
                self.assertRegex(closure, r'^[a-f0-9]{64}$')
                rules = {'targets': {'aarch64-linux': []}}
                record = {'commit':'a'*40, 'policy':c.digest(rules), 'activationAuthorized':False,
                          'proofs': {'aarch64-linux':c.digest({'commit':'a'*40,'policy':c.digest(rules),'system':'aarch64-linux','closure':closure})}}
                with patch.object(c,'evaluated_roots',return_value=[path]):
                    c.audit(rules,'a'*40,'aarch64-linux',record,dict(c.os.environ))
                narinfo.write_text('\n'.join(line for line in signed.splitlines() if not line.startswith('Sig:'))+'\n')
                with self.assertRaises(RuntimeError): c.verify([path], expected, dict(c.os.environ))
                narinfo.write_text(signed)
                nar = next((root/'cache/nar').iterdir())
                nar.write_bytes(b'truncated NAR')
                with self.assertRaises(RuntimeError): c.verify([path], expected, dict(c.os.environ))
                nar.unlink()
                with self.assertRaises(RuntimeError): c.verify([path], expected, dict(c.os.environ))
                self.assertIn(path, c.info([path], dict(c.os.environ)))


class RetentionDiagnostics(unittest.TestCase):
    def test_ledger_fetch_failure_reports_retention_phase(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['release-channel.py', 'retain', '--system', 'x86_64-linux']), \
             patch.object(c, 'policy', return_value={}), \
             patch.object(c, 'release_refs', side_effect=c.CommandFailure('transport (exit 128)')), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(c.main(), 1)
        self.assertIn('failed during read-release-ledgers: transport (exit 128)', output.getvalue())
        self.assertIn('the previous channel is retained', output.getvalue())

    def test_retained_audit_failures_report_the_operation_without_private_values(self):
        rules = {'targets': {'x86_64-linux': []}}
        sha = 'a'*40
        record = {'commit': sha, 'policy': c.digest(rules), 'activationAuthorized': False,
                  'proofs': {'x86_64-linux': 'b'*64}}
        failures = [('evaluated_roots', 'evaluate-retained-roots'),
                    ('remote_closure', 'discover-retained-closure'),
                    ('verify', 'verify-retained-cache')]
        for operation, expected_phase in failures:
            with self.subTest(operation=operation):
                output = io.StringIO()
                with patch.object(sys, 'argv', ['release-channel.py', 'retain', '--system', 'x86_64-linux']), \
                     patch.object(c, 'retain', side_effect=lambda system: c.audit(rules, sha, system, record, {})), \
                     patch.object(c, 'evaluated_roots', return_value=[A]), \
                     patch.object(c, 'remote_closure', return_value={A: ENTRY}), \
                     patch.object(c, 'verify', return_value='c'*64), \
                     patch.object(c, operation, side_effect=c.CommandFailure('command-failed (exit 4)')), \
                     contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    self.assertEqual(c.main(), 1)
                self.assertIn('failed during '+expected_phase+': command-failed (exit 4)', output.getvalue())
                self.assertIn('the previous channel is retained', output.getvalue())
                self.assertNotIn('/nix/store', output.getvalue())
                self.assertNotIn(sha, output.getvalue())


class RetentionSelection(unittest.TestCase):
    def test_advertised_old_stable_and_three_recent_releases_are_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)/'source'
            def git(*args, env=None):
                return c.subprocess.check_output(['git','-C',str(repo),*args], env=env, stderr=c.subprocess.PIPE, text=True).strip()
            c.subprocess.run(['git','init','-q','-b','main',str(repo)],check=True)
            git('config','user.name','Fixture')
            git('config','user.email','fixture@example.invalid')
            revisions=[]
            for number in range(5):
                (repo/'file').write_text(str(number))
                git('add','file')
                git('commit','-qm','Fixture '+str(number))
                sha=git('rev-parse','HEAD')
                revisions.append(sha)
                env=dict(c.os.environ,GIT_COMMITTER_DATE='2020-01-0'+str(number+1)+'T00:00:00Z')
                git('tag','-a','tested-'+sha,'-m',json.dumps({'commit':sha}),env=env)
            git('tag','-a','stable-'+revisions[0],revisions[0],'-m',json.dumps({'commit':revisions[0]}))
            git('branch','tested',revisions[-1])
            git('branch','stable',revisions[0])
            records=c.release_refs({'forge':'github','remote':repo.as_uri()})
            self.assertEqual(set(records),set(revisions[-3:]+[revisions[0]]))


@unittest.skipUnless(shutil.which('nix'), 'Nix required for whole-flake evaluation fixture')
class WholeFlakeEvaluation(unittest.TestCase):
    def test_cache_roots_and_checks_are_selected_from_the_complete_flake(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)/'source'
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE,text=True).strip()
            git('init','-q','-b','main')
            git('config','user.name','Fixture')
            git('config','user.email','fixture@example.invalid')
            (repo/'flake.nix').write_text('''{ outputs = { self }: {
              packages.x86_64-linux.default = { wrongDefault = true; };
              packages.x86_64-linux.fixture = {
                outputs = [ "out" ]; out.outPath = "'''+A+'''";
              };
              checks.x86_64-linux.smoke = 1;
            }; }''')
            git('add','flake.nix')
            git('commit','-qm','Fixture whole flake')
            flake = 'git+'+repo.as_uri()+'?rev='+git('rev-parse','HEAD')
            rules = {'targets':{'x86_64-linux':[{'attribute':'packages.x86_64-linux.fixture'}]}}
            self.assertEqual(c.evaluated_roots(rules,'x86_64-linux',flake=flake),[A])
            self.assertEqual(c.native_check_names(flake,'x86_64-linux',dict(os.environ)),['smoke'])
            self.assertEqual(c.native_check_names(flake,'aarch64-linux',dict(os.environ)),[])


if __name__ == '__main__': unittest.main()
