#!/usr/bin/env python3
import importlib.util
import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from threading import Event
from urllib.error import HTTPError
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
        self.assertEqual(report['origin'], 'niks3')
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

    @patch.dict(os.environ, {"NIX_REMOTE": ""})
    def test_read_only_nix_commands_retry_transient_failures_only(self):
        bad = subprocess.CompletedProcess(['nix'], 1, stdout='', stderr='error: HTTP/2 framing error')
        good = subprocess.CompletedProcess(['nix'], 0, stdout='ok\n', stderr='')
        with patch.object(c.subprocess, 'run', side_effect=[bad, good]) as run, patch.object(c.time, 'sleep'):
            self.assertEqual(c.run('nix', 'path-info', 'x'), 'ok')
        self.assertEqual(run.call_count, 2)
        missing = subprocess.CompletedProcess(['nix'], 1, stdout='', stderr="error: Cannot build '/nix/store/" + 'a'*32 + "-src.drv'")
        with patch.object(c.subprocess, 'run', side_effect=[missing, good]), patch.object(c.time, 'sleep'):
            self.assertEqual(c.run('nix', 'eval', 'x'), 'ok')
        # A build is never retried, and neither is a non-transient failure.
        with patch.object(c.subprocess, 'run', return_value=bad) as run, patch.object(c.time, 'sleep'):
            with self.assertRaises(c.CommandFailure): c.run('nix', 'build', 'x')
        self.assertEqual(run.call_count, 1)
        with patch.object(c.subprocess, 'run', return_value=missing) as run, patch.object(c.time, 'sleep'):
            with self.assertRaises(c.CommandFailure): c.run('nix', 'path-info', 'x')
        self.assertEqual(run.call_count, 1)

    def test_command_failure_detail_is_redacted(self):
        diagnostic = ('building\nerror: unable to download \'https://user:fixture-secret@host/x\': '
                      'HTTP error 503 for /nix/store/' + 'a'*32 + '-private ghp_abc123')
        result = subprocess.CompletedProcess(['nix'], 1, stdout='', stderr=diagnostic)
        with patch.object(c.subprocess, 'run', return_value=result), patch.object(c, 'TRANSPORT_RETRY_DELAYS', ()):
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
        with patch.dict(c.os.environ, {'SOURCE_TOKEN': 'fixture', 'CHANNEL_TOKEN': 'fixture'}):
            with c.build_environment({'PATH': '/bin'}):
                self.assertNotIn('SOURCE_TOKEN', c.os.environ)
                self.assertNotIn('CHANNEL_TOKEN', c.os.environ)
            self.assertEqual(c.os.environ['SOURCE_TOKEN'], 'fixture')

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


class CacheIdentity(unittest.TestCase):
    def load(self, forge):
        with patch.object(Path, 'read_text', return_value='{"forge":"%s"}' % forge):
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        return module

    def test_forgejo_uses_niks3_and_its_own_key(self):
        module = self.load('forgejo')
        self.assertEqual(module.CACHE, 'https://niks3.monke.fail')
        self.assertEqual(module.KEY, 'niks3.monke.fail-1:q13GqiZgAxx7SyoLZInXoJjviZMOdNpfG03xs0VUD2M=')

    def test_github_reads_through_the_oidc_route(self):
        module = self.load('github')
        self.assertEqual(module.CACHE, 'https://niks3.monke.fail/oidc')
        self.assertEqual(module.PUBLIC_CACHE, 'https://niks3.monke.fail')

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
        public = self.audit_proof('https://niks3.monke.fail')
        # A record written through one transport is accepted through the others.
        for server in ['https://niks3.monke.fail/oidc']:
            other = self.audit_proof(server)
            self.assertEqual(public[:2], other[:2])
            self.assertEqual(public[2], other[2])
            self.assertNotIn('/oidc', json.dumps(other[2]))

    def test_diagnostics_never_carry_the_transport(self):
        cached = dict(ENTRY, narSize=99)
        for cache in ['https://niks3.monke.fail', 'https://niks3.monke.fail/oidc']:
            output = io.StringIO()
            with patch.object(c, 'CACHE', cache), patch.object(c, 'info', return_value={A: cached}), \
                    patch.object(c, 'run', return_value=''), contextlib.redirect_stdout(output):
                c.verify([A], {A: ENTRY}, {})
            self.assertNotIn('monke.fail', output.getvalue())
            self.assertEqual(json.loads(output.getvalue().splitlines()[0].split(': ', 1)[1])['origin'], 'niks3')


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

    def test_promotion_gate_reads_signed_metadata_and_leaves_nar_bytes_to_the_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root/'artifact'
            artifact.write_text('Release channel metadata fixture; no compiler or production credential\n')
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
                full = c.verify([path], expected, dict(c.os.environ))
                self.assertEqual(c.verify_published([path], expected, dict(c.os.environ)), full)
                narinfo.write_text('\n'.join(line for line in signed.splitlines() if not line.startswith('Sig:'))+'\n')
                with self.assertRaises(RuntimeError): c.verify_published([path], expected, dict(c.os.environ))
                narinfo.write_text(signed)
                nar = next((root/'cache/nar').iterdir())
                nar.write_bytes(b'truncated NAR')
                # Honest scope: a corrupt NAR behind valid signed metadata passes
                # promotion; the scheduled content audit (verify) rejects it.
                self.assertEqual(c.verify_published([path], expected, dict(c.os.environ)), full)
                with self.assertRaises(RuntimeError): c.verify([path], expected, dict(c.os.environ))
                narinfo.unlink()
                with self.assertRaises(ValueError): c.verify_published([path], expected, dict(c.os.environ))
            with contextlib.redirect_stdout(io.StringIO()):
                manifest = c.release_manifest([path], dict(c.os.environ))
            self.assertRegex(manifest, c.MANIFEST.pattern)
            self.assertEqual(c.run('nix-store', '--query', '--references', manifest).split(), [path])


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


class PublishedMetadataGate(unittest.TestCase):
    """The promotion gate reads signed narinfo metadata only, in batches."""

    def commands(self, present, signatures_ok=True, calls=None):
        calls = [] if calls is None else calls
        def info(paths, env, store):
            calls.append(('info', tuple(paths), store))
            if any(p not in present.get(store, {}) for p in paths):
                raise c.CommandFailure("missing-input-or-output (exit 1): error: path '<store-path>' is not valid",
                                       'missing-input-or-output')
            return {p: present[store][p] for p in paths}
        def run(*args, env=None):
            calls.append(('run', args, env))
            if not signatures_ok:
                raise c.CommandFailure('cache-signature (exit 2)', 'cache-signature')
            return ''
        return info, run, calls

    def test_signed_metadata_passes_without_reading_nars_and_matches_the_full_proof(self):
        info, run, calls = self.commands({c.CACHE: {A: ENTRY}})
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', side_effect=run):
            proof = c.verify_published([A], {A: ENTRY}, {})
        self.assertEqual(proof, c.digest({'roots': [A], 'metadata': {A: ENTRY}}))
        verifies = [args for kind, args, _ in calls if kind == 'run']
        self.assertEqual(len(verifies), 1)
        self.assertIn('--no-contents', verifies[0])
        self.assertIn('--sigs-needed', verifies[0])
        self.assertNotIn('copy', verifies[0])

    def test_niks3_paths_need_the_niks3_key_and_upstream_paths_the_upstream_key(self):
        root = dict(ENTRY, references=[B])
        info, run, calls = self.commands({c.CACHE: {A: root}, c.UPSTREAM: {B: ENTRY}})
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', side_effect=run):
            c.verify_published([A], {A: root, B: ENTRY}, {})
        verifies = {args[args.index('--store')+1]: (args, env) for kind, args, env in calls if kind == 'run'}
        self.assertEqual(set(verifies), {c.CACHE, c.UPSTREAM})
        cache_config = verifies[c.CACHE][1]['NIX_CONFIG'].splitlines()[-1]
        upstream_config = verifies[c.UPSTREAM][1]['NIX_CONFIG'].splitlines()[-1]
        self.assertEqual(cache_config, 'trusted-public-keys = ' + c.KEY)
        self.assertEqual(upstream_config, 'trusted-public-keys = ' + c.UPSTREAM_KEY)
        self.assertIn(A, verifies[c.CACHE][0]); self.assertNotIn(B, verifies[c.CACHE][0])
        self.assertIn(B, verifies[c.UPSTREAM][0])

    def test_missing_root_fails_and_never_falls_back_to_upstream(self):
        info, run, calls = self.commands({c.CACHE: {}, c.UPSTREAM: {A: ENTRY}})
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', side_effect=run):
            with self.assertRaises(ValueError): c.verify_published([A], {A: ENTRY}, {})
        self.assertFalse(any(store == c.UPSTREAM for kind, _, store in calls if kind == 'info'))

    def test_path_missing_everywhere_fails(self):
        root = dict(ENTRY, references=[B])
        info, run, _ = self.commands({c.CACHE: {A: root}, c.UPSTREAM: {}})
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', side_effect=run):
            with self.assertRaises(ValueError): c.verify_published([A], {A: root, B: ENTRY}, {})

    def test_bad_signature_fails(self):
        info, run, _ = self.commands({c.CACHE: {A: ENTRY}}, signatures_ok=False)
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', side_effect=run):
            with self.assertRaises(c.CommandFailure) as raised: c.verify_published([A], {A: ENTRY}, {})
        self.assertEqual(raised.exception.category, 'cache-signature')

    def test_lookup_failures_other_than_missing_are_not_masked(self):
        def info(paths, env, store):
            raise c.CommandFailure('authorization (exit 1)', 'authorization')
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', return_value=''):
            with self.assertRaises(c.CommandFailure): c.verify_published([A], {A: ENTRY}, {})

    def test_missing_dependency_is_isolated_within_a_large_batch(self):
        names = ['/nix/store/' + format(n, '032d').translate(str.maketrans('0123456789', 'abcdfghijk')) + '-dep' for n in range(200)]
        lost = names[137]
        expected = {p: ENTRY for p in names}
        expected[A] = dict(ENTRY, references=names)
        cache = {p: e for p, e in expected.items() if p != lost}
        info, run, calls = self.commands({c.CACHE: cache, c.UPSTREAM: {lost: ENTRY}})
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', side_effect=run):
            c.verify_published([A], expected, {})
        upstream = [paths for kind, paths, store in calls if kind == 'info' and store == c.UPSTREAM]
        self.assertEqual(upstream, [(lost,)])
        lookups = [paths for kind, paths, store in calls if kind == 'info' and store == c.CACHE]
        self.assertLess(len(lookups), 40)

    def test_reference_or_size_mismatch_is_rejected_and_same_reference_rebuild_adopted(self):
        cached = dict(ENTRY, narHash='sha256-'+'B'*43+'=')
        info, run, _ = self.commands({c.CACHE: {A: cached}})
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', side_effect=run), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(c.verify_published([A], {A: ENTRY}, {}), c.digest({'roots': [A], 'metadata': {A: cached}}))
        info, run, _ = self.commands({c.CACHE: {A: dict(ENTRY, references=[A])}})
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', side_effect=run), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError): c.verify_published([A], {A: ENTRY}, {})
        root = dict(ENTRY, references=[B])
        info, run, _ = self.commands({c.CACHE: {A: root}, c.UPSTREAM: {B: dict(ENTRY, narSize=99)}})
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', side_effect=run), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError): c.verify_published([A], {A: root, B: ENTRY}, {})

    def test_incomplete_or_empty_closures_cannot_be_green(self):
        with self.assertRaises(ValueError): c.verify_published([A], {A: dict(ENTRY, references=[B])}, {})
        with self.assertRaises(ValueError): c.verify_published([], {}, {})

    def test_missing_path_diagnostics_are_classified(self):
        self.assertEqual(c.failure_category("error: path '/nix/store/x' is not valid"), 'missing-input-or-output')
        self.assertEqual(c.failure_category("path '/nix/store/x' is untrusted"), 'cache-signature')


class NativeCheckSelection(unittest.TestCase):
    def test_checks_reusing_inventory_outputs_are_skipped(self):
        outputs = {'hello': [A], 'multi': [A, B], 'real-test': ['/nix/store/' + 'c'*32 + '-test']}
        self.assertEqual(c.distinct_checks(outputs, [A]), ['multi', 'real-test'])
        self.assertEqual(c.distinct_checks(outputs, [A, B]), ['real-test'])
        self.assertEqual(c.distinct_checks({}, [A]), [])

    def test_check_outputs_are_validated(self):
        for value in [[], {'x': []}, {'x': ['/tmp/x']}, {'x': [A + '.drv']}]:
            with self.subTest(value=value), patch.object(c, 'run', return_value=json.dumps(value)):
                with self.assertRaises(ValueError): c.native_check_outputs('git+file:///x', 'x86_64-linux', {})
        with patch.object(c, 'run', return_value=json.dumps({'x': [A]})) as run:
            self.assertEqual(c.native_check_outputs('git+file:///x', 'x86_64-linux', {}), {'x': [A]})
        self.assertIn('max-jobs', run.call_args.args)


class LiveProgress(unittest.TestCase):
    ENV = {'STATUS_TOKEN': 'synthetic', 'GITHUB_SERVER_URL': 'https://github.com',
           'GITHUB_REPOSITORY': 'dweee/fixture', 'GITHUB_RUN_ID': '42'}

    def setUp(self):
        saved = dict(c.PROGRESS)
        self.addCleanup(lambda: (c.PROGRESS.clear(), c.PROGRESS.update(saved)))
        c.PROGRESS.update(system='x86_64-linux', sha='a'*40, id=None, last=0.0, disabled=False)

    def test_one_check_run_is_created_then_updated_and_completed(self):
        calls = []
        def request(method, path, body):
            calls.append((method, path, body))
            return {'id': 7} if method == 'POST' else {}
        with patch.dict(c.os.environ, self.ENV, clear=True), patch.object(c, 'progress_request', side_effect=request):
            self.assertTrue(c.progress('target 1/3 alpha', force=True))
            self.assertFalse(c.progress('target 2/3 beta'))
            self.assertTrue(c.progress('target 3/3 gamma', force=True))
            self.assertTrue(c.progress('passed', state='success'))
        self.assertEqual([m for m, _, _ in calls], ['POST', 'PATCH', 'PATCH'])
        self.assertEqual(calls[0][2]['name'], 'release progress / x86_64-linux')
        self.assertEqual(calls[0][2]['head_sha'], 'a'*40)
        self.assertEqual(calls[0][2]['details_url'], 'https://github.com/dweee/fixture/actions/runs/42')
        self.assertEqual(calls[1][1], '/check-runs/7')
        self.assertEqual(calls[1][2]['output']['title'], 'x86_64-linux target 3/3 gamma')
        self.assertEqual((calls[2][2]['status'], calls[2][2]['conclusion']), ('completed', 'success'))

    def test_progress_is_inert_without_a_trusted_github_token(self):
        for env in [{}, dict(self.ENV, STATUS_TOKEN=''), dict(self.ENV, GITHUB_SERVER_URL='https://git.monke.fail')]:
            with self.subTest(env=env), patch.dict(c.os.environ, env, clear=True), \
                    patch.object(c, 'progress_request') as request:
                self.assertFalse(c.progress('target 1/1 alpha', force=True))
                request.assert_not_called()

    def test_progress_failure_never_fails_the_gate_and_stops_further_calls(self):
        with patch.dict(c.os.environ, self.ENV, clear=True), \
                patch.object(c, 'progress_request', side_effect=OSError('offline')) as request, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(c.progress('target 1/1 alpha', force=True))
            self.assertFalse(c.progress('failed', state='failure'))
        self.assertEqual(request.call_count, 1)

    def test_status_token_never_reaches_nix_or_the_publisher(self):
        captured = {}
        def stop(rules, system, env):
            captured['env'] = env
            raise ValueError('stop')
        with patch.dict(c.os.environ, dict(self.ENV, PATH='/bin'), clear=True), \
                patch.object(c, 'policy', return_value={'forge': 'github', 'targets': {'x86_64-linux': []}}), \
                patch.object(c, 'source', return_value='a'*40), patch.object(c, 'progress', return_value=False), \
                patch.object(c, 'native_platform_ready', side_effect=stop):
            with self.assertRaises(ValueError): c.build('x86_64-linux')
        self.assertNotIn('STATUS_TOKEN', captured['env'])


class RetentionPins(unittest.TestCase):
    RULES = {'repository': 'dweee/fixture', 'forge': 'github', 'remote': 'https://github.com/dweee/fixture.git'}
    MANIFEST = '/nix/store/' + 'm'*32 + '-release-roots'

    def test_pin_names_are_fixed_roles_per_repository_and_system(self):
        self.assertEqual(c.pin_name(self.RULES, 'x86_64-linux', 'tested'), 'dweee-fixture.x86_64-linux.tested')
        self.assertEqual(c.pin_name(self.RULES, 'aarch64-darwin', 'stable-recent-3'), 'dweee-fixture.aarch64-darwin.stable-recent-3')
        for system, role in [('x86_64-linux', 'tested-recent-4'), ('x86_64-linux', 'arbitrary'), ('riscv64-linux', 'tested')]:
            with self.subTest(role=role), self.assertRaises(ValueError): c.pin_name(self.RULES, system, role)

    def test_recorded_manifests_become_role_pins_and_older_releases_are_reported(self):
        records = {'a'*40: {'retention': {'x86_64-linux': self.MANIFEST}}, 'b'*40: {'proofs': {}}}
        roles = {'tested': 'a'*40, 'tested-recent-1': 'a'*40, 'stable': 'b'*40}
        with contextlib.redirect_stdout(io.StringIO()) as output:
            pins = c.retention_pins(self.RULES, 'x86_64-linux', records, roles)
        self.assertEqual(pins, {'dweee-fixture.x86_64-linux.tested': self.MANIFEST,
                                'dweee-fixture.x86_64-linux.tested-recent-1': self.MANIFEST})
        self.assertIn('stable predates retention manifests', output.getvalue())
        self.assertEqual(c.retention_pins(self.RULES, 'aarch64-linux', records, {'tested': 'a'*40}), {})
        with self.assertRaises(ValueError):
            c.retention_pins(self.RULES, 'x86_64-linux', {'a'*40: {'retention': {'x86_64-linux': A}}}, {'tested': 'a'*40})

    def test_recovery_releases_are_pinned_before_the_candidate(self):
        calls = []
        def run(*args, env=None):
            calls.append(args)
            return ''
        records = {'a'*40: {'retention': {'x86_64-linux': self.MANIFEST}}}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(c, 'release_ledger', return_value=(records, {'tested': 'a'*40})), \
                patch.object(c, 'release_manifest', return_value=self.MANIFEST), \
                patch.object(c, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(c.pin_release(self.RULES, 'x86_64-linux', [A], {}, {}, directory), self.MANIFEST)
        self.assertIn('--pins', calls[0])
        self.assertIn('--pin', calls[1])
        self.assertEqual(calls[1][calls[1].index('--pin')+1], 'dweee-fixture.x86_64-linux.candidate')

    def test_promotion_records_validated_retention_manifests(self):
        rules = {'targets': {'x86_64-linux': []}, 'remote': 'https://github.com/dweee/fixture.git',
                 'repository': 'dweee/fixture', 'branch': 'main'}
        with patch.object(c, 'policy', return_value=rules):
            for retention in [{'x86_64-linux': A}, {'aarch64-linux': self.MANIFEST}]:
                with self.subTest(retention=retention), self.assertRaises(ValueError):
                    c.promote('tested', 'a'*40, {'x86_64-linux': 'b'*64}, retention)
        messages = []
        def run(*args, env=None):
            if args[:2] == ('git', 'rev-parse'): return 'a'*40
            if 'tag' in args and '-m' in args: messages.append(json.loads(args[args.index('-m')+1]))
            return ''
        with patch.object(c, 'policy', return_value=rules), patch.object(c, 'run', side_effect=run), \
                patch.dict(c.os.environ, {'CHANNEL_TOKEN': 'fixture'}), contextlib.redirect_stdout(io.StringIO()):
            c.promote('tested', 'a'*40, {'x86_64-linux': 'b'*64}, {'x86_64-linux': self.MANIFEST})
        self.assertEqual(messages[0]['retention'], {'x86_64-linux': self.MANIFEST})
        self.assertIs(messages[0]['activationAuthorized'], False)


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
            records,roles=c.release_ledger({'forge':'github','remote':repo.as_uri()})
            self.assertEqual(roles,{'tested':revisions[-1],'stable':revisions[0],
                                    'tested-recent-1':revisions[4],'tested-recent-2':revisions[3],
                                    'tested-recent-3':revisions[2],'stable-recent-1':revisions[0]})
            self.assertTrue(set(roles.values())<=set(records))


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


class BuildDependencies(unittest.TestCase):
    def test_recursive_graph_tracks_all_outputs_in_both_json_formats(self):
        graph = {'/nix/store/' + 'c'*32 + '-root.drv': {'outputs': {'out': {'path': A}, 'dev': {'path': B}}}}
        relative = {key.removeprefix('/nix/store/'): {'outputs': {name: {'path': value['path'].removeprefix('/nix/store/')} for name, value in entry['outputs'].items()}} for key, entry in graph.items()}
        for document in (graph, {'version': 3, 'derivations': graph}, {'version': 4, 'derivations': relative}):
            with patch.object(c, 'run', return_value=json.dumps(document)) as run:
                self.assertEqual(c.derivation_output_paths('fixture#package', {}), {A, B})
                self.assertIn('--recursive', run.call_args.args)
                self.assertNotIn('build', run.call_args.args)

    def test_json4_fixed_output_identities_are_resolved_by_nix_without_building(self):
        drv = '/nix/store/' + 'c'*32 + '-fetch.drv'
        graph = {'version': 4, 'derivations': {drv.removeprefix('/nix/store/'): {
            'outputs': {'out': {'hash': 'sha256-fixture', 'method': 'flat'}}}}}
        with patch.object(c, 'run', side_effect=[json.dumps(graph), B]) as run:
            self.assertEqual(c.derivation_output_paths('fixture#package', {}), {B})
            self.assertEqual(run.call_args.args, ('nix-store', '--query', '--outputs', drv))

    def test_unresolved_or_invalid_graph_outputs_fail_before_build(self):
        for output in ({}, {'path': None}, {'path': '/tmp/arbitrary'}, {'path': A + '.drv'}):
            graph = {'/nix/store/' + 'c'*32 + '-root.drv': {'outputs': {'out': output}}}
            with patch.object(c, 'run', return_value=json.dumps(graph)) as run:
                with self.assertRaises(ValueError): c.derivation_output_paths('fixture#package', {})
                self.assertEqual(run.call_count, 1)

    def test_only_valid_graph_outputs_are_selected_without_substitution(self):
        for document in ({A: None, B: dict(ENTRY, signatures=[])},
                         [None, dict(ENTRY, path=B, signatures=[])]):
            with patch.object(c, 'run', return_value=json.dumps(document)) as run:
                self.assertEqual(c.completed_build_outputs({A, B}, {}), [B])
                args = run.call_args.args
                self.assertEqual(args[:3], ('nix', 'path-info', '--json'))
                self.assertEqual(args[args.index('substituters')+1], '')
                self.assertEqual(args[args.index('extra-substituters')+1], '')
                self.assertNotIn('--all', args)
                self.assertNotIn('build', args)

    def test_unrelated_store_outputs_cannot_enter_dependency_publication(self):
        unrelated = '/nix/store/' + 'd'*32 + '-unrelated-private-output'
        with patch.object(c, 'run', return_value=json.dumps({unrelated: ENTRY})):
            with self.assertRaises(ValueError): c.completed_build_outputs({A, B}, {})

    def test_public_cache_pairs_match_the_reviewed_substituters(self):
        config = c.module('cache-config.py')
        expected = {
            'https://install.determinate.systems': 'cache.flakehub.com-3',
            'https://cache.lix.systems': 'cache.lix.systems',
            'https://nix-community.cachix.org': 'nix-community.cachix.org-1',
            'https://cache.nixos.org/': 'cache.nixos.org-1',
            'https://ai.cachix.org': 'ai.cachix.org-1',
            'https://cache.numtide.com': 'niks3.numtide.com-1',
            'https://codex-desktop-linux.cachix.org': 'codex-desktop-linux.cachix.org-1',
            'https://nix-on-droid.cachix.org': 'nix-on-droid.cachix.org-1',
            'https://virby-nix-darwin.cachix.org': 'virby-nix-darwin.cachix.org-1',
            'https://cache.nixos-cuda.org': 'cache.nixos-cuda.org',
            'https://cache.flox.dev': 'flox-cache-public-1',
        }
        self.assertEqual(set(config.PUBLIC), set(expected))
        self.assertEqual({url: key.split(':', 1)[0] for url, key in config.PUBLIC_CACHES.items()}, expected)

    @staticmethod
    def public_response(url, body=b'', *, status=200, headers=None):
        response = contextlib.closing(io.BytesIO(body))
        response.thing.status = status
        response.thing.url = url
        response.thing.headers = headers or {}
        return response

    def public_nar_response(self, url, size):
        return self.public_response(url, b'x', status=206, headers={'Content-Range': f'bytes 0-0/{size}'})

    def test_path_with_both_niks3_and_public_signatures_uses_live_public_proof(self):
        local = dict(ENTRY, signatures=['niks3.monke.fail-1:fixture', 'niks3.numtide.com-1:fixture'])
        origin = 'https://cache.numtide.com'
        narinfo = (f'StorePath: {A}\nURL: nar/example.nar.zst\nFileSize: 160\n'
                   'Sig: niks3.numtide.com-1:fixture\nSig: niks3.monke.fail-1:fixture\n')
        calls = []

        def request(req, timeout):
            byte_range = req.get_header('Range')
            calls.append((req.get_method(), req.full_url, byte_range))
            if byte_range is not None:
                return self.public_nar_response(req.full_url, 160)
            return self.public_response(req.full_url, narinfo.encode())

        def verify(paths, cache, reader, *, deadline):
            self.assertEqual(paths, [A])
            file = next(Path(cache.removeprefix('file://')).glob('*.narinfo'))
            self.assertEqual(file.read_bytes(), narinfo.encode())
            self.assertTrue(reader['NIX_CONFIG'].splitlines()[-1].startswith('trusted-public-keys = niks3.numtide.com-1:'))

        with patch.object(c, 'run', return_value=json.dumps({A: local})), \
                patch.object(c, 'build_opener', return_value=SimpleNamespace(open=request)), \
                patch.object(c, 'info', return_value={A: ENTRY}), \
                patch.object(c, 'verify_signatures', side_effect=verify) as check:
            self.assertEqual(c.completed_build_outputs({A}, {}), [])
            check.assert_called_once()
        self.assertEqual(calls, [('GET', origin + '/' + 'a'*32 + '.narinfo', None),
                                 ('GET', origin + '/nar/example.nar.zst', 'bytes=0-0')])

    def test_unauthorized_or_missing_public_narinfo_is_retained(self):
        local = dict(ENTRY, signatures=['cache.flakehub.com-3:fixture'])
        for status in (401, 403, 404):
            with self.subTest(status=status), patch.object(c, 'run', return_value=json.dumps({A: local})), \
                    patch.object(c, 'build_opener') as opener, patch.object(c, 'verify_signatures') as verify:
                url = 'https://install.determinate.systems/' + 'a'*32 + '.narinfo'
                opener.return_value.open.side_effect = HTTPError(url, status, 'fixture', {}, None)
                self.assertEqual(c.completed_build_outputs({A}, {}), [A])
                self.assertEqual(opener.return_value.open.call_args.args[0].full_url, url)
                verify.assert_not_called()

    def test_public_probe_rejections_keep_the_output(self):
        origin = 'https://cache.numtide.com'
        local = dict(ENTRY, signatures=['niks3.numtide.com-1:fixture'])
        wire = f'StorePath: {A}\nURL: nar/example.nar.zst\nFileSize: 160\nSig: niks3.numtide.com-1:fixture\n'.encode()
        cases = [
            (wire.replace(A.encode(), B.encode()), None, 1),
            (wire.replace(b'Sig:', b'Comment:'), None, 1),
            (wire + b'x' * 65536, None, 1),
            (wire.replace(b'nar/example.nar.zst', b'https://niks3.monke.fail/nar'), None, 1),
            (wire.replace(b'nar/example.nar.zst', b'https://cache.lantian.pub/nar'), None, 1),
            (wire.replace(b'nar/example.nar.zst', b'https://other.example/nar'), None, 1),
            (wire, 404, 2),
            (wire, TimeoutError(), 2),
        ]
        for body, nar_error, count in cases:
            def request(req, timeout):
                if req.full_url.endswith('.narinfo'):
                    return self.public_response(req.full_url, body)
                self.assertEqual(req.full_url, origin + '/nar/example.nar.zst')
                if isinstance(nar_error, Exception):
                    raise nar_error
                raise HTTPError(req.full_url, nar_error, 'fixture', {}, None)
            with self.subTest(nar_error=nar_error, calls=count), \
                    patch.object(c, 'run', return_value=json.dumps({A: local})), \
                    patch.object(c, 'build_opener') as opener, patch.object(c, 'info') as verify:
                opener.return_value.open.side_effect = request
                self.assertEqual(c.completed_build_outputs({A}, {}), [A])
                self.assertEqual(opener.return_value.open.call_count, count)
                verify.assert_not_called()

    def test_head_success_does_not_hide_a_forbidden_nar_get(self):
        local = dict(ENTRY, signatures=['niks3.numtide.com-1:fixture'])
        wire = f'StorePath: {A}\nURL: nar/example.nar.zst\nFileSize: 160\nSig: niks3.numtide.com-1:fixture\n'.encode()

        def request(req, timeout):
            if req.full_url.endswith('.narinfo'):
                return self.public_response(req.full_url, wire)
            if req.get_method() == 'HEAD':
                return self.public_response(req.full_url)
            self.assertEqual(req.get_header('Range'), 'bytes=0-0')
            raise HTTPError(req.full_url, 403, 'fixture', {}, None)

        with patch.object(c, 'run', return_value=json.dumps({A: local})), \
                patch.object(c, 'build_opener', return_value=SimpleNamespace(open=request)), \
                patch.object(c, 'info', return_value={A: ENTRY}), patch.object(c, 'verify_signatures') as verify:
            self.assertEqual(c.completed_build_outputs({A}, {}), [A])
            verify.assert_not_called()

    def test_nar_probe_validates_range_and_bounds_the_read(self):
        origin = 'https://cache.numtide.com'
        key = 'niks3.numtide.com-1:fixture'
        base = f'StorePath: {A}\nURL: nar/example.nar.zst\nSig: {key}\n'.encode()
        without_size = base + b'Compression: zstd\n'
        wire = without_size + b'FileSize: 160\n'
        for narinfo_body, status, headers, body, expected in (
            (wire, 206, {'Content-Range': 'bytes 0-0/160'}, b'x', wire),
            (wire, 206, {'Content-Range': 'bytes 0-0/1'}, b'x', None),
            (without_size, 206, {'Content-Range': 'bytes 0-0/160'}, b'\x28', without_size),
            (without_size, 206, {'Content-Range': 'bytes 0-0/71447'}, b'\x28', without_size),
            (without_size, 206, {'Content-Range': 'bytes 0-0/71447'}, b'<', None),
            (without_size, 206, {'Content-Range': 'bytes 0-0/0'}, b'\x28', None),
            (base + b'Compression: unknown\n', 206, {'Content-Range': 'bytes 0-0/71447'}, b'\x28', None),
            (base, 206, {'Content-Range': 'bytes 0-0/71447'}, b'\x28', None),
            (wire, 206, {'Content-Range': 'bytes 0-0/160'}, b'', None),
            (wire, 206, {'Content-Range': 'bytes 1-1/160'}, b'x', None),
            (wire, 206, {'Content-Range': 'bytes 0-0/160', 'Content-Length': '160'}, b'x', None),
            (wire, 206, {}, b'x', None),
            (wire, 200, {'Content-Type': 'text/html', 'Content-Length': '12'}, b'<p>error</p>', None),
        ):
            response = self.public_response(origin + '/nar/example.nar.zst', body, status=status, headers=headers)
            narinfo = self.public_response(origin + '/fixture.narinfo', narinfo_body)
            with self.subTest(status=status, headers=headers, body=body, narinfo=narinfo_body), \
                    patch.object(response.thing, 'read', wraps=response.thing.read) as read, \
                    patch.object(c, 'build_opener') as opener:
                opener.return_value.open.side_effect = [narinfo, response]
                item = (origin, key, A)
                results = list(c.probe_public_caches([item], c.time.monotonic() + 5))
                self.assertEqual(results, [(item, expected, 'nar-miss' if expected is None else None)])
                if expected is not None or body == b'<':
                    read.assert_called_once_with(1)
                if narinfo_body in (wire, without_size):
                    self.assertTrue(response.thing.closed)
                else:
                    opener.return_value.open.assert_called_once()
                    response.thing.close()

    def test_nar_probe_miss_logs_kept_paths_to_stderr(self):
        local = dict(ENTRY, signatures=['niks3.numtide.com-1:fixture'])
        stderr, stdout = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout), \
                patch.object(c, 'public_narinfo', side_effect=c.NarProbeMiss):
            self.assertEqual(c.served_build_outputs({A: local}, {}), set())
        self.assertEqual(stderr.getvalue(), 'Public NAR probe failed; kept 1 paths.\n')
        self.assertEqual(stdout.getvalue(), '')

    def test_public_redirects_are_misses(self):
        handler = c.PublicCacheRedirect()
        origin = 'https://cache.numtide.com'
        request = c.Request(origin + '/input', headers={'Range': 'bytes=0-0'})
        for target in (origin + '/same', 'http://cache.numtide.com/input', 'https://other.example/input',
                       'https://niks3.monke.fail/input', 'https://cache.lantian.pub/input'):
            with self.subTest(target=target):
                self.assertIsNone(handler.redirect_request(request, None, 302, 'fixture', {}, target))

    def test_origin_cutoff_keeps_paths_and_allows_other_origins(self):
        bad = dict(ENTRY, signatures=['niks3.numtide.com-1:fixture'])
        good = dict(ENTRY, signatures=['cache.nixos.org-1:fixture'])
        entries = {A: bad, B: bad, A + '-third': bad, B + '-other': good}

        def probe(origin, key, path, deadline):
            if origin == 'https://cache.numtide.com':
                raise TimeoutError
            return b'wire'

        log = io.StringIO()
        with contextlib.redirect_stderr(log), patch.object(c, 'METADATA_WORKERS', 1), \
                patch.object(c, 'PUBLIC_ORIGIN_FAILURES', 2), patch.object(c, 'public_narinfo', side_effect=probe) as probe, \
                patch.object(c, 'info', return_value={B + '-other': ENTRY}), patch.object(c, 'verify_signatures'):
            self.assertEqual(c.served_build_outputs(entries, {}), {B + '-other'})
        self.assertEqual(probe.call_count, 3)
        self.assertIn('origin cutoff reached; kept 1 paths', log.getvalue())
        self.assertIn('probing unavailable or incomplete; kept 3 paths', log.getvalue())

    def test_failed_nix_parse_retains_every_path_in_the_batch(self):
        local = dict(ENTRY, signatures=['cache.nixos.org-1:fixture'])
        with patch.object(c, 'public_narinfo', return_value=b'wire'), \
                patch.object(c, 'run', return_value=json.dumps({A: local, B: local})), \
                patch.object(c, 'info', side_effect=c.CommandFailure('malformed narinfo')) as info, \
                patch.object(c, 'verify_signatures') as verify:
            self.assertEqual(c.completed_build_outputs({A, B}, {}), [A, B])
        self.assertEqual(set(info.call_args.args[0]), {A, B})
        verify.assert_not_called()

    def test_shared_deadline_does_not_wait_for_a_stalled_probe(self):
        blocked, release = Event(), Event()

        def stall(*args):
            blocked.set()
            release.wait(timeout=5)

        log = io.StringIO()
        local = dict(ENTRY, signatures=['cache.nixos.org-1:fixture'])
        try:
            with contextlib.redirect_stderr(log), patch.object(c, 'PUBLIC_PROBE_SECONDS', 0.2), \
                    patch.object(c, 'run', return_value=json.dumps({A: local, B: local})), \
                    patch.object(c, 'public_narinfo', side_effect=stall):
                self.assertEqual(c.completed_build_outputs({A, B}, {}), [A, B])
                self.assertTrue(blocked.is_set())
                self.assertIn('deadline or origin cutoff reached; kept 2 paths', log.getvalue())
                self.assertIn('probing unavailable or incomplete; kept 2 paths', log.getvalue())
        finally:
            release.set()

    def test_blocked_origin_leaves_probe_workers_for_healthy_origin(self):
        release = Event()
        bad_calls = c.SimpleQueue()
        bad_origin = 'https://cache.numtide.com'
        bad = [(bad_origin, 'bad-key', f'{A}-{index}') for index in range(c.METADATA_WORKERS)]
        good = ('https://cache.nixos.org', 'good-key', B)

        def probe(origin, key, path, deadline):
            if origin == bad_origin:
                bad_calls.put(path)
                release.wait(timeout=5)
            else:
                return b'wire'

        try:
            with patch.object(c, 'public_narinfo', side_effect=probe):
                results = list(c.probe_public_caches([*bad, good], c.time.monotonic() + 0.5))
            self.assertEqual(results, [(good, b'wire', None)])
            self.assertEqual(bad_calls.qsize(), c.PUBLIC_ORIGIN_WORKERS)
        finally:
            release.set()

    def test_public_lookup_skips_ineligible_outputs_and_preserves_uncovered_references(self):
        entries = (
            dict(ENTRY, signatures=['hydra.nixos.org-1:fixture', 'niks3.monke.fail-1:fixture', 'lantian:fixture']),
            dict(ENTRY, signatures=['cache.nixos.org-1:fixture'], ultimate=True),
            dict(ENTRY, signatures=['cache.nixos.org-1:fixture'], references=[B]),
        )
        for entry in entries:
            with self.subTest(entry=entry), patch.object(c, 'run', return_value=json.dumps({A: entry})), \
                    patch.object(c, 'build_opener') as opener:
                self.assertEqual(c.completed_build_outputs({A}, {}), [A])
                opener.assert_not_called()

    @unittest.skipUnless(shutil.which('nix'), 'Nix required for signed cache fixture')
    def test_public_proof_cryptographically_binds_local_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            env = dict(os.environ, NIX_REMOTE=f'local?root={root / "store"}',
                       NIX_CONFIG='experimental-features = nix-command flakes\n')
            artifact = root / 'fixture'
            artifact.write_text('Signed public build output fixture\n')
            path = c.run('nix', 'store', 'add-path', str(artifact), env=env)
            c.run('nix-store', '--generate-binary-cache-key', 'public-fixture',
                  str(root/'secret'), str(root/'public'), env=env)
            c.run('nix', 'store', 'sign', '--key-file', str(root/'secret'), path, env=env)
            c.run('nix', 'copy', '--to', (root/'cache').as_uri(), path, env=env)
            signed = next((root/'cache').glob('*.narinfo')).read_bytes()
            size = next(line.removeprefix(b'FileSize: ').decode() for line in signed.splitlines()
                        if line.startswith(b'FileSize: '))
            key = (root/'public').read_text().strip()
            entry = dict(c.info([path], env)[path], ultimate=False)
            # Signing this fixture does not require its content-address claim.
            plain = b'\n'.join(line for line in signed.split(b'\n') if not line.startswith(b'CA:'))
            other_secret = root / 'other-secret'
            c.run('nix-store', '--generate-binary-cache-key', 'other-fixture',
                  str(other_secret), str(root/'other-public'), env=env)
            c.run('nix', 'store', 'sign', '--key-file', str(other_secret), path, env=env)
            c.run('nix', 'copy', '--to', (root/'other-cache').as_uri(), path, env=env)
            other_sig = next(line for line in next((root/'other-cache').glob('*.narinfo')).read_bytes().splitlines()
                             if line.startswith(b'Sig: other-fixture:'))
            wrong_signer = b'\n'.join(line for line in plain.splitlines() if not line.startswith(b'Sig:'))
            wrong_signer += b'\n' + other_sig + b'\nSig: public-fixture:' + b'A'*86 + b'==\n'
            env['NIX_CONFIG'] += f'secret-key-files = {other_secret}\n'
            for narinfo, expected, actual in (
                (plain, {path}, entry),
                (plain.rstrip(b'\n'), set(), entry),
                (plain.replace(b'\n', b'\r\n'), set(), entry),
                (plain + b'CA: invalid\n', set(), entry),
                (plain + b'Sig: invalid\n', set(), entry),
                (signed, set() if signed != plain else {path}, entry),
                (plain.replace(b'Sig: public-fixture:', b'Sig: public-fixture:A'), set(), entry),
                (plain, set(), dict(entry, narSize=entry['narSize'] + 1)),
                (wrong_signer, set(), entry),
            ):
                def request(req, timeout):
                    if req.get_header('Range') is not None:
                        return self.public_nar_response(req.full_url, size)
                    return self.public_response(req.full_url, narinfo)
                with patch.object(c, 'module', return_value=SimpleNamespace(PUBLIC_CACHES={'https://example.org': key})), \
                        patch.object(c, 'build_opener', return_value=SimpleNamespace(open=request)):
                    self.assertEqual(c.served_build_outputs({path: actual}, env), expected)

    def test_later_build_failure_still_publishes_completed_dependencies_and_propagates(self):
        graph = {'/nix/store/' + 'c'*32 + '-root.drv': {'outputs': {'out': {'path': A}, 'dev': {'path': B}}}}
        original = c.CommandFailure('fixture build failed')
        build_env = {'PATH': '/fixture/bin'}
        publisher_env = dict(build_env, NIKS3_WRITE_TOKEN='synthetic-writer')
        with tempfile.TemporaryDirectory() as temporary:
            outputs = Path(temporary) / 'outputs'
            def run(*args, **kwargs):
                if args[:3] == ('nix', 'derivation', 'show'):
                    self.assertEqual(kwargs['env'], build_env)
                    return json.dumps(graph)
                if args[:2] == ('nix', 'build'):
                    self.assertEqual(kwargs['env'], build_env)
                    raise original
                if args[:3] == ('nix', 'path-info', '--json'):
                    self.assertEqual(kwargs['env'], build_env)
                    return json.dumps({B: dict(ENTRY, signatures=[])})
                self.assertEqual(kwargs['env'], publisher_env)
                self.assertEqual(args[1], str(c.ROOT / 'ci/push-niks3.py'))
                self.assertEqual(outputs.read_text(), B + '\n')
                return ''
            with patch.object(c, 'run', side_effect=run) as commands, patch.object(c, 'info', return_value={B: ENTRY}):
                with self.assertRaises(c.CommandFailure) as raised:
                    c.build_with_dependencies('fixture#package', {'forge': 'forgejo'}, 'x86_64-linux',
                                              'private', build_env, publisher_env, outputs, 'build-required-output')
            self.assertIs(raised.exception, original)
            self.assertEqual(commands.call_count, 4)

    def test_publication_failure_blocks_a_successful_build(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(c, 'derivation_output_paths', return_value={A, B}), \
                patch.object(c, 'completed_build_outputs', return_value=[B]), patch.object(c, 'info', return_value={B: ENTRY}), \
                patch.object(c, 'run', side_effect=[A, c.CommandFailure('fixture upload failed')]):
            with self.assertRaises(c.CommandFailure):
                c.build_with_dependencies('fixture#package', {'forge': 'forgejo'}, 'x86_64-linux',
                                          'private', {}, {}, Path(temporary) / 'outputs', 'build-required-output')


class RetainedArchives(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        cache = root / 'cache'
        (cache / 'nar').mkdir(parents=True)
        (cache / 'nix-cache-info').write_text('StoreDir: /nix/store\n')
        stem = A.removeprefix('/nix/store/').split('-', 1)[0]
        (cache / (stem + '.narinfo')).write_text('StorePath: ' + A + '\nURL: nar/' + stem + '.nar\n')
        (cache / 'nar' / (stem + '.nar')).write_bytes(b'fixture data')
        rules = {'forge': 'github'}
        value = {'version': 1, 'commit': 'c'*40, 'policy': c.digest(rules),
                 'system': 'x86_64-linux', 'roots': [A], 'metadata': {A: ENTRY}, 'archivedPaths': [A]}
        proof = c.digest({'commit': value['commit'], 'policy': value['policy'], 'system': value['system'],
                          'closure': c.digest({'roots': [A], 'metadata': {A: ENTRY}})})
        record = {'proofs': {'x86_64-linux': proof}}
        (root / 'manifest.json').write_text(json.dumps(value))
        return root, value, rules, record

    def validate(self, root, rules, record):
        return c.archived_manifest(root, rules, 'c'*40, 'x86_64-linux', record, [A])

    def test_archive_must_reproduce_original_source_and_complete_metadata_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root, value, rules, record = self.fixture(directory)
            expected, origin, paths = self.validate(root, rules, record)
            self.assertEqual(expected, {A: ENTRY})
            self.assertEqual(paths, {A})
            self.assertEqual(origin, (root / 'cache').as_uri())
            for change in [{'commit': 'd'*40}, {'policy': 'e'*64}, {'roots': [B]},
                           {'metadata': {A: dict(ENTRY, narSize=99)}},
                           {'metadata': {A: dict(ENTRY, references=[B])}}]:
                (root / 'manifest.json').write_text(json.dumps(dict(value, **change)))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    self.validate(root, rules, record)

    def test_archive_cannot_redirect_to_network_or_escape_its_data_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root, value, rules, record = self.fixture(directory)
            info = next((root / 'cache').glob('*.narinfo'))
            for url in ['https://example.invalid/private', '../outside.nar', '/absolute.nar']:
                info.write_text('URL: ' + url + '\n')
                with self.subTest(url=url), self.assertRaises(ValueError):
                    self.validate(root, rules, record)
            info.write_text('URL: nar/' + 'a'*32 + '.nar\n')
            nar = root / 'cache/nar' / ('a'*32 + '.nar')
            nar.unlink()
            nar.symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                self.validate(root, rules, record)

    def test_archive_variants_still_read_nar_contents_and_require_the_legacy_signature(self):
        origin = 'file:///fixture/cache'
        with patch.object(c, 'info', return_value={A: ENTRY}) as info, \
                patch.object(c, 'run', return_value='') as run:
            proof = c.verify([A], {A: ENTRY}, {}, archived_cache=origin, archived_paths={A})
        self.assertEqual(proof, c.digest({'roots': [A], 'metadata': {A: ENTRY}}))
        self.assertTrue(all(call.args[2] == origin for call in info.call_args_list))
        self.assertIn('--sigs-needed', run.call_args.args)
        self.assertNotIn('--no-contents', run.call_args.args)
        self.assertIn(c.LEGACY_KEY, run.call_args.kwargs['env']['NIX_CONFIG'])
        # A signed alternate variant must still match the original metadata.
        with patch.object(c, 'info', return_value={A: dict(ENTRY, narSize=99)}), \
                patch.object(c, 'run', return_value=''):
            with self.assertRaises(ValueError):
                c.verify([A], {A: ENTRY}, {}, archived_cache=origin, archived_paths={A})

    def test_canonical_variants_cannot_be_adopted_during_archived_retention(self):
        with patch.object(c, 'info', return_value={A: dict(ENTRY, narSize=99)}), \
                patch.object(c, 'run', return_value=''):
            with self.assertRaises(ValueError):
                c.verify([A], {A: ENTRY}, {}, archived_cache='file:///fixture/cache', archived_paths={B})

    def test_original_signer_is_not_enabled_for_canonical_cache_reads(self):
        expected = {A: dict(ENTRY, references=[B]), B: ENTRY}
        def info(paths, env, origin):
            return {paths[0]: expected[paths[0]]}
        with patch.object(c, 'info', side_effect=info), patch.object(c, 'run', return_value='') as run:
            c.verify([A], expected, {}, archived_cache='file:///fixture/cache', archived_paths={A})
        settings = {call.args[-1]: call.kwargs['env']['NIX_CONFIG'] for call in run.call_args_list}
        self.assertIn(c.LEGACY_KEY, settings[A])
        self.assertNotIn(c.LEGACY_KEY, settings[B])

    def test_archive_nar_is_read_freshly_before_importing_and_validating_it(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(c, 'ROOT', Path(directory)):
            (Path(directory) / 'ci').mkdir()
            archive = A + '-archive'
            selection = {'version': 1, 'releases': {'c'*40: {'x86_64-linux': archive}}}
            (Path(directory) / 'ci/retained-archives.json').write_text(json.dumps(selection))
            with patch.object(c, 'run', return_value='') as run, \
                    patch.object(c, 'archived_manifest', return_value='validated'):
                self.assertEqual(c.retained_archive({}, 'c'*40, 'x86_64-linux', {}, [A], {}), 'validated')
            self.assertEqual(run.call_args_list[0].args,
                             ('nix', 'store', 'verify', '--store', c.CACHE, '--sigs-needed', '1', archive))
            self.assertEqual(run.call_args_list[1].args, ('nix', 'copy', '--from', c.CACHE, archive))

    def test_archive_selection_is_absent_by_default_and_rejects_non_store_paths(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(c, 'ROOT', Path(directory)):
            self.assertIsNone(c.retained_archive({}, 'c'*40, 'x86_64-linux', {}, [A], {}))
            (Path(directory) / 'ci').mkdir()
            selection = {'version': 1, 'releases': {'c'*40: {'x86_64-linux': '/tmp/untrusted'}}}
            (Path(directory) / 'ci/retained-archives.json').write_text(json.dumps(selection))
            with self.assertRaises(ValueError):
                c.retained_archive({}, 'c'*40, 'x86_64-linux', {}, [A], {})


if __name__ == '__main__': unittest.main()
