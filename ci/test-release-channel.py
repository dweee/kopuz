#!/usr/bin/env python3
import importlib.util
import json
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
    def test_truncated_nar_blocks_release(self):
        with patch.object(c, 'info', return_value={A: ENTRY}), patch.object(c, 'run', side_effect=RuntimeError('truncated')):
            with self.assertRaises(RuntimeError): c.verify([A], {A: ENTRY}, {})

    def test_metadata_mismatch_blocks_before_download(self):
        with patch.object(c, 'info', return_value={A: dict(ENTRY, narSize=99)}), patch.object(c, 'run') as run:
            with self.assertRaises(ValueError): c.verify([A], {A: ENTRY}, {})
            run.assert_not_called()

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
        with patch.object(c, 'evaluated_roots', return_value=[A]), patch.object(c, 'remote_closure', return_value={A:ENTRY}), patch.object(c, 'verify', return_value='c'*64):
            with self.assertRaises(ValueError): c.audit(rules,'a'*40,'aarch64-linux',record,{})

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


if __name__ == '__main__': unittest.main()
