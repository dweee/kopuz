import importlib.util
import contextlib
import errno
import io
import gzip
import subprocess
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('transfer', Path(__file__).with_name('transfer-attic.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TransferSafetyTests(unittest.TestCase):
    def test_transfer_limit_accepts_explicit_eight_gib_but_rejects_more(self):
        for value, expected in [('8192', 0), ('8193', 1), ('0', 1)]:
            with self.subTest(value=value), patch.dict(os.environ, {'ATTIC_MAX_CLOSURE_MIB': value}), \
                    patch.object(module, 'transfer') as transfer, \
                    patch('sys.argv', ['transfer', 'export', '--directory', '/tmp/fixture']), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(module.main(), expected)
                if not expected:
                    self.assertEqual(transfer.call_args.args[2], 8192 * 1024 * 1024)
                else:
                    transfer.assert_not_called()

    def test_safe_failure_categories_do_not_expose_exception_details(self):
        cases = [
            (module.TransferSizeExceeded('secret'), 'exceeded ATTIC_MAX_CLOSURE_MIB'),
            (OSError(errno.ENOSPC, 'secret'), 'disk space or quota'),
            (OSError(errno.EDQUOT, 'secret'), 'disk space or quota'),
            (OSError(errno.EACCES, 'secret'), 'transfer failed'),
            (ValueError('secret'), 'transfer failed'),
        ]
        for error, expected in cases:
            with self.subTest(error=error), patch.object(module, 'transfer', side_effect=error), \
                    patch('sys.argv', ['transfer', 'export', '--directory', '/tmp/fixture']), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(module.main(), 1)
                self.assertIn(expected, stderr.getvalue())
                self.assertNotIn('secret', stderr.getvalue())

    def test_oversize_stream_is_rejected_before_excess_is_written(self):
        target = io.BytesIO()
        with self.assertRaises(ValueError): module.copy_bounded(io.BytesIO(b'x' * 1025), target, 1024)
        self.assertEqual(target.getvalue(), b'')

    def test_bounded_stream_round_trips(self):
        target = io.BytesIO()
        self.assertEqual(module.copy_bounded(io.BytesIO(b'public fixture'), target, 100), 14)
        self.assertEqual(target.getvalue(), b'public fixture')

    def test_manifest_excludes_non_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / 'outputs.txt'
            for value in ['', '/tmp/credential', '/nix/store/' + 'a' * 32 + '-file.drv', '/nix/store/' + 'a' * 32 + '-file/child']:
                manifest.write_text(value)
                with self.subTest(value=value), self.assertRaises(ValueError): module.roots(manifest)

    def test_manifest_preserves_only_unique_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / 'outputs.txt';value='/nix/store/'+'a'*32+'-public'
            manifest.write_text(value+'\n'+value+'\n')
            self.assertEqual(module.roots(manifest), [value])

    def test_import_restores_official_signatures_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = '/nix/store/' + 'a' * 32 + '-custom-package'
            (directory / 'outputs.txt').write_text(root + '\n')
            with gzip.open(directory / 'closure.nar.gz', 'wb') as stream:
                stream.write(b'public data fixture')
            process = MagicMock()
            process.stdin = io.BytesIO()
            process.wait.return_value = 0
            process.poll.return_value = 0
            with patch.dict(os.environ, {}, clear=True), \
                    patch.object(module.subprocess, 'Popen', return_value=process), \
                    patch.object(module.policy, 'runtime', return_value=[root]) as guard, \
                    patch.object(module.subprocess, 'run') as call:
                module.transfer('import', directory, 1024)
            guard.assert_called_once_with([root])
            self.assertEqual(call.call_args_list[0].args[0], ['nix-store', '--check-validity', root])
            self.assertEqual(call.call_args_list[1].args[0],
                             ['nix', 'store', 'copy-sigs', '--substituter',
                              'https://cache.nixos.org', '--recursive', root])
            self.assertTrue(call.call_args_list[1].kwargs['check'])
            self.assertEqual(call.call_args_list[1].kwargs['timeout'], 120)

    def test_transfer_refuses_upload_credentials(self):
        for name in ['ATTIC_TOKEN','FLAKEY_ATTIC_TOKEN','NIKS3_WRITE_TOKEN','NIKS3_AUTH_TOKEN_FILE']:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {name:'synthetic-fixture'}):
                with self.assertRaises(ValueError): module.transfer('export', Path(temporary), 1024)

    def test_export_can_select_completed_build_manifest_without_changing_import_contract(self):
        with patch.object(module,'transfer') as transfer, \
                patch('sys.argv',['transfer','export','--directory','/tmp/archive','--manifest','cache-outputs.txt']):
            self.assertEqual(module.main(),0)
            self.assertEqual(transfer.call_args.args[3],Path('cache-outputs.txt'))
        with patch.object(module,'transfer') as transfer, \
                patch('sys.argv',['transfer','import','--directory','/tmp/archive','--manifest','cache-outputs.txt']), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(module.main(),1);transfer.assert_not_called()



if __name__ == '__main__': unittest.main()
