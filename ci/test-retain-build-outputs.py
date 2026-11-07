import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('retention',Path(__file__).with_name('retain-build-outputs.py'))
retention=importlib.util.module_from_spec(spec);spec.loader.exec_module(retention)
A='/nix/store/'+'a'*32+'-selected'
B='/nix/store/'+'b'*32+'-completed-dependency'
C='/nix/store/'+'c'*32+'-unrelated-store-member'


class Retention(unittest.TestCase):
    def test_failure_retains_completed_graph_dependencies_and_original_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest=Path(temporary)/'cache-outputs.txt';manifest.write_text(C+'\n')
            argv=['retain','--target','.#packages.x86_64-linux.sample','--manifest',str(manifest),
                  '--','nix','build','.#packages.x86_64-linux.sample','--print-out-paths']
            with patch.object(sys,'argv',argv),patch.dict(os.environ,{},clear=True), \
                    patch.object(retention.public,'derivation') as source_guard, \
                    patch.object(retention.channel,'derivation_output_paths',return_value={A,B}), \
                    patch.object(retention.channel,'completed_build_outputs',return_value=[B]) as completed, \
                    patch.object(retention.public,'runtime',return_value=[B]) as runtime, \
                    patch.object(retention.subprocess,'run',return_value=subprocess.CompletedProcess([],23,'')):
                self.assertEqual(retention.main(),23)
            self.assertEqual(manifest.read_text(),B+'\n')
            self.assertEqual(completed.call_args.args[0],{A,B})
            source_guard.assert_called_once()
            runtime.assert_called_once_with([B])

    def test_no_completed_output_removes_stale_manifest_without_export_authorization(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest=Path(temporary)/'outputs';manifest.write_text(C+'\n')
            with patch.object(retention.public,'derivation'), \
                    patch.object(retention.channel,'derivation_output_paths',return_value={A,B}), \
                    patch.object(retention.channel,'completed_build_outputs',return_value=[]), \
                    patch.object(retention.public,'runtime') as runtime:
                collector=retention.Collector(['.#sample'],manifest,{})
                collector.retain()
            self.assertFalse(manifest.exists());runtime.assert_not_called()

    def test_reviewed_multitarget_script_retains_completed_check_outputs_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);script=directory/'build.sh';script.write_text('exit 7\n')
            manifest=directory/'cache'
            argv=['retain','--target','.#package','--target','.#check','--manifest',str(manifest),'--script',str(script)]
            with patch.object(sys,'argv',argv),patch.dict(os.environ,{},clear=True), \
                    patch.object(retention.public,'derivation'), \
                    patch.object(retention.channel,'derivation_output_paths',side_effect=[{A},{B}]), \
                    patch.object(retention.channel,'completed_build_outputs',return_value=[A,B]), \
                    patch.object(retention.public,'runtime'), \
                    patch.object(retention.subprocess,'run',return_value=subprocess.CompletedProcess([],7,'')) as run:
                self.assertEqual(retention.main(),7)
            self.assertEqual(manifest.read_text(),A+'\n'+B+'\n')
            self.assertEqual(run.call_args.args[0],['bash','-eu','-o','pipefail',str(script)])

    def test_successful_root_is_retained_even_when_upstream_signed(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest=Path(temporary)/'outputs'
            with patch.object(retention.public,'derivation'), \
                    patch.object(retention.channel,'derivation_output_paths',return_value={A,B}), \
                    patch.object(retention.channel,'completed_build_outputs',return_value=[B]), \
                    patch.object(retention.public,'runtime') as runtime:
                collector=retention.Collector(['.#sample'],manifest,{})
                collector.retain([A])
            self.assertEqual(manifest.read_text(),A+'\n'+B+'\n')
            runtime.assert_called_once_with([A,B])

    def test_nonselected_roots_and_denied_closures_cannot_be_exported(self):
        for roots in [[C],[A]]:
            with self.subTest(roots=roots),tempfile.TemporaryDirectory() as temporary:
                manifest=Path(temporary)/'outputs'
                with patch.object(retention.public,'derivation'), \
                        patch.object(retention.channel,'derivation_output_paths',return_value={A,B}), \
                        patch.object(retention.channel,'completed_build_outputs',return_value=[B]), \
                        patch.object(retention.public,'runtime',side_effect=ValueError('denied')):
                    collector=retention.Collector(['.#sample'],manifest,{})
                    with self.assertRaises(ValueError):collector.retain(roots)
                self.assertFalse(manifest.exists())

    def test_private_source_guard_precedes_graph_collection(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(retention.public,'derivation',side_effect=ValueError('denied')), \
                patch.object(retention.channel,'derivation_output_paths') as graph:
            with self.assertRaises(ValueError):retention.Collector(['.#private'],Path(temporary)/'outputs',{})
            graph.assert_not_called()

    def test_writer_credentials_are_rejected_and_forge_tokens_never_reach_builds(self):
        for name in retention.WRITERS:
            with self.subTest(name=name),self.assertRaises(ValueError):retention.build_environment({name:'fixture'})
        env=retention.build_environment({'GH_TOKEN':'fixture','ACTIONS_ID_TOKEN_REQUEST_TOKEN':'fixture',
                                         'NIX_CONFIG':'http2 = false','NIKS3_NETRC_FILE':'/readonly/netrc'})
        self.assertNotIn('GH_TOKEN',env);self.assertNotIn('ACTIONS_ID_TOKEN_REQUEST_TOKEN',env)
        self.assertEqual(env['NIKS3_NETRC_FILE'],'/readonly/netrc')
        self.assertIn('accept-flake-config = false',env['NIX_CONFIG'])


if __name__=='__main__':unittest.main()
