#!/usr/bin/env python3
"""Safety policy checks use synthetic graphs and never build packages."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("policy", Path(__file__).with_name("public-closure.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

class PublicClosureTests(unittest.TestCase):
    def test_forbidden_inputs_anywhere_in_derivation_closure(self):
        for name in ["wiicompiled-disc-rmcp01", "veracrypt-1", "nvidia-x11-580.1", "nvidia-580.1-6.1", "ffmpeg-full-8", "subnetter-1"]:
            graph={"/nix/store/parent.drv": {"outputs": {}, "env": {"buildInputs": "/nix/store/hidden-"+name}}}
            with self.subTest(name=name), patch.object(policy.subprocess, "run", return_value=subprocess.CompletedProcess([],0,json.dumps(graph),"")):
                with self.assertRaises(ValueError): policy.derivation(".#packages.x86_64-linux.innocent")

    def test_all_four_disc_free_attributes_are_checked_recursively(self):
        graph={"/nix/store/public.drv": {"outputs": {}, "inputDrvs": {"/nix/store/compiler.drv": {}}}}
        for name in policy.WII_PUBLIC:
            with self.subTest(name=name), patch.object(policy.subprocess, "run", return_value=subprocess.CompletedProcess([],0,json.dumps(graph),"")) as call:
                policy.derivation(".#packages.x86_64-linux."+name)
                self.assertIn("--recursive",call.call_args.args[0])

    def test_nix_234_versioned_graph_checks_transitive_inputs(self):
        graph={"version":4,"derivations":{"public.drv":{"outputs":{},"inputs":{"drvs":{"hidden-wiicompiled-disc-rmcp01.drv":{}}}}}}
        with patch.object(policy.subprocess,"run",return_value=subprocess.CompletedProcess([],0,json.dumps(graph),"")):
            with self.assertRaises(ValueError): policy.derivation(".#packages.x86_64-linux.innocent")

    def test_final_and_translated_wii_are_never_evaluated(self):
        with patch.object(policy.subprocess,"run") as call:
            for name in ["wiicompiled", "wiicompiled-translated", "wiicompiled-disc-rmcp01"]:
                with self.assertRaises(ValueError): policy.derivation(".#packages.x86_64-linux."+name)
            call.assert_not_called()

    def test_runtime_rejects_transitive_forbidden_reference(self):
        with patch.object(policy.subprocess,"run",return_value=subprocess.CompletedProcess([],0,"/nix/store/root\n/nix/store/hidden-wiicompiled-disc-rmcp01\n","")):
            with self.assertRaises(ValueError): policy.runtime(["/nix/store/root"])

    def test_failed_evaluation_does_not_print_nix_diagnostics(self):
        with patch.object(policy.subprocess,"run",side_effect=subprocess.CalledProcessError(1,[],stderr="private fixture")), patch("sys.argv",["guard",".#bad"]), patch("sys.stderr") as stderr:
            self.assertEqual(policy.main(),1)
            self.assertNotIn("private fixture",str(stderr.write.call_args_list))

if __name__ == "__main__": unittest.main()
