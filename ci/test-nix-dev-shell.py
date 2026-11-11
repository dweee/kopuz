#!/usr/bin/env python3
"""Regression checks for the bounded Nix dev-shell flag normalization."""
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).with_name("nix-dev-shell.py")
spec = importlib.util.spec_from_file_location("nix_dev_shell", SCRIPT)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class NormalizationTests(unittest.TestCase):
    def test_path_groups_preserve_first_occurrence_and_pairing(self):
        raw = "-isystem /nix/store/a/include -isystem /nix/store/b/include -isystem /nix/store/a/include -rpath /nix/store/a/lib -L/nix/store/a/lib -rpath /nix/store/a/lib"
        value, before, after = helper.normalize(raw)
        self.assertEqual(shlex.split(value), ["-isystem", "/nix/store/a/include", "-isystem", "/nix/store/b/include", "-rpath", "/nix/store/a/lib", "-L/nix/store/a/lib"])
        self.assertEqual((before, after), (6, 4))

    def test_identical_prefix_maps_and_seed_are_preserved(self):
        raw = "-frandom-seed=abc -fmacro-prefix-map=/nix/store/a=/nix/store/e -frandom-seed=abc -fmacro-prefix-map=/nix/store/a=/nix/store/e"
        value, before, after = helper.normalize(raw)
        self.assertEqual(shlex.split(value), ["-frandom-seed=abc", "-fmacro-prefix-map=/nix/store/a=/nix/store/e"])
        self.assertEqual((before, after), (4, 2))

    def test_shell_output_rpath_is_allowed_only_as_declared(self):
        self.assertEqual(helper.normalize("-rpath /tmp/dev/outputs/out/lib", "/tmp/dev/outputs/out")[1:], (1, 1))
        with self.assertRaises(ValueError):
            helper.normalize("-rpath /tmp/foreign/lib", "/tmp/dev/outputs/out")
        with self.assertRaises(ValueError):
            helper.normalize("-isystem /tmp/dev/outputs/out/lib", "/tmp/dev/outputs/out")

    def test_definitions_libraries_and_stateful_flags_fail_closed(self):
        for raw in ["-DA=1 -DA=1", "-UFOO", "-lfoo -lfoo", "-Wl,--start-group", "-isystem", "-L/tmp/lib", "-fmacro-prefix-map=/nix/store/a=x -fmacro-prefix-map=/nix/store/a=y", "-frandom-seed=a -frandom-seed=b"]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                helper.normalize(raw)

    def test_unrelated_environment_and_original_are_unchanged(self):
        original = {"NIX_LDFLAGS": "-L/nix/store/a -L/nix/store/a", "CARGO_BUILD_JOBS": "2"}
        saved = original.copy()
        result, receipt = helper.environment(original)
        self.assertEqual(original, saved)
        self.assertEqual(result["CARGO_BUILD_JOBS"], "2")
        self.assertEqual(result["NIX_LDFLAGS"], "-L/nix/store/a")
        self.assertNotIn("NIX_CFLAGS_COMPILE", result)
        self.assertEqual(receipt["NIX_LDFLAGS"]["after_groups"], 1)

    def test_exec_preserves_arguments_and_nonzero_exit(self):
        env = {k: v for k, v in os.environ.items() if k not in helper.FLAG_VARIABLES}
        env["NIX_LDFLAGS"] = "-L/nix/store/a -L/nix/store/a"
        code = "import os,sys; assert os.environ['NIX_LDFLAGS']=='-L/nix/store/a'; assert sys.argv[1]=='a $ b'; sys.exit(7)"
        result = subprocess.run([sys.executable, str(SCRIPT), sys.executable, "-c", code, "a $ b"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 7, result.stderr)

    def test_unknown_flag_prevents_command_execution(self):
        env = {k: v for k, v in os.environ.items() if k not in helper.FLAG_VARIABLES}
        env["NIX_CFLAGS_COMPILE"] = "-DA=1"
        result = subprocess.run([sys.executable, str(SCRIPT), sys.executable, "-c", "print('MUST_NOT_RUN')"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("MUST_NOT_RUN", result.stdout)


if __name__ == "__main__":
    unittest.main()
