#!/usr/bin/env python3
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location("auth",Path(__file__).with_name("configure-attic-read.py"))
auth=importlib.util.module_from_spec(spec);spec.loader.exec_module(auth)

class PrivateReadTests(unittest.TestCase):
    def test_netrc_is_private_and_token_does_not_enter_nix_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp)/"home"; home.mkdir()
            token="synthetic-scoped-token"
            with patch.dict(os.environ,{"ATTIC_TOKEN":token,"RUNNER_TEMP":tmp},clear=True),patch.object(Path,"home",return_value=home): auth.configure()
            netrc=Path(tmp)/"flakey-attic.netrc"
            self.assertEqual(netrc.stat().st_mode & 0o777,0o600)
            self.assertEqual(netrc.read_text(),"machine attic.monke.fail login ci password "+token+"\n")
            config=(home/".config/nix/nix.conf").read_text()
            self.assertNotIn(token,config)
            self.assertIn("https://attic.monke.fail/flakey",config)
            self.assertIn("netrc-file = "+str(netrc),config)

    def test_missing_or_multiline_tokens_are_rejected(self):
        for token in ["","two words","first\nsecond"]:
            with patch.dict(os.environ,{"ATTIC_TOKEN":token},clear=True):
                with self.assertRaises(ValueError): auth.configure()

    def test_no_pr_or_non_default_branch_receives_secret(self):
        for workflow in Path(__file__).resolve().parents[1].joinpath(".github/workflows").glob("*.yml"):
            text=workflow.read_text()
            if "Configure authenticated private cache" not in text: continue
            build=text.split("\n  publish:\n")[0]
            lines=build.splitlines()
            for index,line in enumerate(lines):
                if "secrets.ATTIC_TOKEN" in line:
                    preceding="\n".join(lines[max(0,index-5):index])
                    self.assertIn("github.event_name == 'push'",preceding)
                    self.assertIn("github.event_name == 'workflow_dispatch'",preceding)
                    self.assertIn("github.event.repository.default_branch",preceding)
                    self.assertNotIn("pull_request",preceding)

if __name__ == "__main__": unittest.main()
