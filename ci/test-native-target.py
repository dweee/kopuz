import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


spec = importlib.util.spec_from_file_location("native_target", Path(__file__).with_name("native-target.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ImmutableNativeTargetTests(unittest.TestCase):
    environment = {
        "GITHUB_REPOSITORY": "dweee/kopuz",
        "GITHUB_SHA": "a04bd96e23750dbb2076319a1ef938208a64fce1",
        "GITHUB_REF": "refs/heads/flakey",
        "TARGET_SYSTEM": "x86_64-linux",
        "TARGET_PACKAGE": "default",
    }
    root = "/nix/store/" + "a" * 32 + "-kopuz-0.21.0-qobuz"

    def test_native_platforms_select_the_same_exact_git_revision_for_package_and_check(self):
        for system in ["x86_64-linux", "aarch64-linux", "aarch64-darwin"]:
            with self.subTest(system=system):
                selected = module.targets({**self.environment, "TARGET_SYSTEM": system})
                package, check = (urlsplit(selected[key]) for key in ["package", "check"])
                self.assertEqual(package.scheme, "git+https")
                self.assertEqual(package.netloc, "github.com")
                self.assertEqual(package.path, "/dweee/kopuz")
                self.assertEqual(parse_qs(package.query), {
                    "ref": ["flakey"], "rev": [self.environment["GITHUB_SHA"]]})
                self.assertEqual(package.query, check.query)
                self.assertEqual(package.fragment, "packages." + system + ".default")
                self.assertEqual(check.fragment, "checks." + system + ".qobuz")

    def test_pull_request_uses_the_exact_public_merge_ref_without_credentials(self):
        selected = module.targets({**self.environment, "GITHUB_REF": "refs/pull/7/merge"})
        self.assertEqual(parse_qs(urlsplit(selected["package"]).query), {
            "ref": ["refs/pull/7/merge"], "rev": [self.environment["GITHUB_SHA"]]})

    def test_unpinned_or_injected_context_is_rejected_before_nix_runs(self):
        cases = [
            ("GITHUB_SHA", "flakey"), ("GITHUB_SHA", "a" * 39),
            ("GITHUB_REPOSITORY", "dweee/kopuz?submodules=1"),
            ("GITHUB_REPOSITORY", "dweee/kopuz/other"),
            ("GITHUB_REF", "flakey"), ("GITHUB_REF", "refs/heads/a?rev=other"),
            ("GITHUB_REF", "refs/heads/../flakey"),
            ("TARGET_SYSTEM", "x86_64-darwin"), ("TARGET_PACKAGE", "other"),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                module.targets({**self.environment, key: value})

    def test_manifest_must_equal_the_selected_immutable_output(self):
        selected = module.targets(self.environment)["package"]
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "outputs.txt"
            result = subprocess.CompletedProcess([], 0, self.root + "\n", "")
            with patch.object(module.subprocess, "run", return_value=result) as evaluate:
                manifest.write_text(self.root + "\n")
                module.verify_outputs(selected, manifest)
                self.assertEqual(evaluate.call_args.args[0], [
                    "nix", "eval", "--raw", selected + ".outPath",
                    "--no-update-lock-file", "--no-write-lock-file"])
                for content in ["", self.root + "-different\n", self.root + "\n" + self.root + "\n"]:
                    manifest.write_text(content)
                    with self.subTest(content=content), self.assertRaises(ValueError):
                        module.verify_outputs(selected, manifest)

    def test_evaluation_failure_blocks_manifest_verification(self):
        selected = module.targets(self.environment)["package"]
        with patch.object(module.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "nix")):
            with self.assertRaises(subprocess.CalledProcessError):
                module.verify_outputs(selected, Path("outputs.txt"))

    def test_workflow_builds_and_checks_immutable_targets_before_transferring_the_manifest(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/native.yml").read_text()
        build = workflow.split("  build:\n", 1)[1].split("\n  publish:\n", 1)[0]
        self.assertIn('target=$(python3 ci/native-target.py package)', build)
        self.assertIn('check=$(python3 ci/native-target.py check)', build)
        self.assertIn('nix build "$target"', build)
        self.assertIn('nix build "$check"', build)
        self.assertNotIn('target=".#', build)
        self.assertNotIn('".#checks.', build)
        self.assertLess(build.index('ci/native-target.py verify --outputs outputs.txt'),
                        build.index('ci/transfer-attic.py export'))
        self.assertIn('ci/test-native-target.py', build)
        publisher = workflow.split("\n  publish:\n", 1)[1]
        self.assertIn('ci/push-attic.py --outputs attic-transfer/outputs.txt', publisher)
        self.assertNotIn('ci/native-target.py', publisher)


if __name__ == "__main__":
    unittest.main()
