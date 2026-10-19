#!/usr/bin/env python3
"""Select the immutable Git source shared by native CI and flake consumers."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlencode


def targets(environment):
    repository = environment.get("GITHUB_REPOSITORY", "")
    revision = environment.get("GITHUB_SHA", "")
    ref = environment.get("GITHUB_REF", "")
    system = environment.get("TARGET_SYSTEM", "")
    package = environment.get("TARGET_PACKAGE", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_][A-Za-z0-9_.-]*", repository):
        raise ValueError("Invalid GitHub repository")
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("An exact Git revision is required")
    if ref.startswith("refs/heads/"):
        ref = ref.removeprefix("refs/heads/")
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]*", ref) or any(
                part in ref for part in ("..", "//", "/.")) or ref.endswith(("/", ".")):
            raise ValueError("Invalid branch ref")
    elif not re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", ref):
        raise ValueError("Unsupported workflow ref")
    if system not in {"x86_64-linux", "aarch64-linux", "aarch64-darwin"}:
        raise ValueError("Unsupported native platform")
    if package not in {"default", "kopuz"}:
        raise ValueError("Unsupported native package")
    # Match input consumers' Git fetch policy; checkout submodules and other
    # workspace state must not select a different Nix source tree.
    source = "git+https://github.com/" + repository + "?" + urlencode(
        {"ref": ref, "rev": revision}, safe="/")
    return {
        "package": source + "#packages." + system + "." + package,
        "check": source + "#checks." + system + ".qobuz",
    }


def verify_outputs(target, manifest):
    expected = subprocess.run(
        ["nix", "eval", "--raw", target + ".outPath", "--no-update-lock-file",
         "--no-write-lock-file"], capture_output=True, text=True, check=True).stdout.strip()
    if not re.fullmatch(r"/nix/store/[a-z0-9]{32}-[^/\s]+", expected):
        raise ValueError("Invalid selected output")
    if manifest.stat().st_size > 1024 or manifest.read_text().splitlines() != [expected]:
        raise ValueError("Build outputs differ from the immutable selection")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["package", "check", "verify"])
    parser.add_argument("--outputs", type=Path, default=Path("outputs.txt"))
    args = parser.parse_args()
    try:
        selected = targets(os.environ)
        if args.mode == "verify":
            verify_outputs(selected["package"], args.outputs)
        else:
            print(selected[args.mode])
    except (ValueError, OSError, subprocess.SubprocessError):
        print("Native target or output manifest validation failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
