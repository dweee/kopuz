#!/usr/bin/env python3
"""Transfer selected Nix outputs between disposable jobs without running them."""
import argparse
import gzip
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


spec = importlib.util.spec_from_file_location("public_closure", Path(__file__).with_name("public-closure.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

def roots(manifest):
    if manifest.stat().st_size > 1024 * 1024:
        raise ValueError("Output manifest is too large")
    paths = list(dict.fromkeys(manifest.read_text().splitlines()))
    if not paths or len(paths) > 1024 or any(not re.fullmatch(r"/nix/store/[a-z0-9]{32}-[^/\s]+", p)
                                           or p.endswith(".drv") for p in paths):
        raise ValueError("Invalid output manifest")
    return paths


def copy_bounded(source, target, limit):
    total = 0
    while chunk := source.read(1024 * 1024):
        total += len(chunk)
        if total > limit:
            raise ValueError("Closure transfer exceeds ATTIC_MAX_CLOSURE_MIB")
        target.write(chunk)
    return total


def transfer(mode, directory, limit):
    if os.environ.get("ATTIC_TOKEN"):
        raise ValueError("A transfer job must not receive an Attic upload credential")
    directory.mkdir(parents=True, exist_ok=True)
    manifest = directory / "outputs.txt"
    if mode == "export":
        paths = roots(Path("outputs.txt"))
        # This must run before an archive or public artifact is created.
        requisites = policy.runtime(paths)
        if any(not re.fullmatch(r"/nix/store/[a-z0-9]{32}-[^/\s]+", p) for p in requisites):
            raise ValueError("Invalid closure paths")
        process = subprocess.Popen(["nix-store", "--export", *requisites], stdout=subprocess.PIPE)
        try:
            with gzip.open(directory / "closure.nar.gz", "wb", compresslevel=1) as archive:
                copy_bounded(process.stdout, archive, limit)
            if process.wait():
                raise ValueError("Closure export failed")
            manifest.write_text("\n".join(paths) + "\n")
            archive_path = directory / "closure.nar.gz"
            digest = hashlib.sha256()
            with archive_path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            (directory / "SHA256SUMS").write_text(digest.hexdigest() + "  closure.nar.gz\n")
            with (directory / "closure-info.json").open("w") as stream:
                subprocess.run(["nix", "path-info", "--json", "--recursive", *paths], stdout=stream, check=True)

        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
    else:
        paths = roots(manifest)
        # Import NAR data only. Existing trusted client paths were installed from
        # cache.nixos.org before this step and cannot be replaced by this import.
        process = subprocess.Popen(["nix-store", "--import", "--option", "require-sigs", "false"],
                                   stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
        try:
            with gzip.open(directory / "closure.nar.gz", "rb") as archive:
                copy_bounded(archive, process.stdin, limit)
            process.stdin.close()
            if process.wait():
                raise ValueError("Closure import failed")
            subprocess.run(["nix-store", "--check-validity", *paths], check=True)
            policy.runtime(paths)
            # The export/import format drops signatures. Restore them only
            # from the official cache so Attic can skip its existing outputs.
            # Builder-supplied metadata never decides which paths to skip.
            subprocess.run(["nix", "store", "copy-sigs", "--substituter",
                            "https://cache.nixos.org", "--recursive", *paths],
                           check=True, timeout=120)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["export", "import"])
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        mib = int(os.environ.get("ATTIC_MAX_CLOSURE_MIB") or "2048")
        if not 1 <= mib <= 4096:
            raise ValueError("Closure transfer limit must be between 1 and 4096 MiB")
        transfer(args.mode, args.directory, mib * 1024 * 1024)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Nix closure transfer failed; no cache publication is authorized.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
