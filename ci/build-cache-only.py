#!/usr/bin/env python3
"""Build and push in one trusted job; never export archives or publish build logs."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

STORE = re.compile(r"/nix/store/[a-z0-9]{32}-[^/\s]+")
DENIED = re.compile(r"wiicompiled|subnetter", re.I)

def check(value):
    if isinstance(value, str):
        if DENIED.search(value):
            raise ValueError("On-prem-only input")
    elif isinstance(value, dict):
        for key, item in value.items():
            check(key)
            check(item)
    elif isinstance(value, list):
        for item in value:
            check(item)

def failure_class(blob):
    # Classify without copying compiler output, store paths or server responses
    # into the public log. The raw diagnostic is discarded with the temp file.
    if isinstance(blob, bytes):
        blob = blob.decode("utf-8", "replace")
    text = blob.lower()
    if "transferred a partial file" in text or "stream error in the http/2 framing layer" in text:
        return "attic-partial-nar"
    if "unable to download" in text:
        return "substitute-download-failed"
    if "cannot allocate memory" in text or "out of memory" in text:
        return "out-of-memory"
    if "hash mismatch" in text:
        return "hash-mismatch"
    if "builder for" in text and "failed" in text:
        return "builder-failed"
    return "build-or-publication-failed"

def quiet(args, env, *, stdout=None):
    # Even on failure, neither compiler logs, server responses nor store paths
    # enter the public job log. Temporary output is deleted, never uploaded.
    with tempfile.TemporaryFile() as diagnostic:
        result = subprocess.run(args, env=env, stdout=stdout if stdout is not None else subprocess.PIPE,
                                stderr=diagnostic, text=True)
        if result.returncode != 0:
            diagnostic.seek(0)
            kind = failure_class(diagnostic.read())
            error = subprocess.CalledProcessError(result.returncode, args)
            error.failure_class = kind
            raise error
        return result

def build(system, package):
    root = Path(__file__).resolve().parents[1]
    inventory = json.loads((root / "nix/cache-only-platforms.json").read_text())
    if package not in inventory.get(system, []):
        raise ValueError("Not an approved cache-only target")
    env = {key: value for key, value in os.environ.items() if key != "ATTIC_TOKEN"}
    if quiet(["nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem"], env).stdout.strip() != system:
        raise ValueError("Native runner mismatch")
    target = f".#cacheOnlyPackages.{system}.{package}"
    flags = ["--no-update-lock-file", "--no-write-lock-file"]
    document = json.loads(quiet(["nix", "derivation", "show", "--recursive", target, *flags], env).stdout)
    graph = document.get("derivations", document) if isinstance(document, dict) else None
    if (not isinstance(graph, dict) or not graph or
            any(not isinstance(drv, dict) or not isinstance(drv.get("outputs"), dict)
                for drv in graph.values())):
        raise ValueError("Missing derivation graph")
    check(graph)
    client = quiet(["nix", "build", "--inputs-from", ".", "nixpkgs#attic-client", *flags,
                    "--no-link", "--print-out-paths", "--max-jobs", "0", "--builders", ""], env).stdout.strip()
    if not STORE.fullmatch(client):
        raise ValueError("Invalid client path")
    with tempfile.TemporaryDirectory(prefix="flakey-cache-only-", dir=os.environ["RUNNER_TEMP"]) as directory:
        manifest = Path(directory) / "outputs.txt"
        with manifest.open("w") as outputs:
            quiet(["nix", "build", "--fallback", target + "^*", *flags, "--no-link", "--print-out-paths"], env, stdout=outputs)
        paths = manifest.read_text().splitlines()
        if not paths or any(not STORE.fullmatch(p) or p.endswith(".drv") for p in paths):
            raise ValueError("Invalid built output")
        closure = quiet(["nix-store", "--query", "--requisites", *paths], env).stdout.splitlines()
        if not closure or any(not STORE.fullmatch(p) for p in closure):
            raise ValueError("Missing runtime closure")
        check(closure)
        publish_env = dict(os.environ, ATTIC_BIN=client + "/bin/attic",
                           ATTIC_ENDPOINT="https://attic.monke.fail", ATTIC_CACHE="flakey")
        with tempfile.TemporaryFile() as log:
            # The existing helper confines credentials to mode-0600 client
            # configuration and uploads roots plus their runtime closures.
            quiet([sys.executable, str(root / "ci/push-attic.py"), "--outputs", str(manifest)],
                  publish_env, stdout=log)

if __name__ == "__main__":
    try:
        build(os.environ["TARGET_SYSTEM"], os.environ["TARGET_PACKAGE"])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        kind = getattr(error, "failure_class", None) or "build-or-publication-failed"
        print("Cache-only build/publication failed [" + kind + "]. No artifacts or diagnostic logs were published.", file=sys.stderr)
        sys.exit(1)
    print("Cache-only build and private cache publication succeeded.")
