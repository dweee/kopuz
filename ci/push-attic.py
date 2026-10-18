#!/usr/bin/env python3
"""Publish one successful package build to an explicitly configured Attic cache."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit


def publish(outputs):
    endpoint = os.environ.get("ATTIC_ENDPOINT", "")
    cache = os.environ.get("ATTIC_CACHE", "")
    token = os.environ.get("ATTIC_TOKEN", "")
    binary = os.environ.get("ATTIC_BIN", "")
    parsed = urlsplit(endpoint)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or any(c.isspace() for c in endpoint)):
        raise ValueError("ATTIC_ENDPOINT must be an HTTPS server URL without credentials, query or fragment")
    # Accessing port also validates a malformed or out-of-range port.
    _ = parsed.port
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", cache):
        raise ValueError("ATTIC_CACHE must name the existing destination cache")
    if not token.strip():
        raise ValueError("ATTIC_TOKEN is required when uploads are enabled")
    if not binary or not Path(binary).is_file() or not os.access(binary, os.X_OK):
        raise ValueError("ATTIC_BIN must identify the installed Attic client")
    paths = list(dict.fromkeys(outputs.read_text().splitlines()))
    if not paths or any(not re.fullmatch(r"/nix/store/[a-z0-9]{32}-[^/\s]+", p)
                        or p.endswith(".drv") for p in paths):
        raise ValueError("Output manifest must contain only built Nix store output paths")

    # This token is supplied only to the publication step. Never use a personal
    # login, put the token in process arguments, or modify the runner's Nix config.
    child_env = {key: value for key, value in os.environ.items() if key != "ATTIC_TOKEN"}
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="attic-ci-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        config_dir = Path(temporary) / "attic"
        config_dir.mkdir(mode=0o700)
        config_path = config_dir / "config.toml"
        descriptor = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as config:
            config.write('default-server = "ci"\n[servers.ci]\n')
            config.write("endpoint = " + json.dumps(endpoint.rstrip("/") + "/") + "\n")
            config.write("token = " + json.dumps(token) + "\n")
        child_env["XDG_CONFIG_HOME"] = temporary
        # Attic follows runtime closures by default. Only this manifest's roots
        # are selected; the rest of the runner store is never enumerated.
        subprocess.run([binary, "push", "--jobs", "1", "--stdin", "ci:" + cache],
                       input="\n".join(paths) + "\n", text=True, env=child_env, check=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as output:
            output.write(f"Uploaded {len(paths)} output(s) and runtime closures to Attic "
                         f"in {time.monotonic() - started:.0f}s.\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outputs", type=Path, default=Path("outputs.txt"))
    args = parser.parse_args()
    try:
        publish(args.outputs)
    except subprocess.CalledProcessError as error:
        print("Attic publication failed; this build is not successfully cached.", file=sys.stderr)
        return error.returncode if error.returncode > 0 else 1
    except (ValueError, OSError):
        # Avoid echoing credentials, URL values or server responses in validation errors.
        print("Attic publication configuration or output manifest is invalid; see README.md.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
