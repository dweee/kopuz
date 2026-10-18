#!/usr/bin/env python3
"""Install a private read netrc outside the store for a trusted build job."""
import os
from pathlib import Path
import sys


def configure():
    token = os.environ.get("ATTIC_TOKEN", "").strip()
    if not token or any(c.isspace() for c in token):
        raise ValueError("Missing scoped Attic token")
    directory = Path(os.environ["RUNNER_TEMP"])
    netrc = directory / "flakey-attic.netrc"
    descriptor = os.open(netrc, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write("machine attic.monke.fail login ci password " + token + "\n")
    config = Path.home() / ".config/nix/nix.conf"
    config.parent.mkdir(parents=True, exist_ok=True)
    with config.open("a") as stream:
        stream.write("\nextra-substituters = https://attic.monke.fail/flakey\n")
        stream.write("extra-trusted-public-keys = flakey:mDx4DiNpH5w1Pl8OAKFFWq1ZsypA9lbaFKNiRWhqYE8=\n")
        stream.write("netrc-file = " + str(netrc) + "\n")

if __name__ == "__main__":
    try: configure()
    except (ValueError, OSError, KeyError):
        print("Private cache read credential configuration failed.", file=sys.stderr)
        sys.exit(1)
