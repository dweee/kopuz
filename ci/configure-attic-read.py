#!/usr/bin/env python3
"""Install a private read netrc outside the store for a trusted build job."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit

START = "# BEGIN managed private cache reads\n"
END = "# END managed private cache reads\n"
PUBLIC_ATTIC = "https://attic.monke.fail"
# Same cache and keys, reachable only from jobs on the icicle `nix` runner.
INTERNAL_ATTIC = "http://172.29.0.1:8080"
# The same listener over the tailnet, for the host-mode braco runner.
TAILNET_ATTIC = "http://icicle.eel-ling.ts.net:8080"
REVIEWED_ATTIC = {PUBLIC_ATTIC, INTERNAL_ATTIC, TAILNET_ATTIC}


def attic_server():
    """Mirror of release-channel.py: only the three reviewed origins, public by default."""
    value = os.environ.get("ATTIC_SERVER", "").strip().rstrip("/")
    if value and value not in REVIEWED_ATTIC:
        raise ValueError("ATTIC_SERVER is not a reviewed Attic origin")
    return value or PUBLIC_ATTIC


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate credential metadata")
        result[key] = value
    return result


def reviewed_pr():
    """An operational owner opt-in, not an ACL against repository writers."""
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        raise ValueError("Expected a reviewed pull request")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "")
    approved = os.environ.get("ATTIC_APPROVED_PR_SHA", "")
    if (not owner or repository.split("/")[0] != owner
            or os.environ.get("GITHUB_ACTOR") != owner
            or not re.fullmatch(r"[0-9a-f]{40}", approved)):
        raise ValueError("Pull request is not owner approved")
    event_path = Path(os.environ["GITHUB_EVENT_PATH"])
    if event_path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Oversize event metadata")
    event = json.loads(event_path.read_text(), object_pairs_hook=unique_object)
    if (event["repository"]["full_name"] != repository
            or event["repository"]["owner"]["login"] != owner
            or event["sender"]["login"] != owner
            or event["pull_request"]["head"]["repo"]["full_name"] != repository
            or event["pull_request"]["head"]["sha"] != approved):
        raise ValueError("Pull request is not owner approved")


def pull_token():
    token = os.environ.get("ATTIC_PULL_TOKEN", "")
    if (not token or len(token) > 16384
            or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)
            or os.environ.get("ATTIC_TOKEN")):
        raise ValueError("Expected only a dedicated pull credential")
    def decode(part):
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)),
                          object_pairs_hook=unique_object)
    header, claims = map(decode, token.split(".")[:2])
    grants = claims.get("https://jwt.attic.rs/v1")
    now = time.time()
    exp = claims.get("exp")
    if (header.get("alg") != "RS256"
            or grants != {"caches": {"flakey": {"r": 1}}}
            or type(grants["caches"]["flakey"]["r"]) is not int
            or type(exp) is not int or not now < exp <= now + 90 * 86400):
        raise ValueError("Unexpected pull credential scope or expiry")
    for field in ("nbf", "iat"):
        if field in claims and (type(claims[field]) is not int or claims[field] > now):
            raise ValueError("Credential is not yet valid")
    if "iat" in claims and exp - claims["iat"] > 90 * 86400:
        raise ValueError("Credential lifetime exceeds policy")
    # This is a fail-closed scope/expiry check, not local signature verification.
    # The HTTPS Attic server verifies the JWT signature when Nix authenticates.
    return token


def configure(pr_read=False):
    server = attic_server()
    if pr_read:
        reviewed_pr()
        token = pull_token()
    else:
        token = os.environ.get("ATTIC_TOKEN", "").strip()
        if not token or any(c.isspace() for c in token):
            raise ValueError("Missing scoped Attic token")
    directory = Path(os.environ["RUNNER_TEMP"])
    netrc = directory / "flakey-attic.netrc"
    descriptor = os.open(netrc, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        # Only the host this job contacts: the other origin never sees the token.
        stream.write("machine " + urlsplit(server).hostname + " login ci password " + token + "\n")
    config = Path.home() / ".config/nix/nix.conf"
    config.parent.mkdir(parents=True, exist_ok=True)
    with config.open("a") as stream:
        stream.write("\n" + START)
        stream.write("extra-substituters = " + server + "/flakey\n")
        stream.write("always-allow-substitutes = true\n")
        stream.write("extra-trusted-public-keys = flakey:mDx4DiNpH5w1Pl8OAKFFWq1ZsypA9lbaFKNiRWhqYE8=\n")
        stream.write("netrc-file = " + str(netrc) + "\n")
        stream.write(END)


def cleanup():
    (Path(os.environ["RUNNER_TEMP"]) / "flakey-attic.netrc").unlink(missing_ok=True)
    config = Path.home() / ".config/nix/nix.conf"
    if config.exists():
        text = config.read_text()
        config.write_text(re.sub(re.escape(START) + r".*?" + re.escape(END), "", text,
                                 flags=re.DOTALL))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--pr-read", action="store_true")
    mode.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    try:
        if args.cleanup:
            cleanup()
        else:
            configure(args.pr_read)
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        print("Private cache read credential configuration failed.", file=sys.stderr)
        sys.exit(1)
