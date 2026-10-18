#!/usr/bin/env python3
"""Reject on-prem-only derivations before public builds and runtime exports."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

# Check names throughout the recursive derivation graph, including sources and
# output paths. No rejected path or evaluator diagnostic goes into public logs.
DENIED = re.compile(r"(?:wiicompiled-disc(?:-rmcp01)?|veracrypt|nvidia(?:-x11|-kernel|-modules)?(?:-open)?-580|ffmpeg-full|subnetter)", re.I)
WII_PUBLIC = {"wiicompiled-native-prebuilt", "wiicompiled-translator", "wiicompiled-setup", "wiicompiled-setup-unwrapped"}

def check_paths(paths):
    for path in paths:
        if not isinstance(path, str) or DENIED.search(path):
            raise ValueError("Public closure policy rejected a path")

def derivation(target):
    attr = target.rsplit(".", 1)[-1]
    if attr.startswith("wiicompiled") and attr not in WII_PUBLIC:
        raise ValueError("Public Wii attribute is not approved")
    result = subprocess.run(["nix", "derivation", "show", "--recursive", target,
                             "--no-update-lock-file", "--no-write-lock-file"],
                            capture_output=True, text=True, check=True)
    document = json.loads(result.stdout)
    # Nix 2.34 uses versioned JSON with a derivations map; older releases
    # returned that map directly. Reject incomplete or unfamiliar graphs.
    graph = document.get("derivations", document) if isinstance(document, dict) else None
    if not isinstance(graph, dict) or not graph:
        raise ValueError("Missing recursive derivation graph")
    for path, drv in graph.items():
        if not isinstance(drv, dict) or not isinstance(drv.get("outputs"), dict):
            raise ValueError("Invalid derivation graph")
        check_paths([path])
        check_strings(drv)

def check_strings(value):
    if isinstance(value, str):
        check_paths([value])
    elif isinstance(value, dict):
        check_paths(value.keys())
        for item in value.values(): check_strings(item)
    elif isinstance(value, list):
        for item in value: check_strings(item)

def runtime(paths):
    result = subprocess.run(["nix-store", "--query", "--requisites", *paths],
                            capture_output=True, text=True, check=True)
    closure = result.stdout.splitlines()
    if not closure: raise ValueError("Missing runtime closure")
    check_paths(closure)
    return closure

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    args = parser.parse_args()
    try:
        derivation(args.target)
    except (ValueError, OSError, subprocess.SubprocessError):
        print("Public derivation closure check failed; build and publication are blocked.", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__": sys.exit(main())
