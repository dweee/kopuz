#!/usr/bin/env python3
"""Cache-only policy guard: reject on-prem-only inputs in a closure or derivation graph.

release-channel.py applies it to `cache-only` repositories before publishing.
The repository that owns cache-only packages (dave-packages) keeps its own
build-and-publish driver."""
import re

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
