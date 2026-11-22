#!/usr/bin/env python3
"""Run a dev-shell command after removing redundant Nix path flag groups."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys

FLAG_VARIABLES = (
    "NIX_CFLAGS_COMPILE",
    "NIX_CFLAGS_COMPILE_FOR_BUILD",
    "NIX_LDFLAGS",
    "NIX_LDFLAGS_FOR_BUILD",
)


def normalize(raw, output=None):
    """Deduplicate only order-insensitive store-path groups; reject other flags."""
    tokens = shlex.split(raw)
    groups = []
    maps = {}
    seeds = set()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in ("-isystem", "-rpath"):
            if index + 1 == len(tokens):
                raise ValueError("missing path argument")
            path = tokens[index + 1]
            output_lib = str(Path(output) / "lib") if output else None
            if not path.startswith("/nix/store/") and not (
                token == "-rpath" and output_lib and path == output_lib
            ):
                raise ValueError("unexpected non-store path argument")
            group = (token, path)
            index += 2
        else:
            if token.startswith("-fmacro-prefix-map=/nix/store/"):
                mapping = token[len("-fmacro-prefix-map="):]
                if "=" not in mapping:
                    raise ValueError("missing prefix-map destination")
                source, destination = mapping.split("=", 1)
                if source in maps and maps[source] != destination:
                    raise ValueError("conflicting macro prefix maps")
                # GCC prefix maps use the last matching rule. Even an identical
                # repeated rule cannot move across an overlapping source prefix.
                if any(
                    source != prior and (source.startswith(prior) or prior.startswith(source))
                    for prior in maps
                ):
                    raise ValueError("overlapping macro prefix maps")
                maps[source] = destination
            elif token.startswith("-frandom-seed="):
                seeds.add(token)
                if len(seeds) > 1:
                    raise ValueError("conflicting random seeds")
            elif not token.startswith("-L/nix/store/"):
                # Definitions, libraries and stateful linker flags are deliberately
                # unsupported: removing their repeated occurrences can change behavior.
                raise ValueError("unsupported flag; environment left unchanged")
            group = (token,)
            index += 1
        groups.append(group)
    unique = list(dict.fromkeys(groups))
    return shlex.join([token for group in unique for token in group]), len(groups), len(unique)


def environment(original):
    result = original.copy()
    receipt = {}
    # Validate every variable before any command can run.
    for key in FLAG_VARIABLES:
        if key not in original:
            continue
        raw = original[key]
        value, before, after = normalize(raw, original.get("out"))
        result[key] = value
        receipt[key] = {
            "before_bytes": len(raw.encode()),
            "after_bytes": len(value.encode()),
            "before_groups": before,
            "after_groups": after,
            "before_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(value.encode()).hexdigest(),
        }
    return result, receipt


def main(argv):
    if not argv:
        raise ValueError("a command is required")
    env, receipt = environment(os.environ)
    print(json.dumps({"nix_path_flag_normalization": receipt}), flush=True)
    os.execvpe(argv[0], argv, env)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, OSError) as error:
        print(f"Nix dev-shell command rejected: {error}", file=sys.stderr)
        sys.exit(1)
