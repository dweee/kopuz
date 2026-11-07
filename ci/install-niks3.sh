#!/usr/bin/env bash
set -euo pipefail
if [[ -n ${NATIVE_BUILD_ADMISSION_COMMAND:-} ]]; then
  [[ $NATIVE_BUILD_ADMISSION_COMMAND == /nix/store/* && -x $NATIVE_BUILD_ADMISSION_COMMAND ]]
  "$NATIVE_BUILD_ADMISSION_COMMAND"
fi
client=$(nix build --option accept-flake-config false --out-link "${RUNNER_TEMP:-/tmp}/niks3-client" --print-out-paths \
  github:Mic92/niks3/2d5a6b14e0df5c8fecc27571b79c40563c98ec32#niks3)
test -x "$client/bin/niks3"
printf 'NIKS3_BIN=%s/bin/niks3\n' "$client" >> "$GITHUB_ENV"
