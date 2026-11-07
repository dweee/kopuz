#!/usr/bin/env bash
set -euo pipefail
if [[ $# -gt 1 || ( $# -eq 1 && $1 != --retain-bootstrap ) ]]; then
  echo 'Usage: install-niks3.sh [--retain-bootstrap]' >&2
  exit 2
fi
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
target=github:Mic92/niks3/2d5a6b14e0df5c8fecc27571b79c40563c98ec32#niks3
if [[ -n ${NATIVE_BUILD_ADMISSION_COMMAND:-} ]]; then
  [[ $NATIVE_BUILD_ADMISSION_COMMAND == /nix/store/* && -x $NATIVE_BUILD_ADMISSION_COMMAND ]]
  "$NATIVE_BUILD_ADMISSION_COMMAND"
fi
# Only the later explicit publisher step receives write/forge/OIDC request
# credentials. Keep the refreshing read-only Nix configuration for substitution.
clean=(env -u ATTIC_TOKEN -u FLAKEY_ATTIC_TOKEN -u NIKS3_WRITE_TOKEN -u NIKS3_AUTH_TOKEN_FILE
  -u GH_TOKEN -u GITHUB_TOKEN -u CHANNEL_TOKEN -u SOURCE_TOKEN -u SSH_AUTH_SOCK
  -u ACTIONS_ID_TOKEN_REQUEST_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_URL)
build=(nix build --option accept-flake-config false --out-link "${RUNNER_TEMP:-/tmp}/niks3-client" --print-out-paths "$target")
if [[ ${1:-} == --retain-bootstrap ]]; then
  client=$("${clean[@]}" python3 "$directory/retain-build-outputs.py" --target "$target" \
    --manifest niks3-bootstrap-outputs.txt -- "${build[@]}")
else
  client=$("${clean[@]}" "${build[@]}")
fi
test -x "$client/bin/niks3"
printf 'NIKS3_BIN=%s/bin/niks3\n' "$client" >> "$GITHUB_ENV"
