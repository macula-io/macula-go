#!/usr/bin/env bash
# Copies macula's sealed group vectors (test/vectors/e2e_seal_v1_group_keys.json, macula 13.2) into group/testdata,
# where group's TestVectors holds macula-go to the same group_keys_v1 payloads byte for byte and to the verdicts
# macula_ucan:authorize/3 reaches on the org's group_keys grants.
#
#   scripts/interop/copy_group_keys_vectors.sh <macula checkout> [git ref]
#
# The ref defaults to origin/main; macula regenerates the vectors with scripts/generate-seal-group-keys-vectors.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
macula=$(cd "$1" && pwd)
ref=${2:-origin/main}
target="$root/group/testdata"
from=$(git -C "$macula" rev-parse --short "$ref")

mkdir -p "$target"
git -C "$macula" show "$ref:test/vectors/e2e_seal_v1_group_keys.json" > "$target/e2e_seal_v1_group_keys.json"
echo "copied $from:test/vectors/e2e_seal_v1_group_keys.json to $target"
