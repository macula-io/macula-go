#!/usr/bin/env bash
# Copies macula's E2E seal scheme 1 vectors and their spec (test/vectors/e2e_seal_v1.json, E2E_SEAL_V1.md) into
# seal/testdata, where seal's TestVectors holds macula-go to the same bytes.
#
#   scripts/interop/copy_e2e_seal_vectors.sh <macula checkout> [git ref]
#
# The ref defaults to origin/main; macula regenerates the vectors with scripts/e2e_seal_vectors.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
macula=$(cd "$1" && pwd)
ref=${2:-origin/main}
target="$root/seal/testdata"

mkdir -p "$target"
for file in e2e_seal_v1.json E2E_SEAL_V1.md; do
  git -C "$macula" show "$ref:test/vectors/$file" > "$target/$file"
done
echo "copied $(git -C "$macula" rev-parse --short "$ref"):test/vectors/{e2e_seal_v1.json,E2E_SEAL_V1.md} to $target"
