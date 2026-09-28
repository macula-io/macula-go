#!/usr/bin/env bash
# Copies macula's E2E seal scheme 1 vectors and their spec (test/vectors/e2e_seal_v1.json, E2E_SEAL_V1.md) into
# seal/testdata, where seal's TestVectors holds macula-go to the same bytes, and its keyed advertisement vectors
# (test/vectors/e2e_seal_v1_advertisements.json, amendment A1) into record/testdata, where record's
# TestKeyedAdvertisementVectors holds Verify to macula's verdicts.
#
#   scripts/interop/copy_e2e_seal_vectors.sh <macula checkout> [git ref]
#
# The ref defaults to origin/main; macula regenerates the vectors with scripts/e2e_seal_vectors, and the
# advertisement vectors with scripts/generate-seal-advertisement-vectors.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
macula=$(cd "$1" && pwd)
ref=${2:-origin/main}
target="$root/seal/testdata"
advertisements="$root/record/testdata"
from=$(git -C "$macula" rev-parse --short "$ref")

mkdir -p "$target" "$advertisements"
for file in e2e_seal_v1.json E2E_SEAL_V1.md; do
  git -C "$macula" show "$ref:test/vectors/$file" > "$target/$file"
done
git -C "$macula" show "$ref:test/vectors/e2e_seal_v1_advertisements.json" > "$advertisements/e2e_seal_v1_advertisements.json"
echo "copied $from:test/vectors/{e2e_seal_v1.json,E2E_SEAL_V1.md} to $target"
echo "copied $from:test/vectors/e2e_seal_v1_advertisements.json to $advertisements"
