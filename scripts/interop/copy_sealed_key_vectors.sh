#!/usr/bin/env bash
# Copies macula's sealed key file vectors (test/vectors/sealed_key_v1.json) into identity/testdata, where
# identity's TestSealedKeyVectors holds the sealed form (MACULA-SEALED-KEY-V1) to the same bytes.
#
#   scripts/interop/copy_sealed_key_vectors.sh <macula checkout> [git ref]
#
# The ref defaults to origin/main. macula writes the vectors once with
# scripts/generate-sealed-key-vectors.sh (key generation is random, so a run makes new keys and the
# committed file is the vector), and the three implementations are held to that file
# (docs/design/DESIGN_SEALED_KEY_FILE.md, "7. Vectors").
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
macula=$(cd "$1" && pwd)
ref=${2:-origin/main}
target="$root/identity/testdata"
from=$(git -C "$macula" rev-parse --short "$ref")

mkdir -p "$target"
git -C "$macula" show "$ref:test/vectors/sealed_key_v1.json" > "$target/sealed_key_v1.json"
echo "copied $from:test/vectors/sealed_key_v1.json to $target"
echo "sha256 $(sha256sum "$target/sealed_key_v1.json" | cut -d' ' -f1)"
