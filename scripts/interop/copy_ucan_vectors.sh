#!/usr/bin/env bash
# Copies macula's UCAN vectors and their spec (test/vectors/ucan_v1.json, UCAN_V1.md) into
# ucan/testdata, where ucan's vector tests hold macula-go to macula's verdicts.
#
#   scripts/interop/copy_ucan_vectors.sh <macula checkout> [git ref]
#
# The ref defaults to origin/main; macula regenerates the vectors with scripts/generate-ucan-vectors.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
macula=$(cd "$1" && pwd)
ref=${2:-origin/main}
target="$root/ucan/testdata"

mkdir -p "$target"
for file in ucan_v1.json UCAN_V1.md; do
  git -C "$macula" show "$ref:test/vectors/$file" > "$target/$file"
done
echo "copied $(git -C "$macula" rev-parse --short "$ref"):test/vectors/{ucan_v1.json,UCAN_V1.md} to $target"
