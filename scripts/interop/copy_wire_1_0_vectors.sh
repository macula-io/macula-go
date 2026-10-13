#!/usr/bin/env bash
# Copies macula's wire 1.0 conformance vectors (priv/vectors/wire_1_0/*.json and FORMAT.md, macula#97) into
# testdata/wire_1_0, where each package's wire 1.0 runner holds macula-go to the same verdicts, and records the macula
# commit they came from in testdata/wire_1_0/MACULA_COMMIT: the vectors are pinned by that commit
# (docs/design/WIRE_1_0.md section 9). The generator's test-only private keys are not copied: no runner needs them.
#
#   scripts/interop/copy_wire_1_0_vectors.sh <macula checkout> [git ref]
#
# The ref defaults to origin/main.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
macula=$(cd "$1" && pwd)
ref=${2:-origin/main}
target="$root/testdata/wire_1_0"
commit=$(git -C "$macula" rev-parse "$ref^{commit}")

rm -rf "$target"
mkdir -p "$target"
files=()
while IFS= read -r path; do
  files+=("$path")
done < <(git -C "$macula" ls-tree --name-only "$commit" priv/vectors/wire_1_0/ | grep -E '\.(json|md)$')
for path in "${files[@]}"; do
  git -C "$macula" show "$commit:$path" > "$target/$(basename "$path")"
done
echo "$commit" > "$target/MACULA_COMMIT"
echo "copied ${#files[@]} files from $commit:priv/vectors/wire_1_0 to $target"
