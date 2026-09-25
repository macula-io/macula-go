#!/usr/bin/env bash
# Copies macula's own-namespace fixtures (signed procedure advertisements under ~<node_id>/<name> and the verdicts
# macula reaches on them) into record/testdata/own_namespace, where record's TestOwnNamespaceFixtures holds
# macula-go to the same verdicts.
#
#   scripts/interop/copy_own_namespace_fixtures.sh <macula checkout> [git ref]
#
# The ref defaults to origin/main; macula regenerates the files with scripts/generate-own-namespace-fixtures.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
macula=$(cd "$1" && pwd)
ref=${2:-origin/main}
source_dir=test/fixtures/own_namespace
target="$root/record/testdata/own_namespace"

rm -rf "$target"
mkdir -p "$target"
git -C "$macula" ls-tree -r --name-only "$ref" "$source_dir" | while read -r file; do
  relative=${file#"$source_dir"/}
  mkdir -p "$target/$(dirname "$relative")"
  git -C "$macula" show "$ref:$file" > "$target/$relative"
done
echo "copied $(git -C "$macula" rev-parse --short "$ref"):$source_dir to $target"
