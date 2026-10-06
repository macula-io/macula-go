#!/usr/bin/env bash
# Copies macula's realm member endorsement vectors (test/vectors/realm_member_endorsement_v1.json) into record/testdata, where
# record's TestRealmMemberEndorsementVectors holds VerifyRealmMemberEndorsement to macula's
# macula_hyparview_endorsement:verify_endorsement/4.
#
#   scripts/interop/copy_realm_member_endorsement_vectors.sh <macula checkout> [git ref]
#
# The ref defaults to origin/main; macula regenerates the vectors with scripts/generate-realm-member-endorsement-vectors.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
macula=$(cd "$1" && pwd)
ref=${2:-origin/main}
target="$root/record/testdata"
from=$(git -C "$macula" rev-parse --short "$ref")

mkdir -p "$target"
git -C "$macula" show "$ref:test/vectors/realm_member_endorsement_v1.json" > "$target/realm_member_endorsement_v1.json"
echo "copied $from:test/vectors/realm_member_endorsement_v1.json to $target"
