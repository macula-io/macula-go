#!/usr/bin/env bash
# Cross-checks macula-go's post-quantum identity with a compiled macula. macula checks the node keys, bindings and
# status statements macula-go makes, and refuses altered copies of them. With a fixtures file it also writes bindings
# and statements of its own, for macula-go's tests to verify.
#
#   scripts/interop/run.sh <macula lib dir> [fixtures file]
#
# <macula lib dir> is a compiled macula application with its NIFs, <macula checkout>/_build/default/lib/macula after
# rebar3 compile at the revision to check. Needs Go and OTP 28's erl and escript on PATH. Passing
# identity/testdata/erlang_bindings.json as the fixtures file refreshes macula-go's test data. Exits non-zero when any
# check fails.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
lib=$(cd "$1" && pwd)
fixtures=${2:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for needed in ebin/macula_node_keys.beam ebin/macula_key_bindings.beam ebin/macula_cbor_nif.beam priv/macula_cbor_nif.so; do
  if [ ! -e "$lib/$needed" ]; then
    echo "run.sh: $lib has no $needed; compile macula first" >&2
    exit 2
  fi
done

revision=unknown
if checkout=$(git -C "$lib" rev-parse --show-toplevel 2>/dev/null); then
  revision=$(git -C "$checkout" rev-parse HEAD)
fi

echo "macula-go: $(git -C "$root" rev-parse HEAD)"
echo "macula: $revision ($lib)"
echo "erlang: OTP $(erl -noshell -eval 'io:format("~s", [erlang:system_info(otp_release)]), halt().')"
echo "go: $(go version)"

(cd "$root" && go run ./scripts/interop/goartifacts "$work")
status=0
escript "$here/verify_go_identity.escript" "$lib/ebin" "$work/go_identity_artifacts.json" || status=1
escript "$here/verify_go_bindings.escript" "$lib/ebin" "$work/go_binding_artifacts.json" || status=1
if [ -n "$fixtures" ]; then
  escript "$here/emit_erlang_bindings.escript" "$lib/ebin" "$fixtures" "${revision:0:7}"
fi
exit "$status"
