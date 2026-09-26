#!/usr/bin/env bash
# Sealed calls and streams across macula 13 and macula-go, both ways, through
# macula-go's test station: an Erlang provider named-key and required, called
# and streamed to by gosealed; then a Go provider, called and streamed to by
# erlang_sealed.escript. The Erlang side runs in macula's pinned CI image.
#
#   MACULA_BUILD=<macula checkout at v13.x, compiled> scripts/interop/sealed.sh [pq_hybrid|pq_pure]
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${MACULA_CI_IMAGE:-ghcr.io/macula-io/macula-ci-otp@sha256:aff1d39bc4aa29d13044b90b38e9b7f4b757d50818cc11c5bb7e84cdbf82ac70}"
profile="${1:-pq_hybrid}"
: "${MACULA_BUILD:?a compiled macula checkout at v13.x}"
work="$(mktemp -d)"
erl_name="macula-go-sealed-$$"
cleanup() {
  podman rm -f "$erl_name" > /dev/null 2>&1 || true
  [ -n "${go_pid:-}" ] && kill "$go_pid" 2> /dev/null || true
  exec 3>&- || true
  rm -rf "$work"
}
trap cleanup EXIT

(cd "$root" && go build -o "$work/teststation" ./teststation/cmd/teststation && go build -o "$work/gosealed" ./scripts/interop/gosealed)
mkfifo "$work/stations.in"
"$work/teststation" "$profile" < "$work/stations.in" > "$work/stations.out" &
exec 3> "$work/stations.in"

# first_line FILE PATTERN waits up to 180 s for a line of FILE matching PATTERN.
first_line() {
  for _ in $(seq 1 900); do
    line="$(grep -m1 -E "$2" "$1" 2> /dev/null || true)"
    [ -n "$line" ] && { echo "$line"; return 0; }
    sleep 0.2
  done
  echo "sealed.sh: no line matching $2 in $1" >&2
  cat "$1" >&2 || true
  return 1
}
info="$(first_line "$work/stations.out" '^\{')"
read -r host port station realm < <(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); s=d["stations"][0]; print(s["host"], s["port"], s["node_id"], d["realm_id"])' "$info")
erl() {
  podman run --rm --name "$erl_name" --network host -v "$MACULA_BUILD:/macula:ro" -v "$root/scripts/interop:/interop:ro" \
    "$image" escript /interop/erlang_sealed.escript /macula/_build/default/lib/macula "$host" "$port" "$station" "$realm" "$profile" "$@"
}

echo "== $profile: an Erlang provider, a Go caller"
erl serve 180 > "$work/erlang.out" 2>&1 &
first_line "$work/erlang.out" '^serving' > /dev/null
provider="$(first_line "$work/erlang.out" '^node ' | awk '{print $2}')"
"$work/gosealed" -station "$host:$port@$station" -profile "$profile" -realm "$realm" -provider "$provider" call
podman rm -f "$erl_name" > /dev/null 2>&1 || true

echo "== $profile: a Go provider, an Erlang caller"
"$work/gosealed" -station "$host:$port@$station" -profile "$profile" -realm "$realm" -hold 180s serve > "$work/go.out" 2>&1 &
go_pid=$!
first_line "$work/go.out" '^serving' > /dev/null
provider="$(first_line "$work/go.out" '^node ' | awk '{print $2}')"
erl call "$provider"
echo "== $profile: both ways sealed"
