#!/usr/bin/env bash
# Sealed groups across macula (13.2 on, wire 1.0) and macula-go, both ways, through macula-go's test station and
# macula's own distributor (macula_group_keys): the org's distributor runs in Erlang; an Erlang member and a Go member
# each subscribe under the group, pulling its epoch from it over a sealed call with the org's grant, and each
# publishes sealed under it; each must open the other's event. Then a Go node the distributor's removed set names
# must be refused not_a_member. The Erlang side runs in macula's pinned CI image.
#
#   MACULA_BUILD=<macula 15.0.0-rc.1 or later, compiled> scripts/interop/groups.sh [pq_hybrid|pq_pure]
#
# MACULA_BUILD may be a rebar3 project that depends on macula from hex, as for sealed.sh.
#
# GROUPS_PEER=ts runs the Go member's and the stranger's part with @macula-io/ts in their place
# (scripts/interop/tsgroups/tsgroups.mjs, from npm at the version its package-lock pins, or TS_PACKAGE, a local
# @macula-io/ts checkout, built). Needs node and npm.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${MACULA_CI_IMAGE:-ghcr.io/macula-io/macula-ci-otp@sha256:aff1d39bc4aa29d13044b90b38e9b7f4b757d50818cc11c5bb7e84cdbf82ac70}"
profile="${1:-pq_hybrid}"
: "${MACULA_BUILD:?a compiled macula at 15.0.0-rc.1 or later (wire 1.0)}"
work="$(mktemp -d)"
shared="$work/shared"
mkdir -p "$shared"
chmod 777 "$shared"
names=("macula-go-groups-dist-$$" "macula-go-groups-member-$$")
cleanup() {
  for n in "${names[@]}"; do podman rm -f "$n" > /dev/null 2>&1 || true; done
  [ -n "${go_pid:-}" ] && kill "$go_pid" 2> /dev/null || true
  exec 3>&- || true
  rm -rf "$work"
}
trap cleanup EXIT

peer="${GROUPS_PEER:-go}"
case "$peer" in go|ts) ;; *) echo "groups.sh: GROUPS_PEER is go or ts, not $peer" >&2; exit 2 ;; esac
(cd "$root" && go build -o "$work/teststation" ./teststation/cmd/teststation && go build -o "$work/gogroups" ./scripts/interop/gogroups)
if [ "$peer" = ts ]; then
  if [ -n "${TS_PACKAGE:-}" ]; then
    mkdir -p "$work/ts/node_modules/@macula-io"
    ln -s "$(cd "$TS_PACKAGE" && pwd)" "$work/ts/node_modules/@macula-io/ts"
    cp "$root/scripts/interop/tsgroups/tsgroups.mjs" "$work/ts/"
    tsgroups="$work/ts/tsgroups.mjs"
  else
    (cd "$root/scripts/interop/tsgroups" && npm ci --silent --no-audit --no-fund)
    tsgroups="$root/scripts/interop/tsgroups/tsgroups.mjs"
  fi
fi
mkfifo "$work/stations.in"
"$work/teststation" "$profile" < "$work/stations.in" > "$work/stations.out" &
exec 3> "$work/stations.in"

# nth_line FILE PATTERN N waits up to 180 s for the Nth line of FILE matching PATTERN.
nth_line() {
  for _ in $(seq 1 900); do
    line="$(grep -E "$2" "$1" 2> /dev/null | sed -n "$3p" || true)"
    [ -n "$line" ] && { echo "$line"; return 0; }
    sleep 0.2
  done
  echo "groups.sh: no line $3 matching $2 in $1" >&2
  cat "$1" >&2 || true
  return 1
}
info="$(nth_line "$work/stations.out" '^\{' 1)"
read -r host port station realm realm_key org org_key_id < <(python3 -c '
import json,sys; d=json.loads(sys.argv[1]); s=d["stations"][0]
print(s["host"], s["port"], s["node_id"], d["realm_id"], d["realm_key"], d["org"], d["org_key_id"])' "$info")
realm_name="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["realm_name"])' "$info")"
prefix="$realm_name/$org/chat"
topic="$prefix/said_v1"
grants=0

# grant NODE asks the test station for the org's grant to NODE and writes it where NODE waits for it.
grant() {
  echo "grant $1" >&3
  grants=$((grants + 1))
  # Written aside and moved into place: the node reads the file the moment it exists.
  nth_line "$work/stations.out" '^grant ' "$grants" | cut -d' ' -f2 > "$work/grant.tmp"
  mv "$work/grant.tmp" "$shared/grant.$1"
}
erl() {
  local name="$1"; shift
  podman run --rm --name "$name" --network host -v "$MACULA_BUILD:/macula:ro" -v "$root/scripts/interop:/interop:ro" \
    -v "$shared:/work" "$image" escript /interop/erlang_groups.escript /macula/_build/default/lib/macula \
    "$host" "$port" "$station" "$realm" "$realm_key" "$profile" /work "$@"
}
gogroups() {
  case "$peer" in
    go) "$work/gogroups" -station "$host:$port@$station" -profile "$profile" -realm "$realm" -realm-key "$realm_key" \
          -work "$shared" -prefix "$prefix" -topic "$topic" "$1" ;;
    ts) node "$tsgroups" "$host:$port@$station" "$profile" "$realm" "$realm_key" "$shared" "$prefix" "$topic" "$1" ;;
  esac
}
name="$( [ "$peer" = ts ] && echo TypeScript || echo Go )"

echo "== $profile: the org's distributor in Erlang"
erl "${names[0]}" distribute "$org" "$org_key_id" 300 > "$work/dist.out" 2>&1 &
distributor="$(nth_line "$work/dist.out" '^node ' 1 | awk '{print $2}')"
echo "admit $distributor" >&3
nth_line "$work/stations.out" '^admitted ' 1 > /dev/null
touch "$shared/admitted.$distributor"
nth_line "$work/dist.out" '^serving' 1 > /dev/null

echo "== $profile: an Erlang member and a $name member, each opening the other's sealed event"
erl "${names[1]}" member "$prefix" "$topic" > "$work/erlang.out" 2>&1 &
erl_pid=$!
gogroups member > "$work/go.out" 2>&1 &
go_pid=$!
# Each node id is read into a variable first: a failed read then ends the script (set -e), where an argument would not.
erlang_member="$(nth_line "$work/erlang.out" '^node ' 1 | awk '{print $2}')"
peer_member="$(nth_line "$work/go.out" '^node ' 1 | awk '{print $2}')"
grant "$erlang_member"
grant "$peer_member"
status=0
wait "$go_pid" || status=1
go_pid=
wait "$erl_pid" || status=1
cat "$work/erlang.out" "$work/go.out"
[ "$status" = 0 ] || { echo "groups.sh: a member failed"; cat "$work/dist.out"; exit 1; }

echo "== $profile: a $name node the distributor removed"
gogroups stranger > "$work/stranger.out" 2>&1 &
go_pid=$!
stranger="$(nth_line "$work/stranger.out" '^node ' 1 | awk '{print $2}')"
echo "$stranger" >> "$shared/removed"
grant "$stranger"
wait "$go_pid" || { cat "$work/stranger.out"; exit 1; }
go_pid=
cat "$work/stranger.out"
echo "== $profile: sealed groups both ways ($name)"
