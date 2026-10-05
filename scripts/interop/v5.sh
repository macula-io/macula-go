#!/usr/bin/env bash
# Live handshake v5 across stacks, on real TLS sessions: a macula station (erlang_v5_station.escript, macula's own
# macula_peering on macula_quic, run in the macula CI image) and macula-go's stationlink (gov5link) dialling it. Both
# derive E from their own TLS exporter (quinn's, Go's crypto/tls), so a context order, label or exporter that differs
# fails the handshake. The station probes the link with liveness_ping every 500 ms for the hold, so the link must
# answer. Passes when the link is v5 on SecP384r1MLKEM1024, not resumed, and both sides kept it up.
#
#   MACULA_BUILD=<compiled macula checkout, 13.2.0 or later> scripts/interop/v5.sh [profile]
#
# The other direction, macula's client against macula-go's station, is sealed.sh: its teststation answers v5.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${MACULA_CI_IMAGE:-ghcr.io/macula-io/macula-ci-otp@sha256:aff1d39bc4aa29d13044b90b38e9b7f4b757d50818cc11c5bb7e84cdbf82ac70}"
profile="${1:-pq_hybrid}"
: "${MACULA_BUILD:?a compiled macula checkout at 13.2.0 or later}"
work="$(mktemp -d)"
name="macula-go-v5-$$"
cleanup() {
  podman rm -f "$name" > /dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

(cd "$root" && go build -o "$work/gov5link" ./scripts/interop/gov5link)
podman run --rm --name "$name" --network host ${CI_RUNNER_CGROUP_PARENT:+--cgroup-parent "$CI_RUNNER_CGROUP_PARENT"} \
  -v "$MACULA_BUILD:/macula:ro" -v "$root/scripts/interop:/interop:ro" \
  "$image" escript /interop/erlang_v5_station.escript /macula/_build/default/lib/macula "$profile" 15 \
  > "$work/station.out" 2>&1 < /dev/null &
station_pid=$!
for _ in $(seq 1 300); do
  grep -q '^station ' "$work/station.out" 2> /dev/null && break
  sleep 0.2
done
if ! grep -q '^station ' "$work/station.out"; then
  echo "v5.sh: the macula station did not start:" >&2
  cat "$work/station.out" >&2
  exit 1
fi
read -r _ host port node < <(grep -m1 '^station ' "$work/station.out")
echo "== $profile: macula-go's link to a macula station ($host:$port)"
link=0
"$work/gov5link" -host "$host" -port "$port" -profile "$profile" -node "$node" -hold 5s || link=$?
wait "$station_pid" || true
echo "== $profile: the macula station"
cat "$work/station.out"
grep -q '^verdict: PASS' "$work/station.out" && [ "$link" -eq 0 ]
