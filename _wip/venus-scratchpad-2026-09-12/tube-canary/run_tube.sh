#!/usr/bin/env bash
# One tube canary run: one SDK, one station. Go does both lookups on identity A
# and tube.watch_video_clip by direct dial on identity B; TS does the lookups
# only. Prints the JSON lines and saves them to logs/. Run only on Saturnus's "go".
#
# Usage: bash run_tube.sh <go|ts> <station-host> <run-id>
#   station-host: station-de-frankfurt.macula.io, then station-fr-paris.macula.io
set -u
D="$(cd "$(dirname "$0")" && pwd)"
E="$D/../canary-echo"
NODE_BIN="${NODE_BIN:-/home/rl/.local/share/mise/installs/node/26.8.1/bin/node}"
sdk="${1:-}"
host="${2:-}"
run="${3:-}"
if [ -z "$sdk" ] || [ -z "$host" ] || [ -z "$run" ]; then
  echo "usage: bash run_tube.sh <go|ts> <station-host> <run-id>" >&2
  exit 2
fi
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log="$D/logs/${sdk}-${host%%.*}-${run}-${stamp}.jsonl"
mkdir -p "$D/logs"
export MACULA_CANARY_RUN="$run"
case "$sdk" in
  go) "$D/go/tube-canary-go" "$host" ;;
  ts) "$NODE_BIN" "$E/ts/tube_lookups.mts" "$host" ;;
  *)  echo "unknown sdk: $sdk (go or ts)" >&2; exit 2 ;;
esac 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
echo "exit=${rc} run=${run} started_utc=${stamp} log=${log}"
exit "$rc"
