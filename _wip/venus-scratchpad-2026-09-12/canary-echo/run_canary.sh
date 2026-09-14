#!/usr/bin/env bash
# One canary run: one SDK, one station, one fresh identity, at most two calls
# to io.macula.echo. Prints the JSON lines and saves them to logs/.
# Run only when Saturnus calls the baseline.
#
# Usage: bash run_canary.sh <go|ts|php> <station-host> <run-id>
#   run-id: the run id Saturnus names (e.g. baseline); sent as MACULA_CANARY_RUN.
#   station-host: station-de-frankfurt.macula.io or station-fr-paris.macula.io
# Route order (Saturnus): station-de-frankfurt.macula.io:4433 first, then
#   station-fr-paris.macula.io:4433, for every SDK.
# Each line reports "match" (content, ignoring text versus bytes and map key
#   order) and "exact_match" where the SDK can see the difference.
# Interpreters are pinned to absolute paths: the asdf (php) and mise (node)
# shims fail in folders whose .tool-versions does not name a version.
set -u
D="$(cd "$(dirname "$0")" && pwd)"
PHP_BIN="${PHP_BIN:-/home/rl/.asdf/installs/php/8.5.10/bin/php}"
NODE_BIN="${NODE_BIN:-/home/rl/.local/share/mise/installs/node/26.8.1/bin/node}"
sdk="${1:-}"
host="${2:-}"
run="${3:-}"
if [ -z "$sdk" ] || [ -z "$host" ] || [ -z "$run" ]; then
  echo "usage: bash run_canary.sh <go|ts|php> <station-host> <run-id>" >&2
  exit 2
fi
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log="$D/logs/${sdk}-${host%%.*}-${run}-${stamp}.jsonl"
export MACULA_CANARY_RUN="$run"
mkdir -p "$D/logs"
case "$sdk" in
  go)  "$D/go/canary-echo-go" "$host" ;;
  ts)  "$NODE_BIN" "$D/ts/call_echo.mts" "$host" ;;
  php) MACULA_LIBRARY_PATH="$D/php/libmacula.so" "$PHP_BIN" "$D/php/call_echo.php" "$host" ;;
  *)   echo "unknown sdk: $sdk (go, ts or php)" >&2; exit 2 ;;
esac 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
echo "exit=${rc} run=${run} started_utc=${stamp} log=${log}"
exit "$rc"
