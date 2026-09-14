#!/usr/bin/env bash
# Starts record_watch.mts detached for the rollout watch: 600 s through frankfurt, arrival times per
# event. Returns at once so mesh_watch can start right after it. Run only on Saturnus's "watch now".
#
# Usage: bash start_rollout_watch.sh
set -u
D="$(cd "$(dirname "$0")" && pwd)"
E="$D/../canary-echo"
NODE_BIN="${NODE_BIN:-/home/rl/.local/share/mise/installs/node/26.8.1/bin/node}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$D/logs/record-rollout-${stamp}.jsonl"
mkdir -p "$D/logs"
setsid nohup "$NODE_BIN" "$E/ts/record_watch.mts" station-de-frankfurt.macula.io 600 "$out" \
  > "$D/logs/record-rollout-${stamp}.stderr" 2>&1 < /dev/null &
echo "recorder pid=$! started_utc=${stamp} out=${out}"
