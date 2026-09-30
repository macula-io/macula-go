#!/usr/bin/env bash
# Copies macula's station endpoint vectors (test/vectors/station_endpoint_v1.json) into record/testdata, where
# record's TestStationEndpointVectors holds ReadStationEndpoint to macula's read_station_endpoint/1.
#
#   scripts/interop/copy_station_endpoint_vectors.sh <macula checkout> [git ref]
#
# The ref defaults to origin/main; macula regenerates the vectors with scripts/generate-station-endpoint-vectors.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
macula=$(cd "$1" && pwd)
ref=${2:-origin/main}
target="$root/record/testdata"
from=$(git -C "$macula" rev-parse --short "$ref")

mkdir -p "$target"
git -C "$macula" show "$ref:test/vectors/station_endpoint_v1.json" > "$target/station_endpoint_v1.json"
echo "copied $from:test/vectors/station_endpoint_v1.json to $target"
