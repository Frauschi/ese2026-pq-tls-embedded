#!/usr/bin/env bash
# Reruns ese_host into the same --out until it exits cleanly; finished scenarios are skipped.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TRIES=${ESE_TRIES:-20}

for i in $(seq 1 "$TRIES"); do
    "$ROOT/build-host/ese_host" "$@" && exit 0
    echo "ese_host failed (attempt $i/$TRIES); retrying in 90 s" >&2
    sleep 90
done
exit 1
