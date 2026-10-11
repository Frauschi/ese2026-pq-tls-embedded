#!/bin/bash
# Builds every image the 2026-10-10 campaign flashes or deploys.
cd "$(dirname "$0")/../.." || exit 1
LOGS=${ESE_CAMPAIGN_LOGS:-$HOME/ese-campaign-logs}
mkdir -p "$LOGS"
for t in host pi pi5 pi5-nocrypto h743-fpu h743-fpu-tcp-iw10 h743-fpu-tcp-iw10-rto1000 h743-fpu-int \
         h743-fpu-pqc-default rw612 rw612-tcp-iw10 rw612-trace rw612-pqc-default; do
    echo "=== $(date +%T) build $t"
    if ./scripts/build.sh "$t" > "$LOGS/build-$t.log" 2>&1; then echo "ok $t"; else echo "FAIL $t"; fi
done
