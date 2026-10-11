#!/usr/bin/env bash
# Copies a Pi DUT build to <host>, pins the CPU clock, and starts it in the foreground,
# or with -b in the background (log in ~/ese_dut.log on the Pi).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BG=0
if [ "${1:-}" = -b ]; then
    BG=1
    shift
fi
PI=${1:?usage: $0 [-b] [user@]pi-host [build-dir]}
BUILD=${2:-build-pi}
case $BUILD in /*) ;; *) BUILD=$ROOT/$BUILD ;; esac

ssh "$PI" 'pkill -x ese_dut; while pgrep -x ese_dut >/dev/null; do sleep 0.1; done' || true
scp -q "$BUILD/ese_dut" "$PI:ese_dut"
ssh "$PI" '
    echo performance | sudo -n tee /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor >/dev/null
    echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)" \
         "freq: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq) kHz" \
         "throttled: $(vcgencmd get_throttled 2>/dev/null || echo n/a)"'
if [ $BG = 0 ]; then
    exec ssh -t "$PI" ./ese_dut
fi
ssh "$PI" 'nohup ./ese_dut >ese_dut.log 2>&1 </dev/null &
    for i in $(seq 50); do grep -q ready ese_dut.log && break; sleep 0.1; done
    cat ese_dut.log; grep -q ready ese_dut.log'
