#!/usr/bin/env bash
# Adds an artificial RTT on the DUT link of a Linux host, all of it on ingress
# through an ifb device. The control port 11111 is not delayed.
set -euo pipefail

DUT_IP=${ESE_DUT_IP:-192.168.0.2}
CTRL_PORT=11111
IFB=ifb-ese
SPIN_PIDS=${XDG_RUNTIME_DIR:-/tmp}/ese-netem-spin.pids
LOCK=${XDG_RUNTIME_DIR:-/tmp}/ese-netem.lock
CMD=${1:-}
RTT=
SET_IP=
if [ "$CMD" = on ]; then
    RTT=${2:-}
    shift 2 || true
elif [ "$CMD" = set ]; then
    SET_IP=${2:-}
    RTT=${3:-}
    DUT_IP=$SET_IP
    shift 3 || true
else
    shift || true
fi
DEV=${1:-$(ip -o route get "$DUT_IP" | sed -n 's/.* dev \([^ ]*\).*/\1/p')}
SUDO=
[ "$(id -u)" -ne 0 ] && SUDO=sudo

usage() {
    echo "usage: $0 on <rtt_ms> [dev] | set <dut_ip> <rtt_ms> [dev] | off [dev] | show [dev]" >&2
    echo "  dev defaults to the interface routing to \$ESE_DUT_IP ($DUT_IP)" >&2
    echo "  set gives one DUT its own RTT, so DUTs on one link can run at different RTTs" >&2
    exit 2
}

# redirect <dev>: all ingress of <dev> goes through the ifb device.
redirect() {
    if ! ip link show "$IFB" >/dev/null 2>&1; then
        $SUDO ip link add "$IFB" type ifb
        $SUDO ip link set "$IFB" up
    fi
    $SUDO tc qdisc add dev "$1" handle ffff: ingress
    $SUDO tc filter add dev "$1" parent ffff: protocol all u32 match u32 0 0 \
        action mirred egress redirect dev "$IFB"
}

# per_dut_layout: 16 bands, band 1:2 undelayed by default, one band per DUT octet.
per_dut_layout() {
    local f
    $SUDO tc qdisc add dev "$IFB" root handle 1: prio bands 16 \
        priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
    for f in sport dport; do
        $SUDO tc filter add dev "$IFB" parent 1: protocol ip prio 1 u32 \
            match ip "$f" "$CTRL_PORT" 0xffff flowid 1:1
    done
}

# shape <dev> <delay>: everything through netem except the control port.
shape() {
    $SUDO tc qdisc add dev "$1" root handle 1: prio bands 3 \
        priomap 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2
    $SUDO tc qdisc add dev "$1" parent 1:3 handle 30: netem delay "$2" limit 10000
    for f in sport dport; do
        $SUDO tc filter add dev "$1" parent 1: protocol ip prio 1 u32 \
            match ip "$f" "$CTRL_PORT" 0xffff flowid 1:1
    done
}

spin_stop() {
    if [ -f "$SPIN_PIDS" ]; then
        kill $(cat "$SPIN_PIDS") 2>/dev/null || true
        rm -f "$SPIN_PIDS"
    fi
}

# Idle vCPUs fire netem's timers late, so SCHED_IDLE loops keep them busy.
spin_start() {
    local i
    spin_stop
    for i in $(seq "$(nproc)"); do
        chrt -i 0 sh -c 'while :; do :; done' </dev/null >/dev/null 2>&1 &
        echo $! >> "$SPIN_PIDS"
    done
}

off() {
    spin_stop
    $SUDO tc qdisc del dev "$DEV" root 2>/dev/null || true
    $SUDO tc qdisc del dev "$DEV" ingress 2>/dev/null || true
    $SUDO tc qdisc del dev "$IFB" root 2>/dev/null || true
}

case "$CMD" in
on)
    [[ $RTT =~ ^[0-9]+(\.[0-9]+)?$ ]] || usage
    off
    redirect "$DEV"
    shape "$IFB" "${RTT}ms"
    [ "${ESE_NETEM_SPIN:-1}" = 1 ] && spin_start
    echo "$DEV: ${RTT} ms RTT on ingress, port $CTRL_PORT exempt"
    ping -c 5 -q "$DUT_IP" | tail -1
    ;;
set)
    [[ $RTT =~ ^[0-9]+(\.[0-9]+)?$ ]] || usage
    octet=${SET_IP##*.}
    [[ $SET_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ "$octet" -ge 2 ] &&
        [ "$octet" -le 15 ] || usage
    band=$((octet + 1))
    exec 9>"$LOCK"
    flock 9
    qd=$(tc qdisc show dev "$IFB" 2>/dev/null || true)
    if [[ $qd != *"qdisc prio 1: root"*"bands 16"* ]]; then
        off
        redirect "$DEV"
        per_dut_layout
    fi
    $SUDO tc qdisc replace dev "$IFB" parent "1:$band" handle "$((band * 10)):" \
        netem delay "${RTT}ms" limit 10000
    hex=$(printf '%02x%02x%02x%02x' ${SET_IP//./ })
    flt=$(tc filter show dev "$IFB" parent 1: 2>/dev/null || true)
    if [[ $flt != *"match $hex/ffffffff at 12"* ]]; then
        $SUDO tc filter add dev "$IFB" parent 1: protocol ip prio 2 u32 \
            match ip src "$SET_IP/32" flowid "1:$band"
    fi
    if [ "${ESE_NETEM_SPIN:-1}" = 1 ] && ! { [ -f "$SPIN_PIDS" ] &&
            kill -0 $(cat "$SPIN_PIDS") 2>/dev/null; }; then
        spin_start
    fi
    flock -u 9
    echo "$DEV: ${RTT} ms RTT on ingress from $SET_IP, port $CTRL_PORT exempt"
    ping -c 5 -q "$SET_IP" | tail -1
    ;;
off)
    off
    echo "$DEV: no added delay"
    ;;
show)
    tc qdisc show dev "$DEV"
    ip link show "$IFB" >/dev/null 2>&1 && tc qdisc show dev "$IFB"
    echo "spin loops: $([ -f "$SPIN_PIDS" ] && wc -l < "$SPIN_PIDS" || echo 0)"
    ping -c 5 -q "$DUT_IP" | tail -1
    ;;
*)
    usage
    ;;
esac
