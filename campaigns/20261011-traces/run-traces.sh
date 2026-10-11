#!/bin/bash
# Packet captures behind the paper's TCP explanations: H743 stock, IW10 and IW10 + 1 s RTO, Pi 3B+.
BOARD=h743 DUT=192.168.0.3
source "${ESE_COMMON:-$(dirname "$0")/../20261010/common.sh}"
IF=$(ip -o route get "$DUT" | sed -n 's/.* dev \([^ ]*\).*/\1/p')

# cap <out> <rtt> [ese_host args...]: ML-DSA-44, ML-KEM-768, three handshakes per scenario.
cap() {
    local out=$1 r=$2 pid
    shift 2
    mkdir -p "$REPO/results/$out"
    rtt "$r"
    tcpdump -i "$IF" -s 256 -U -w "$REPO/results/$out/capture.pcap" \
        "host $DUT and not port 11111" 2>> "$LOGS/tcpdump-$BOARD.log" &
    pid=$!
    sleep 2
    host "$out" "$r" --tls --kex mlkem768 --chain mldsa44 --n 3 "$@"
    sleep 2
    kill "$pid"
    wait "$pid" 2>/dev/null
}

LABEL=h743-fpu
wait_hello "$DUT" tcp_ca=iw1-ss3 || exit 1
cap h743/20261011-trace-stock-rtt100 100 --auth server --role server

flash_h743 build-zdut-nucleo_h743zi-fpu-tcp-iw10 tcp_ca=iw10-ss0 falcon_fpr=double || exit 1
LABEL=h743-fpu-iw10
cap h743/20261011-trace-iw10-rtt100 100 --auth server --role server
cap h743/20261011-trace-iw10-rtt600 600 --role client

flash_h743 build-zdut-nucleo_h743zi-fpu-tcp-iw10-rto1000 tcp_ca=iw10-ss0 falcon_fpr=double || exit 1
LABEL=h743-fpu-iw10-rto1000
cap h743/20261011-trace-iw10-rto1000-rtt600 600 --role client

flash_h743 build-zdut-nucleo_h743zi-fpu falcon_fpr=double tcp_ca=iw1-ss3

BOARD=rpi3 DUT=192.168.0.6 LABEL=rpi3
cap rpi3/20261011-trace-rtt100 100 --auth server --role server

"$REPO/scripts/netem.sh" off >> "$LOGS/netem-h743.log" 2>&1
log "traces done"
