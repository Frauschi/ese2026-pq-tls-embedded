#!/bin/bash
# Shared helpers for the 2026-10-10 campaign, sourced by the run-*.sh scripts.
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOGS=${ESE_CAMPAIGN_LOGS:-$HOME/ese-campaign-logs}
HOST_IP=192.168.0.1
WEST=${WEST:-$(command -v west || echo "$HOME/zephyrproject/.venv/bin/west")}
SDK=${ZEPHYR_SDK_INSTALL_DIR:-$HOME/.local/zephyr-sdk-1.0.1}
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)} ZEPHYR_SDK_INSTALL_DIR=$SDK
mkdir -p "$LOGS"
cd "$REPO" || exit 1

NON_SLH=ecdsa_p256,rsa3072,mldsa44,falcon512,lms+mldsa44,xmss+mldsa44
SLH_F=slhdsa_sha2_128f,slhdsa_shake_128f,lms+slhdsa_sha2_128f,lms+slhdsa_shake_128f,xmss+slhdsa_sha2_128f,xmss+slhdsa_shake_128f
SLH_S=slhdsa_sha2_128s,slhdsa_shake_128s,lms+slhdsa_sha2_128s,lms+slhdsa_shake_128s,xmss+slhdsa_sha2_128s,xmss+slhdsa_shake_128s
NOFAL=ecdsa_p256,rsa3072,mldsa44,lms_h10,lms_h15,xmss_h10,xmss_h16,secp256r1,x25519,mlkem768
SLHA_F=slhdsa_sha2_128f,slhdsa_shake_128f
SLHA_S=slhdsa_sha2_128s,slhdsa_shake_128s

log() { echo "$(date '+%F %T') [$BOARD] $*" | tee -a "$LOGS/campaign.log"; }

hello() {
    timeout 15 bash -c "exec 3<>/dev/tcp/$1/11111 && echo HELLO >&3 && read -t 10 l <&3 && echo QUIT >&3 && echo \"\$l\"" 2>/dev/null
}

# wait_hello <ip> <substring>...: up to 5 min until HELLO carries every substring.
wait_hello() {
    local ip=$1 l= i e ok
    shift
    for i in $(seq 60); do
        if l=$(hello "$ip"); then
            ok=1
            for e in "$@"; do [[ $l == *"$e"* ]] || ok=0; done
            if [ $ok = 1 ]; then log "HELLO $l"; return 0; fi
        fi
        sleep 5
    done
    log "HELLO check FAILED for $ip, want: $*, last: $l"
    return 1
}

rtt() { "$REPO/scripts/netem.sh" set "$DUT" "$1" >> "$LOGS/netem-$BOARD.log" 2>&1; }

# host <out> <rtt|-> [ese_host args...]: retries; never pin ese_host, it then wakes on 1 ms ticks.
host() {
    local out=$REPO/results/$1 r=$2 i
    shift 2
    local ra=()
    [ "$r" != - ] && ra=(--rtt-ms "$r")
    mkdir -p "$out"
    for i in $(seq 8); do
        [ "$r" != - ] && rtt "$r"
        log "ese_host $1 rtt=$r $*"
        if "$REPO/build-host/ese_host" --dut "$DUT" --host-ip "$HOST_IP" \
                --label "$LABEL" --out "$out" "${ra[@]}" "$@" >> "$LOGS/host-$BOARD.log" 2>&1; then
            return 0
        fi
        log "ese_host failed ($1, attempt $i), retry in 90 s"
        sleep 90
        wait_hello "$DUT" OK || true
    done
    log "GIVING UP $1 $*"
    return 1
}

# Full matrix at 0 ms: N=1000, SLH-DSA-128f 50, SLH-DSA-128s 10 (ML-KEM-768 only).
tls_full() {
    host "$1" 0 --tls --chain "$NON_SLH"
    host "$1" 0 --tls --chain "$SLH_F" --n 50
    host "$1" 0 --tls --chain "$SLH_S" --n 10
}

# Every operation: N=1000, Falcon keygen 100, SLH-DSA keygen/sign 50 (f) and 10 (s).
alg_full() {
    host "$1" - --alg --alg-filter "$NOFAL"
    host "$1" - --alg --alg-filter falcon512 --op-filter sign,verify
    host "$1" - --alg --alg-filter falcon512 --op-filter keygen --n 100
    host "$1" - --alg --alg-filter "$SLHA_F,$SLHA_S" --op-filter verify
    host "$1" - --alg --alg-filter "$SLHA_F" --op-filter keygen,sign --n 50
    host "$1" - --alg --alg-filter "$SLHA_S" --op-filter keygen,sign --n 10
}

# PQC memory-profile comparison: ML-KEM, ML-DSA and Falcon only.
alg_pqc() {
    host "$1" - --alg --alg-filter mlkem768,mldsa44
    host "$1" - --alg --alg-filter falcon512 --op-filter sign,verify
    host "$1" - --alg --alg-filter falcon512 --op-filter keygen --n 100
}

# rtt_sel <out> <rtt> <n> <n_slh_f> <n_slh_s> [extra]: the chains the paper uses, ML-KEM-768.
rtt_sel() {
    local o=$1 r=$2 n=$3 nf=$4 ns=$5
    shift 5
    host "$o" "$r" --tls --kex mlkem768 --chain ecdsa_p256,rsa3072,falcon512,mldsa44,lms+mldsa44 --n "$n" "$@"
    host "$o" "$r" --tls --kex x25519 --chain ecdsa_p256 --n "$n" "$@"
    host "$o" "$r" --tls --kex mlkem768 --chain lms+slhdsa_sha2_128f,slhdsa_sha2_128f --n "$nf" "$@"
    host "$o" "$r" --tls --kex mlkem768 --chain slhdsa_sha2_128s --auth server --role client --n "$ns" "$@"
}

# 600 ms (GEO satellite): fewer chains and samples.
rtt_sat() {
    local o=$1
    host "$o" 600 --tls --kex mlkem768 --chain ecdsa_p256,falcon512,mldsa44,lms+mldsa44 --n 20
    host "$o" 600 --tls --kex x25519 --chain ecdsa_p256 --n 20
    host "$o" 600 --tls --kex mlkem768 --chain slhdsa_sha2_128f --n 5
    host "$o" 600 --tls --kex mlkem768 --chain slhdsa_sha2_128s --auth server --role client --n 5
}

rtt_family() {
    local p=$1
    rtt_sel "$p-rtt0" 0 100 10 10
    rtt_sel "$p-rtt10" 10 100 10 10
    rtt_sel "$p-rtt100" 100 100 10 10
    rtt_sat "$p-rtt600"
}

flash_rw612() {
    local b=$1 i
    shift
    for i in 1 2 3 4 5 6; do
        log "flash RW612 $b (attempt $i)"
        if timeout 240 "$WEST" flash -d "$REPO/$b" -r jlink --skip-rebuild >> "$LOGS/flash-$BOARD.log" 2>&1 \
                && wait_hello "$DUT" "$@"; then
            return 0
        fi
        log "RW612 flash or HELLO failed; if J-Link hangs: accept the popup or hold RESET"
        if [ "$(date +%H%M)" -gt 2330 ]; then log "too late for a J-Link flash today"; return 1; fi
        sleep 120
    done
    return 1
}

flash_h743() {
    local b=$1 i
    local oocd scr
    shift
    oocd=$(ls "$SDK"/hosttools/sysroots/*/usr/bin/openocd | head -1)
    scr=$(ls -d "$SDK"/hosttools/sysroots/*/usr/share/openocd/scripts | head -1)
    for i in 1 2 3; do
        log "flash H743 $b (attempt $i)"
        if timeout 150 "$oocd" -s "$scr" -f interface/stlink-dap.cfg -c "reset_config connect_assert_srst" \
                -f target/stm32h7x.cfg -c "init; reset halt; program $REPO/$b/zephyr/zephyr.elf verify; reset run; shutdown" \
                >> "$LOGS/flash-$BOARD.log" 2>&1 && wait_hello "$DUT" "$@"; then
            return 0
        fi
        sleep 60
    done
    return 1
}

deploy_pi() {
    local pi=$1 b=$2
    shift 2
    log "deploy $b to $pi"
    "$REPO/scripts/pi-deploy.sh" -b "$pi" "$b" >> "$LOGS/deploy-$BOARD.log" 2>&1 && wait_hello "$DUT" "$@"
}
