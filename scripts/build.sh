#!/usr/bin/env bash
# Builds one target: host | pi | pi5 | pi5-nocrypto | sim | rw612 | rw612-els | h743 |
# h743-fpu | h743-fpu-int, each optionally with a -trace suffix for the heap-trace
# variant, or a -pqc-<profile> suffix (default, smallmem, smallmem-fast, cache, small).
# Pi targets take -fpr-<int|double|neon> for the Falcon backend (default neon).
# Zephyr targets also take a -tcp-iw<N> suffix (initial window N, no ssthresh) and a
# final -rto<ms> suffix for the initial TCP retransmission timeout.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WEST=${WEST:-$(command -v west || echo "$HOME/zephyrproject/.venv/bin/west")}
export ZEPHYR_SDK_INSTALL_DIR=${ZEPHYR_SDK_INSTALL_DIR:-$HOME/.local/zephyr-sdk-1.0.1}
ELS_WOLFSSL=${ESE_ELS_WOLFSSL:-}
APP=$ROOT/dut/zephyr

TARGET=${1:-}
SUFFIX=
CONFS=()
ZARGS=()
PROFILE=
TCPIW=
RTO=
FPR=
if [[ $TARGET == pi*-fpr-* ]]; then
    FPR=${TARGET##*-fpr-}
    TARGET=${TARGET%-fpr-*}
fi
if [[ $TARGET == *-rto* ]]; then
    RTO=${TARGET##*-rto}
    TARGET=${TARGET%-rto*}
    if ! [[ $RTO =~ ^[0-9]+$ ]] || [[ $TARGET == host* || $TARGET == pi* ]]; then
        echo "-rto<ms> needs a Zephyr target and a number" >&2
        exit 2
    fi
    ZARGS+=("-DCONFIG_NET_TCP_INIT_RETRANSMISSION_TIMEOUT=$RTO")
fi
if [[ $TARGET == *-tcp-iw* ]]; then
    TCPIW=${TARGET##*-tcp-iw}
    TARGET=${TARGET%-tcp-iw*}
    if ! [[ $TCPIW =~ ^[0-9]+$ ]] || [[ $TARGET == host* || $TARGET == pi* ]]; then
        echo "-tcp-iw<N> needs a Zephyr target and a number" >&2
        exit 2
    fi
    ZARGS+=("-DCONFIG_NET_TCP_CONGESTION_INITIAL_WIN=$TCPIW"
            "-DCONFIG_NET_TCP_CONGESTION_INITIAL_SSTHRESH=0")
fi
if [[ $TARGET == *-pqc-* ]]; then
    PROFILE=${TARGET##*-pqc-}
    TARGET=${TARGET%-pqc-*}
    SUFFIX=-pqc-$PROFILE
    ZARGS+=("-DCONFIG_ESE_PQC_$(echo "$PROFILE" | tr 'a-z-' 'A-Z_')=y")
fi
if [[ $TARGET == *-trace ]]; then
    TARGET=${TARGET%-trace}
    SUFFIX=-trace
    CONFS+=(overlay-trace.conf)
fi
if [ -n "$TCPIW" ]; then
    SUFFIX+=-tcp-iw$TCPIW
fi
if [ -n "$RTO" ]; then
    SUFFIX+=-rto$RTO
fi

# zbuild <board> <build dir> [extra cmake args...]; uses CONFS and SUFFIX.
zbuild() {
    local args=()
    if [ ${#CONFS[@]} -gt 0 ]; then
        args+=("-DEXTRA_CONF_FILE=$(IFS=';'; echo "${CONFS[*]}")")
    fi
    "$WEST" build -p always -b "$1" -d "$ROOT/$2$SUFFIX" "$APP" -- \
        "${args[@]}" "${ZARGS[@]}" "${@:3}"
}

case "$TARGET" in
host)
    trace=OFF
    [ -n "$SUFFIX" ] && trace=ON
    if [ -n "$PROFILE" ]; then
        cmake -S "$ROOT" -B "$ROOT/build-host$SUFFIX" -G Ninja -DESE_DUT_ONLY=ON \
            -DESE_PQC_PROFILE="$PROFILE"
    else
        cmake -S "$ROOT" -B "$ROOT/build-host$SUFFIX" -G Ninja -DESE_HEAP_TRACE=$trace
    fi
    ninja -C "$ROOT/build-host$SUFFIX"
    ;;
pi|pi5|pi5-nocrypto)
    case $TARGET in
    pi)           cpu=cortex-a53;           name=rpi3bplus ;;
    pi5)          cpu=cortex-a76+crypto;    name=rpi5 ;;
    pi5-nocrypto) cpu=cortex-a76+nocrypto;  name=rpi5 ;;
    esac
    tc=()
    if [ "$(uname -m)" != aarch64 ]; then
        tc=(-DCMAKE_TOOLCHAIN_FILE="$ROOT/cmake/aarch64-linux-gnu.cmake")
    fi
    trace=OFF
    [ -n "$SUFFIX" ] && trace=ON
    [ -n "$FPR" ] && SUFFIX+=-fpr-$FPR
    cmake -S "$ROOT" -B "$ROOT/build-$TARGET$SUFFIX" -G Ninja "${tc[@]}" \
        -DESE_DUT_ONLY=ON -DESE_STATIC=ON -DESE_PLATFORM_NAME=$name \
        -DESE_HEAP_TRACE=$trace -DESE_FALCON_FPR="${FPR:-neon}" \
        -DCMAKE_C_FLAGS="-mcpu=$cpu"
    ninja -C "$ROOT/build-$TARGET$SUFFIX"
    ;;
sim)
    zbuild native_sim/native/64 build-zdut-sim
    ;;
rw612)
    zbuild frdm_rw612 build-zdut-frdm_rw612
    ;;
rw612-els)
    CONFS=(overlay-els.conf "${CONFS[@]}")
    if [ -z "$ELS_WOLFSSL" ]; then
        zbuild frdm_rw612 build-zdut-frdm_rw612-els
        exit 0
    fi
    # Same module set as the manifest, with wolfSSL swapped for ESE_ELS_WOLFSSL.
    mods=$(cd "$ROOT" && "$WEST" list -f '{abspath}' |
           grep -v -e '/manifest$' -e '/zephyr$' -e '/modules/crypto/wolfssl$' |
           tr '\n' ';')
    zbuild frdm_rw612 build-zdut-frdm_rw612-els "-DZEPHYR_MODULES=${mods}${ELS_WOLFSSL}"
    ;;
h743)
    zbuild nucleo_h743zi build-zdut-nucleo_h743zi
    ;;
h743-fpu)
    CONFS=(overlay-fpu.conf overlay-falcon-fpr.conf "${CONFS[@]}")
    zbuild nucleo_h743zi build-zdut-nucleo_h743zi-fpu
    ;;
h743-fpu-int)
    CONFS=(overlay-fpu.conf "${CONFS[@]}")
    zbuild nucleo_h743zi build-zdut-nucleo_h743zi-fpu-int
    ;;
*)
    echo "usage: $0 host|pi|pi5|pi5-nocrypto|sim|rw612|rw612-els|h743|h743-fpu|h743-fpu-int[-trace][-fpr-<int|double|neon>][-tcp-iw<N>][-rto<ms>]" >&2
    exit 2
    ;;
esac
