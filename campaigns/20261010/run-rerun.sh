#!/bin/bash
# Reruns the TLS parts first measured with a CPU-pinned ese_host: run-rerun.sh rw612|rpi3|rpi5|h743
case $1 in
rw612) BOARD=rw612 DUT=192.168.0.2 ;;
h743) BOARD=h743 DUT=192.168.0.3 ;;
rpi3) BOARD=rpi3 DUT=192.168.0.6 ;;
rpi5) BOARD=rpi5 DUT=192.168.0.5 ;;
*) exit 2 ;;
esac
source "$(dirname "$0")/common.sh"
log "rerun start (unpinned ese_host)"
case $BOARD in
rw612)
    LABEL=rw612
    wait_hello "$DUT" tcp_ca=iw1-ss3 trace=0 pqc_profile=smallmem && tls_full rw612/20261010-rw612
    ;;
rpi3|rpi5)
    LABEL=$BOARD
    B=build-pi; [ $BOARD = rpi5 ] && B=build-pi5
    if deploy_pi "$BOARD" "$B" tcp_ca=os pqc_profile=default; then
        tls_full "$BOARD/20261010-$BOARD"
        rtt_family "$BOARD/20261010-$BOARD"
        [ $BOARD = rpi5 ] && rtt_sel rpi5/20261010-rpi5-grp-rtt100 100 100 10 10 --group-messages
    fi
    ;;
h743)
    while pgrep -f run-h743-rto.sh >/dev/null; do sleep 60; done
    mkdir -p "$LOGS/discarded-pinned/h743"
    mv "$REPO"/results/h743/20261010-h743-fpu-iw10-rto1000-* "$LOGS/discarded-pinned/h743/" 2>/dev/null
    LABEL=h743-fpu
    flash_h743 build-zdut-nucleo_h743zi-fpu falcon_fpr=double tcp_ca=iw1-ss3 pqc_profile=smallmem &&
        { tls_full h743/20261010-h743-fpu; rtt_family h743/20261010-h743-fpu; }
    LABEL=h743-fpu-iw10
    flash_h743 build-zdut-nucleo_h743zi-fpu-tcp-iw10 tcp_ca=iw10-ss0 falcon_fpr=double &&
        rtt_family h743/20261010-h743-fpu-iw10
    LABEL=h743-fpu-iw10-rto1000
    flash_h743 build-zdut-nucleo_h743zi-fpu-tcp-iw10-rto1000 tcp_ca=iw10-ss0 falcon_fpr=double &&
        { rtt_sat h743/20261010-h743-fpu-iw10-rto1000-rtt600
          rtt_sel h743/20261010-h743-fpu-iw10-rto1000-rtt100 100 100 10 10; }
    flash_h743 build-zdut-nucleo_h743zi-fpu falcon_fpr=double tcp_ca=iw1-ss3
    ;;
esac
log "rerun done"
