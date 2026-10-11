#!/bin/bash
# Matching 0 ms baselines: Pi 5 with grouped host messages, and the H743 RTO 1 s image at 0, 100 and 600 ms.
source "${ESE_COMMON:-$(dirname "$0")/../20261010/common.sh}"

BOARD=rpi5 DUT=192.168.0.5 LABEL=rpi5
if wait_hello "$DUT" build=3fe0f20 tcp_ca=os hw_crypto=1 pqc_profile=default; then
    rtt_sel rpi5/20261011-rpi5-grp-rtt0 0 100 10 10 --group-messages
fi

BOARD=h743 DUT=192.168.0.3 LABEL=h743-fpu-iw10-rto1000
if flash_h743 build-zdut-nucleo_h743zi-fpu-tcp-iw10-rto1000 tcp_ca=iw10-ss0 falcon_fpr=double; then
    rtt_sel h743/20261011-h743-fpu-iw10-rto1000-rtt0 0 100 10 10
    rtt_sel h743/20261011-h743-fpu-iw10-rto1000-rtt100 100 100 10 10
    rtt_sat h743/20261011-h743-fpu-iw10-rto1000-rtt600
fi
flash_h743 build-zdut-nucleo_h743zi-fpu falcon_fpr=double tcp_ca=iw1-ss3

"$REPO/scripts/netem.sh" off >> "$LOGS/netem-h743.log" 2>&1
log "baselines done"
