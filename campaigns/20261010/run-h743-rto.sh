#!/bin/bash
# Waits for run-h743.sh, then measures IW10 with a 1 s initial RTO on the H743 at 600 and 100 ms.
BOARD=h743 DUT=192.168.0.3
source "$(dirname "$0")/common.sh"
while pgrep -f run-h743.sh >/dev/null; do sleep 60; done
log "start RTO 1000 ms follow-up"
LABEL=h743-fpu-iw10-rto1000
if flash_h743 build-zdut-nucleo_h743zi-fpu-tcp-iw10-rto1000 tcp_ca=iw10-ss0 falcon_fpr=double; then
    rtt_sat h743/20261010-h743-fpu-iw10-rto1000-rtt600
    rtt_sel h743/20261010-h743-fpu-iw10-rto1000-rtt100 100 100 10 10
fi
flash_h743 build-zdut-nucleo_h743zi-fpu falcon_fpr=double tcp_ca=iw1-ss3
log "done RTO follow-up"
