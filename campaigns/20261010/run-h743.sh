#!/bin/bash
BOARD=h743 DUT=192.168.0.3
source "$(dirname "$0")/common.sh"
log "start"
LABEL=h743-fpu
if flash_h743 build-zdut-nucleo_h743zi-fpu falcon_fpr=double tcp_ca=iw1-ss3 pqc_profile=smallmem; then
    alg_full h743/20261010-h743-fpu
    tls_full h743/20261010-h743-fpu
    rtt_family h743/20261010-h743-fpu
fi
LABEL=h743-fpu-iw10
flash_h743 build-zdut-nucleo_h743zi-fpu-tcp-iw10 tcp_ca=iw10-ss0 falcon_fpr=double &&
    rtt_family h743/20261010-h743-fpu-iw10
LABEL=h743-fpu-int
flash_h743 build-zdut-nucleo_h743zi-fpu-int falcon_fpr=emulated tcp_ca=iw1-ss3 &&
    alg_pqc h743/20261010-h743-fpu-int-alg
LABEL=h743-fpu-default
flash_h743 build-zdut-nucleo_h743zi-fpu-pqc-default pqc_profile=default falcon_fpr=double &&
    alg_pqc h743/20261010-h743-fpu-default-alg
flash_h743 build-zdut-nucleo_h743zi-fpu falcon_fpr=double tcp_ca=iw1-ss3
log "done"
