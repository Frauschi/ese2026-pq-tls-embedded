#!/bin/bash
BOARD=rw612 DUT=192.168.0.2
source "$(dirname "$0")/common.sh"
log "start"
LABEL=rw612-iw10
flash_rw612 build-zdut-frdm_rw612-tcp-iw10 tcp_ca=iw10-ss0 trace=0 pqc_profile=smallmem &&
    rtt_family rw612/20261010-rw612-iw10
LABEL=rw612-trace
flash_rw612 build-zdut-frdm_rw612-trace trace=1 tcp_ca=iw1-ss3 &&
    host rw612/20261010-heap-trace 0 --heap-trace
LABEL=rw612-default
flash_rw612 build-zdut-frdm_rw612-pqc-default pqc_profile=default tcp_ca=iw1-ss3 trace=0 &&
    alg_pqc rw612/20261010-rw612-default-alg
LABEL=rw612
if flash_rw612 build-zdut-frdm_rw612 tcp_ca=iw1-ss3 trace=0 pqc_profile=smallmem; then
    rtt_family rw612/20261010-rw612
    alg_full rw612/20261010-rw612
    tls_full rw612/20261010-rw612
fi
log "done"
