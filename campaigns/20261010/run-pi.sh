#!/bin/bash
# run-pi.sh rpi3|rpi5
case $1 in
rpi3) BOARD=rpi3 DUT=192.168.0.6 BUILD=build-pi ;;
rpi5) BOARD=rpi5 DUT=192.168.0.5 BUILD=build-pi5 ;;
*) exit 2 ;;
esac
source "$(dirname "$0")/common.sh"
log "start"
until ping -c1 -W1 "$DUT" >/dev/null && ssh -o BatchMode=yes -o ConnectTimeout=5 "$BOARD" true 2>/dev/null; do
    sleep 30
done
LABEL=$BOARD
if deploy_pi "$BOARD" "$BUILD" tcp_ca=os pqc_profile=default; then
    alg_full "$BOARD/20261010-$BOARD"
    tls_full "$BOARD/20261010-$BOARD"
    rtt_family "$BOARD/20261010-$BOARD"
fi
if [ "$BOARD" = rpi5 ]; then
    rtt_sel rpi5/20261010-rpi5-grp-rtt100 100 100 10 10 --group-messages
    LABEL=rpi5-nocrypto
    deploy_pi rpi5 build-pi5-nocrypto hw_crypto=0 &&
        alg_full rpi5/20261010-rpi5-nocrypto
    deploy_pi rpi5 build-pi5 hw_crypto=1
fi
log "done"
