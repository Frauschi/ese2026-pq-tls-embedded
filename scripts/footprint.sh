#!/usr/bin/env bash
# Flash and static RAM cost per algorithm and PQC profile:
# ./scripts/footprint.sh rw612|h743 <out dir>  (writes <out dir>/footprint.csv)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WEST=${WEST:-$(command -v west || echo "$HOME/zephyrproject/.venv/bin/west")}
export ZEPHYR_SDK_INSTALL_DIR=${ZEPHYR_SDK_INSTALL_DIR:-$HOME/.local/zephyr-sdk-1.0.1}
BIN=$ZEPHYR_SDK_INSTALL_DIR/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi

SIG="mldsa44_full mldsa44_verify falcon512_full falcon512_verify"
SLH="slhdsa_full slhdsa_verify"
HBS="lms_verify xmss_verify"
OPS="mlkem768_keygen mlkem768_encap mlkem768_decap mldsa44_keygen mldsa44_sign falcon512_keygen falcon512_sign slhdsa_keygen slhdsa_sign"
declare -A ITEMS=(
    [default]="rng ecdsa_p256_full ecdsa_p256_verify rsa3072_full rsa3072_verify x25519_full mlkem768_full $SIG $SLH $HBS $OPS"
    [smallmem]="mlkem768_full $SIG $SLH $OPS"
    [smallmem-fast]="$SIG"
    [cache]="mlkem768_full $SIG"
    [small]="mlkem768_full mldsa44_full mldsa44_verify $SLH $HBS"
)

case ${1:-} in
rw612) BOARD=frdm_rw612; EXTRA=() ;;
h743)  BOARD=nucleo_h743zi; EXTRA=("-DEXTRA_CONF_FILE=$ROOT/dut/zephyr/overlay-fpu.conf") ;;
*)     echo "usage: $0 rw612|h743 <out dir>" >&2; exit 2 ;;
esac
OUT=${2:?usage: $0 rw612|h743 <out dir>}
mkdir -p "$OUT"
RAW=$(mktemp)
LOG=$(mktemp)
trap 'rm -f "$RAW" "$LOG"' EXIT

for p in default smallmem smallmem-fast cache small; do
    dir=$ROOT/build-fp-$1-$p
    cfg="-DCONFIG_ESE_PQC_$(echo "$p" | tr 'a-z-' 'A-Z_')=y"
    for it in baseline ${ITEMS[$p]}; do
        # Only main.c changes between items, so all but the first build relink.
        args=(-d "$dir" "$ROOT/dut/footprint" -- -DFP_ITEM=$it)
        if [ "$it" = baseline ]; then
            args=(-p always -b $BOARD "${args[@]}" "${EXTRA[@]}" "$cfg")
        fi
        if ! "$WEST" build "${args[@]}" > "$LOG" 2>&1; then
            tail -n 30 "$LOG"
            echo "footprint build failed: $1 $p $it" >&2
            exit 1
        fi
        "$BIN-size" "$dir/zephyr/zephyr.elf" |
            awk -v p=$p -v it=$it 'NR == 2 { print p, it, $1 + $2, $2 + $3 }' >> "$RAW"
    done
    echo "$1 $p done"
done

# Costs are against the same profile's baseline (RNG and SHA-3); sha3 is the baseline over RNG only.
awk -v plat=$1 'BEGIN { print "platform,variant,alg,flavor,flash,ram,flash_delta,ram_delta" }
    { f[$1, $2] = $3; r[$1, $2] = $4; order[++n] = $1 SUBSEP $2 }
    END {
        for (i = 1; i <= n; i++) {
            split(order[i], k, SUBSEP); p = k[1]; it = k[2]
            if (it == "rng") continue
            if (it == "baseline") {
                print plat "," p ",baseline,-," f[p, it] "," r[p, it] ",0,0"
                if ((p, "rng") in f)
                    print plat "," p ",sha3,full," f[p, it] "," r[p, it] "," \
                        f[p, it] - f[p, "rng"] "," r[p, it] - r[p, "rng"]
                continue
            }
            alg = it; sub(/_[a-z]+$/, "", alg); fl = it; sub(/.*_/, "", fl)
            print plat "," p "," alg "," fl "," f[p, it] "," r[p, it] "," \
                f[p, it] - f[p, "baseline"] "," r[p, it] - r[p, "baseline"]
        }
    }' "$RAW" > "$OUT/footprint.csv"
echo "wrote $OUT/footprint.csv"
