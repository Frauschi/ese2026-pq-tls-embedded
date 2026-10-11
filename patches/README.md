# Patches and pinned sources

`manifest/west.yml` pins every module to the commit the measurements used. All of them are public.

## Zephyr

`github.com/Frauschi/zephyr` at `293d8738dd2` is Zephyr 4.4.1 with three commits on top:

- `0001-zephyr-net-tcp-make-initial-cwnd-and-ssthresh-configurable.patch` (this directory) adds `NET_TCP_CONGESTION_INITIAL_WIN` and `NET_TCP_CONGESTION_INITIAL_SSTHRESH`. The `-tcp-iw<N>` targets of `scripts/build.sh` set the first to N and the second to 0, which removes the slow-start threshold. The paper's "initial window of ten segments" results come from both changes together.
- Two FRDM-RW612 board fixes that the Ethernet port needs: the ENET reference clock before the PHY reset, and the swapped PHY reset and interrupt pins.

The `-rto<ms>` targets only set Zephyr's existing `NET_TCP_INIT_RETRANSMISSION_TIMEOUT`.

## wolfSSL

`github.com/Frauschi/wolfssl` branch `ese_2026` at `c065d363a` reports itself as 5.9.4. It is wolfSSL master of 2026-10-09 (`ac66af8ec`) with these pending changes:

| Change | Pull request |
|---|---|
| NXP EdgeLock (ELS) crypto callback port, only used by `rw612-els` | wolfSSL/wolfssl#11703 and its follow-up |
| TLS 1.3 handshake memory reductions (`tls_mem_2`, `tls_mem_3`) | not yet opened |
| Pre-master secret buffer sized by the key exchanges (`tls_mem_4`) | wolfSSL/wolfssl#11345, since merged |
| ML-KEM small-memory heap reductions and cached matrix A | wolfSSL/wolfssl#11565 |
| SLH-DSA speed and memory improvements | wolfSSL/wolfssl#11566 |
| Falcon memory, MCU signing speed and constant-time floating-point emulation | wolfSSL/wolfssl#11656 |

The memory-reduced PQC options (`smallmem` profile) and the SLH-DSA and Falcon timings depend on these changes, so a released wolfSSL gives different numbers.
