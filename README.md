# Post-quantum TLS on embedded devices: measurement artifact

This repository is the artifact of the ESE Kongress 2026 paper *Post-Quantum TLS on Embedded Devices: What It Costs* (Tobias Frauenschläger, wolfSSL Inc.). It holds the measurement framework, the pinned build configuration and patches, the raw data and packet captures behind the paper, and the scripts that draw its figures and print every number it cites.

The framework measures wolfSSL's post-quantum algorithms on embedded systems: raw algorithm performance, TLS 1.3 time to first byte (TTFB), and heap and stack usage. The same C core runs as a Zephyr application on the NXP FRDM-RW612 and the ST NUCLEO-H743ZI and as a Linux binary on a Raspberry Pi 3B+ and a Raspberry Pi 5. A host helper acts as the TLS peer and writes CSVs.

## Reproducing the paper

`results/<board>/` holds every run the paper uses: `20261010-*` from the main campaign, `20261011-trace-*` with the packet captures, and the other `20261011-*` runs, which add matching 0 ms baselines: the Pi 5 with grouped host messages, and the H743 1 s RTO image at 0, 100 and 600 ms, which replaces the `20261010` RTO runs. Each run's `meta.txt` records the DUT image, revisions and options. With Python 3, pandas, NumPy and Matplotlib:

```sh
python3 paper/figures.py                      # paper/out/fig1_ops.png ... fig4_heap.png
python3 paper/cited.py                        # every cited number, with its source run
scripts/check_results.py results/*/2026101*   # sample counts, failures, off-RTT connects
```

To repeat measurements, build and flash as described below, then for example on the H743 (192.168.0.3):

1. Primitive benchmark: flash `h743-fpu` and run `./build-host/ese_host --dut 192.168.0.3 --host-ip 192.168.0.1 --alg --alg-filter mldsa44 --out results/h743/<date>-alg`.
2. TTFB: with the same image, run `./build-host/ese_host --dut 192.168.0.3 --host-ip 192.168.0.1 --tls --kex mlkem768 --chain mldsa44 --auth server --role server --rtt-ms 0 --out results/h743/<date>-tls`.
3. TCP comparison: repeat step 2 on `h743-fpu` and `h743-fpu-tcp-iw10`, each at 0 and 100 ms RTT (see [Network latency](#network-latency)). Excess TTFB in RTT units is (TTFB - TTFB at 0 ms) / measured RTT - 3, where the measured RTT is the rise in median TCP connect time.

The full campaign, `campaigns/20261010/`, takes about a day per board.

## Matrix

| Dimension | Values |
|---|---|
| Key exchange | `secp256r1`, `x25519`, `mlkem768`, `x25519mlkem768` |
| Chains (root, intermediate, leaf) | `ecdsa_p256`, `rsa3072`, `mldsa44`, `falcon512`, `slhdsa_{sha2,shake}_128{s,f}`, and LMS and XMSS CAs over the ML-DSA-44 and SLH-DSA leaves |
| Authentication | server-only, mutual |
| DUT role | client, server |
| Samples | 1000 per scenario; 50 for SLH-DSA-128f leaves; SLH-DSA-128s leaves only with ML-KEM-768 and 10 samples |

That gives 216 TLS scenarios and 101,040 handshakes per platform (`ese_host --tls --dry-run` lists them), plus 34 raw operations. Every scenario uses TLS 1.3 with `TLS_AES_128_GCM_SHA256`, full handshakes, one key share and one supported group (so no HelloRetryRequest), SNI with a server name check, and a preinstalled root that is never sent. [certs/README.md](certs/README.md) lists the certificate contents.

## Layout

| Path | What |
|---|---|
| `config/ese_user_settings.h` | The wolfSSL configuration of every build |
| `common/`, `dut/` | Portable core (TLS endpoint, benchmarks, heap tracker, control protocol), platform layers and DUT entry points; `dut/footprint` is the flash footprint app |
| `host/ese_host.c` | Host helper |
| `certs/` | Chain and stateful-signature vector generators and their committed output |
| `scripts/` | `build.sh`, `netem.sh`, `pi-deploy.sh` and the analysis helpers |
| `paper/` | `figures.py` and `cited.py` |
| `manifest/west.yml`, `patches/` | Pinned revisions and what they change against upstream |
| `campaigns/`, `results/` | Campaign scripts and their output |

## Setup

The measurements used these versions; `manifest/west.yml` pins the sources and [patches/README.md](patches/README.md) describes them.

| Component | Version |
|---|---|
| Zephyr | 4.4.1 with the configurable initial TCP window, `github.com/Frauschi/zephyr` at `293d8738dd2` |
| wolfSSL | 5.9.4 development branch with pending memory and speed changes, `github.com/Frauschi/wolfssl` at `c065d363a` |
| Zephyr SDK | 1.0.1 (arm-zephyr-eabi-gcc 14.3.0); 0.17.x does not work |
| west, CMake, host GCC | 1.5.0, 4.2.3, 15.2.0 |
| Host | Ubuntu, Linux 7.0.0 aarch64, in a Parallels VM on an Apple silicon Mac, with the USB Ethernet adapter (RTL8156) passed through; TCP cubic, initial window 10, `tcp_slow_start_after_idle=1`, GRO and TSO on |
| Raspberry Pi 3B+, Pi 5 | Raspberry Pi OS, Linux 6.18.50, TCP cubic, CPU governor `performance` |

```sh
west init -l manifest && west update
./scripts/build.sh host          # ese_host, ese_certgen, Linux ese_dut, ese_wctest
./scripts/build.sh pi            # Pi 3B+
./scripts/build.sh pi5           # Pi 5 with the AES and SHA instructions
./scripts/build.sh pi5-nocrypto  # Pi 5 without them
./scripts/build.sh rw612         # FRDM-RW612
./scripts/build.sh h743-fpu      # NUCLEO-H743ZI, Falcon on the double-precision FPU
./scripts/build.sh h743-fpu-int  # NUCLEO-H743ZI, Falcon on the integer backend
./scripts/build.sh sim           # Zephyr on native_sim, for local tests
```

Targets take these suffixes, for example `h743-fpu-tcp-iw10-rto1000`:

| Suffix | Targets | Effect |
|---|---|---|
| `-trace` | all | Heap-trace build with wolfSSL's debug logging; never use it for timing |
| `-pqc-<profile>` | all | PQC profile: `default`, `smallmem`, `smallmem-fast`, `cache` or `small` |
| `-fpr-int`, `-fpr-double`, `-fpr-neon` | Pi | Falcon floating-point backend (default `neon`) |
| `-tcp-iw<N>` | Zephyr | Initial TCP window of N segments and no slow-start threshold |
| `-rto<ms>` | Zephyr | Initial TCP retransmission timeout |

Zephyr images use the `smallmem` profile and the Linux DUT uses `default`; `config/ese_user_settings.h` defines all five. `ESE_ALL_PQC_PARAMS` adds more parameter sets to the benchmarks and must be set on the host and DUT alike. `ESE_NO_ASM` builds portable C. The HELLO line in `meta.txt` reports what a DUT runs, including `pqc_profile=`, `falcon_fpr=` and `tcp_ca=`.

## Running

Cable each DUT to the host directly or through a switch, with static addresses: host 192.168.0.1/24, RW612 .2 and H743 .3 (set in `dut/zephyr/boards/`), Pi 5 .5, Pi 3B+ .6. Flash the Zephyr image, or start the Pi DUT with `./scripts/pi-deploy.sh [-b] <pi-host> [build-dir]`, which also sets the CPU governor. Then:

```sh
./build-host/ese_host --dut 192.168.0.2 --host-ip 192.168.0.1 --label rw612 --alg --tls
```

| Option | Effect |
|---|---|
| `--chain`, `--kex`, `--auth`, `--role`, `--alg-filter`, `--op-filter` | Restrict the matrix (comma-separated) |
| `--n N`, `--scale 0.02` | Fixed sample count, or a fraction of the default counts |
| `--out DIR` | Output directory; rerunning into it skips scenarios already in `tls.csv` |
| `--rtt-ms R` | Expected added RTT, checked per scenario |
| `--group-messages` | The host sends each handshake flight in one write instead of one per message |
| `--heap-trace` | One traced handshake per scenario, on a `-trace` build |

To measure several boards at once, run one `ese_host` per DUT with its own `--dut`, `--label` and `--out`. Each needs a free core, because a DUT client's TTFB includes the host's signing. Do not pin `ese_host` with `taskset`: next to the netem spin loops it then wakes only on the 1 ms scheduler tick.

## Network latency

`scripts/netem.sh` adds an RTT on the host's DUT link with Linux netem. It delays the packets arriving from the DUT and leaves the control port alone. In a VM it also keeps every vCPU busy until `off`, because netem's timers fire late while the vCPUs idle. It needs root for `tc`.

```sh
./scripts/netem.sh set 192.168.0.2 100
./build-host/ese_host --dut 192.168.0.2 --host-ip 192.168.0.1 --label rw612 --tls \
    --rtt-ms 100 --out results/rw612/<date>-rw612-rtt100
./scripts/netem.sh off
```

`ese_host` stops if a scenario's median TCP connect time is not within 10% plus 2 ms of `--rtt-ms`. Pass `--rtt-ms 0` on baselines so leftover shaping is caught too.

Stock Zephyr TCP starts with a congestion window of one segment and a slow-start threshold of three; Linux starts with ten and no threshold. `-tcp-iw10` matches Linux and RFC 6928. Zephyr also retransmits after a fixed 200 to 300 ms without estimating the RTT, so beyond about 200 ms of RTT a client retransmits while it waits for the server's flight and collapses its own window. `-rto1000` sets the 1 s initial timeout of RFC 6298.

## Campaign scripts

`campaigns/20261010/build-all.sh` builds every image; `run-rw612.sh`, `run-h743.sh` and `run-pi.sh rpi3|rpi5` then measure one board each in parallel, and `run-h743-rto.sh` adds the 1 s RTO image. `run-rerun.sh` repeated runs from a first pass that had pinned `ese_host` with `taskset`. `campaigns/20261011-baselines/` measures the matching 0 ms baselines, and `campaigns/20261011-traces/` records the packet captures with `tcpdump`, which needs `cap_net_raw` and `cap_net_admin`. The scripts expect `west` on the `PATH` or in `$WEST` and the SDK in `$ZEPHYR_SDK_INSTALL_DIR`.

`scripts/pcap_flights.py <pcap> --dut <ip> [--mss <B>]` counts rounds and retransmissions in a capture. tcpdump sees the DUT's packets before netem delays them. The host's GRO merges consecutive DUT segments into one frame, which `--mss` splits again (1460 for Zephyr, 1448 for Linux with TCP timestamps).

## Output

Every run directory has `meta.txt` (DUT HELLO line, git revisions, options) and CSVs with a header row:

- **`tls.csv`**: one row per handshake with timing marks, wire bytes, DUT heap and stack.
- **`tls_ctx.csv`**: per scenario, heap and time of loading certificates and keys into the context.
- **`alg.csv`**: one row per operation with time, heap, stack and the heap the keys still hold (`key_held`); `variant` is the PQC profile.
- **`heap_trace.csv`**: every allocation of one traced handshake, with `mark`/`end` events around framework steps and wolfSSL handshake functions. Peak heap matches the normal build.
- **`footprint.csv`**, from `./scripts/footprint.sh rw612|h743 <run dir>`: flash and RAM growth of `dut/footprint` with one algorithm linked in, over the same profile's image with only the RNG and SHA-3.

| Metric | Definition |
|---|---|
| `ttfb_ns` | On the client: from just before `connect()` to receipt of the server's reply to the first 64-byte application message. It covers the TCP handshake, the TLS handshake and one application round trip. |
| `tcp_ns`, `client_hs_ns` | Client-side marks inside that interval: `connect()` done, and `wolfSSL_connect()` done. |
| `server_hs_ns`, `server_total_ns` | Server side, from `accept()` to handshake done and to reply sent. |
| `dut_heap_*` | Every wolfSSL allocation on the DUT from `wolfSSL_new()` to `wolfSSL_free()`. `peak` is the high-water mark above the level before the connection. |
| `dut_stack` | Deepest stack use below the entry frame of a fresh thread that runs one whole connection. |
| `c2s_bytes`, `s2c_bytes` | TLS bytes on the wire, including records and close_notify, excluding TCP/IP headers. |

`./scripts/view.sh` serves a browser viewer for `results/` at `http://127.0.0.1:8000/tools/viewer/`.

## License and citation

The code is licensed under the GNU General Public License, version 3 or later (see `LICENSE`), like wolfSSL, which every binary links. The keys in `certs/out` are test material, see [certs/README.md](certs/README.md). To cite the artifact, use `CITATION.cff`.
