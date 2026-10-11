# Post-quantum TLS on embedded devices: measurement artifact

This repository is the artifact of the ESE Kongress 2026 paper *Post-Quantum TLS on Embedded Devices: What It Costs* (Tobias Frauenschläger, wolfSSL Inc.). It holds the measurement framework, the pinned build configuration and patches, the raw data of the 2026-10-10 campaign and the 2026-10-11 packet captures, and the scripts that draw the paper's figures and print every number it cites. It is a snapshot of the working repository; see [Reproducing the paper](#reproducing-the-paper).

The framework measures wolfSSL's post-quantum algorithms on embedded systems: raw algorithm performance, TLS 1.3 time to first byte (TTFB), and heap and stack usage during both. The same C core runs as a Zephyr application on the NXP FRDM-RW612 and the ST NUCLEO-H743ZI and as a Linux binary on a Raspberry Pi 3B+ and a Raspberry Pi 5. A host helper plays the TLS peer and writes CSVs.

## Matrix

| Dimension | Values |
|---|---|
| Key exchange | `secp256r1`, `x25519`, `mlkem768`, `x25519mlkem768` |
| Chains (root, intermediate, leaf) | `ecdsa_p256`, `rsa3072`, `mldsa44`, `falcon512`, `slhdsa_{sha2,shake}_128{s,f}` |
| Stateful CA chains | LMS (root L1 SHA256/M32/H10/W4, intermediate H15/W4) and XMSS (root XMSS-SHA2_10_256, intermediate XMSS-SHA2_16_256) CAs over ML-DSA-44 and all four SLH-DSA leaves; the verify benchmark covers all four sets |
| Authentication | server-only, mutual |
| DUT role | client, server |
| Samples | 1000 per scenario; 50 for SLH-DSA-128f leaves; SLH-DSA-128s leaves only with ML-KEM-768 and 10 samples |

That gives 216 TLS scenarios and 101,040 handshakes per platform (`ese_host --tls --dry-run` lists them), plus 34 raw operations.

The TLS profile is TLS 1.3 only with `TLS_AES_128_GCM_SHA256`, full handshakes (no resumption, no tickets), one key share and one supported group per scenario so there is never a HelloRetryRequest, SNI plus a DNS check of the server name, and a preinstalled root that is never sent.

All certificates at one level carry identical metadata and differ only in key and signature algorithm:

| Level | Validity | Extensions |
|---|---|---|
| Root | 2026-2046 | BC CA (crit), KU keyCertSign+cRLSign (crit), SKI, AKI |
| Intermediate | 2026-2036 | BC CA pathlen 0 (crit), KU (crit), SKI, AKI, CRL DP |
| Server / client leaf | 2026-2031 | BC (crit), KU digitalSignature (crit), EKU serverAuth / clientAuth, SAN, SKI, AKI, CRL DP |

## Layout

| Path | What |
|---|---|
| `config/ese_user_settings.h` | The one wolfSSL configuration every build uses |
| `common/` | Portable core: TLS endpoint, algorithm benchmark, heap tracker, control protocol, DUT loop |
| `common/posix/`, `dut/zephyr/src/` | Platform layers (sockets, clock, stack probe) |
| `dut/linux/`, `dut/zephyr/` | DUT entry points; `dut/zephyr` is the Zephyr application |
| `dut/footprint/` | Zephyr app that links one algorithm in, for the flash footprint |
| `host/ese_host.c` | Host helper: drives the DUT, acts as the TLS peer, writes CSVs |
| `certs/gen/certgen.c`, `certs/gen/hbsgen.c`, `certs/out/` | Chain and stateful-signature vector generators and their committed output (DER files, C arrays, `sizes.csv`) |
| `scripts/` | `build.sh` for every target, `footprint.sh`, `pi-deploy.sh`, `view.sh` (results viewer), `plot_heap_trace.py`, `check_results.py` (counts, failures and off-RTT connects per run directory), `pcap_flights.py` (rounds and retransmissions in a capture), `run-until-done.sh` (retries `ese_host` into one directory) |
| `tools/viewer/` | Browser viewer for `results/` |
| `paper/` | `figures.py` draws Figures 1-4 of the paper into `paper/out/`, `cited.py` prints every number the paper cites; both read `results/` |
| `manifest/west.yml`, `patches/` | The pinned Zephyr, wolfSSL and module revisions, and what they change against upstream |
| `campaigns/<date>/` | The scripts that produced a campaign's result sets |
| `results/<label>/<date>/` | Measurement output |

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
./scripts/build.sh host        # ese_host, ese_certgen, ese_dut (Linux), ese_wctest
./scripts/build.sh pi          # static Cortex-A53 ese_dut for the Raspberry Pi 3B+
./scripts/build.sh pi5         # static Cortex-A76 ese_dut for the Raspberry Pi 5, with the AES and SHA instructions
./scripts/build.sh pi5-nocrypto  # Raspberry Pi 5 without the AES and SHA instructions
./scripts/build.sh sim         # Zephyr on native_sim with host sockets, for local testing
./scripts/build.sh rw612       # FRDM-RW612, software crypto
./scripts/build.sh rw612-els   # FRDM-RW612 with the EdgeLock offload
./scripts/build.sh h743        # NUCLEO-H743ZI
./scripts/build.sh h743-fpu    # NUCLEO-H743ZI, FPU on, Falcon on the double-precision FPU
./scripts/build.sh h743-fpu-int  # NUCLEO-H743ZI, FPU on, Falcon on the integer backend
```

Any target takes a `-trace` suffix (`rw612-trace`, `h743-fpu-trace`, `host-trace`, ...) for the heap-trace variant described under [Heap traces](#heap-traces). Trace builds compile in wolfSSL's debug logging, so never use them for timing.

Any target also takes a `-pqc-<profile>` suffix (`rw612-pqc-cache`, `host-pqc-small`, ...) to build with another PQC profile, see [PQC profiles and footprint](#pqc-profiles-and-footprint).

Zephyr targets take a final `-tcp-iw<N>` suffix (`rw612-tcp-iw10`) to change the TCP initial window, see [Network latency](#network-latency).

The plain `h743` build leaves the FPU off, and Falcon then uses wolfSSL's emulated integer floating point. For the FPU comparison, run `h743-fpu` against `h743-fpu-int`: both enable the FPU, so only the Falcon backend differs. The DUT reports its backend as `falcon_fpr=double|emulated` in the HELLO line in `meta.txt`. The RW612's Cortex-M33 only has a single-precision FPU, where the double backend is slower.

The Pi targets take a `-fpr-int`, `-fpr-double` or `-fpr-neon` suffix (`pi5-fpr-int`) for the Falcon backend; without one they use `neon`, the NEON FFT on top of the double backend. Both Pi cores have a double-precision FPU. The HELLO line reports `falcon_fpr=` and `hw_crypto=`, which is 1 when the build uses the Armv8 AES and SHA instructions. The Pi 3B+'s BCM2837 does not have them. `ese_host` signs Falcon on the double backend, with the NEON FFT on aarch64, and records it as `host_falcon_fpr=` in `meta.txt`.

`rw612-els` needs a wolfSSL that carries the EdgeLock CryptoCb port (the `els_pkc` branch). It builds against the module in `modules/crypto/wolfssl`; set `ESE_ELS_WOLFSSL` to a separate wolfSSL checkout named `wolfssl` to swap that in instead. A swapped module links in a different flash order, which alone cost about 24% on SHA2, LMS and XMSS, so compare only images built the same way.

The host helper also builds on macOS (`cmake -S . -B build-host -G Ninja && ninja -C build-host ese_host`). If the Arm assembly does not build there, configure with `-DESE_NO_ASM=ON`.

## Network

Cable the DUT directly to the host, or put several DUTs on a switch, with static addresses:

| Node | Address |
|---|---|
| Host helper | 192.168.0.1/24 |
| FRDM-RW612 | 192.168.0.2/24 (set in `dut/zephyr/boards/frdm_rw612.conf`) |
| NUCLEO-H743ZI | 192.168.0.3/24 (set in `dut/zephyr/boards/nucleo_h743zi.conf`) |
| Raspberry Pi 5 | 192.168.0.5/24 |
| Raspberry Pi 3B+ | 192.168.0.6/24 |

## Running

Start the DUT: flash the Zephyr image, or run `./scripts/pi-deploy.sh [-b] <pi-host> [build-dir]` (default `build-pi`), which also pins the governor to `performance`. It needs passwordless `sudo tee` on `scaling_governor`. `-b` starts the DUT in the background, logging to `~/ese_dut.log` on the Pi. It listens for the host on TCP port 11111. Then:

```sh
./build-host/ese_host --dut 192.168.0.2 --host-ip 192.168.0.1 --label rw612-sw --alg --tls
```

Useful options:

| Option | Effect |
|---|---|
| `--chain`, `--kex`, `--auth`, `--role`, `--alg-filter`, `--op-filter` | Restrict the matrix (comma-separated) |
| `--scale 0.02` | Pilot run with 2% of the sample counts |
| `--n N` | Fixed sample count |
| `--out DIR` | Output directory; rerunning into it skips scenarios already in `tls.csv` |
| `--dry-run` | List scenarios and sample counts without connecting |
| `--host-port P` | Port of the host's TLS server for DUT-client scenarios; defaults to 4400 plus the last octet of the DUT IP |
| `--rtt-ms R` | RTT added with `scripts/netem.sh`; recorded in `meta.txt` and checked per scenario, see [Network latency](#network-latency) |
| `--group-messages` | The host sends each handshake flight in one write instead of one per message |

To measure two boards at once, put them on a switch with the host and start one `ese_host` per DUT, each with its own `--dut`, `--label` and `--out`. The default host port differs per DUT IP, so the two never collide. For DUT-client scenarios the TTFB includes the host's signing time, so the host needs a free core per run. The Mac has that; a small VM may not. Do not pin `ese_host` to a core with `taskset`: next to the netem spin loops it then wakes only on the 1 ms scheduler tick, which adds 1 to 2 ms to every handshake shorter than about 30 ms. To run two Linux DUTs on one machine, give each its own loopback address with `ESE_BIND_IP=127.0.0.2 ./build-host/ese_dut`.

## Network latency

To measure TTFB over a slower network, `scripts/netem.sh` adds an RTT on the host's DUT link with Linux netem. It delays the packets arriving from the DUT by the whole RTT and leaves the control port alone, so only the TLS connections see it. In a VM, netem's timers fire up to a few milliseconds late while the vCPUs idle, so the script also keeps every vCPU busy with a `SCHED_IDLE` loop until `off`:

```sh
./scripts/netem.sh on 100     # on the interface that routes to $ESE_DUT_IP (192.168.0.2)
./build-host/ese_host --dut 192.168.0.2 --host-ip 192.168.0.1 --label rw612-sw --tls \
    --rtt-ms 100 --out results/rw612/<date>-rw612-sw-rtt100
./scripts/netem.sh off
```

Use one run directory per RTT. `--rtt-ms` goes into `meta.txt`, and `ese_host` stops if the median TCP connect time of a scenario is not within 10% plus 2 ms of it, before that scenario's rows are written. That catches a re-plugged USB adapter, which loses its shaping. Pass `--rtt-ms 0` on baseline runs so leftover shaping is caught too.

To run several DUTs at different RTTs at the same time, give each its own delay with `./scripts/netem.sh set <dut_ip> <ms>` instead of `on`. Each DUT gets its own netem band, keyed by the last octet of its address (2 to 15), and setting one DUT leaves the others alone. `off` removes all of them.

Name the runs of one campaign `<date>-<label>[-iw<N>]-rtt<R>`, plus `<date>-<label>[-iw<N>]-alg` for an `--alg` run of each TCP image. The viewer's **Network RTT** tab then lines up every run of that family for the selected run A: TTFB, added time or extra round trips per scenario and TCP variant, where extra round trips = (TTFB - 0 ms TTFB) / added delay - 3 and the added delay is the rise in median TCP connect time. With the `-alg` runs present it can subtract each image's compute drift, which a changed Kconfig value alone can cause.

The script needs root for `tc`, and for `ip` the first time, when it creates the `ifb-ese` device. For unattended runs, allow `/usr/sbin/tc` without a password in `/etc/sudoers.d/`.

Stock Zephyr TCP starts with a congestion window of one segment and a slow-start threshold of three segments, where Linux starts with ten and no threshold. Large flights therefore take more round trips from a Zephyr DUT. The `-tcp-iw<N>` build suffix sets the initial window to N segments and removes the threshold, as RFC 5681 recommends: `iw3` matches RFC 3390 and lwIP, `iw10` matches RFC 6928 and Linux. It needs the `NET_TCP_CONGESTION_INITIAL_WIN` and `NET_TCP_CONGESTION_INITIAL_SSTHRESH` Kconfig options in the Zephyr fork. The DUT reports its setting as `tcp_ca=` in the HELLO line: `iw1-ss3` for stock Zephyr, `iw<N>-ss0` for the suffix builds, `os` for the Linux DUT.

Zephyr also retransmits after a fixed 200 ms, randomized up to 300 ms, without estimating the RTT. Beyond about 200 ms of RTT a client therefore retransmits while it still waits for the server's flight and collapses its own window: at 600 ms a mutually authenticated ML-DSA-44 client needs 3.9 s instead of 2.4 s. The `-rto<ms>` build suffix sets `NET_TCP_INIT_RETRANSMISSION_TIMEOUT`; `-rto1000` matches the 1 s initial timeout of RFC 6298.

## Campaign scripts

`campaigns/20261010/` holds the scripts behind the `20261010` result sets. `build-all.sh` builds every image; `run-rw612.sh`, `run-h743.sh` and `run-pi.sh rpi3|rpi5` then measure one board each and run in parallel, each at its own RTT through `netem.sh set`, and `run-h743-rto.sh` follows `run-h743.sh` with the 1 s RTO image. They expect the network above, `west` on the `PATH` or in `$WEST`, and the Zephyr SDK in `$ZEPHYR_SDK_INSTALL_DIR`, and log to `$ESE_CAMPAIGN_LOGS` (default `~/ese-campaign-logs`). The first pass ran `ese_host` pinned with `taskset`, so `run-rerun.sh` repeated the affected TLS runs; a fresh run needs only the `run-*.sh` scripts without it. Check the output with `scripts/check_results.py results/*/20261010-*`.

`campaigns/20261011-traces/run-traces.sh` records the packet captures behind the paper's TCP explanations: the H743 with stock, IW10 and IW10 + 1 s RTO TCP and the Pi 3B+, three ML-DSA-44 handshakes per case, into `results/*/20261011-trace-*/capture.pcap`. It needs `tcpdump` with `cap_net_raw` and `cap_net_admin`. Summarize a capture with `scripts/pcap_flights.py <pcap> --dut <ip>`; the host's GRO and TSO merge its packet counts, while byte counts and timing are exact.

## Output

Every run directory has `meta.txt` (DUT HELLO line, git revisions, options) and three CSVs, one row per sample:

- **`tls.csv`**: `chain, ca_alg, leaf_alg, kex, auth, dut_role, iter, n, dut_status, host_status, ttfb_ns, tcp_ns, client_hs_ns, server_hs_ns, server_total_ns, c2s_bytes, s2c_bytes, dut_heap_peak, dut_heap_total, dut_heap_allocs, dut_stack`
- **`tls_ctx.csv`**: one row per scenario with the heap and time spent loading certificates and keys into the context.
- **`alg.csv`**: `alg, op, iter, n, status, ns, heap_peak, heap_total, heap_allocs, stack, key_held, variant`. `variant` is the DUT's PQC profile; runs from before the column existed all used `smallmem`.

To browse runs, start `./scripts/view.sh [port]` and open `http://127.0.0.1:8000/tools/viewer/`. Pick a category first (TLS handshakes, context setup, algorithms, footprint, heap trace or network RTT); the A and B lists then offer only the `results/<board>/<run>` directories that carry it. TLS handshakes and context setup pick an added RTT (0, 10 or 100 ms) first, and the network RTT list shows each run family once. It shows per-scenario medians, p99 and sizes, with filters, search, sorting and per-sample drill-down. Clicking a column header sorts by it and draws it as bars in the table. Picking a second run as B compares the two, with the B/A ratio in green where B is lower and red where it is higher. The URL keeps the runs, tab, filters and selected traces, so a copied link opens the same view. Set `ESE_VIEW_BIND=0.0.0.0` to reach it from another machine.

## Heap traces

A heap trace records every wolfSSL `malloc`, `free` and `realloc` of one handshake, with markers, so you can see where in the handshake the heap peaks. Flash a `-trace` build, then:

```sh
./build-host/ese_host --dut 192.168.0.2 --host-ip 192.168.0.1 --label rw612-trace --heap-trace [--chain ...]
```

`--heap-trace` runs one traced handshake per scenario (n=1) and writes **`heap_trace.csv`**: `platform, chain, kex, auth, dut_role, seq, t_us, event, size, heap, label`. `event` is `alloc`, `free` or `realloc` (with the new size), or `mark`/`end` for a marker. `heap` is the bytes allocated since the trace started, which includes the context. The trace covers context setup, the connection and the context teardown.

- **Coarse markers** come from the framework: `ctx_setup`, `ctx_ready`, `ssl_new`, `handshake_start`, `handshake_done`, `app_data_done`, `shutdown_done`, `ssl_freed`, `ctx_freed`.
- **Setup steps** wrap each context call in `common/ese_tls.c` with a `mark` and an `end`: `wolfSSL_CTX_new`, `wolfSSL_CTX_set_cipher_list`, `wolfSSL_CTX_set_groups`, `wolfSSL_CTX_use_certificate_chain_buffer`, `wolfSSL_CTX_use_PrivateKey_buffer` and `wolfSSL_CTX_load_verify_buffer`.
- **Handshake steps** come from wolfSSL's debug log, as a `mark` on entry and an `end` on return: `SendTls13ClientHello`, `DoTls13ServerHello`, `DoTls13Certificate` (with `ProcessPeerCerts`, the chain verification, inside it), `SendTls13CertificateVerify`, `DoTls13CertificateVerify`, `SendTls13Finished` and so on.

The DUT buffers 12,288 events (10,240 on the H743, where the buffer lives in DTCM so the heap keeps its size). The largest handshake, SLH-DSA-s with mutual auth, needs about 8,100. The host reports dropped events if the buffer fills.

Peak heap in a trace build matches the normal build exactly. The allocation count can differ by a few, because debug-only code paths allocate on the client side and ML-DSA signing retries vary from run to run.

To look at traces, use the **Heap trace** tab in the viewer: click scenarios of one DUT role to overlay them, align them at the markers (each step between shared markers is as wide as the widest trace in it, so no trace gets compressed), switch between heap operations and time on the x-axis, and hover for the individual events. For figures, `scripts/plot_heap_trace.py` (needs matplotlib) draws the same plot as a PDF. `--align ref` instead warps every trace onto the first one:

```sh
scripts/plot_heap_trace.py --out heap.pdf \
  results/rw612/<run>:ecdsa_p256,mlkem768,mutual,client=ECDSA \
  results/rw612/<run>:mldsa44,mlkem768,mutual,client=ML-DSA-44
```

## PQC profiles and footprint

The PQC algorithms have memory and speed options that trade against each other. A profile sets them for all algorithms at once:

| Profile | ML-KEM | ML-DSA | Falcon | SLH-DSA, LMS, XMSS |
|---|---|---|---|---|
| `default` | none | none | none | none |
| `smallmem` | small-mem keygen and encapsulation, dynamic keys | smallest-mem sign and verify, small-mem keygen, dynamic keys | smallest-mem sign, dynamic keys | SLH-DSA small-mem |
| `smallmem-fast` | as `smallmem` | small-mem sign with precalculation, small-mem verify | small-mem sign | as `smallmem` |
| `cache` | cached matrix A | cached matrix A and key vectors | cached expanded key | none |
| `small` | small code, no large code | small code, no large code | none | small code |

Zephyr images use `smallmem` unless built with a `-pqc-<profile>` suffix; the Linux DUT uses `default`. On aarch64 ML-KEM has no small-mem paths, because they cannot build with the assembly, so there `smallmem` only adds dynamic keys. The DUT reports its profile as `pqc_profile=` in the HELLO line.

For the algorithm comparison, flash each profile in turn and run `--alg` into one directory per profile, then concatenate the `alg.csv` files. The viewer's **Algorithms** tab then shows one row per profile and a trade-off plot of time against heap, key size, stack or flash.

The benchmarks cover ML-KEM-768, ML-DSA-44 and Falcon-512. Building with `ESE_ALL_PQC_PARAMS` defined adds ML-KEM-512/1024, ML-DSA-65/87, Falcon-1024, SLH-DSA-192/256 (s and f, SHA2 and SHAKE) and more LMS and XMSS verify sets, and `ESE_NO_ASM` builds portable C. On Zephyr pass them as `-DEXTRA_CFLAGS="-DESE_ALL_PQC_PARAMS -DESE_NO_ASM"` to `west build`; on the host as `-DCMAKE_C_FLAGS=-DESE_ALL_PQC_PARAMS`. The host helper must be built with the same `ESE_ALL_PQC_PARAMS` setting as the DUT, because both index the same operation table.

`./scripts/footprint.sh rw612|h743 <run dir>` writes **`footprint.csv`**: `platform, variant, alg, flavor, flash, ram, flash_delta, ram_delta`. For each profile it builds `dut/footprint` once with only the RNG and SHA-3 linked in (the baseline), then once per algorithm, and reports the growth over that baseline. `full` links keygen, sign and verify (keygen, encapsulation and decapsulation for ML-KEM), `verify` only key import and verify. In `default` and `smallmem` the flavors `keygen`, `sign`, `encap` and `decap` link one operation each, with key import where it needs one. The `sha3` row is the baseline's own cost over the RNG. SLH-DSA has one row for both hash families, because the parameter set is chosen at run time. Put `footprint.csv` in the same run directory as the profile `alg.csv`, and the Algorithms tab shows the flash cost next to each operation.

## Measurement definitions

| Metric | Definition |
|---|---|
| `ttfb_ns` | Measured on whichever side is the client: from just before `connect()` to receipt of the server's reply to the first 64-byte application message. It covers the TCP handshake, the TLS handshake and one application round trip. |
| `tcp_ns`, `client_hs_ns` | Client-side marks inside that interval: `connect()` done, and `wolfSSL_connect()` done. |
| `server_hs_ns`, `server_total_ns` | Server side, from `accept()` to handshake done and to reply sent. |
| `dut_heap_*` | Every wolfSSL allocation on the DUT from `wolfSSL_new()` to `wolfSSL_free()`. `peak` is the high-water mark above the level before the connection. |
| `dut_stack` | Deepest stack use below the entry frame of a fresh measurement thread that runs one whole connection. |
| `c2s_bytes`, `s2c_bytes` | TLS bytes on the wire, including records and close_notify, excluding TCP/IP headers. |
| `key_held` | Heap the key objects of an algorithm benchmark still hold after the measured operations, including the key structs and any caches they filled. 0 for keygen. |
| `flash_delta`, `ram_delta` | Growth of `text + data` and `data + bss` of the footprint image over the same profile's baseline. |

When the DUT is the client, TTFB includes the host's server-side work; `server_hs_ns` records that separately so it can be subtracted. Timings on `native_sim` are simulated time and are only good for functional testing.

## Certificates

`certs/out` is generated and committed. To regenerate it, run `./build-host/ese_certgen certs/out`. That rebuilds every chain, verifies each one with wolfSSL, and writes `sizes.csv` with certificate, public-key and private-key sizes. The extra LMS and XMSS verify vectors in `certs/out/ese_hbs_data.c` come from `ese_hbsgen certs/out/ese_hbs_data.c`, run from a host build with `ESE_ALL_PQC_PARAMS`; it takes about three minutes.

## Reproducing the paper

`results/` holds every run the paper uses: `results/<board>/20261010-*` from the 2026-10-10 campaign and `results/<board>/20261011-trace-*` with the packet captures. Each run's `meta.txt` records the DUT image, revisions and options, and `note=` lines where a run needs a remark. `scripts/check_results.py results/*/2026101*` reports sample counts, failures and off-RTT connects for all of them.

To redraw the figures and recompute the cited numbers from the data, with Python 3, pandas, NumPy and Matplotlib:

```sh
python3 paper/figures.py      # paper/out/fig1_ops.png ... fig4_heap.png
python3 paper/cited.py        # every number the paper cites, with its source run
```

To repeat measurements, build and flash as described above, then for example on the H743 (192.168.0.3):

1. One primitive benchmark: flash `h743-fpu` and run `./build-host/ese_host --dut 192.168.0.3 --host-ip 192.168.0.1 --alg --alg-filter mldsa44 --out results/h743/<date>-alg`.
2. One TTFB experiment: with the same image, run `./build-host/ese_host --dut 192.168.0.3 --host-ip 192.168.0.1 --tls --kex mlkem768 --chain mldsa44 --auth server --role server --rtt-ms 0 --out results/h743/<date>-tls`.
3. One TCP comparison: for each of the images `h743-fpu` and `h743-fpu-tcp-iw10`, run the TTFB experiment once after `./scripts/netem.sh set 192.168.0.3 0` with `--rtt-ms 0` and once after `./scripts/netem.sh set 192.168.0.3 100` with `--rtt-ms 100`, each into its own directory, and compare the extra round trips as defined under [Network latency](#network-latency). `campaigns/20261011-traces/run-traces.sh` does the same with packet captures.

The full campaign is `campaigns/20261010/`; it takes about a day per board.

## License and citation

The code is licensed under the GNU General Public License, version 3 or later (see `LICENSE`), like wolfSSL, which every binary links. The keys in `certs/out` are test material, see [certs/README.md](certs/README.md). To cite the artifact, use `CITATION.cff`.
