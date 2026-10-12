# Test certificates

`certs/out` holds the 18 test chains (root, intermediate, server and client leaf per algorithm) that `ese_certgen` generated for the measurements, as DER files and as the C arrays every build compiles in, plus `sizes.csv`. The private keys (`*-key.der` and the keys inside `ese_certs_data.c`) are test material, published so the measurements can be reproduced. Never use them outside this test setup.

All certificates at one level carry identical metadata and differ only in key and signature algorithm:

| Level | Validity | Extensions |
|---|---|---|
| Root | 2026-2046 | BC CA (crit), KU keyCertSign+cRLSign (crit), SKI, AKI |
| Intermediate | 2026-2036 | BC CA pathlen 0 (crit), KU (crit), SKI, AKI, CRL DP |
| Server / client leaf | 2026-2031 | BC (crit), KU digitalSignature (crit), EKU serverAuth / clientAuth, SAN, SKI, AKI, CRL DP |

The stateful CA chains use an LMS root (L1 SHA256/M32/H10/W4) with an H15/W4 intermediate, and an XMSS-SHA2_10_256 root with an XMSS-SHA2_16_256 intermediate.

To regenerate the chains, run `./build-host/ese_certgen certs/out`, then rebuild every target, because all of them compile `certs/out/ese_certs_data.c` in. `ese_certgen` verifies each chain with wolfSSL and writes `sizes.csv`. The extra LMS and XMSS verify vectors in `ese_hbs_data.c` come from `ese_hbsgen certs/out/ese_hbs_data.c` in a host build with `ESE_ALL_PQC_PARAMS`, which takes about three minutes.
