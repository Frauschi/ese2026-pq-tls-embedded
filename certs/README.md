# Test certificates

`certs/out` holds the 18 test chains (root, intermediate, server and client leaf per algorithm) that `ese_certgen` generated for the measurements, as DER files and as the C arrays every build compiles in, plus `sizes.csv`. The private keys (`*-key.der` and the keys inside `ese_certs_data.c`) are test material, published so the measurements can be reproduced. Never use them outside this test setup.

To regenerate the chains, run `./build-host/ese_certgen certs/out`, then rebuild every target, because all of them compile `certs/out/ese_certs_data.c` in.
