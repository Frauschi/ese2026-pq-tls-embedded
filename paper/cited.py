#!/usr/bin/env python3
"""Prints every number the paper cites, from the 2026-10-10 campaign, in the order the paper uses them."""
import os

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.environ.get("ESE_RESULTS", os.path.join(ROOT, "results"))
APP_TAIL = 86 + 24  # 64 B app record + close_notify, both sides
CV_TAIL = 30 + 58   # CertificateVerify record minus the signature, plus the Finished record

ALG = {"rw612": "rw612/20261010-rw612", "h743": "h743/20261010-h743-fpu",
       "rpi3": "rpi3/20261010-rpi3", "rpi5": "rpi5/20261010-rpi5",
       "rpi5nc": "rpi5/20261010-rpi5-nocrypto", "h743int": "h743/20261010-h743-fpu-int-alg",
       "rw612def": "rw612/20261010-rw612-default-alg"}
TLS = {p: ALG[p] for p in ("rw612", "h743", "rpi3", "rpi5")}
RTT = {"rw612 stock": ("rw612/20261010-rw612-rtt0", "rw612/20261010-rw612-rtt{}"),
       "rw612 iw10": ("rw612/20261010-rw612-iw10-rtt0", "rw612/20261010-rw612-iw10-rtt{}"),
       "h743 stock": ("h743/20261010-h743-fpu-rtt0", "h743/20261010-h743-fpu-rtt{}"),
       "h743 iw10": ("h743/20261010-h743-fpu-iw10-rtt0", "h743/20261010-h743-fpu-iw10-rtt{}"),
       "h743 iw10+rto1s": ("h743/20261010-h743-fpu-iw10-rtt0",
                           "h743/20261010-h743-fpu-iw10-rto1000-rtt{}"),
       "rpi3": ("rpi3/20261010-rpi3-rtt0", "rpi3/20261010-rpi3-rtt{}"),
       "rpi5": ("rpi5/20261010-rpi5-rtt0", "rpi5/20261010-rpi5-rtt{}"),
       "rpi5 grouped": ("rpi5/20261010-rpi5-rtt0", "rpi5/20261010-rpi5-grp-rtt{}")}
TRACE = "rw612/20261010-heap-trace"
FOOT = "rw612/20261010-rw612"
SIG = {"ecdsa_p256": 71, "rsa3072": 384, "mldsa44": 2420, "falcon512": 655,
       "slhdsa_sha2_128s": 7856, "slhdsa_sha2_128f": 17088}
MAIN_CHAINS = ["ecdsa_p256", "rsa3072", "mldsa44", "falcon512", "lms+mldsa44", "xmss+mldsa44"]
SLH = ["slhdsa_sha2_128s", "slhdsa_sha2_128f"]
SHAKE = {"slhdsa_sha2_128s": "slhdsa_shake_128s", "slhdsa_sha2_128f": "slhdsa_shake_128f"}


def alg(run):
    d = pd.read_csv(os.path.join(RES, run, "alg.csv"))
    return d[d.status == 0]


def q(d, a, o, p=0.5):
    return d[(d.alg == a) & (d.op == o)].ns.quantile(p) / 1e6


def tls(run, p=0.5):
    d = pd.read_csv(os.path.join(RES, run, "tls.csv"))
    d = d[(d.dut_status == 0) & (d.host_status == 0)]
    return d.groupby(["chain", "kex", "auth", "dut_role"]).agg(
        ttfb=("ttfb_ns", lambda s: s.quantile(p)), tcp=("tcp_ns", "median"),
        c2s=("c2s_bytes", "median"), s2c=("s2c_bytes", "median"), heap=("dut_heap_peak", "max"),
        stack=("dut_stack", "max"), n=("iter", "size")).reset_index()


def extra_rtts(base_run, run):
    k = ["chain", "kex", "auth", "dut_role"]
    x = tls(run).merge(tls(base_run)[k + ["ttfb", "tcp"]], on=k, suffixes=("", "_0"))
    x["extra"] = (x.ttfb - x.ttfb_0) / (x.tcp - x.tcp_0) - 3
    x["ttfb"] = x.ttfb / 1e6
    return x[x.kex == "mlkem768"].set_index(["chain", "auth", "dut_role"])


def rng(v):
    return f"{min(v):.2f} .. {max(v):.2f}"


def main():
    out = []
    A = {p: alg(r) for p, r in ALG.items()}
    r = A["rw612"]

    for p in ("rw612", "h743", "rpi3", "rpi5"):
        d = A[p]
        out.append((f"{p} kex per side [ms]", {
            "mlkem encap": q(d, "mlkem768", "encap"),
            "mlkem keygen+decap": q(d, "mlkem768", "keygen") + q(d, "mlkem768", "decap"),
            "x25519 keygen+shared": q(d, "x25519", "keygen") + q(d, "x25519", "shared"),
            "p256 keygen+shared": q(d, "secp256r1", "keygen") + q(d, "secp256r1", "shared")}))
    out.append(("RW612 verify [ms]", {a: q(r, a, "verify") for a in
                ("falcon512", "lms_h15", "mldsa44", "ecdsa_p256", "rsa3072", "xmss_h16", *SLH,
                 *SHAKE.values())}))
    out.append(("RW612 ML-DSA-44 sign median / p99 / n",
                (q(r, "mldsa44", "sign"), q(r, "mldsa44", "sign", 0.99),
                 len(r[(r.alg == "mldsa44") & (r.op == "sign")]))))
    out.append(("Falcon-512 sign H743 FPU / H743 int / RW612",
                (q(A["h743"], "falcon512", "sign"), q(A["h743int"], "falcon512", "sign"),
                 q(r, "falcon512", "sign"))))
    out.append(("RW612 SLH-DSA sign SHA-2 / SHAKE [s]",
                {a: (q(r, a, "sign") / 1e3, q(r, SHAKE[a], "sign") / 1e3) for a in SLH}))
    out.append(("ECDSA sign -> SLH-128s sign, orders of magnitude",
                np.log10(q(r, "slhdsa_sha2_128s", "sign") / q(r, "ecdsa_p256", "sign"))))
    for p in ("rw612", "h743"):
        out.append((f"{p} SHAKE / SHA-2 time", {f"{a} {o}": q(A[p], SHAKE[a], o) / q(A[p], a, o)
                                                for a in SLH for o in ("sign", "verify")}))
    ratios = {}
    for a, o in r.groupby(["alg", "op"]).size().index:
        v = q(r, a, o) / q(A["rpi5"], a, o)
        if v == v:
            ratios[f"{a} {o}"] = v
    lo, hi = min(ratios, key=ratios.get), max(ratios, key=ratios.get)
    out.append(("RW612 / Pi 5 time ratio min, max", f"{ratios[lo]:.1f} ({lo}), {ratios[hi]:.1f} ({hi})"))
    rows = [[("x25519", "keygen"), ("x25519", "shared")], [("secp256r1", "keygen"), ("secp256r1", "shared")],
            [("mlkem768", "encap")], [("mlkem768", "keygen"), ("mlkem768", "decap")]]
    rows += [[(x, "verify")] for x in ("ecdsa_p256", "rsa3072", "mldsa44", "falcon512", "lms_h15",
                                      "xmss_h16", *SLH)]
    rows += [[(x, "sign")] for x in ("ecdsa_p256", "rsa3072", "mldsa44", "falcon512", *SLH)]
    fr = [sum(q(r, *o) for o in ops) / sum(q(A["rpi5"], *o) for o in ops) for ops in rows]
    out.append(("RW612 / Pi 5 time ratio over the Figure 1 rows", rng(fr)))
    sp = {f"{a} {o}": q(A["rpi5nc"], a, o) / q(A["rpi5"], a, o) for a, o in
          [(a, o) for a in SLH for o in ("sign", "verify")] + [("lms_h15", "verify"),
                                                               ("xmss_h16", "verify")]}
    out.append(("Pi 5 SHA-2 instruction speedup", f"{rng(sp.values())} {sp}"))

    T = {p: tls(rn) for p, rn in TLS.items()}
    t = T["rw612"].set_index(["chain", "kex", "auth", "dut_role"])
    out.append(("RW612 TTFB mlkem server-only [ms] (client, server)",
                {c: (t.loc[(c, "mlkem768", "server", "client"), "ttfb"] / 1e6,
                     t.loc[(c, "mlkem768", "server", "server"), "ttfb"] / 1e6)
                 for c in MAIN_CHAINS + SLH}))
    out.append(("RW612 SLH-DSA server TTFB SHAKE [s]",
                {c: t.loc[(c, "mlkem768", "server", "server"), "ttfb"] / 1e9
                 for c in SHAKE.values() if (c, "mlkem768", "server", "server") in t.index}))
    out.append(("RW612 SHAKE-128s client TTFB vs SHA-2-128f client [ms]",
                (t.loc[("slhdsa_shake_128s", "mlkem768", "server", "client"), "ttfb"] / 1e6,
                 t.loc[("slhdsa_sha2_128f", "mlkem768", "server", "client"), "ttfb"] / 1e6)))
    p99 = tls(TLS["rw612"], 0.99).set_index(["chain", "kex", "auth", "dut_role"])
    out.append(("RW612 ML-DSA-44 server TTFB p99 [ms]",
                p99.loc[("mldsa44", "mlkem768", "server", "server"), "ttfb"] / 1e6))
    hy = [(t.loc[(c, "x25519mlkem768", "server", ro), "ttfb"] -
           t.loc[(c, kx, "server", ro), "ttfb"]) / 1e6
          for c in MAIN_CHAINS for ro in ("client", "server") for kx in ("x25519",)]
    out.append(("RW612 hybrid minus X25519 TTFB [ms]", rng(hy)))
    for p in ("rw612", "h743"):
        tt = T[p].set_index(["chain", "kex", "auth", "dut_role"])
        for kx, auths in (("mlkem768", ("server",)), ("x25519mlkem768", ("server", "mutual")),
                          ("secp256r1", ("server",))):
            for ro in ("client", "server"):
                dt = [(tt.loc[(c, kx, au, ro), "ttfb"] - tt.loc[(c, "x25519", au, ro), "ttfb"]) / 1e6
                      for c in MAIN_CHAINS for au in auths]
                dh = [tt.loc[(c, kx, au, ro), "heap"] - tt.loc[(c, "x25519", au, ro), "heap"]
                      for c in MAIN_CHAINS for au in auths]
                out.append((f"{p} {kx} minus X25519, {ro} ({'/'.join(auths)}): TTFB [ms], heap [B]",
                            f"{rng(dt)}; {min(dh):.0f} .. {max(dh):.0f}"))
    vc = {c: t.loc[(c, "mlkem768", "server", "client"), "ttfb"] / 1e6 for c in
          t.xs(("mlkem768", "server", "client"), level=(1, 2, 3)).index}
    sha2 = {c: v for c, v in vc.items() if "shake" not in c and not c.endswith("sha2_128f")}
    out.append(("RW612 verify-only client TTFB: max SHA-2 chain except *128f; 128f chains; SHAKE min [ms]",
                (max(sha2.values()), {c: round(v) for c, v in vc.items() if c.endswith("sha2_128f")},
                 min(v for c, v in vc.items() if "shake" in c))))
    by = t.xs("server", level=2)[["c2s", "s2c"]].unstack("kex")
    out.append(("bytes vs X25519, median over chains: mlkem c2s, s2c; hybrid c2s",
                ((by.c2s.mlkem768 - by.c2s.x25519).median(), (by.s2c.mlkem768 - by.s2c.x25519).median(),
                 (by.c2s.x25519mlkem768 - by.c2s.x25519).median())))
    p5 = T["rpi5"]
    p5 = p5[(p5.kex == "mlkem768") & (p5.auth == "server") & p5.chain.isin(
        ["ecdsa_p256", "mldsa44", "falcon512", "lms+mldsa44", "xmss+mldsa44"])]
    out.append(("Pi 5 TTFB, all chains but RSA and SLH-DSA [ms]", rng(p5.ttfb / 1e6)))

    fl = t.xs(("mlkem768", "server", "server"), level=(1, 2, 3)).s2c - APP_TAIL
    out.append(("server flight [kB]", (fl / 1000).round(2).to_dict()))
    out.append(("flight sent before signing [kB]",
                {c: (fl[c] - SIG[c.split("+")[-1]] - CV_TAIL) / 1000
                 for c in ("mldsa44", "slhdsa_sha2_128f", "lms+slhdsa_sha2_128f")}))
    out.append(("ten segments of 1,460 B [kB]; Zephyr send window 64 x 1536 / 3 [B]",
                (14.6, 64 * 1536 // 3)))
    for name in ("h743 iw10", "h743 iw10+rto1s"):
        x = extra_rtts(RTT[name][0], RTT[name][1].format(600))
        out.append((f"RTT {name} 600 ms: SLH-DSA-128f server, ML-DSA-44 mutual client median [ms]",
                    (round(x.loc[("slhdsa_sha2_128f", "server", "server"), "ttfb"]),
                     round(x.loc[("mldsa44", "mutual", "client"), "ttfb"]))))
    for name in ("rw612 stock", "rw612 iw10", "h743 stock", "h743 iw10", "h743 iw10+rto1s"):
        d = pd.read_csv(os.path.join(RES, RTT[name][1].format(600), "tls.csv"))
        d = d[(d.chain == "mldsa44") & (d.kex == "mlkem768") & (d.dut_role == "client")]
        out.append((f"RTT {name} 600 ms: ML-DSA-44 client per-sample TTFB range [s]",
                    {a: rng(g.ttfb_ns / 1e9) for a, g in d.groupby("auth")}))
    for name, (base, pat) in RTT.items():
        for delay in (100, 600):
            if not os.path.exists(os.path.join(RES, pat.format(delay), "tls.csv")):
                continue
            x = extra_rtts(base, pat.format(delay))
            sel = [k for k in x.index if k[1:] == ("server", "server") or
                   (k[0] == "mldsa44" and k[2] == "client")]
            out.append((f"RTT {name} {delay} ms: ttfb [ms] / extra RTTs",
                        {"/".join(k): f"{x.loc[k, 'ttfb']:.0f} / {x.loc[k, 'extra']:.2f} (n={x.loc[k, 'n']})"
                         for k in sel}))

    for p in ("rw612", "h743", "rpi3", "rpi5"):
        d = pd.read_csv(os.path.join(RES, TLS[p], "tls.csv"))
        g = d[(d.dut_status == 0) & (d.host_status == 0)].groupby(
            ["chain", "kex", "auth", "dut_role"]).ttfb_ns
        iqr = ((g.quantile(0.75) - g.quantile(0.25)) / g.median() * 100).reset_index(name="pct")
        mlsign = iqr.chain.str.endswith("mldsa44") & ((iqr.dut_role == "server") | (iqr.auth == "mutual"))
        out.append((f"{p} TTFB IQR as % of median: median; max without ML-DSA-44 signing; max with",
                    (iqr.pct.median(), iqr[~mlsign].pct.max(), iqr[mlsign].pct.max())))
    m = T["rw612"][T["rw612"].kex == "mlkem768"]
    hp = m.pivot_table(index="chain", columns=["auth", "dut_role"], values="heap") / 1000
    out.append(("RW612 heap peak, mlkem [kB] per auth/role", hp.round(1).to_dict("index")))
    out.append(("RW612 heap max over auth/role is the mutual client for",
                [c for c in hp.index if hp.loc[c].idxmax() == ("mutual", "client")]))
    out.append(("RW612 stack peak per chain range [kB]",
                rng(T["rw612"].groupby("chain").stack.max() / 1000)))
    h = pd.read_csv(os.path.join(RES, TRACE, "heap_trace.csv"))
    held, peak = [], {}
    for k, g in h.groupby(["chain", "kex", "auth", "dut_role"]):
        mk = g[g.event == "mark"].set_index("label").heap
        held.append((mk["handshake_done"] - mk["ssl_new"]) / 1000)
        if k[1:] == ("mlkem768", "mutual", "client"):
            peak[k[0]] = g.heap.max() / 1000
    out.append(("session heap kept after the handshake [kB]", rng(held)))
    out.append(("trace peak incl. context, mutual client [kB]", {c: round(v, 1) for c, v in peak.items()}))
    for nm, run in (("smallmem", "rw612"), ("default", "rw612def")):
        d = A[run]
        s = d[(d.alg == "mldsa44") & (d.op == "sign")]
        out.append((f"RW612 ML-DSA-44 sign {nm}: heap peak [B], median [ms]",
                    (s.heap_peak.max(), s.ns.median() / 1e6)))
    f = pd.read_csv(os.path.join(RES, FOOT, "footprint.csv"))
    f = f[f.variant.isin(["default", "smallmem"])].set_index(["variant", "alg", "flavor"]).flash_delta
    out.append(("flash [kB] smallmem per operation (full = keygen + sign + verify)", {
        k[1] + " " + k[2]: round(f[k] / 1000, 1) for k in f.index
        if k[0] == "smallmem" and k[1] in ("mldsa44", "falcon512", "slhdsa")}))
    out.append(("flash [kB] smallmem PQC / default traditional", {
        k: round(f[k] / 1000, 1) for k in f.index if
        (k[0] == "smallmem" and k[2] in ("full", "verify")) or
        (k[0] == "default" and k[1] in ("ecdsa_p256", "rsa3072", "x25519", "lms", "xmss", "sha3"))}))

    ml = fl["mldsa44"]
    out.append(("HQC-1 ML-DSA-44 flight [kB] (ct 4,433 B)", (ml - 1088 + 4433) / 1000))
    out.append(("ML-DSA-65 + P-256 hybrid flight estimate [kB] (+2 x 91 B SPKI, +3 x 72 B sig)",
                (ml + 3 * (3309 - 2420) + 2 * (1952 - 1312) + 2 * 91 + 3 * 72) / 1000))
    out.append(("ML-DSA-87 + P-256 hybrid flight estimate [kB] (pk 2,592, sig 4,627 B)",
                (ml + 3 * (4627 - 2420) + 2 * (2592 - 1312) + 2 * 91 + 3 * 72) / 1000))
    out.append(("ML-DSA-65 flight estimate [kB] (pk 1,952, sig 3,309 B)",
                (ml + 3 * (3309 - 2420) + 2 * (1952 - 1312)) / 1000))
    out.append(("P-256 hybrid chain adds per level [kB] (SPKI 91 + sig 72)", 0.163))
    for k, v in out:
        if isinstance(v, dict):
            v = {a: (round(b, 2) if isinstance(b, float) else b) for a, b in v.items()}
        elif isinstance(v, tuple):
            v = tuple(round(b, 2) if isinstance(b, float) else b for b in v)
        elif isinstance(v, float):
            v = round(v, 2)
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
