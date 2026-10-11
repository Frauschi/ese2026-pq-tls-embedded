#!/usr/bin/env python3
"""Figures for the ESE 2026 paper, drawn from results/ as 300 dpi PNGs for Word."""
import argparse
import importlib.util
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.transforms as mtrans
import numpy as np
import pandas as pd
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.environ.get("ESE_RESULTS", os.path.join(ROOT, "results"))

# Board colours, each at least 3:1 against white for print.
COLORS = ["#2a78d6", "#eb6834", "#13906a", "#b0327f"]
MARKERS = ["o", "s", "^", "D"]
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#d9d8d4"
SPAN = "#ebeae6"
WIDTH_IN = 15 / 2.54

plt.rcParams.update({
    "font.family": "Times New Roman",
    "font.size": 9,
    "axes.labelsize": 9,
    "axes.titlesize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 8,
    "axes.edgecolor": INK2,
    "axes.labelcolor": INK,
    "xtick.color": INK2,
    "ytick.color": INK2,
    "xtick.labelcolor": INK,
    "ytick.labelcolor": INK,
    "axes.linewidth": 0.6,
    "savefig.dpi": 300,
    "pdf.fonttype": 42,
})

PLATFORMS = [
    ("rw612", "RW612 (Cortex-M33)"),
    ("h743", "H743 (Cortex-M7)"),
    ("rpi3", "Pi 3B+ (Cortex-A53)"),
    ("rpi5", "Pi 5 (Cortex-A76)"),
]

# One name and one order per chain in every figure and in Table 1.
NAMES = {
    "ecdsa_p256": "ECDSA P-256", "rsa3072": "RSA-3072", "mldsa44": "ML-DSA-44",
    "falcon512": "Falcon-512", "lms+mldsa44": "LMS CA + ML-DSA-44",
    "xmss+mldsa44": "XMSS CA + ML-DSA-44", "slhdsa_sha2_128s": "SLH-DSA-128s",
    "slhdsa_sha2_128f": "SLH-DSA-128f", "lms+slhdsa_sha2_128f": "LMS CA + SLH-DSA-128f",
}
ORDER = ["ecdsa_p256", "rsa3072", "mldsa44", "falcon512", "lms+mldsa44", "xmss+mldsa44",
         "slhdsa_sha2_128s", "slhdsa_sha2_128f"]


def time_axis(ax, lo, hi):
    ax.set_xscale("log")
    ax.set_xlim(lo, hi)

    def fmt(v, _):
        if v < 1:
            return f"{v * 1000:g} µs"
        if v < 1000:
            return f"{v:g} ms"
        return f"{v / 1000:g} s"
    ax.xaxis.set_major_locator(LogLocator(base=10, numticks=20))
    ax.xaxis.set_major_formatter(FuncFormatter(fmt))
    ax.xaxis.set_minor_formatter(NullFormatter())


def clean(ax, left=False):
    for s in ("top", "right") + (("left",) if not left else ()):
        ax.spines[s].set_visible(False)


def load_alg(run, q=0.5):
    d = pd.read_csv(os.path.join(RES, run, "alg.csv"))
    d = d[d.status == 0]
    return d.groupby(["alg", "op"]).ns.quantile(q) / 1e6


def load_tls(run):
    d = pd.read_csv(os.path.join(RES, run, "tls.csv"))
    d = d[(d.dut_status == 0) & (d.host_status == 0)]
    g = d.groupby(["chain", "kex", "auth", "dut_role"])
    return g.agg(ttfb=("ttfb_ns", "median"), tcp=("tcp_ns", "median"),
                 c2s=("c2s_bytes", "median"), s2c=("s2c_bytes", "median"),
                 heap=("dut_heap_peak", "max"), stack=("dut_stack", "max")).reset_index()


# Rows of Fig. 1: (group, label, [(alg, op), ...]) - the time is the sum of the ops.
OPS = [
    ("Key exchange, per side", "X25519 keygen + shared", [("x25519", "keygen"), ("x25519", "shared")]),
    ("Key exchange, per side", "ECDH P-256 keygen + shared", [("secp256r1", "keygen"), ("secp256r1", "shared")]),
    ("Key exchange, per side", "ML-KEM-768 encaps (server)", [("mlkem768", "encap")]),
    ("Key exchange, per side", "ML-KEM-768 keygen + decaps (client)", [("mlkem768", "keygen"), ("mlkem768", "decap")]),
    ("Verify", "ECDSA P-256", [("ecdsa_p256", "verify")]),
    ("Verify", "RSA-3072", [("rsa3072", "verify")]),
    ("Verify", "ML-DSA-44", [("mldsa44", "verify")]),
    ("Verify", "Falcon-512", [("falcon512", "verify")]),
    ("Verify", "LMS (H15/W4)", [("lms_h15", "verify")]),
    ("Verify", "XMSS (H16)", [("xmss_h16", "verify")]),
    ("Verify", "SLH-DSA-128s", [("slhdsa_sha2_128s", "verify")]),
    ("Verify", "SLH-DSA-128f", [("slhdsa_sha2_128f", "verify")]),
    ("Sign", "ECDSA P-256", [("ecdsa_p256", "sign")]),
    ("Sign", "RSA-3072", [("rsa3072", "sign")]),
    ("Sign", "ML-DSA-44", [("mldsa44", "sign")]),
    ("Sign", "Falcon-512", [("falcon512", "sign")]),
    ("Sign", "SLH-DSA-128s", [("slhdsa_sha2_128s", "sign")]),
    ("Sign", "SLH-DSA-128f", [("slhdsa_sha2_128f", "sign")]),
]
P99_ROW = ("Sign", "ML-DSA-44")


def fig_ops(runs, out):
    meds = {p: load_alg(r) for p, r in runs.items()}
    p99 = {p: load_alg(r, 0.99) for p, r in runs.items()}
    fig, ax = plt.subplots(figsize=(WIDTH_IN, 4.3))
    y = 0
    ys, labels, heads = [], [], []
    last = None
    for grp, label, ops in OPS:
        if grp != last:
            if last is not None:
                y += 0.8
            heads.append((y, grp))
            y += 1
            last = grp
        ys.append(y)
        labels.append(label)
        y += 1
    for i, (p, name) in enumerate(PLATFORMS):
        if p not in meds:
            continue
        xs = [sum(meds[p].get(op, np.nan) for op in ops) for _, _, ops in OPS]
        ax.plot(xs, ys, linestyle="none", marker=MARKERS[i], markersize=5,
                markerfacecolor="none", markeredgewidth=1.1, color=COLORS[i], label=name)
        for (grp, label, ops), yy, x in zip(OPS, ys, xs):
            if (grp, label) == P99_ROW and p == "rw612":
                hi = p99[p][ops[0]]
                ax.plot([x * 1.12, hi], [yy, yy], color=COLORS[i], linewidth=0.8)
                ax.plot([hi], [yy], marker="|", markersize=6, markeredgewidth=1.0, color=COLORS[i])
                ax.text(hi * 1.4, yy, "99th percentile", va="center", fontsize=8, color=INK2)
    for yy in ys:
        ax.axhline(yy, color=GRID, linewidth=0.4, zorder=0)
    time_axis(ax, 0.01, 1e5)
    ax.set_yticks(ys, labels)
    for yh, grp in heads:
        ax.text(0.0105, yh, grp, fontweight="bold", va="center", ha="left", color=INK)
    ax.set_ylim(y, -1)
    ax.set_xlabel("Median time per operation, logarithmic")
    ax.grid(axis="x", which="major", color=GRID, linewidth=0.5)
    ax.tick_params(axis="y", length=0)
    clean(ax)
    fig.legend(loc="upper center", bbox_to_anchor=(0.5, 1.0), ncol=2, frameon=False,
               handletextpad=0.3, columnspacing=1.5)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    fig.savefig(out)
    plt.close(fig)


def fig_handshake(runs, out):
    """Client and server TTFB per platform joined by a line, so the length shows what signing costs."""
    fig, ax = plt.subplots(figsize=(WIDTH_IN, 3.6))
    offs = [-0.27, -0.09, 0.09, 0.27]
    for i, (p, name) in enumerate(PLATFORMS):
        if p not in runs:
            continue
        m = pd.concat([load_tls(r) for r in runs[p]]).drop_duplicates(
            ["chain", "kex", "auth", "dut_role"], keep="last")
        m = m[(m.kex == "mlkem768") & (m.auth == "server")].set_index(["chain", "dut_role"])
        for j, c in enumerate(ORDER):
            if (c, "client") not in m.index or (c, "server") not in m.index:
                continue
            xc, xs = m.loc[(c, "client"), "ttfb"] / 1e6, m.loc[(c, "server"), "ttfb"] / 1e6
            yy = j + offs[i]
            ax.plot([xc, xs], [yy, yy], color=COLORS[i], linewidth=0.9, zorder=1)
            ax.plot([xc], [yy], linestyle="none", marker=MARKERS[i], markersize=6.5,
                    markerfacecolor="white", markeredgewidth=1.0, color=COLORS[i], zorder=2,
                    label=name if j == 0 else None)
            ax.plot([xs], [yy], linestyle="none", marker=MARKERS[i], markersize=3.8,
                    markerfacecolor=COLORS[i], markeredgewidth=0, color=COLORS[i], zorder=3)
    for j in range(len(ORDER)):
        ax.axhline(j - 0.5, color=GRID, linewidth=0.4, zorder=0)
    time_axis(ax, 0.6, 1e5)
    ax.set_yticks(range(len(ORDER)), [NAMES[c] for c in ORDER])
    ax.set_ylim(len(ORDER) - 0.5, -0.5)
    ax.set_xlabel("Median time to first byte, logarithmic")
    ax.grid(axis="x", which="major", color=GRID, linewidth=0.5)
    ax.tick_params(axis="y", length=0)
    clean(ax)
    h, l = ax.get_legend_handles_labels()
    h += [plt.Line2D([], [], linestyle="none", marker="o", markersize=6.5, markerfacecolor="white",
                     color=INK2),
          plt.Line2D([], [], linestyle="none", marker="o", markersize=3.8, markeredgewidth=0,
                     markerfacecolor=INK2, color=INK2)]
    l += ["device as client: verifies, host signs", "device as server: signs"]
    fig.legend(h, l, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.5, 1.0),
               handletextpad=0.3, columnspacing=1.2)
    fig.tight_layout(rect=(0, 0, 1, 0.88))
    fig.savefig(out)
    plt.close(fig)


APP_TAIL = 86 + 24  # 64 B app record + close_notify, both sides


def extra_rtts(base_run, run):
    base = load_tls(base_run)
    m = load_tls(run)
    k = ["chain", "kex", "auth", "dut_role"]
    x = m.merge(base[k + ["ttfb", "tcp"]], on=k, suffixes=("", "_0"))
    x["extra"] = ((x.ttfb - x.ttfb_0) / (x.tcp - x.tcp_0)) - 3
    x["flight"] = np.where(x.dut_role == "server", x.s2c, x.c2s) / 1000 - APP_TAIL / 1000
    return x


RTT_CHAINS = ["ecdsa_p256", "rsa3072", "falcon512", "lms+mldsa44", "mldsa44",
              "lms+slhdsa_sha2_128f", "slhdsa_sha2_128f"]
RTT_LIMITS = [(4.5, "\u2193 > 10 segments (14.6 kB)"), (5.5, "\u2193 > 32 KiB send window")]
TCP_STYLE = {
    "stock": ("Zephyr TCP, stock (initial window 1 segment)", INK, "o", "none", -0.3),
    "iw10": ("Zephyr TCP, initial window 10 segments", "#7a7a7a", "s", "none", -0.1),
    "rto": ("Zephyr TCP, initial window 10, RTO 1 s", INK, "s", INK, 0.1),
    "linux": ("Linux TCP (Pi 3B+)", COLORS[2], "^", "none", 0.3),
}


def fig_rtt(panels, out):
    fig, axes = plt.subplots(1, len(panels), figsize=(WIDTH_IN, 3.0), sharey=True, sharex=True)
    sizes = {}
    for ax, pan in zip(axes, panels):
        seen = set()
        for key, base_run, run in pan["series"]:
            name, col, mk, fill, dy = TCP_STYLE[key]
            x = extra_rtts(base_run, run)
            x = x[(x.kex == "mlkem768") & (x.auth == pan["auth"]) & (x.dut_role == pan["role"])
                  & x.chain.isin(RTT_CHAINS)].set_index("chain")
            if pan["role"] == "server":
                for c in x.index:
                    sizes.setdefault(c, x.loc[c, "flight"])
            seen |= set(x.index)
            ax.plot(x.extra.clip(lower=0), [RTT_CHAINS.index(c) + dy for c in x.index],
                    linestyle="none", marker=mk, markersize=4.5, markerfacecolor=fill,
                    markeredgewidth=1.0, color=col, label=name)
        for c in RTT_CHAINS:
            if c not in seen:
                ax.text(0.15, RTT_CHAINS.index(c), "not measured", va="center", fontsize=8,
                        color=INK2, style="italic")
        for yv, _ in RTT_LIMITS:
            ax.axhline(yv, color=INK2, linestyle=(0, (3, 3)), linewidth=0.6)
        for yy in range(len(RTT_CHAINS)):
            ax.axhline(yy, color=GRID, linewidth=0.4, zorder=0)
        ax.set_title(pan["title"], fontsize=9, linespacing=1.15)
        ax.set_xlim(-0.3, 9.6)
        ax.set_xticks(range(0, 10, 2))
        ax.grid(axis="x", color=GRID, linewidth=0.5)
        ax.tick_params(axis="y", length=0)
        clean(ax)
    for yv, lab in RTT_LIMITS:
        axes[0].text(1.0, yv - 0.04, lab, transform=axes[0].get_yaxis_transform(),
                     ha="right", va="bottom", fontsize=8, color=INK2)
    labels = [f"{NAMES[c]} ({sizes.get(c, float('nan')):.1f} kB)" for c in RTT_CHAINS]
    axes[0].set_yticks(range(len(RTT_CHAINS)), labels)
    axes[0].text(-0.025, 1.0, "Chain (server flight)", transform=axes[0].transAxes, ha="right",
                 va="bottom", fontsize=8, color=INK2)
    axes[0].set_ylim(len(RTT_CHAINS) - 0.5, -0.6)
    handles = {}
    for ax in axes:
        for h, l in zip(*ax.get_legend_handles_labels()):
            handles.setdefault(l, h)
    order = [TCP_STYLE[k][0] for k in ("stock", "iw10", "rto", "linux") if TCP_STYLE[k][0] in handles]
    fig.legend([handles[l] for l in order], order, loc="upper center", ncol=2, frameon=False,
               bbox_to_anchor=(0.5, 1.0), handletextpad=0.3, columnspacing=1.5)
    fig.tight_layout(rect=(0, 0.035, 1, 0.86))
    fig.supxlabel("Excess TTFB in RTT units = (TTFB \u2212 TTFB at 0 ms) / RTT \u2212 3", fontsize=9,
                  x=(axes[0].get_position().x0 + axes[-1].get_position().x1) / 2, y=0.01)
    fig.savefig(out)
    plt.close(fig)


def _heap_trace_module():
    spec = importlib.util.spec_from_file_location(
        "plot_heap_trace", os.path.join(ROOT, "scripts", "plot_heap_trace.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Handshake steps of a mutual-auth client: wolfSSL function -> (label, tier above the plot).
HEAP_PHASES = {
    "SendTls13ClientHello": ("key share", 1),
    "DoTls13ServerHello": ("decaps", 0),
    "ProcessPeerCerts": ("server chain", 0),
    "DoTls13CertificateVerify": ("verify sig.", 1),
    "SendTls13Certificate": ("own chain", 0),
    "SendTls13CertificateVerify": ("sign", 1),
}


def fig_heap(run, specs, out):
    ht = _heap_trace_module()
    series = []
    for chain, label in specs:
        _, evs, _ = ht.load(f"{os.path.join(RES, run)}:{chain}")
        series.append([label, evs, list(range(len(evs)))])
    ht.align_shared(series)
    fig, ax = plt.subplots(figsize=(WIDTH_IN, 3.2))
    above = mtrans.blended_transform_factory(ax.transData, ax.transAxes)
    ref_label, ref_evs, ref_xs = series[-1]
    ymax = max(e[3] for _, evs, _ in series for e in evs) / 1000
    opened = {}
    for x, e in zip(ref_xs, ref_evs):
        if e[1] == "end" and e[4] == "DoTls13CertificateRequest":
            opened["ProcessPeerCerts"] = x
        if e[4] in HEAP_PHASES:
            if e[1] == "mark":
                opened.setdefault(e[4], x)
            elif e[1] == "end" and e[4] in opened:
                lab, tier = HEAP_PHASES[e[4]]
                x0 = opened.pop(e[4])
                ax.axvspan(x0, x, color=SPAN, linewidth=0, zorder=0)
                ax.text((x0 + x) / 2, 1.02 + 0.075 * tier, lab, transform=above,
                        ha="center", va="bottom", fontsize=8, color=INK)
    marks = {}
    for x, e in zip(ref_xs, ref_evs):
        if e[1] == "mark" and e[4] in ("ssl_new", "handshake_done"):
            ax.axvline(x, color=INK2, linestyle=(0, (3, 3)), linewidth=0.6)
            marks[e[4]] = x
    ax.text((min(ref_xs) + marks["ssl_new"]) / 2, 1.02, "context setup",
            transform=above, ha="center", va="bottom", fontsize=8, color=INK2)
    ax.text((marks["handshake_done"] + max(ref_xs)) / 2, 1.02, "app data,\nteardown",
            transform=above, ha="center", va="bottom", fontsize=8, color=INK2, linespacing=1.0)
    peaks = []
    for i, (label, evs, xs) in enumerate(series):
        hs = [e[3] / 1000 for e in evs]
        ax.step(xs, hs, where="post", color=COLORS[i], linewidth=1.1)
        k = int(np.argmax(hs))
        ax.plot([xs[k]], [hs[k]], marker="o", markersize=4, color=COLORS[i],
                markeredgecolor="white", markeredgewidth=0.6, zorder=5)
        ctx = next(e[3] for e in evs if e[1] == "mark" and e[4] == "ssl_new") / 1000
        peaks.append([hs[k], label, COLORS[i], ctx])
    peaks.sort()
    ylim = ymax * 1.04
    gap = 0.155 * ylim
    yls = [pk for pk, _, _, _ in peaks]
    for _ in range(200):
        for j in range(1, len(yls)):
            d = gap - (yls[j] - yls[j - 1])
            if d > 0:
                yls[j] += d / 2
                yls[j - 1] -= d / 2
    side = mtrans.blended_transform_factory(ax.transAxes, ax.transData)
    for (pk, label, col, ctx), yl in zip(peaks, yls):
        ax.plot([1.0, 1.012, 1.03], [pk, pk, yl], transform=side, color=col, linewidth=1.4,
                clip_on=False, solid_joinstyle="round")
        ax.text(1.036, yl, f"{label}\n{pk:.0f} kB peak\n({pk - ctx:.0f} kB + context)",
                transform=side, va="center", ha="left", fontsize=8, color=INK, linespacing=1.05)
    ax.set_ylim(0, ylim)
    ax.set_xlim(min(ref_xs), max(ref_xs))
    ax.set_xticks([])
    ax.set_xlabel("Heap operations in order (not time), aligned at the handshake steps")
    ax.set_ylabel("Heap in use [kB]")
    ax.grid(axis="y", color=GRID, linewidth=0.5)
    clean(ax, left=True)
    fig.subplots_adjust(left=0.085, right=0.82, bottom=0.075, top=0.86)
    fig.savefig(out)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "paper", "out"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    alg = {p: f"{p}/20261010-{'h743-fpu' if p == 'h743' else p}" for p, _ in PLATFORMS}
    fig_ops(alg, os.path.join(a.out, "fig1_ops.png"))
    fig_handshake({p: [r] for p, r in alg.items()}, os.path.join(a.out, "fig2_handshake.png"))
    pi3 = ("linux", "rpi3/20261010-rpi3-rtt0", "rpi3/20261010-rpi3-rtt{}")
    panels = [
        {"title": "100 ms RTT, RW612 as server\n(server-only authentication)", "role": "server",
         "auth": "server", "delay": 100,
         "series": [("stock", "rw612/20261010-rw612-rtt0", "rw612/20261010-rw612-rtt{}"),
                    ("iw10", "rw612/20261010-rw612-iw10-rtt0", "rw612/20261010-rw612-iw10-rtt{}"), pi3]},
        {"title": "600 ms RTT, H743 as client\n(mutual authentication)", "role": "client",
         "auth": "mutual", "delay": 600,
         "series": [("stock", "h743/20261010-h743-fpu-rtt0", "h743/20261010-h743-fpu-rtt{}"),
                    ("iw10", "h743/20261010-h743-fpu-iw10-rtt0", "h743/20261010-h743-fpu-iw10-rtt{}"),
                    ("rto", "h743/20261010-h743-fpu-iw10-rtt0",
                     "h743/20261010-h743-fpu-iw10-rto1000-rtt{}"), pi3]},
    ]
    for pan in panels:
        pan["series"] = [(k, b, r.format(pan["delay"])) for k, b, r in pan["series"]]
    fig_rtt(panels, os.path.join(a.out, "fig3_rtt.png"))
    fig_heap("rw612/20261010-heap-trace",
             [("ecdsa_p256,mlkem768,mutual,client", "ECDSA P-256"),
              ("falcon512,mlkem768,mutual,client", "Falcon-512"),
              ("mldsa44,mlkem768,mutual,client", "ML-DSA-44"),
              ("slhdsa_sha2_128f,mlkem768,mutual,client", "SLH-DSA-128f")],
             os.path.join(a.out, "fig4_heap.png"))


if __name__ == "__main__":
    main()
