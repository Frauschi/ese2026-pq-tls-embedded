#!/usr/bin/env python3
"""Plots heap_trace.csv traces (from ese_host --heap-trace) as a publication figure.

usage: plot_heap_trace.py [options] TRACE [TRACE ...]
  TRACE is RUN_DIR:chain,kex,auth,dut_role[=legend label], e.g.
  results/rw612/20261001-trace:mldsa44,mlkem768,mutual,client=ML-DSA-44
"""
import argparse
import csv
import os
import sys

import matplotlib.pyplot as plt

COLORS = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']
MARKERS = ['o', 's', '^', 'd', 'x', '*']
HATCHES = ['//', '\\\\', 'xx', '..', '++', 'oo', '--', '||']
PHASE_COLORS = ['orange', 'red', 'lightblue', 'green', 'purple', 'gold', 'teal', 'pink']


def load(spec):
    path, _, rest = spec.partition(':')
    keys, _, label = rest.partition('=')
    want = keys.split(',')
    if len(want) != 4:
        sys.exit(f'bad trace spec {spec!r}: need chain,kex,auth,dut_role')
    evs = []
    with open(os.path.join(path, 'heap_trace.csv')) as f:
        for r in csv.DictReader(f):
            if [r['chain'], r['kex'], r['auth'], r['dut_role']] == want:
                evs.append((int(r['t_us']) / 1000, r['event'], int(r['size']),
                            int(r['heap']), r['label']))
    if not evs:
        sys.exit(f'no trace for {",".join(want)} in {path}')
    return label or ' / '.join(want), evs, want[3]


def is_step(label):
    return label[:1].isupper()


def anchors(evs, xs):
    seen, out = {}, []
    for x, e in zip(xs, evs):
        if e[1] in ('mark', 'end'):
            key = (e[1], e[4])
            seen[key] = seen.get(key, 0) + 1
            out.append((x, key + (seen[key],)))
    return out


def warp(xs, pts):
    def f(v):
        for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
            if v <= x1:
                return y1 if x1 == x0 else y0 + (v - x0) * (y1 - y0) / (x1 - x0)
        return pts[-1][1] + v - pts[-1][0]
    return [f(v) for v in xs]


def align(xs, evs, ref_xs, ref_evs):
    ref = {k: x for x, k in anchors(ref_evs, ref_xs)}
    pts = [(xs[0], ref_xs[0])]
    for x, k in anchors(evs, xs):
        if k in ref and x >= pts[-1][0] and ref[k] >= pts[-1][1]:
            pts.append((x, ref[k]))
    return warp(xs, pts)


def lcs(a, b):
    n, m = len(a), len(b)
    t = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            t[i][j] = t[i + 1][j + 1] + 1 if a[i] == b[j] else max(t[i + 1][j], t[i][j + 1])
    out, i, j = [], 0, 0
    while i < n and j < m:
        if a[i] == b[j]:
            out.append(a[i])
            i, j = i + 1, j + 1
        elif t[i + 1][j] >= t[i][j + 1]:
            i += 1
        else:
            j += 1
    return out


def align_shared(series):
    """Maps every series onto one timeline whose steps between shared markers are as wide as the widest series."""
    an = [{k: x for x, k in anchors(evs, xs)} for _, evs, xs in series]
    common = list(an[0])
    for a in an[1:]:
        common = lcs(common, list(a))
    pos = [[xs[0]] + [a[k] for k in common] + [xs[-1]] for a, (_, _, xs) in zip(an, series)]
    canon = [0]
    for j in range(1, len(pos[0])):
        canon.append(canon[-1] + max(p[j] - p[j - 1] for p in pos))
    for s, p in zip(series, pos):
        s[2] = warp(s[2], list(zip(p, canon)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('traces', nargs='+')
    ap.add_argument('--x', choices=['ops', 'time'], default='ops')
    ap.add_argument('--align', choices=['shared', 'ref', 'none'], default='shared',
                    help='shared: widest trace per step (default); ref: warp onto the first trace')
    ap.add_argument('--no-phases', action='store_true')
    ap.add_argument('--title', default='Heap memory usage during the TLS 1.3 handshake')
    ap.add_argument('--out', help='output file (PDF, PNG, SVG); shows a window if omitted')
    a = ap.parse_args()

    traces = [load(s) for s in a.traces]
    if len({t[2] for t in traces}) > 1:
        sys.exit('client and server traces cannot be overlaid; pick one dut_role')
    series = []
    for label, evs, _ in traces:
        xs = [e[0] for e in evs] if a.x == 'time' else list(range(len(evs)))
        series.append([label, evs, xs])
    if a.align == 'shared' and len(series) > 1:
        align_shared(series)
    elif a.align == 'ref':
        for s in series[1:]:
            s[2] = align(s[2], s[1], series[0][2], series[0][1])

    print('=== Peak heap ===')
    for label, evs, _ in series:
        peak = max(e[3] for e in evs)
        print(f'{label}: {peak} bytes ({peak / 1000:.3f} kB)')

    plt.figure(figsize=(22, 9))
    ymax = max(e[3] for _, evs, _ in series for e in evs) * 1.075
    ref_label, ref_evs, ref_xs = series[0]
    if not a.no_phases:
        open_at, names = {}, []
        for x, e in zip(ref_xs, ref_evs):
            if not is_step(e[4]):
                continue
            if e[1] == 'mark':
                open_at.setdefault(e[4], []).append(x)
            elif e[1] == 'end' and open_at.get(e[4]):
                if e[4] not in names:
                    names.append(e[4])
                i = names.index(e[4])
                plt.axvspan(open_at[e[4]].pop(), x, facecolor=PHASE_COLORS[i % len(PHASE_COLORS)],
                            alpha=0.2, hatch=HATCHES[i % len(HATCHES)], edgecolor='dimgray',
                            linewidth=0.0, label=e[4])
    for x, e in zip(ref_xs, ref_evs):
        if e[1] == 'mark' and not is_step(e[4]):
            plt.axvline(x=x, color='gray', linestyle='--', linewidth=0.8)
            plt.text(x, ymax * 0.99, ' ' + e[4], rotation=90, fontsize=12, va='top')

    for i, (label, evs, xs) in enumerate(series):
        n = len(xs)
        plt.step(xs, [e[3] for e in evs], where='post', label=label,
                 color=COLORS[i % len(COLORS)], linewidth=2.0,
                 marker=MARKERS[i % len(MARKERS)], markersize=9, markerfacecolor='none',
                 markeredgewidth=1.5, markevery=(i * 12 % max(n, 1), max(n // 12, 1)))

    plt.ylim(0, ymax)
    plt.title(a.title, fontsize=24, pad=20)
    xlabel = 'Time (ms)' if a.x == 'time' else 'Heap operations'
    if a.align == 'shared' and len(series) > 1:
        xlabel += ', aligned at markers'
    plt.xlabel(xlabel, fontsize=20, labelpad=15)
    plt.ylabel('Heap memory usage (kB)', fontsize=20, labelpad=15)
    plt.tick_params(axis='both', which='major', labelsize=16)
    plt.gca().yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f'{v / 1000:g}'))
    plt.grid(True, linewidth=0.2)
    legend = plt.legend(fontsize=13, loc='upper left', bbox_to_anchor=(1.01, 1.0))
    legend.get_frame().set_edgecolor('black')
    plt.tight_layout()
    if a.out:
        plt.savefig(a.out)
        print(f'wrote {a.out}')
    else:
        plt.show()


if __name__ == '__main__':
    main()
