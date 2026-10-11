#!/usr/bin/env python3
"""Checks result directories: sample and scenario counts, failures, and TCP connects off the run's RTT."""
import collections
import csv
import os
import re
import sys


def check(d):
    msg = os.path.relpath(d)
    tls = os.path.join(d, "tls.csv")
    if os.path.exists(tls):
        rows = list(csv.DictReader(open(tls)))
        sc = collections.Counter((r["chain"], r["kex"], r["auth"], r["dut_role"]) for r in rows)
        fails = sum(r["dut_status"] != "0" or r["host_status"] != "0" for r in rows)
        m = re.search(r"rtt(\d+)", os.path.basename(d.rstrip("/")))
        rtt = int(m.group(1)) if m else 0
        off = sum(not 0.9 * rtt - 0.5 <= int(r["tcp_ns"]) / 1e6 <= 1.1 * rtt + 2 for r in rows)
        msg += (f"  tls: {len(rows)} rows, {len(sc)} scenarios, n {min(sc.values())}-{max(sc.values())},"
                f" {fails} failed, {off} connects off {rtt} ms")
    alg = os.path.join(d, "alg.csv")
    if os.path.exists(alg):
        rows = list(csv.DictReader(open(alg)))
        ops = collections.Counter((r["alg"], r["op"]) for r in rows)
        fails = sum(r["status"] != "0" for r in rows)
        msg += f"  alg: {len(ops)} ops, n {min(ops.values())}-{max(ops.values())}, {fails} failed"
    print(msg)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: check_results.py RUN_DIR...")
    for d in sys.argv[1:]:
        check(d)
