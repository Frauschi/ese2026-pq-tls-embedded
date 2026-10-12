#!/usr/bin/env python3
"""Summarizes a DUT-link capture per TCP connection: data segments per direction grouped into
rounds, and retransmitted DUT segments."""
import argparse
import math
import struct
from collections import defaultdict


def packets(path):
    with open(path, "rb") as f:
        magic = f.read(24)[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                return
            sec, frac, incl, _ = struct.unpack(endian + "IIII", hdr)
            data = f.read(incl)
            ts = sec + frac / (1e9 if nano else 1e6)
            if len(data) < 34 or data[12:14] != b"\x08\x00" or data[23] != 6:
                continue
            ihl = (data[14] & 0x0F) * 4
            tot = struct.unpack(">H", data[16:18])[0]
            src, dst = ".".join(map(str, data[26:30])), ".".join(map(str, data[30:34]))
            t = 14 + ihl
            sport, dport, seq, ack = struct.unpack(">HHII", data[t:t + 12])
            doff = (data[t + 12] >> 4) * 4
            flags = data[t + 13]
            yield ts, src, sport, dst, dport, seq, ack, flags, tot - ihl - doff


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--dut", required=True)
    ap.add_argument("--gap-ms", type=float, default=20.0,
                    help="a pause longer than this starts a new round")
    ap.add_argument("--mss", type=int,
                    help="reconstruct DUT segment counts from GRO-merged frames as "
                         "ceil(payload / MSS), assuming all merged segments but the last are full")
    a = ap.parse_args()
    conns = defaultdict(list)
    for p in packets(a.pcap):
        ts, src, sport, dst, dport = p[:5]
        key = (sport, dport) if src == a.dut else (dport, sport)
        conns[key].append(p)
    for i, (key, ps) in enumerate(sorted(conns.items(), key=lambda kv: kv[1][0][0])):
        t0 = ps[0][0]
        seen, retx = set(), []
        rounds, last = [], None
        for ts, src, _, _, _, seq, _, flags, plen in ps:
            if plen <= 0:
                continue
            d = "dut" if src == a.dut else "host"
            n = math.ceil(plen / a.mss) if a.mss and d == "dut" else 1
            if d == "dut":
                if (seq, plen) in seen:
                    retx.append(round((ts - t0) * 1000))
                seen.add((seq, plen))
            if rounds and rounds[-1][0] == d and (ts - last) * 1000 < a.gap_ms:
                rounds[-1][1] += n
                rounds[-1][2] += plen
            else:
                rounds.append([d, n, plen, round((ts - t0) * 1000)])
            last = ts
        print(f"conn {i} dut port {key[0]}: " + "; ".join(
            f"{d} {n} seg {b} B @{t} ms" for d, n, b, t in rounds))
        if retx:
            print(f"  DUT retransmissions at {retx} ms")


if __name__ == "__main__":
    main()
