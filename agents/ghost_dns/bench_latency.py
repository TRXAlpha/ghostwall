#!/usr/bin/env python3
"""How long an inline-mode answer takes for a name ghost-dns has never seen, with the
shipped models, scoring before the answer (learning off, or score_after_answer: false)
and after it (learning on, the default). A local stand-in upstream answers instantly,
so the numbers are ghost-dns's own time.

    python agents/ghost_dns/bench_latency.py [-n 200]
"""
from __future__ import annotations

import argparse
import os
import random
import socket
import string
import struct
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import config as config_mod  # noqa: E402
from app import build  # noqa: E402


def query(name: str) -> bytes:
    return (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
            + struct.pack(">HH", 1, 1))


def upstream() -> int:
    """A UDP server answering every A query with 192.0.2.10."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))

    def serve():
        while True:
            q, addr = s.recvfrom(512)
            end = 12
            while q[end]:
                end += q[end] + 1
            end += 5
            s.sendto(q[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + q[12:end]
                     + struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton("192.0.2.10"), addr)
    threading.Thread(target=serve, daemon=True).start()
    return s.getsockname()[1]


def measure(port: int, after: bool, n: int) -> tuple[float, float, str]:
    d = tempfile.mkdtemp(prefix="gw-bench-")
    cfg = config_mod.load_config(None, {
        "state_path": f"{d}/s.json", "events_path": f"{d}/e.jsonl", "query_log": None,
        "resolved_ips_path": None, "devices_json": f"{d}/none.json", "threat_feed_path": None,
        "neighbours_path": "", "upstream": "127.0.0.1", "upstream_port": port,
        "upstream_fallbacks": [], "score_after_answer": after, "learning": True})
    *_, scorer, _, _, _, r = build(cfg)
    rng = random.Random(7)
    names = ["".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(5, 12))) + ".com"
             for _ in range(n + 20)]
    for name in names[:20]:              # warm up
        r.handle_packet("192.168.1.30", query(name))
    r.drain()
    took = []
    for name in names[20:]:
        t = time.perf_counter()
        r.handle_packet("192.168.1.30", query(name))
        took.append(time.perf_counter() - t)
    r.drain()
    took.sort()
    return took[len(took) // 2] * 1000, took[int(len(took) * 0.95)] * 1000, getattr(scorer, "backend", "?")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-n", type=int, default=200, help="new names per run (default 200)")
    a = ap.parse_args(argv)
    port = upstream()
    for label, after in (("score, then answer", False), ("answer, then score", True)):
        med, p95, models = measure(port, after, a.n)
        print(f"{label:20s} median {med:6.2f} ms   p95 {p95:6.2f} ms   (models: {models})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
