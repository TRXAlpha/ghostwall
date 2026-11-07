#!/usr/bin/env python3
"""Memory and speed of the two big lists ghost-dns holds: the threat feed and the
popular-domain list, loaded from the files update_feed.py writes.

    python agents/ghost_dns/bench_lists.py --dir /var/lib/ghostwall [--top 1000000]

"held" is what stays allocated once loaded; "peak" is the most allocated at once while
loading (Python's tracemalloc, which also sees numpy's buffers).
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import numpy  # noqa: E402  (imported first so its own memory isn't counted)
import detectors as D  # noqa: E402

NUMPY = numpy.__version__


def measure(name: str, make) -> None:
    tracemalloc.start()
    t = time.perf_counter()
    obj = make()
    n = len(obj)
    took = time.perf_counter() - t
    held, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    probe = "cdn.some-name.example.com"
    t = time.perf_counter()
    for _ in range(20000):
        obj.match(probe)
    look = (time.perf_counter() - t) / 20000 * 1e6
    print(f"{name:28s} {n:>9,} names  held {held / 2**20:6.2f} MiB  peak {peak / 2**20:6.2f} MiB  "
          f"load {took:5.1f} s  lookup {look:4.1f} us")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default="/var/lib/ghostwall", help="folder with threat_feed.txt and popular_domains.txt")
    ap.add_argument("--top", type=int, default=1_000_000, help="popular_top_n (default 1000000)")
    a = ap.parse_args(argv)
    feed, pop = os.path.join(a.dir, "threat_feed.txt"), os.path.join(a.dir, "popular_domains.txt")
    measure("threat feed", lambda: D.ThreatFeed(feed))
    measure(f"popular domains, top {a.top:,}", lambda: D.PopularDomains(pop, top=a.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
