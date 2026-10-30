#!/usr/bin/env python3
"""Replay REAL AdGuard query history through the full detection pipeline.

    python replay_querylog.py --querylog /opt/AdGuardHome/data/querylog.json

Runs in shadow mode with throw-away state and a private events file: it changes
nothing, alerts nobody, and shows what Ghostwall WOULD have flagged on your real
traffic, using the query timestamps as the clock (so beacon/burst timing is real).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import config as config_mod
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from scoring import Scorer
from shadow import parse_line
from state import GhostState

_FRAC = re.compile(r"(\.\d{6})\d+")


class MemoScorer:
    """Real queries repeat the same domains constantly; score each one once."""

    def __init__(self, inner):
        self.inner, self.cache = inner, {}

    def score_one(self, domain):
        r = self.cache.get(domain)
        if r is None:
            r = self.cache[domain] = self.inner.score_one(domain)
        return r


def parse_time(s: str) -> float | None:
    try:
        return datetime.fromisoformat(_FRAC.sub(r"\1", s.replace("Z", "+00:00"))).timestamp()
    except (ValueError, TypeError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--querylog", required=True)
    ap.add_argument("--devices", default=None)
    ap.add_argument("--max-lines", type=int, default=0, help="0 = all")
    ap.add_argument("--allowlist", default=os.path.join(HERE, "allowlist.txt"))
    ap.add_argument("--no-allowlist", action="store_true")
    ap.add_argument("--feed", default=os.path.join(HERE, "threat_feed.txt"))
    a = ap.parse_args()

    wd = tempfile.mkdtemp(prefix="ghostwall-replay-")
    cfg = config_mod.load_config(None, {
        "state_path": os.path.join(wd, "s.json"), "events_path": os.path.join(wd, "e.jsonl"),
        "query_log": None, "resolved_ips_path": None, "shadow": True,
        "threat_feed_path": a.feed if os.path.exists(a.feed) else None})
    state = GhostState(cfg["state_path"], learning_default=True)
    if not a.no_allowlist:
        state.load_allowlist_file(a.allowlist)
    dm = DeviceMap.from_json([]) if not a.devices else DeviceMap.load(a.devices)
    r = Resolver(cfg, state, MemoScorer(Scorer(cfg["onnx_model"], cfg["lr_coef"], cfg["lr_meta"])),
                 Enforcer(NullBackend()), dm, EventLog(cfg["events_path"]))
    clock = {"t": 0.0}
    r.clock = lambda: clock["t"]

    n = bad = 0
    first = last = None
    with open(a.querylog, encoding="utf-8", errors="replace") as f:
        for line in f:
            if a.max_lines and n >= a.max_lines:
                break
            try:
                j = json.loads(line)
            except ValueError:
                bad += 1
                continue
            parsed = parse_line(line)
            ts = parse_time(j.get("T", ""))
            if not parsed or ts is None:
                continue
            clock["t"] = ts
            first = first or ts
            last = ts
            ip, host, qtype = parsed
            try:
                r.decide(ip, host, qtype)
            except Exception as exc:  # noqa: BLE001
                print("decide failed:", host, repr(exc), file=sys.stderr)
            n += 1

    evs = []
    with open(cfg["events_path"], encoding="utf-8") as f:
        evs = [json.loads(l) for l in f if l.strip()]
    span = (last - first) / 3600 if first and last else 0
    print(f"replayed {n} queries over {span:.1f} h  ({bad} unreadable lines)")
    print(f"feed: {len(r.det.threat_feed)} domains | allowlist entries: {len(state.allowlist)}")
    print(f"alerts: {len(evs)}  (suppressed repeats: {r.stats['suppressed']})\n")
    by_rule = Counter(e["rule"] for e in evs)
    for rule, c in by_rule.most_common():
        print(f"  {rule:18s} {c}")
        for e in [e for e in evs if e["rule"] == rule][:6]:
            print(f"      {e['device']:18s} {e['domain'][:60]:60s} {', '.join(e.get('reasons', []))[:70]}")
    per_dev = Counter(e["device"] for e in evs)
    print("\nalerts per device:", dict(per_dev))
    return 0


if __name__ == "__main__":
    sys.exit(main())
