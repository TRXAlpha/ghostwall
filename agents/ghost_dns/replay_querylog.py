#!/usr/bin/env python3
"""Replay REAL AdGuard or Pi-hole query history through the full detection pipeline.

    python replay_querylog.py --querylog /opt/AdGuardHome/data/querylog.json
    python replay_querylog.py --querylog /var/log/pihole/pihole.log   # also .gz rotations

Runs in shadow mode with throw-away state and a private events file: it changes
nothing, alerts nobody, and shows what Ghostwall WOULD have flagged on your real
traffic, using the query timestamps as the clock (so beacon/burst timing is real).
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import config as config_mod
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from scoring import Scorer
from shadow import detect_format, parse_adguard_entry, parse_pihole_line, pihole_blocked_host, pihole_reply
from state import GhostState

_FRAC = re.compile(r"(\.\d{6})\d+")
_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d:\d\d:\d\d)")


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


def parse_syslog_time(line: str) -> float | None:
    """Pi-hole lines start `Oct 31 12:00:00` (no year): assume the most recent such date."""
    m = _SYSLOG_TS.match(line)
    if not m:
        return None
    now = time.time()
    year = datetime.now().year
    try:
        ts = datetime.strptime(f"{year} {m[1]} {m[2]} {m[3]}", "%Y %b %d %H:%M:%S").timestamp()
    except ValueError:
        return None
    if ts > now + 86400:  # a December line read in January
        ts = datetime.strptime(f"{year - 1} {m[1]} {m[2]} {m[3]}", "%Y %b %d %H:%M:%S").timestamp()
    return ts


def first_existing(*paths: str) -> str | None:
    return next((p for p in paths if os.path.exists(p)), None)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--querylog", required=True, help="AdGuard querylog.json or Pi-hole pihole.log[.N.gz]")
    ap.add_argument("--format", choices=["auto", "adguard", "pihole"], default="auto")
    ap.add_argument("--devices", default=first_existing("/etc/ghostwall/devices.json"),
                    help="device names (default: /etc/ghostwall/devices.json if present)")
    ap.add_argument("--max-lines", type=int, default=0, help="0 = all")
    ap.add_argument("--allowlist", default=os.path.join(HERE, "allowlist.txt"))
    ap.add_argument("--no-allowlist", action="store_true")
    ap.add_argument("--feed", default=first_existing(os.path.join(HERE, "threat_feed.txt"),
                                                     "/var/lib/ghostwall/threat_feed.txt") or "",
                    help="threat feed (default: the installed one in /var/lib/ghostwall)")
    ap.add_argument("--popular", default="",
                    help="popular-domain list for the DGA guard (default: popular_domains.txt "
                         "next to the feed, as update_feed.py writes it)")
    a = ap.parse_args()

    wd = tempfile.mkdtemp(prefix="ghostwall-replay-")
    cfg = config_mod.load_config(None, {
        "state_path": os.path.join(wd, "s.json"), "events_path": os.path.join(wd, "e.jsonl"),
        "query_log": None, "resolved_ips_path": None, "shadow": True,
        "threat_feed_path": a.feed if os.path.exists(a.feed) else None,
        "popular_path": a.popular or None})
    state = GhostState(cfg["state_path"], learning_default=True)
    if not a.no_allowlist:
        state.load_allowlist_file(a.allowlist)
    dm = DeviceMap.from_json([]) if not a.devices else DeviceMap.load(a.devices)
    r = Resolver(cfg, state, MemoScorer(Scorer(cfg["onnx_model"], cfg["lr_coef"], cfg["lr_meta"])),
                 Enforcer(NullBackend()), dm, EventLog(cfg["events_path"]))
    clock = {"t": 0.0}
    r.clock = lambda: clock["t"]
    # novelty, device baselines and alert de-duplication follow the log's time too
    state.clock = lambda: datetime.fromtimestamp(clock["t"], timezone.utc)

    fmt = detect_format(a.querylog) if a.format == "auto" else a.format
    opener = gzip.open if a.querylog.endswith(".gz") else open
    n = bad = 0
    first = last = None
    held: list = []   # Pi-hole: queries waiting for their "blocked" or "reply" line (oldest first)

    def run(q):
        nonlocal n
        ip, host, qtype, blocked, rcode, zone, ts = q
        clock["t"] = ts
        try:
            r.decide(ip, host, qtype, upstream_blocked=blocked,
                     rcode=None if blocked else rcode, nx_zone=zone)
        except Exception as exc:  # noqa: BLE001
            print("decide failed:", host, repr(exc), file=sys.stderr)
        n += 1

    with opener(a.querylog, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if a.max_lines and n >= a.max_lines:
                break
            if fmt == "pihole":
                # As the live follower does: several queries can wait for their
                # "blocked" or "reply" line at once (other clients' lines come between).
                bh = pihole_blocked_host(line)
                if bh:
                    for q in held:
                        if q[1] == bh:
                            q[3] = True
                    continue
                rep = pihole_reply(line)
                if rep:
                    for q in held:
                        if q[1] == rep[0] and q[4] is None:
                            q[4] = rep[1]
                            break
                    continue
                parsed = parse_pihole_line(line)
                ts = parse_syslog_time(line) if parsed else None
                if not parsed or ts is None:
                    continue
                while held and (len(held) >= 64 or ts - held[0][6] > 3
                                or held[0][3] or held[0][4] is not None):
                    run(held.pop(0))
                held.append(list(parsed) + [False, None, None, ts])
            else:
                parsed = parse_adguard_entry(line)
                if not parsed:
                    bad += 1
                    continue
                ts = parse_time(json.loads(line).get("T", ""))
                if ts is None:
                    continue
                run(list(parsed) + [ts])
            first = first or ts
            last = ts
    for q in held:
        run(q)

    evs = []
    with open(cfg["events_path"], encoding="utf-8") as f:
        evs = [json.loads(l) for l in f if l.strip()]
    span = (last - first) / 3600 if first and last else 0
    print(f"replayed {n} queries over {span:.1f} h  ({bad} unreadable lines)")
    print(f"feed: {len(r.det.threat_feed)} domains | popular: {len(r.det.popular)} | "
          f"allowlist entries: {len(state.allowlist)}")
    print(f"alerts: {len(evs)}  (suppressed repeats: {r.stats['suppressed']}, "
          f"popular-domain guard: {r.stats['popular']})\n")
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
