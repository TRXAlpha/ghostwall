"""Simulated before/after evaluation of the detection pipeline on REAL labelled data.

    python eval_detection.py --data ../../data/drift --year 25

For each trial a fresh resolver sees a virtual-time stream of DNS queries:
  benign device   N distinct normal domains spread over 24h        -> should stay quiet
  infected device a DGA implant mixed into that same normal traffic -> should alert

"old"  = the first deployment: thresholds 0.60/0.90, no behavioural detectors, no dedupe
"new"  = shipped defaults: measured thresholds + burst/tunnel/beacon detectors + dedupe

Domains come from the frozen test years (never seen in training). Scores come from
the real model ensemble. This measures the *domain-label* detectors; it cannot
measure the threat feed or DoH rules, which depend on live traffic.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import tempfile

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import config as config_mod
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from scoring import Scorer
from state import GhostState

DGA_TLDS = ["com", "net", "org", "biz", "info", "top", "xyz", "ru", "cn", "cc"]


class CachedScorer:
    """Scores precomputed in one batch, so thousands of trials stay fast."""

    def __init__(self, table):
        self.t = table

    def score_one(self, domain):
        s = self.t.get(domain, 0.0)
        return {"dga": s, "dga_trm": s, "dga_lr": s}


def load_labels(data_dir, year, cls, n, rng):
    import pyarrow.parquet as pq
    col = pq.read_table(os.path.join(data_dir, f"T{year}_{cls}.parquet"), columns=["domain"]).column("domain")
    idx = rng.sample(range(len(col)), n)
    return [str(col[i].as_py()).lower() for i in idx]


def make_resolver(cfg_over, table, workdir):
    cfg = config_mod.load_config(None, {
        "state_path": os.path.join(workdir, "s.json"), "events_path": os.path.join(workdir, "e.jsonl"),
        "query_log": None, "resolved_ips_path": None, "allowlist_path": None,
        "threat_feed_path": None, "novelty_days": 7, **cfg_over})
    st = GhostState(cfg["state_path"], learning_default=True)
    dm = DeviceMap.from_json([{"name": "dev", "ip": "10.0.0.2"}])
    r = Resolver(cfg, st, CachedScorer(table), Enforcer(NullBackend()), dm, EventLog(cfg["events_path"]))
    r.shadow = True
    return r, cfg


OLD = {"recommend_threshold": 0.60, "block_threshold": 0.90, "event_dedupe_seconds": 0,
       "corroborated_threshold": 2.0, "burst_min_distinct": 10 ** 9, "tunnel_min_distinct": 10 ** 9,
       "beacon_min_samples": 10 ** 9}
NEW = {}   # shipped defaults


def run_trial(over, table, stream):
    """stream: list of (t_seconds, domain, is_dga). Returns (events, first_dga_alert_index)."""
    wd = tempfile.mkdtemp()
    r, cfg = make_resolver(over, table, wd)
    clock = {"t": 0.0}
    r.clock = lambda: clock["t"]
    alerts_at, n_dga_seen = [], 0
    first_dga_alert = None
    for t, dom, is_dga in stream:
        clock["t"] = t
        d = r.decide("10.0.0.2", dom, "A")
        if is_dga:
            n_dga_seen += 1
        if d.action != "allow" and is_dga and first_dga_alert is None:
            first_dga_alert = n_dga_seen
        # count only alerts that were actually emitted (after dedupe)
    ev_path = cfg["events_path"]
    events = []
    if os.path.exists(ev_path):
        with open(ev_path, encoding="utf-8") as f:
            events = [json.loads(l) for l in f if l.strip()]
    return events, first_dga_alert


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(HERE, "..", "..", "data", "drift"))
    ap.add_argument("--year", default="25")
    ap.add_argument("--trials", type=int, default=150)
    ap.add_argument("--benign-per-day", type=int, default=300)
    ap.add_argument("--dga-per-trial", type=int, default=30)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rng = random.Random(a.seed)

    scorer = Scorer()
    print(f"models: {scorer.backend}; year 20{a.year}; trials {a.trials}; "
          f"{a.benign_per_day} benign domains/day; {a.dga_per_trial} DGA domains/infection\n")

    need_b = a.trials * a.benign_per_day
    need_d = a.trials * a.dga_per_trial
    benign = [l + ".com" for l in load_labels(a.data, a.year, "benign", min(need_b, 400000), rng)]
    dga_labels = load_labels(a.data, a.year, "dga", min(need_d, 400000), rng)
    dga = [l + "." + rng.choice(DGA_TLDS) for l in dga_labels]
    allnames = list(set(benign + dga))
    labels = [n.rsplit(".", 1)[0] for n in allnames]
    scores = (scorer.trm.score(labels) + scorer.lr.score(labels)) / 2
    table = dict(zip(allnames, map(float, scores)))

    res = {"old": {"b_alerts": [], "b_any": 0, "i_det": 0, "i_first": [], "i_alerts_on_dga": []},
           "new": {"b_alerts": [], "b_any": 0, "i_det": 0, "i_first": [], "i_alerts_on_dga": []}}

    for k in range(a.trials):
        # benign device: distinct normal domains at random times over 24h
        bset = rng.sample(benign, a.benign_per_day)
        bstream = sorted((rng.uniform(0, 86400), d, False) for d in bset)
        # infected device: same normal traffic plus a DGA burst starting at a random time,
        # one DGA lookup every ~4-20 s (implants cycle through candidates quickly)
        start = rng.uniform(3600, 80000)
        t = start
        istream = list(bstream)
        for d in rng.sample(dga, a.dga_per_trial):
            t += rng.uniform(4, 20)
            istream.append((t, d, True))
        istream.sort()
        for name, over in (("old", OLD), ("new", NEW)):
            ev, _ = run_trial(over, table, bstream)
            res[name]["b_alerts"].append(len(ev))
            res[name]["b_any"] += bool(ev)
            ev, first = run_trial(over, table, istream)
            res[name]["i_det"] += first is not None
            if first is not None:
                res[name]["i_first"].append(first)
            res[name]["i_alerts_on_dga"].append(
                sum(1 for e in ev if e["domain"] in set(dga)))

    def pct(x):
        return f"{100 * x / a.trials:5.1f}%"

    print(f"{'':44s} {'OLD (first deploy)':>20s} {'NEW (shipped)':>16s}")
    print(f"{'benign device: alerts per day (mean)':44s} {statistics.mean(res['old']['b_alerts']):20.1f} "
          f"{statistics.mean(res['new']['b_alerts']):16.1f}")
    print(f"{'benign device: alerts per day (95th pct)':44s} "
          f"{np.percentile(res['old']['b_alerts'], 95):20.0f} {np.percentile(res['new']['b_alerts'], 95):16.0f}")
    print(f"{'benign devices with >=1 alert':44s} {pct(res['old']['b_any']):>20s} {pct(res['new']['b_any']):>16s}")
    print(f"{'infected device detected (within '+str(a.dga_per_trial)+' DGA lookups)':44s} "
          f"{pct(res['old']['i_det']):>20s} {pct(res['new']['i_det']):>16s}")
    for name in ("old", "new"):
        f = res[name]["i_first"]
        res[name]["med"] = statistics.median(f) if f else float("nan")
    print(f"{'median DGA lookups until first alert':44s} {res['old']['med']:20.1f} {res['new']['med']:16.1f}")
    print(f"\nnote: 'old' alerts on benign include every repeat; 'new' dedupes to one per device per domain family.")


if __name__ == "__main__":
    main()
