#!/usr/bin/env python3
"""SIMULATION: how fast nx_burst catches a DGA implant, per family, next to what the
character models alone catch. Not field data: there is no real home traffic here.

    python agents/dga_eval/nx_sim.py --data DIR [--out agents/dga_eval/results_nx_sim.md]

DIR holds dga_domains_full.csv (Netlab 360's DGA feed via chrmor/DGA_domains_dataset,
the same pinned file as public_bench.py; `public_bench.py --data DIR --download` fetches it).

What is simulated: one infected device that looks up its family's names one after
another, in the order the feed lists them, one name every GAP seconds. Every name goes
through the real Resolver.decide() (shadow mode, the shipped models, default config),
with the answer's rcode, exactly as AdGuard's query log would report it.

Assumptions, stated plainly:
  * every name the implant looks up is unregistered and answers NXDOMAIN (with the TLD's
    SOA, as a real resolver sends). Real DGAs have a few registered names (the operator's,
    researchers' sinkholes, parked domains), so the run is repeated with 5% of names
    answering NOERROR; the implant is assumed to keep going (a sinkhole is not its server).
  * if instead the implant stops at the first name that resolves, nx_burst only fires
    if 10 NXDOMAINs come first: the last table measures how often that happens.
  * the query gap is a parameter, not a measured property of each family.
  * the device does nothing else, so nothing else can push it over a threshold.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import random
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "agents", "ghost_dns"))

import config as config_mod  # noqa: E402
import detectors as D  # noqa: E402
from devices import DeviceMap  # noqa: E402
from enforce import Enforcer, NullBackend  # noqa: E402
from resolver import Resolver  # noqa: E402
from scoring import Scorer  # noqa: E402
from state import GhostState  # noqa: E402
from tokenizer import registrable_label  # noqa: E402

CSV_SHA256 = "e8bbe54f180cd127a07abaa3dbddcd843e7b7943dff2f18628619b1bd22e8253"   # as in public_bench.py
GAPS = (2, 10, 30, 60)          # seconds between two lookups of the implant
MAX_QUERIES = 300               # per run; a rule that hasn't fired by then is reported as "no"
MODEL_SAMPLE = 2000             # names per family for the model-only catch rates
TRIALS = 2000                   # per family, for "stops at the first name that resolves"
RESOLVE_RUNS = 20               # runs (different random 5%) per family and gap
SEED = 20261107
SINGLE_RULES = ("dga_high", "dga_suspect", "dga_corroborated")
DEVICE_IP = "192.168.1.66"


class Collect:
    """Stands in for EventLog: keeps the events in memory."""

    def __init__(self):
        self.events = []

    def write(self, evt):
        self.events.append(evt)


def load(path: str) -> dict[str, list[str]]:
    with open(path, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    if sha != CSV_SHA256:
        sys.exit(f"{path}: sha256 {sha} is not the pinned file ({CSV_SHA256})")
    fams: dict[str, list[str]] = defaultdict(list)
    with open(path, encoding="utf-8", newline="") as f:
        for cls, fam, dom in csv.reader(f):
            if cls == "dga":
                fams[fam].append(dom.strip().lower())
    return dict(fams)


def run(scorer, names: list[str], gap: float, resolve_frac: float, seed: int) -> dict:
    """Feed one implant's lookups to a fresh Resolver; when (query count, minutes) each
    rule first fired, or None."""
    wd = tempfile.mkdtemp(prefix="nx-sim-")
    cfg = config_mod.load_config(None, {
        "state_path": os.path.join(wd, "s.json"), "events_path": os.path.join(wd, "e.jsonl"),
        "query_log": None, "resolved_ips_path": None, "allowlist_path": None,
        "threat_feed_path": None, "shadow": True})
    state = GhostState(cfg["state_path"], learning_default=True)
    log = Collect()
    r = Resolver(cfg, state, scorer, Enforcer(NullBackend()), DeviceMap.from_json([]), log)
    clock = {"t": 1_700_000_000.0}
    r.clock = lambda: clock["t"]
    state.clock = lambda: datetime.fromtimestamp(clock["t"], timezone.utc)
    rng = random.Random(seed)
    first: dict[str, tuple[int, float]] = {}
    t0 = clock["t"]
    for i, name in enumerate(names[:MAX_QUERIES], 1):
        if rng.random() < resolve_frac:
            r.decide(DEVICE_IP, name, "A", rcode="NOERROR")
        else:
            r.decide(DEVICE_IP, name, "A", rcode="NXDOMAIN", nx_zone=name.rsplit(".", 1)[-1])
        for e in log.events:
            rule = "single" if e["rule"] in SINGLE_RULES else e["rule"]
            first.setdefault(rule, (i, (clock["t"] - t0) / 60))
        # One storm raises one alert: when dga_burst already alerted, nx_burst's own
        # alert is skipped. Its detector still fires; that is what this measures.
        if "nx_burst" not in first and DEVICE_IP in r.det.nx._flagged:
            first["nx_burst"] = (i, (clock["t"] - t0) / 60)
        log.events.clear()
        if {"nx_burst", "dga_burst", "single"} <= first.keys():
            break
        clock["t"] += gap
    return first


def prefill(scorer, names: list[str]) -> None:
    """Score names in batches into the Scorer's own cache (same values as score_one,
    which would run the models one name at a time)."""
    if not (scorer.trm or scorer.lr):
        return
    labels = [lb for lb in dict.fromkeys(registrable_label(n) for n in names) if lb not in scorer._cache]
    for i in range(0, len(labels), 512):
        chunk = labels[i:i + 512]
        trm = scorer.trm.score(chunk) if scorer.trm else None
        lr = scorer.lr.score(chunk) if scorer.lr else None
        for j, lb in enumerate(chunk):
            vals = [float(m[j]) for m in (trm, lr) if m is not None]
            scorer._cache[lb] = {"dga_trm": None if trm is None else round(float(trm[j]), 4),
                                 "dga_lr": None if lr is None else round(float(lr[j]), 4),
                                 "dga": round(sum(vals) / len(vals), 4)}


def model_rates(scorer, names: list[str], rec: float, burst: float) -> tuple[float, float]:
    rng = random.Random(SEED)
    sample = rng.sample(names, min(MODEL_SAMPLE, len(names)))
    prefill(scorer, sample)
    scores = [scorer.score_one(n)["dga"] for n in sample]
    return (sum(s >= rec for s in scores) / len(scores), sum(s >= burst for s in scores) / len(scores))


def stops_at_first_resolve(names: list[str], frac: float, min_distinct: int, seed: int) -> float:
    """Share of runs where nx_burst fires before the implant's first resolving name
    (the detector and name guards themselves, at 10 s per lookup)."""
    rng = random.Random(seed)
    fired = 0
    for _ in range(TRIALS):
        nb = D.NxBurst(min_distinct=min_distinct)
        start = rng.randrange(len(names))
        for k in range(MAX_QUERIES):
            name = names[(start + k) % len(names)]
            if rng.random() < frac:
                break   # it found a name that answers and stops looking
            if D.nx_countable(name) and nb.observe("pc", name, k * 10.0):
                fired += 1
                break
    return fired / TRIALS


def fmt_runs(hits: list) -> str:
    """median lookups (minutes), and the range, over several runs"""
    if not all(hits):
        return f"{sum(1 for h in hits if not h)}/{len(hits)} runs: no"
    hits = sorted(hits)
    n, minutes = hits[len(hits) // 2]
    return f"{n} ({minutes:.1f} min), range {hits[0][0]}-{hits[-1][0]}"


def fmt(hit) -> str:
    if not hit:
        return f"no ({MAX_QUERIES} lookups)"
    n, minutes = hit
    return f"{n} ({minutes:.1f} min)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="directory with dga_domains_full.csv")
    ap.add_argument("--out", default=os.path.join(HERE, "results_nx_sim.md"))
    ap.add_argument("--families", nargs="*", help="only these (default: all 25)")
    a = ap.parse_args()

    fams = load(os.path.join(a.data, "dga_domains_full.csv"))
    if a.families:
        fams = {f: fams[f] for f in a.families}
    cfg = config_mod.load_config(None)
    scorer = Scorer(cfg["onnx_model"], cfg["lr_coef"], cfg["lr_meta"])
    scorer.cache_max = 10 ** 6
    rec, burst, nmin = cfg["recommend_threshold"], cfg["burst_min_score"], cfg["nx_burst_min_distinct"]
    print(f"scorer: {scorer.backend}; nx_burst: {nmin} in {cfg['nx_burst_window']} s", flush=True)

    rows = []
    for fam in sorted(fams):
        names = fams[fam]
        countable = sum(D.nx_countable(n) for n in names) / len(names)
        single, counted = model_rates(scorer, names, rec, burst)
        prefill(scorer, names[:MAX_QUERIES])
        by_gap = {g: run(scorer, names, g, 0.0, SEED) for g in GAPS}
        res5 = {g: [run(scorer, names, g, 0.05, SEED + k).get("nx_burst") for k in range(RESOLVE_RUNS)]
                for g in (10, 60)}
        stop5 = stops_at_first_resolve(names, 0.05, nmin, SEED)
        rows.append((fam, countable, single, counted, by_gap, res5, stop5))
        g10 = by_gap[10]
        print(f"{fam:13s} countable {countable:6.1%}  model>= {rec}: {single:6.1%}  >= {burst}: {counted:6.1%}  "
              f"@10s nx_burst {fmt(g10.get('nx_burst'))}  dga_burst {fmt(g10.get('dga_burst'))}  "
              f"single {fmt(g10.get('single'))}", flush=True)

    dict_fams = ("gozi", "matsnu", "nymaim", "suppobox")
    md = ["# nx_burst: simulated time to detection per DGA family", "",
          "**This is a simulation, not field data.** Generated by `agents/dga_eval/nx_sim.py`: "
          "one infected device looks up its family's names from the Netlab 360 DGA feed "
          "(chrmor/DGA_domains_dataset, pinned by hash, 25 families) in feed order, one name every "
          "GAP seconds, through the real `Resolver.decide()` in shadow mode with the shipped models and "
          f"the default config (`nx_burst_min_distinct` {nmin}, `nx_burst_window` {cfg['nx_burst_window']} s, "
          f"`recommend_threshold` {rec}, `burst_min_score` {burst}). Scorer backend: {scorer.backend}.", "",
          "Assumptions: every looked-up name is unregistered and answers NXDOMAIN (with the TLD's SOA). "
          "The query gap is a parameter, not a measured property of each family. The device does "
          "nothing else. There is no real home traffic in this repository, so this says nothing "
          "about false positives on real networks; the guards against those are unit-tested "
          "(`agents/ghost_dns/tests/test_nx_burst.py`).", "",
          "Cells are `lookups until the first alert (minutes)`; `no` = not within "
          f"{MAX_QUERIES} lookups.", "",
          "## All names NXDOMAIN", "",
          "| Family | names nx_burst can count | model: single-name alert | model: counts toward dga_burst | "
          + " | ".join(f"nx_burst, 1 lookup / {g} s" for g in GAPS)
          + " | dga_burst, 1 / 10 s | first single-name alert, 1 / 10 s |",
          "|---|---|---|---|" + "---|" * len(GAPS) + "---|---|"]
    for fam, countable, single, counted, by_gap, _, _ in rows:
        name = f"**{fam}** (dictionary)" if fam in dict_fams else fam
        md.append(f"| {name} | {countable:.1%} | {single:.1%} | {counted:.1%} | "
                  + " | ".join(fmt(by_gap[g].get("nx_burst")) for g in GAPS)
                  + f" | {fmt(by_gap[10].get('dga_burst'))} | {fmt(by_gap[10].get('single'))} |")
    fired = {g: sum(1 for r in rows if r[4][g].get("nx_burst")) for g in GAPS}
    md += ["", "nx_burst fired for " + ", ".join(f"{fired[g]}/{len(rows)} families at 1 lookup / {g} s"
                                                 for g in GAPS) + ". "
           f"\"model: single-name alert\" is the share of {MODEL_SAMPLE} sampled names scoring >= {rec} "
           f"(`dga_suspect`/`dga_high`); \"counts toward dga_burst\" is the share scoring >= {burst}. "
           f"Slower than one lookup per {cfg['nx_burst_window'] / (nmin - 1):.0f} s, {nmin} names never fit "
           f"in one {cfg['nx_burst_window']} s window. One storm raises one alert: where dga_burst "
           "alerts first, nx_burst's detector still fires at the lookup shown but its alert is skipped.", "",
           "## 5% of names resolve (NOERROR), the implant keeps looking", "",
           f"Median lookups until nx_burst (minutes), and the range, over {RESOLVE_RUNS} runs with a "
           "different random 5% each.", "",
           "| Family | nx_burst, 1 / 10 s | nx_burst, 1 / 60 s | fires before the first resolving name "
           "(implant stops there), 1 / 10 s |",
           "|---|---|---|---|"]
    for fam, _, _, _, _, res5, stop5 in rows:
        md.append(f"| {fam} | {fmt_runs(res5[10])} | {fmt_runs(res5[60])} | {stop5:.1%} |")
    md += ["", f"Last column: {TRIALS} runs per family from random start points in the family's list; the share "
           f"of runs in which {nmin} countable NXDOMAINs came before the first name that resolves "
           f"(for comparison, 0.95^{nmin} = {0.95 ** nmin:.1%})."]
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
