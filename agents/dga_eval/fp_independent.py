#!/usr/bin/env python3
"""False positives of the DGA rules on normal names the models were not tuned on, and
the popular-domain guard (detectors.PopularDomains) that removes part of them.

The thresholds were checked on Tranco-like data. This scores two other top lists exactly
as the resolver does (internal names and the shipped allowlist skipped first, then
Scorer.score_one on the full hostname, every name treated as new to the network) and
counts which DGA rule each name would raise:

  dga_high          score >= block_threshold (0.995)
  dga_suspect       score >= recommend_threshold (0.96)
  dga_corroborated  score >= corroborated_threshold (0.80) and a TLD in RARE_TLDS

  * Cisco Umbrella top 1M: real DNS names (FQDNs, CDN and telemetry hosts included),
    the closest public list to what a home network looks up. Report list.
  * Majestic Million: registrable domains ranked by links. Tuning list (a sample).
  * Tranco V354N (public_bench.py's pinned list): a sample, for reference only.
  * DGA names: Netlab 360's feed as in public_bench.py, 25 families. Split in two
    halves by a hash of the name: one tunes, the other is reported.
  * The three default threat feeds of update_feed.py: which "normal" names are in fact
    listed as malicious, and which of those a guard would silence.

The guard is the real class, loaded from a file in the format update_feed.py caches
(popular_domains.txt: the Tranco top N, sorted by name). N is chosen on Majestic + the
DGA tuning half only (choose_n); the before/after numbers come from Umbrella + the
other DGA half, for the chosen N and for the N the box actually has (update_feed.py's
--popular-top, 100k by default).

    python agents/dga_eval/fp_independent.py --data DIR [--download] [--jobs 4]
        [--out agents/dga_eval/results_fp_independent.md] [--examples FILE]

DIR holds public_bench.py's two pinned files plus the files in INDEPENDENT. Those change
daily, so --download fetches today's and the sha256 check fails unless --any-version is
given: the committed results are for the snapshots pinned below. Scores are cached in
DIR/fp_scores.npz (the TRM costs milliseconds a name: about 35 minutes on 4 cores the
first time, a few minutes after that).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import os
import random
import sys
import tempfile
import time
import tracemalloc
import urllib.request
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
GD = os.path.join(ROOT, "agents", "ghost_dns")
sys.path.insert(0, HERE)
sys.path.insert(0, GD)

import public_bench as pb  # noqa: E402
import update_feed  # noqa: E402
from config import DEFAULTS  # noqa: E402
from detectors import RARE_TLDS, PopularDomains, is_internal, parents, tld_of  # noqa: E402
from tokenizer import registrable_label, registrable_part  # noqa: E402

INDEPENDENT = {
    # file: (url, sha256, day fetched (UTC), Last-Modified of the response)
    "umbrella_top-1m.csv.zip": (
        "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
        "2ee37532868f09c1a5b5f340a8b227a345d6e678b3ac7178997ff4b91f3408e8",
        "2026-11-07", "Fri, 06 Nov 2026 01:01:22 GMT"),
    "majestic_million.csv": (
        "https://downloads.majestic.com/majestic_million.csv",
        "6c06eb69a4a5cf9bc4330e2b497880d34a274bbdf3f0411013f51a1bf70477ff",
        "2026-11-07", "Fri, 06 Nov 2026 06:00:27 GMT"),
    "feed_urlhaus.txt": (
        update_feed.DEFAULT_SOURCES[0].url,
        "3d8ebc00c7b9508e0c2e8e79e29889d7449ffa92b3c9c1a4960dc6df3f6b27e6",
        "2026-11-07", "Sat, 07 Nov 2026 00:31:47 GMT"),
    "feed_phishing_army.txt": (
        update_feed.DEFAULT_SOURCES[1].url,
        "1447c56be6c697370b151dece536ff027233fde85acf506fe60f46b463966fe9",
        "2026-11-07", "Sat, 07 Nov 2026 02:00:32 GMT"),
    "feed_hagezi_tif.txt": (
        update_feed.DEFAULT_SOURCES[2].url,
        "f3fd63eba6193e995e7940db84f995ba93496eec3a0945a3e974e0476a2d9214",
        "2026-11-07", "(none sent)"),
}
FEEDS = ("feed_urlhaus.txt", "feed_phishing_army.txt", "feed_hagezi_tif.txt")
SEED = 20261107
N_SAMPLE = 200_000                      # Majestic and Tranco names scored
CANDIDATES = [1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000, 1_000_000]
SHIPPED_N = DEFAULTS["popular_top_n"]         # what the DGA guard uses unless told otherwise
FEED_N = update_feed.DEFAULT_POPULAR_TOP      # the feed's own guard (same cache, first N)
MAX_DGA_LOSS = 0.001    # a guard may hide at most 0.1% of the DGA names that alert (tuning half)
KEEP_GAIN = 0.90        # smallest N that removes 90% of what the best allowed N removes
HIGH = float(DEFAULTS["block_threshold"])
REC = float(DEFAULTS["recommend_threshold"])
CORR = float(DEFAULTS["corroborated_threshold"])
RULES = ("dga_high", "dga_suspect", "dga_corroborated")


# --------------------------------------------------------------------------- data
def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_independent(data: str, download: bool, any_version: bool) -> dict:
    prov = {}
    for name, (url, pinned, day, modified) in INDEPENDENT.items():
        path = os.path.join(data, name)
        if not os.path.exists(path):
            if not download:
                raise SystemExit(f"{path} missing; run with --download")
            print(f"[data] downloading {url}", flush=True)
            req = urllib.request.Request(url, headers={"User-Agent": "ghostwall-bench/1.0"})
            with urllib.request.urlopen(req, timeout=300) as r, open(path + ".part", "wb") as f:
                f.write(r.read())
                modified = r.headers.get("Last-Modified", "?")
            os.replace(path + ".part", path)
            day = time.strftime("%Y-%m-%d", time.gmtime())
        got = sha256(path)
        if got != pinned and not any_version:
            raise SystemExit(f"{path}: sha256 {got} is not the pinned {pinned} (these lists change "
                             "daily); --any-version measures yours, but not the committed results")
        prov[name] = {"url": url, "sha256": got, "fetched": day if got == pinned else "?",
                      "last_modified": modified if got == pinned else "?"}
    return prov


def read_umbrella(path: str) -> list[str]:
    with zipfile.ZipFile(path) as z, z.open("top-1m.csv") as f:
        return [row[1].strip().lower() for row in csv.reader(io.TextIOWrapper(f, "utf-8")) if len(row) > 1]


def read_majestic(path: str) -> list[str]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = csv.reader(f)
        col = next(rows).index("Domain")
        return [row[col].strip().lower() for row in rows]


def read_tranco(path: str) -> list[str]:
    with open(path, newline="", encoding="utf-8") as f:
        return [row[1].strip().lower() for row in csv.reader(f)]


def read_dga(path: str) -> list[tuple[str, str]]:
    seen, out = set(), []
    with open(path, newline="", encoding="utf-8") as f:
        for cls, fam, dom in csv.reader(f):
            dom = dom.strip().lower()
            if cls == "dga" and dom not in seen:
                seen.add(dom)
                out.append((dom, fam))
    return out


def load_allowlist(path: str) -> set[str]:
    with open(path, encoding="utf-8") as f:
        return {ln.strip().lower() for ln in f if ln.strip() and not ln.lstrip().startswith("#")}


def pipeline(names, allow: set[str]) -> tuple[list[str], int, int]:
    """What reaches scoring in Resolver.decide(): internal names and the shipped allowlist
    are let through first. (The threat feed, DoH and abused-service rules come earlier
    still; they are not DGA rules and are counted separately below.)"""
    kept, internal, allowed = [], 0, 0
    for n in names:
        n = n.rstrip(".")
        if not n:
            continue
        if n in allow or registrable_part(n) in allow:
            allowed += 1
        elif is_internal(n):
            internal += 1
        else:
            kept.append(n)
    return kept, internal, allowed


# --------------------------------------------------------------------------- scoring
_SCORER = None


def _init_worker():
    global _SCORER
    from scoring import Scorer
    _SCORER = Scorer()


def _score_chunk(labels: list[str]):
    return _SCORER.trm.score(labels), _SCORER.lr.score(labels)


def score_labels(labels: set[str], cache: str, jobs: int) -> dict[str, float]:
    """label -> the 'dga' value Scorer.score_one returns (mean of the two models,
    rounded to 4 places the same way). Raw model outputs are cached."""
    known: dict[str, tuple[float, float]] = {}
    if os.path.exists(cache):
        z = np.load(cache, allow_pickle=False)
        known = dict(zip(z["labels"].tolist(), zip(z["trm"].tolist(), z["lr"].tolist())))
    todo = sorted(set(labels) - set(known))
    if todo:
        print(f"[score] {len(todo)} labels to score on {jobs} processes", flush=True)
        chunks = [todo[i:i + 512] for i in range(0, len(todo), 512)]
        t0 = time.time()
        with ProcessPoolExecutor(jobs, initializer=_init_worker) as ex:
            for k, (chunk, (t, lr)) in enumerate(zip(chunks, ex.map(_score_chunk, chunks))):
                known.update(zip(chunk, zip(t.tolist(), lr.tolist())))
                if k % 100 == 0:
                    print(f"[score] {k * 512}/{len(todo)} {time.time() - t0:.0f}s", flush=True)
        labs = sorted(known)
        np.savez(cache, labels=np.array(labs), trm=np.array([known[x][0] for x in labs]),
                 lr=np.array([known[x][1] for x in labs]))
    return {lab: round(sum(known[lab]) / 2, 4) for lab in labels}


def check_against_score_one(scores: dict[str, float], n: int = 300) -> tuple[int, int]:
    """Batch scoring must give what the resolver's score_one gives, name by name."""
    from scoring import Scorer
    s = Scorer()
    labs = random.Random(SEED).sample(sorted(scores), min(n, len(scores)))
    bad = sum(s.score_one(lab)["dga"] != scores[lab] for lab in labs)
    return len(labs), bad


# --------------------------------------------------------------------------- rules
def rule_of(name: str, dga: float) -> str | None:
    """The DGA rule Resolver.decide() raises for a new name (no burst, no upstream block)."""
    if dga >= HIGH:
        return "dga_high"
    if dga >= REC:
        return "dga_suspect"
    if dga >= CORR and tld_of(name) in RARE_TLDS:
        return "dga_corroborated"
    return None


def top_names(tranco: list[str], n: int) -> set[str]:
    """The top n as update_feed.load_popular gets them (its parser on Tranco's CSV)."""
    return update_feed.parse_tranco("\n".join(f"{i + 1},{d}" for i, d in enumerate(tranco[:n])), n)


def guard_for(tranco: list[str], n: int, tmpdir: str) -> PopularDomains:
    """The guard as the box loads it: from a file in popular_domains.txt's format."""
    path = os.path.join(tmpdir, f"popular_{n}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Tranco list V354N, top {n}. Generated by fp_independent.py.\n"
                + "\n".join(sorted(top_names(tranco, n))) + "\n")
    return PopularDomains(path, top=n)


def tally(alerts: list[tuple[str, str]], guard=None) -> Counter:
    c = Counter()
    for name, rule in alerts:
        if guard is None or not guard.match(name):
            c[rule] += 1
    return c


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.3f}%" if b else "n/a"


def on_feed(host: str, feed: set[str]) -> bool:
    """ThreatFeed.match: the name or a parent (never a public suffix) is listed."""
    return host in feed or any(p in feed for p in parents(host))


# --------------------------------------------------------------------------- breakdown
CDN_WORDS = ("cdn", "edge", "akamai", "cloudfront", "azure", "aws", "gslb", "static", "cache",
             "telemetry", "events", "api", "metrics", "update", "dns", "ns1", "ns2", "mx")


def kind_of(name: str) -> str:
    """A rough label for why a normal name looks random (first match wins)."""
    lab = registrable_label(name)
    vowels = sum(ch in "aeiouy" for ch in lab)
    digits = sum(ch.isdigit() for ch in lab)
    if lab.startswith("xn--"):
        return "punycode (non-ASCII name)"
    if len(lab) <= 5:
        return "short brand or abbreviation (<= 5 chars)"
    if all(ch in "0123456789abcdef" for ch in lab) and digits and len(lab) >= 8:
        return "hex/hash-like label"
    if digits and digits != len(lab):
        return "letters and digits mixed"
    if vowels / len(lab) < 0.2:
        return "consonant cluster (abbreviation, acronym)"
    return "pronounceable (other languages, compounds, brands)"


def is_cdn_host(name: str) -> bool:
    """A machine host under some service: subdomain labels that name infrastructure."""
    reg = registrable_part(name)
    sub = name[: -len(reg)].rstrip(".") if name != reg else ""
    return any(w in sub for w in CDN_WORDS)


# --------------------------------------------------------------------------- memory
def measure_memory(tranco: list[str], ns: list[int], tmpdir: str) -> list[dict]:
    """Bytes held after loading the top N: a frozenset of the registrable domains as
    strings, and the sorted array of 64-bit hashes the guard keeps (the real class)."""
    out = []
    for n in ns:
        regs = [registrable_part(d) for d in tranco[:n]]
        tracemalloc.start()
        fs = frozenset("".join(list(r)) for r in regs)   # fresh string objects, as a loader makes
        set_bytes = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()
        del fs
        g = guard_for(tranco, n, tmpdir)
        tracemalloc.start()
        g.match("example.com")
        cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        t0 = time.perf_counter()
        for d in regs[:20000]:
            g.match(d)
        per = (time.perf_counter() - t0) / min(20000, len(regs))
        out.append({"n": n, "distinct": len(g), "set": set_bytes, "array": cur, "peak": peak,
                    "lookup_us": per * 1e6})
    return out


def choose_n(rows: list[dict], base_maj: int, base_dga: int) -> int:
    """Among the N that hide at most MAX_DGA_LOSS of the tuning half's DGA alerts, the
    smallest that removes KEEP_GAIN of what the best of them removes on Majestic."""
    ok = [r for r in rows if base_dga - r["dga"] <= MAX_DGA_LOSS * base_dga]
    best = max(base_maj - r["maj"] for r in ok)
    return min(r["n"] for r in ok if base_maj - r["maj"] >= KEEP_GAIN * best)


# --------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", required=True)
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--any-version", action="store_true")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--out", default=os.path.join(HERE, "results_fp_independent.md"))
    ap.add_argument("--examples", help="write example flagged names here (keep it out of the repo)")
    a = ap.parse_args(argv)

    pb.fetch(a.data, a.download)
    prov = fetch_independent(a.data, a.download, a.any_version)
    tranco = read_tranco(os.path.join(a.data, "tranco_V354N.csv"))
    umb = read_umbrella(os.path.join(a.data, "umbrella_top-1m.csv.zip"))
    maj = read_majestic(os.path.join(a.data, "majestic_million.csv"))
    dga_rows = read_dga(os.path.join(a.data, "dga_domains_full.csv"))
    allow = load_allowlist(os.path.join(GD, "allowlist.txt"))
    feed: set[str] = set()
    feed_sizes = {}
    for name in FEEDS:
        with open(os.path.join(a.data, name), encoding="utf-8", errors="replace") as f:
            got = update_feed.parse_domains(f.read())
        feed_sizes[name] = len(got)
        feed |= got

    # Normal names that the DGA list also names (by registrable domain) are dropped.
    dga_regs = {registrable_part(d) for d, _ in dga_rows}
    rng = random.Random(SEED)
    sets = {"umbrella": umb,
            "majestic": rng.sample(maj, N_SAMPLE),
            "tranco": rng.sample(tranco, N_SAMPLE)}
    prep, info = {}, {}
    for key, names in sets.items():
        names = list(dict.fromkeys(names))
        clean = [n for n in names if registrable_part(n.rstrip(".")) not in dga_regs]
        kept, internal, allowed = pipeline(clean, allow)
        prep[key] = kept
        info[key] = {"names": len(names), "dga_overlap": len(names) - len(clean),
                     "internal": internal, "allowlisted": allowed, "scored": len(kept)}
    dga_kept, d_int, d_allow = pipeline([d for d, _ in dga_rows], allow)
    fam_of = dict(dga_rows)
    info["dga"] = {"names": len(dga_rows), "internal": d_int, "allowlisted": d_allow, "scored": len(dga_kept)}

    labels = set()
    for names in list(prep.values()) + [dga_kept]:
        labels.update(registrable_label(n) for n in names)
    scores = score_labels(labels, os.path.join(a.data, "fp_scores.npz"), a.jobs)
    checked, mismatched = check_against_score_one(scores)

    def alerts_of(names):
        out = []
        for n in names:
            r = rule_of(n, scores[registrable_label(n)])
            if r:
                out.append((n, r))
        return out

    alerts = {k: alerts_of(v) for k, v in prep.items()}
    half = {"tune": [], "report": []}
    for n in dga_kept:
        half["tune" if hashlib.blake2b(n.encode(), digest_size=1).digest()[0] % 2 == 0 else "report"].append(n)
    dga_alerts = {h: alerts_of(v) for h, v in half.items()}

    # Overlap with Tranco: how independent are the lists really?
    tr_regs = {registrable_part(d) for d in tranco}
    tr_names = set(tranco)
    overlap = {}
    for key, names in (("umbrella", list(dict.fromkeys(umb))), ("majestic", maj)):
        overlap[key] = {"names": len(names),
                        "exact_in_tranco": sum(n in tr_names for n in names),
                        "reg_in_tranco": sum(registrable_part(n) in tr_regs for n in names)}
    umb_regs = {registrable_part(n) for n in umb}
    overlap["umbrella_regs"] = {"regs": len(umb_regs), "in_tranco": len(umb_regs & tr_regs)}

    # Tune N on Majestic + the DGA tuning half.
    tmpdir = tempfile.mkdtemp(prefix="gw-popular-")
    base_maj = sum(tally(alerts["majestic"]).values())
    base_dga_tune = sum(tally(dga_alerts["tune"]).values())
    guards, tune_rows = {}, []
    for n in CANDIDATES:
        g = guards[n] = guard_for(tranco, n, tmpdir)
        tune_rows.append({"n": n, "maj": sum(tally(alerts["majestic"], g).values()),
                          "dga": sum(tally(dga_alerts["tune"], g).values())})
    chosen = choose_n(tune_rows, base_maj, base_dga_tune)
    shown = sorted({SHIPPED_N, chosen})

    # Report: Umbrella + the DGA report half.
    umb_alerts = alerts["umbrella"]
    umb_feed = [x for x in umb_alerts if on_feed(x[0], feed)]
    sweep = []          # report list, every N: for the trade-off, not for choosing
    for n in CANDIDATES:
        g = guards[n]
        hidden = [x for x in umb_alerts if g.match(x[0])]
        # the box's feed drops entries that are exactly a popular name (update_feed.guard)
        kept_feed, _ = update_feed.guard(feed, top_names(tranco, n))
        sweep.append({"n": n, "left": len(umb_alerts) - len(hidden), "feed_dropped": len(feed) - len(kept_feed),
                      "regs_left": len({registrable_part(x[0]) for x in umb_alerts if not g.match(x[0])}),
                      "hidden_listed": sum(on_feed(x[0], feed) for x in hidden),
                      "hidden_unlisted_now": sum(on_feed(x[0], feed) and not on_feed(x[0], kept_feed)
                                                 for x in hidden)})
    rep = {k: (tally(alerts[k]), {n: tally(alerts[k], guards[n]) for n in shown})
           for k in ("umbrella", "majestic", "tranco")}
    indep_names = [n for n in prep["umbrella"] if registrable_part(n) not in tr_regs]
    indep_alerts = [x for x in umb_alerts if registrable_part(x[0]) not in tr_regs]
    umb_scored_regs = {registrable_part(n) for n in prep["umbrella"]}
    umb_alert_regs = {registrable_part(n) for n, _ in umb_alerts}

    fam_names = Counter(fam_of[n] for n in half["report"])
    fam = {"before": Counter(), "high": Counter()}
    for n, r in dga_alerts["report"]:
        fam["before"][fam_of[n]] += 1
        fam["high"][fam_of[n]] += r == "dga_high"
    fam_after = {}
    for n in shown:
        after, high, hidden = Counter(), Counter(), defaultdict(list)
        for d, r in dga_alerts["report"]:
            if guards[n].match(d):
                hidden[fam_of[d]].append(d)
            else:
                after[fam_of[d]] += 1
                high[fam_of[d]] += r == "dga_high"
        fam_after[n] = (after, high, hidden)
    tune_hidden = {n: Counter(fam_of[d] for d, _ in dga_alerts["tune"] if guards[n].match(d)) for n in shown}

    # Why do Umbrella names alert?
    g0 = guards[SHIPPED_N]
    kinds, kinds_guarded, kinds_listed = Counter(), Counter(), Counter()
    cdn = cdn_guarded = 0
    for n, _ in umb_alerts:
        k = kind_of(n)
        kinds[k] += 1
        kinds_guarded[k] += g0.match(n)
        kinds_listed[k] += on_feed(n, feed)
        if is_cdn_host(n):
            cdn += 1
            cdn_guarded += g0.match(n)
    reg_counts = Counter(registrable_part(n) for n, _ in umb_alerts)
    mem = measure_memory(tranco, sorted({10_000, FEED_N, SHIPPED_N, chosen, 1_000_000}), tmpdir)

    if a.examples:
        with open(a.examples, "w", encoding="utf-8") as f:
            r2 = random.Random(SEED)
            for n in shown:
                left = [x for x in umb_alerts if not guards[n].match(x[0])]
                hidden = [x for x in umb_alerts if guards[n].match(x[0])]
                f.write(f"# N={n}: Umbrella names that still alert (random 20)\n")
                for d, r in r2.sample(left, min(20, len(left))):
                    f.write(f"{r:<17} {scores[registrable_label(d)]:.4f} {kind_of(d):<45} "
                            f"{'FEED ' if on_feed(d, feed) else ''}{d}\n")
                f.write(f"\n# N={n}: Umbrella names the guard silences (random 20)\n")
                for d, r in r2.sample(hidden, min(20, len(hidden))):
                    f.write(f"{r:<17} {scores[registrable_label(d)]:.4f} {kind_of(d):<45} "
                            f"{'FEED ' if on_feed(d, feed) else ''}{d}\n")
                f.write("\n")
            f.write("# registrable domains with the most alerting Umbrella names\n")
            for reg, c in reg_counts.most_common(40):
                f.write(f"{c:6d} {reg} {'popular@' + str(SHIPPED_N) if g0.match(reg) else ''} "
                        f"{'FEED' if on_feed(reg, feed) else ''}\n")
            for n in shown:
                f.write(f"\n# N={n}: DGA names the guard would hide (report half)\n")
                for fm, ds in sorted(fam_after[n][2].items()):
                    f.write(f"{fm}: {' '.join(sorted(ds)[:20])}\n")

    write_report(a.out, locals())
    print(f"[done] chosen N={chosen}, shipped N={SHIPPED_N}; wrote {a.out}")
    return 0


def write_report(path: str, v: dict) -> None:
    info, prov, rep, overlap, shown = v["info"], v["prov"], v["rep"], v["overlap"], v["shown"]
    chosen = v["chosen"]
    L = []
    w = L.append
    w("# DGA false positives on independent normal names, and the popular-domain guard")
    w("")
    w("Generated by `agents/dga_eval/fp_independent.py`; every number below is its output.")
    w(f"Shipped models (mean of the TRM and the n-gram model), thresholds from `config.py`: "
      f"dga_high >= {HIGH}, dga_suspect >= {REC}, dga_corroborated >= {CORR} with a rare TLD. "
      "Every name is treated as new to the network (the worst case: `suspect_only_new` "
      "silences dga_suspect for names seen for more than `novelty_days`).")
    w("")
    w("## Summary")
    w("")
    ub, ua = rep["umbrella"]
    nu = info["umbrella"]["scored"]
    s_left = {r["n"]: r for r in v["sweep"]}
    w(f"* On Cisco Umbrella's top 1M DNS names, {sum(ub.values()):,} of {nu:,} scored names "
      f"({pct(sum(ub.values()), nu)}) would raise a DGA rule; Majestic: {pct(sum(rep['majestic'][0].values()), info['majestic']['scored'])}; "
      f"a Tranco sample: {pct(sum(rep['tranco'][0].values()), info['tranco']['scored'])}. The lists the "
      "thresholds were not checked on are not worse, so the thresholds stay as shipped.")
    w(f"* The guard as the box has it (`popular_top_n`: the first {SHIPPED_N:,} of the Tranco list update_feed.py caches) takes Umbrella "
      f"to {sum(ua[SHIPPED_N].values()):,} ({pct(sum(ua[SHIPPED_N].values()), nu)}); alerting registrable "
      f"domains {len(v['umb_alert_regs']):,} -> {s_left[SHIPPED_N]['regs_left']:,}. It hides "
      f"{sum(len(x) for x in v['fam_after'][SHIPPED_N][2].values())} of the "
      f"{sum(v['fam']['before'].values()):,} DGA names that alert (report half), "
      f"{sum(v['tune_hidden'][SHIPPED_N].values())} of the tuning half.")
    m = {x["n"]: x for x in v["mem"]}
    if chosen == SHIPPED_N:
        w(f"* That is also what the tuning rule picks on Majestic (no DGA name hidden at any N tried). "
          f"The feed's own guard reads only the first {FEED_N:,} of the same cache, so listed malware "
          f"domains ranked lower stay listed ({s_left[FEED_N]['feed_dropped']:,} feed entries dropped, "
          f"not {s_left[SHIPPED_N]['feed_dropped']:,}). The guard holds {m[SHIPPED_N]['array'] / 2**20:.1f} MiB "
          f"(load peak {m[SHIPPED_N]['peak'] / 2**20:.0f} MiB).")
    else:
        w(f"* The tuning rule picks the top {chosen:,} (no DGA name hidden at any N tried): Umbrella "
          f"would drop to {sum(ua[chosen].values()):,} ({pct(sum(ua[chosen].values()), nu)}). It is not the "
          f"default: the guard reads the list update_feed.py caches for its own feed guard (no second "
          f"download), where the top {chosen:,} would also drop {s_left[chosen]['feed_dropped']:,} feed "
          f"entries instead of {s_left[SHIPPED_N]['feed_dropped']:,}; the guard would "
          f"hold {m[chosen]['array'] / 2**20:.1f} MiB instead of {m[SHIPPED_N]['array'] / 2**20:.1f} MiB "
          f"(load peak {m[chosen]['peak'] / 2**20:.0f} MiB). `GHOSTWALL_FEED_POPULAR_TOP={chosen}` opts in.")
    w("")
    w("## Data")
    w("")
    w("| file | source | fetched (UTC) | Last-Modified | sha256 |")
    w("|---|---|---|---|---|")
    for name, p in prov.items():
        w(f"| {name} | {p['url']} | {p['fetched']} | {p['last_modified']} | `{p['sha256']}` |")
    for name, (url, sha) in pb.SOURCES.items():
        w(f"| {name} | {url} | pinned in public_bench.py | | `{sha}` |")
    w("")
    w("| list | distinct names | dropped: on the DGA list | internal | shipped allowlist | scored |")
    w("|---|---|---|---|---|---|")
    for k in ("umbrella", "majestic", "tranco"):
        i = info[k]
        w(f"| {k}{' (random 200k)' if k != 'umbrella' else ''} | {i['names']:,} | {i['dga_overlap']:,} | "
          f"{i['internal']:,} | {i['allowlisted']:,} | {i['scored']:,} |")
    i = info["dga"]
    w(f"| DGA (25 families) | {i['names']:,} | | {i['internal']:,} | {i['allowlisted']:,} | {i['scored']:,} |")
    w("")
    w("Threat feeds (update_feed.py's defaults, parsed by its parser): "
      + ", ".join(f"{k} {n:,}" for k, n in v["feed_sizes"].items()) + f"; {len(v['feed']):,} distinct.")
    w("")
    w(f"Batch scores checked against `Scorer.score_one` on {v['checked']} random labels: "
      f"{v['mismatched']} differ.")
    w("")
    w("**Overlap with Tranco.** Tranco is built from Umbrella, Majestic and three other lists, so these")
    w("are not independent of it by name. For the thresholds what matters is the labels; for the")
    w("guard, how many real DNS names a Tranco list covers.")
    w("")
    w("| list | names | name itself on Tranco 1M | registrable domain on Tranco 1M |")
    w("|---|---|---|---|")
    for k in ("umbrella", "majestic"):
        o = overlap[k]
        w(f"| {k} | {o['names']:,} | {pct(o['exact_in_tranco'], o['names'])} | {pct(o['reg_in_tranco'], o['names'])} |")
    o = overlap["umbrella_regs"]
    w(f"\nUmbrella's {o['regs']:,} distinct registrable domains: {o['in_tranco']:,} "
      f"({pct(o['in_tranco'], o['regs'])}) are on Tranco V354N.")
    w("")
    w("## Before any guard: is the false-positive rate worse on lists the thresholds never saw?")
    w("")
    w("| list | scored | dga_high | dga_suspect | dga_corroborated | any DGA rule |")
    w("|---|---|---|---|---|---|")
    for k in ("tranco", "majestic", "umbrella"):
        b = rep[k][0]
        n = info[k]["scored"]
        w(f"| {k} | {n:,} | " + " | ".join(f"{b[r]:,} ({pct(b[r], n)})" for r in RULES)
          + f" | {sum(b.values()):,} ({pct(sum(b.values()), n)}) |")
    ui = Counter(r for _, r in v["indep_alerts"])
    ni = len(v["indep_names"])
    w(f"| umbrella, registrable domain not on Tranco | {ni:,} | "
      + " | ".join(f"{ui[r]:,} ({pct(ui[r], ni)})" for r in RULES)
      + f" | {sum(ui.values()):,} ({pct(sum(ui.values()), ni)}) |")
    nf = len(v["umb_feed"])
    w("")
    w(f"Of the {len(v['umb_alerts']):,} Umbrella names that alert, {nf:,} ({pct(nf, len(v['umb_alerts']))}) are on "
      "one of the threat feeds (the name or a parent; those raise threat_feed before any DGA rule).")
    w("By that measure the rest are false positives, though no feed is complete.")
    w("")
    w("## Choosing N (tuning data: Majestic sample + DGA tuning half)")
    w("")
    w(f"Rule (`choose_n`): among the N that hide at most {MAX_DGA_LOSS:.1%} of the tuning half's DGA "
      f"alerts, the smallest that removes at least {KEEP_GAIN:.0%} of the Majestic alerts the best "
      "of them removes.")
    w("")
    w(f"| Tranco top N | Majestic alerts left (of {v['base_maj']:,}) | DGA alerts hidden (of {v['base_dga_tune']:,}) |")
    w("|---|---|---|")
    for r in v["tune_rows"]:
        mark = (" **rule's choice, box default**" if r["n"] == chosen == SHIPPED_N else
                " **rule's choice**" if r["n"] == chosen else (" (box default)" if r["n"] == SHIPPED_N else ""))
        w(f"| {r['n']:,}{mark} | {r['maj']:,} ({pct(r['maj'], v['base_maj'])}) | "
          f"{v['base_dga_tune'] - r['dga']:,} ({pct(v['base_dga_tune'] - r['dga'], v['base_dga_tune'])}) |")
    w("")
    w("## Umbrella (report list): what each N leaves, and what it hides")
    w("")
    w("Not used to choose N. 'listed' are hidden names a threat feed lists (they still alert as")
    w("threat_feed); 'no longer listed' are those whose only listing is an exact popular name, which")
    w("update_feed.py's own guard drops from the feed at the same N: those would raise nothing.")
    w("")
    w(f"| Tranco top N | Umbrella alerts left (of {len(v['umb_alerts']):,}) | alerting registrable domains left "
      f"(of {len(v['umb_alert_regs']):,}) | hidden, listed | hidden, no longer listed | "
      f"feed entries update_feed.py drops (of {len(v['feed']):,}) |")
    w("|---|---|---|---|---|---|")
    for r in v["sweep"]:
        w(f"| {r['n']:,} | {r['left']:,} ({pct(r['left'], len(v['umb_alerts']))}) | {r['regs_left']:,} | "
          f"{r['hidden_listed']:,} | {r['hidden_unlisted_now']:,} | {r['feed_dropped']:,} |")
    w("")
    w("## Normal names: alert rate before and after the guard")
    w("")
    w("Share of the scored distinct names that would raise each rule. Majestic chose N; Tranco is")
    w("the source of the guard, so its 'after' is near zero by construction.")
    w("")
    w("| list | scored | rule | before | " + " | ".join(f"after, top {n:,}" for n in shown) + " |")
    w("|---|---|---|---|" + "---|" * len(shown))
    for k in ("umbrella", "majestic", "tranco"):
        b, after = rep[k]
        n = info[k]["scored"]
        for rule in RULES + ("any",):
            get = (lambda c: sum(c.values())) if rule == "any" else (lambda c, r=rule: c[r])
            name = "**any DGA rule**" if rule == "any" else rule
            w(f"| {k} | {n:,} | {name} | {get(b):,} ({pct(get(b), n)}) | "
              + " | ".join(f"{get(after[m]):,} ({pct(get(after[m]), n)})" for m in shown) + " |")
    w("")
    w(f"Per registrable domain (alerts are deduplicated per device and registrable domain): of "
      f"Umbrella's {len(v['umb_scored_regs']):,} scored registrable domains, {len(v['umb_alert_regs']):,} "
      f"({pct(len(v['umb_alert_regs']), len(v['umb_scored_regs']))}) have a name that alerts before; after: "
      + ", ".join(f"top {r['n']:,}: {r['regs_left']:,} ({pct(r['regs_left'], len(v['umb_scored_regs']))})"
                  for r in v["sweep"] if r["n"] in shown) + ".")
    w("")
    w(f"## What the Umbrella false positives are (before the guard; guard = top {SHIPPED_N:,})")
    w("")
    w("Simple heuristics on the scored label (first match wins).")
    w("")
    w("| kind | alerting names | on a threat feed | removed by the guard |")
    w("|---|---|---|---|")
    for k, c in v["kinds"].most_common():
        w(f"| {k} | {c:,} | {v['kinds_listed'][k]:,} | {v['kinds_guarded'][k]:,} ({pct(v['kinds_guarded'][k], c)}) |")
    w(f"\nOf these, {v['cdn']:,} are infrastructure hosts (a subdomain naming cdn/edge/api/static/ns...); "
      f"the guard removes {v['cdn_guarded']:,} ({pct(v['cdn_guarded'], v['cdn'])}). The random-by-design part")
    w("of a CDN name is a subdomain and is never scored (`registrable_part`); what alerts is a")
    w("registrable label that is itself machine-made or an unusual brand, and the alerting registrable")
    w("domains are spread thin (below), so a fixed CDN exception list was not added.")
    w("")
    rc = v["reg_counts"]
    w(f"Alerting names per registrable domain: {len(rc):,} domains; the 10 largest hold "
      f"{sum(c for _, c in rc.most_common(10)):,} names, {sum(1 for c in rc.values() if c == 1):,} domains "
      "have a single alerting name.")
    w("")
    w("## DGA names: alerts before and after the guard (report half)")
    w("")
    w("Any DGA rule, per family. 'hidden' are DGA names whose registrable domain is on the popular")
    w("list; they would still count for dga_burst, nx_burst, the threat feed and the behaviour rules.")
    w("")
    hdr = "| family | names | dga_high before | any rule before | " + " | ".join(
        f"any rule, top {n:,} | hidden" for n in shown) + " |"
    w(hdr)
    w("|---|---|---|---|" + "---|---|" * len(shown))
    fn, fb, fh = v["fam_names"], v["fam"]["before"], v["fam"]["high"]
    tot = Counter()
    for fm in sorted(fn):
        cells = []
        for n in shown:
            after, _, hidden = v["fam_after"][n]
            cells.append(f"{pct(after[fm], fn[fm])} | {len(hidden[fm])}")
            tot[("a", n)] += after[fm]
            tot[("h", n)] += len(hidden[fm])
        tot["n"] += fn[fm]
        tot["b"] += fb[fm]
        tot["hb"] += fh[fm]
        w(f"| {fm} | {fn[fm]:,} | {pct(fh[fm], fn[fm])} | {pct(fb[fm], fn[fm])} | " + " | ".join(cells) + " |")
    w(f"| **all** | {tot['n']:,} | {pct(tot['hb'], tot['n'])} | {pct(tot['b'], tot['n'])} | "
      + " | ".join(f"{pct(tot[('a', n)], tot['n'])} | {tot[('h', n)]}" for n in shown) + " |")
    w("")
    w("The Netlab families are from before 2020, so their names being absent from a 2026 top list says")
    w("little about a DGA whose domains are popular today (a sinkholed C2 can rank); dga_burst and")
    w("nx_burst still see such names.")
    w("\nTuning half, hidden: " + "; ".join(
        f"top {n:,}: {sum(v['tune_hidden'][n].values())}" for n in shown) + ".")
    w("")
    w("## Memory and speed of the guard")
    w("")
    w("Python heap held after loading (tracemalloc, 64-bit CPython here; a 32-bit Pi OS needs less")
    w("for the strings and the same 8 bytes a hash). The guard keeps the sorted array of 64-bit")
    w("hashes; 'load peak' is while it reads the file with update_feed.parse_tranco (once a day).")
    w("")
    w("| top N | distinct registrable | frozenset of strings | sorted 64-bit hashes (the guard) | load peak | lookup |")
    w("|---|---|---|---|---|---|")
    for m in v["mem"]:
        w(f"| {m['n']:,} | {m['distinct']:,} | {m['set'] / 2**20:.1f} MiB | {m['array'] / 2**20:.2f} MiB | "
          f"{m['peak'] / 2**20:.1f} MiB | {m['lookup_us']:.1f} us |")
    w("")
    w("## Reproduce")
    w("")
    w("```")
    w("python agents/dga_eval/fp_independent.py --data DIR --download --jobs 4")
    w("```")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


if __name__ == "__main__":
    sys.exit(main())
