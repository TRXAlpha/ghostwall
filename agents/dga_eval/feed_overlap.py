"""Measure the default threat-feed sources against the Tranco popularity list and
write results_feeds.md: entries per source, how many are popular names, how many the
update-time guard drops, overlaps, and the resolver's memory for the loaded feed.

    python agents/dga_eval/feed_overlap.py [--tranco top-1m.csv] [--tranco-id ID]
                                           [--date YYYY-MM-DD] [--out results_feeds.md]

Downloads the sources (and, without --tranco, the Tranco top 1M) over https with the
same code as update_feed.py, so the numbers are for that day only: the feeds change
daily. It measures popularity, not detection: nothing here says how much malware a
list catches.
"""
import argparse
import datetime
import gc
import os
import subprocess
import sys
import tempfile
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "agents", "ghost_dns"))

import update_feed as U  # noqa: E402
from detectors import ThreatFeed  # noqa: E402

TOPS = (1000, 10000, 100000, 1000000)
# Terms as published by each project (checked 2026-11-07). Ghostwall downloads the lists
# on the user's device and never redistributes them.
TERMS = {
    "URLhaus": "abuse.ch URLhaus data CC0; malware-filter list CC0 / MIT",
    "Phishing Army": "free to use, no added restriction (phishing.army/license); upstream terms apply",
    "HaGeZi TIF": "GPL-3.0 (redistribution must carry the license)",
}


def load_ranks(path):
    ranks = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            r, _, name = line.strip().lower().partition(",")
            if r.isdigit() and name:
                ranks.setdefault(name, int(r))
    return ranks


def popular_rank(name, ranks):
    """Rank of the exact name, or of the name without www. (what the guard checks)."""
    bare = name[4:] if name.startswith("www.") else name
    return min(ranks.get(name, 10 ** 9), ranks.get(bare, 10 ** 9))


def under_popular(name, ranks, top):
    """A strict parent of the name (not the name itself) has Tranco rank <= top."""
    labels = name.split(".")
    return any(ranks.get(".".join(labels[i:]), 10 ** 9) <= top for i in range(1, len(labels) - 1))


def updater_peak_rss(tmp):
    """(exit code, peak RSS in MiB) of a real update_feed.main() run (network) in a
    child process. Reads VmHWM: ru_maxrss would carry the parent's peak over exec."""
    code = ("import runpy, sys\n"
            "sys.argv = ['update_feed.py', '--out', sys.argv[1]]\n"
            "try:\n    runpy.run_path(%r, run_name='__main__')\n"
            "except SystemExit as e:\n    rc = e.code\n"
            "hwm = [l for l in open('/proc/self/status') if l.startswith('VmHWM')][0].split()[1]\n"
            "print(rc, int(hwm) // 1024)\n")
    script = os.path.join(ROOT, "agents", "ghost_dns", "update_feed.py")
    res = subprocess.run([sys.executable, "-c", code % script, os.path.join(tmp, "threat_feed.txt")],
                         capture_output=True, text=True, check=True)
    rc, mb = res.stdout.split()[-2:]
    return int(rc), int(mb)


def mib(n):
    return f"{n / 2 ** 20:.1f}"


def measure_feed(path):
    """(tracemalloc current, peak) bytes for loading the file into a ThreatFeed."""
    gc.collect()
    tracemalloc.start()
    feed = ThreatFeed(path)
    n = len(feed)
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del feed
    return n, cur, peak


def measure_frozenset(domains):
    """The same names as a bare frozenset (what ThreatFeed held before sources)."""
    text = "\n".join(sorted(domains))
    gc.collect()
    tracemalloc.start()
    fs = frozenset(text.split("\n"))
    cur, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del fs
    return cur


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tranco", help="local Tranco CSV (rank,domain); default: download the top 1M")
    ap.add_argument("--tranco-id", help="Tranco list id to download (default: latest)")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    ap.add_argument("--out", default=os.path.join(HERE, "results_feeds.md"))
    a = ap.parse_args(argv)

    if a.tranco:
        ranks, tranco_name = load_ranks(a.tranco), os.path.basename(a.tranco)
    else:
        lid = (a.tranco_id or U.fetch(U.TRANCO_ID_URL, timeout=30).strip()).upper()
        text = U.fetch(U.TRANCO_LIST_URL.format(id=lid, n=1000000), timeout=300)
        ranks = {}
        for line in text.splitlines():
            r, _, name = line.strip().lower().partition(",")
            if r.isdigit() and name:
                ranks.setdefault(name, int(r))
        tranco_name = f"Tranco list {lid}"
    guard_set = {d for d, r in ranks.items() if r <= U.DEFAULT_POPULAR_TOP}
    print(f"tranco: {tranco_name}, {len(ranks)} names; guard top {U.DEFAULT_POPULAR_TOP}")

    fetched_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows, sections, raw = [], [], {}
    for src in U.DEFAULT_SOURCES:
        text = U.fetch(src.url)
        doms = U.parse_domains(text)
        raw[src.name] = doms
        hits = [sum(1 for d in doms if popular_rank(d, ranks) <= t) for t in TOPS]
        kept, dropped = U.guard(doms, guard_set)
        never = sum(1 for d in dropped if popular_rank(d, ranks) > U.DEFAULT_POPULAR_TOP)
        under = sum(1 for d in kept if under_popular(d, ranks, 10000))
        rows.append((src, len(text), len(doms), hits, len(dropped), never, len(kept), under))
        sections.append((src, a.date, kept))
        print(src.label, len(doms), hits, len(dropped))

    union_raw = set().union(*raw.values())
    union_kept = set().union(*(k for _, _, k in sections))
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "threat_feed.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(U.render(sections))
        file_bytes = os.path.getsize(path)
        n_loaded, cur, peak = measure_feed(path)
    with tempfile.TemporaryDirectory() as tmp:
        rc, rss = updater_peak_rss(tmp)
    fs_bytes = measure_frozenset(union_kept)

    names = [s.name for s in U.DEFAULT_SOURCES]
    out = [
        "# Threat feed sources vs. popular domains",
        "",
        f"Generated by `agents/dga_eval/feed_overlap.py` on {a.date} (sources fetched {fetched_at}; "
        "the lists change daily, so these counts are for that day only). Popularity: "
        f"{tranco_name}. A name counts as popular in the top N when the exact entry, or the entry "
        "without `www.`, has Tranco rank <= N; subdomains of popular sites (`x.github.io`) do not count. "
        "This measures false-positive risk, not detection: no detection rates here.",
        "",
        "## Per source",
        "",
        "| Source | URL | Download | Entries | in top 1k | 10k | 100k | 1M | Guard drops | of which NEVER_LIST only | Kept | Kept, under a top-10k site |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for src, nbytes, n, hits, ndrop, never, nkept, under in rows:
        out.append(f"| {src.label} | {src.url} | {nbytes / 2 ** 20:.1f} MB | {n} | "
                   + " | ".join(str(h) for h in hits) + f" | {ndrop} | {never} | {nkept} | {under} |")
    out += [
        "",
        f"Guard = exact name (or without `www.`) in the Tranco top {U.DEFAULT_POPULAR_TOP} or in "
        "`update_feed.NEVER_LIST` (shared platforms and service hosts such as drive.google.com, "
        "which a list of registrable domains cannot contain). The last column counts kept "
        "hosts on popular sites (tenant hosts such as `x.pages.dev`, buckets, hijacked subdomains): "
        "exact-host evidence that only blocks that host.",
        "",
        "Terms: " + "; ".join(f"{k}: {v}" for k, v in TERMS.items()) + ".",
        "",
        "## Union and overlap",
        "",
        f"- all sources before the guard: {len(union_raw)} distinct names; after: {len(union_kept)} "
        f"({len(union_raw) - len(union_kept)} dropped)",
        "",
        "| Entries also in -> | " + " | ".join(names) + " |",
        "|---|" + "---|" * len(names),
    ]
    for x in names:
        out.append(f"| {x} | " + " | ".join(str(len(raw[x] & raw[y])) for y in names) + " |")
    out += [
        "",
        "## Memory",
        "",
        f"- feed file as written by update_feed.py: {file_bytes / 2 ** 20:.1f} MB, {n_loaded} names",
        f"- `ThreatFeed` loaded (dict name -> source bitmask), tracemalloc: {mib(cur)} MiB held, "
        f"{mib(peak)} MiB peak while loading",
        f"- the same names as a plain frozenset (the old representation): {mib(fs_bytes)} MiB",
        f"- a full `update_feed.py` run (download, parse, guard, write; exit code {rc}): "
        f"{rss:.0f} MiB peak RSS in its own process, which exits afterwards",
        f"- measured on Python {sys.version.split()[0]}, {sys.maxsize.bit_length() + 1}-bit",
        "",
    ]
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
