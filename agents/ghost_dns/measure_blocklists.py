#!/usr/bin/env python3
"""How much would each blocklist block on YOUR network, and how risky is each one?

    python measure_blocklists.py --querylog /opt/AdGuardHome/data/querylog.json   # or /var/log/pihole/pihole.log
        [--feed /var/lib/ghostwall/threat_feed.txt] [--tranco /var/lib/ghostwall/popular_domains.txt]
        [--download DIR] [--list NAME=FILE ...] [--examples 10]

Reads the query log read-only and reports, for every list:
  * how many distinct names your devices asked for would be blocked, and how many queries;
  * how many of the Tranco top 10k / 100k sites it would block (a false-positive proxy: a list that
    blocks a top-10k site breaks something most people use).
Lists: each source inside threat_feed.txt (the threat feed after update_feed.py's popularity guard),
plus --download DIR, which fetches HaGeZi's TIF medium, Multi Pro, Multi Ultimate and the DoH/VPN/Tor/
Proxy bypass list (adblock syntax) into DIR, plus any --list NAME=FILE (adblock, hosts or plain names).
AdGuard blocks a listed name and its subdomains; Pi-hole (log format pihole) only the exact name, and
this script follows whichever the log says (--exact / --subdomains to force one).

Nothing is changed or sent anywhere. On the Pi:
    sudo -u ghostwall /opt/ghostwall/.venv/bin/python /opt/ghostwall/agents/ghost_dns/measure_blocklists.py \\
        --querylog /opt/AdGuardHome/data/querylog.json --feed /var/lib/ghostwall/threat_feed.txt \\
        --tranco /var/lib/ghostwall/popular_domains.txt --download /tmp/lists
(the Tranco file is the one update_feed.py caches; without it the false-positive columns say n/a).
"""
from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import shadow  # noqa: E402
import update_feed  # noqa: E402

_RAW = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock"
DOWNLOADS = {
    "HaGeZi TIF medium": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
    "HaGeZi Multi PRO": f"{_RAW}/pro.txt",
    "HaGeZi Multi ULTIMATE": f"{_RAW}/ultimate.txt",
    "HaGeZi DoH/VPN/TOR/Proxy bypass": f"{_RAW}/doh-vpn-proxy-bypass.txt",
    "CERT Polska": "https://hole.cert.pl/domains/v2/domains.txt",
}


def hit(name: str, listed: set[str], subdomains: bool = True) -> str | None:
    """The listed name that blocks `name`, or None."""
    if name in listed:
        return name
    if subdomains:
        while "." in name:
            name = name.split(".", 1)[1]
            if "." in name and name in listed:
                return name
    return None


def feed_sections(path: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    label = "threat feed"
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("#@source\t"):
                    p = line.rstrip("\n").split("\t") + ["", "", "", ""]
                    label = f"{p[3]} ({p[4]})" if p[3] and p[4] else (p[3] or "threat feed")
                    out.setdefault(label, set())
                elif line.strip() and not line.startswith("#"):
                    out.setdefault(label, set()).add(line.strip().lower())
    except OSError:
        pass
    if len(out) > 1:
        out["ALL feed sources together"] = set().union(*out.values())
    return out


def read_names(path: str) -> set[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return update_feed.parse_domains(f.read())


def read_log(path: str, fmt: str = "auto") -> tuple[dict[str, int], str]:
    """({name: queries}, format) from an AdGuard or Pi-hole log. Only A/AAAA/HTTPS lookups count
    as queries."""
    fmt = shadow.detect_format(path) if fmt in (None, "", "auto") else fmt
    parse = shadow.ENTRY_PARSERS[fmt]
    counts: dict[str, int] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse(line)
            if e and e[2] in ("A", "AAAA", "HTTPS"):
                counts[e[1]] = counts.get(e[1], 0) + 1
    return counts, fmt


def popular(path: str | None, top: int) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for name in update_feed._tranco_names(f):
            out.append(name)
            if len(out) >= top:
                break
    return out


def measure(lists: dict[str, set[str]], counts: dict[str, int], subdomains: bool, top10k: list[str],
            top100k: list[str], examples: int = 5) -> list[dict]:
    total_q = sum(counts.values())
    rows = []
    for name, listed in lists.items():
        names = {n: hit(n, listed, subdomains) for n in counts}
        names = {n: h for n, h in names.items() if h}
        q = sum(counts[n] for n in names)
        row = {"list": name, "size": len(listed), "names": len(names), "queries": q,
               "names_pct": 100.0 * len(names) / max(1, len(counts)), "queries_pct": 100.0 * q / max(1, total_q),
               "top_names": sorted(names, key=lambda n: -counts[n])[:examples]}
        for label, top in (("fp10k", top10k), ("fp100k", top100k)):
            blocked = [d for d in top if hit(d, listed, subdomains)] if top else None
            row[label] = None if blocked is None else len(blocked)
            row[label + "_examples"] = [] if not blocked else blocked[:examples]
        rows.append(row)
    return rows


def report(rows: list[dict], n_names: int, n_queries: int, fmt: str, subdomains: bool, have_tranco: bool) -> str:
    out = [f"query log: {n_queries} queries, {n_names} distinct names ({fmt}; "
           f"{'a listed name and its subdomains' if subdomains else 'exact names only'} are blocked)", ""]
    out.append(f"{'list':<36}{'size':>9}{'names':>9}{'% names':>9}{'queries':>10}{'% q':>7}{'top10k':>8}{'top100k':>9}")
    for r in rows:
        fp = lambda v: "n/a" if v is None or not have_tranco else str(v)  # noqa: E731
        out.append(f"{r['list'][:35]:<36}{r['size']:>9}{r['names']:>9}{r['names_pct']:>8.2f}%{r['queries']:>10}"
                   f"{r['queries_pct']:>6.2f}%{fp(r['fp10k']):>8}{fp(r['fp100k']):>9}")
    out.append("")
    for r in rows:
        if r["top_names"]:
            out.append(f"{r['list']}: most-asked names it would block: " + ", ".join(r["top_names"]))
        if r["fp10k_examples"]:
            out.append(f"{r['list']}: top-10k sites it would block: " + ", ".join(r["fp10k_examples"]))
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--querylog", required=True)
    ap.add_argument("--format", choices=["auto", "adguard", "pihole"], default="auto")
    ap.add_argument("--feed", default="/var/lib/ghostwall/threat_feed.txt")
    ap.add_argument("--tranco", default=None, help="popular_domains.txt (default: next to --feed)")
    ap.add_argument("--download", metavar="DIR", help="fetch HaGeZi and CERT Polska lists into DIR first")
    ap.add_argument("--list", action="append", default=[], metavar="NAME=FILE")
    ap.add_argument("--examples", type=int, default=5)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--exact", action="store_true", help="a listed name blocks only itself (Pi-hole)")
    g.add_argument("--subdomains", action="store_true", help="a listed name blocks its subdomains too (AdGuard)")
    a = ap.parse_args(argv)

    counts, fmt = read_log(a.querylog, a.format)
    if not counts:
        print(f"no queries in {a.querylog}", file=sys.stderr)
        return 1
    subdomains = False if a.exact else (True if a.subdomains else fmt == "adguard")
    lists = feed_sections(a.feed)
    if a.download:
        os.makedirs(a.download, exist_ok=True)
        for name, url in DOWNLOADS.items():
            dest = os.path.join(a.download, name.replace("/", "-").replace(" ", "_") + ".txt")
            try:
                with open(dest, "w", encoding="utf-8") as f:
                    f.write(update_feed.fetch(url, timeout=180))
                lists[name] = read_names(dest)
            except Exception as exc:  # noqa: BLE001
                print(f"could not download {name}: {exc}", file=sys.stderr)
    for spec in a.list:
        name, _, path = spec.partition("=")
        lists[name] = read_names(path)
    if not lists:
        print("no lists: give --feed, --download or --list", file=sys.stderr)
        return 1
    tranco = a.tranco or os.path.join(os.path.dirname(os.path.abspath(a.feed)), "popular_domains.txt")
    rows = measure(lists, counts, subdomains, popular(tranco, 10000), popular(tranco, 100000), a.examples)
    print(report(rows, len(counts), sum(counts.values()), fmt, subdomains, os.path.exists(tranco)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
