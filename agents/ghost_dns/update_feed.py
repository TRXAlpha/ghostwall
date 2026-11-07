#!/usr/bin/env python3
"""Download threat-intelligence domain lists into threat_feed.txt.

    python update_feed.py [--out threat_feed.txt] [--feed URL ...] [--min 1000]
                          [--popular-top 100000] [--tranco-id ID]

Default sources: URLhaus (malware download hosts), Phishing Army (phishing) and
HaGeZi's Threat Intelligence Feeds, mini version (malware, C2, phishing, scams). On
2026-11-07 that was 272,674 domains, 23 MiB in the resolver and a 109 MiB peak in this
short-lived process (64-bit, agents/dga_eval/results_feeds.md). Multi-million lists
are deliberately not the default: they would cost hundreds of MB on a Raspberry Pi.

False-positive guard: a feed that lists github.com or drive.google.com because someone
hosted malware there would break a household, so an entry is dropped when its exact
name (or the name without "www.") is among the most popular registrable domains (the
Tranco list, downloaded here and cached next to the feed) or is one of the shared
platforms and service hosts in NEVER_LIST. Only the bare name is dropped:
evil.github.io is evidence about one host and stays. The resolver matches a listed
name and its subdomains, never its parents.

Each source is kept separately in the output file (a "#@source" line, then its
domains), which lets the resolver say which list named a domain and lets one source
fail without losing the others: a source that fails, or shrinks to less than half its
last size, keeps its previous contents for up to MAX_CARRY_DAYS. The file is written
atomically and is not touched when nothing new was downloaded, the total is below
--min, or the popularity list is unavailable (no download and no cache). Exit code
1 means the file was not written; a source that failed while the others updated is a
warning in the log (exit 0), so one dead URL doesn't mark the daily job failed. The
resolver notices the changed file by itself (no restart).
"""
from __future__ import annotations

import argparse
import datetime
import io
import os
import re
import sys
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BYTES = 60 * 1024 * 1024
MAX_CARRY_DAYS = 14      # a source that keeps failing stops counting after two weeks
SHRINK_RATIO = 0.5       # a source suddenly half its last size is treated as broken
_HOST = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass(frozen=True)
class Source:
    name: str      # shown in alerts: "on URLhaus (malware)"
    kind: str
    url: str

    @property
    def label(self) -> str:
        return f"{self.name} ({self.kind})" if self.kind else self.name


# Keyless, https, domain-level, maintained daily. See agents/dga_eval/results_feeds.md.
DEFAULT_SOURCES = (
    Source("URLhaus", "malware",   # abuse.ch data (CC0) via malware-filter, popular domains removed
           "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt"),
    Source("Phishing Army", "phishing",
           "https://phishing.army/download/phishing_army_blocklist.txt"),
    Source("HaGeZi TIF", "malware, C2, phishing",   # GPL-3.0; downloaded, never redistributed
           "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt"),
)
DEFAULT_FEEDS = [s.url for s in DEFAULT_SOURCES]

TRANCO_ID_URL = "https://tranco-list.eu/top-1m-id"
TRANCO_LIST_URL = "https://tranco-list.eu/download/{id}/{n}"
DEFAULT_POPULAR_TOP = 100000
_TRANCO_ID = re.compile(r"^[A-Z0-9]{3,10}$")

# Never listed as a bare name, whatever a feed says. Tranco ranks registrable domains,
# so it does not know drive.google.com; and shared platforms are where malware sits
# under someone else's name (their subdomains are kept: that is real evidence).
NEVER_LIST = frozenset("""
drive.google.com docs.google.com sites.google.com forms.gle storage.googleapis.com
firebasestorage.googleapis.com googleusercontent.com docs.googleusercontent.com
translate.goog script.google.com accounts.google.com mail.google.com
s3.amazonaws.com cloudfront.net blob.core.windows.net web.core.windows.net
azurewebsites.net azureedge.net sharepoint.com onedrive.live.com 1drv.ms
forms.office.com login.microsoftonline.com
github.com github.io raw.githubusercontent.com gist.githubusercontent.com
objects.githubusercontent.com gitlab.io bitbucket.io
dropbox.com dl.dropboxusercontent.com dropboxusercontent.com
cdn.discordapp.com media.discordapp.net discord.com t.me telegram.org
blogspot.com wordpress.com weebly.com wixsite.com webflow.io square.site
pages.dev workers.dev r2.dev web.app firebaseapp.com appspot.com vercel.app
netlify.app herokuapp.com glitch.me replit.dev repl.co myshopify.com notion.site
duckdns.org ddns.net no-ip.com hopto.org zapto.org
""".split())


def parse_domains(text: str) -> set[str]:
    """Plain 'domain' lines, hosts-file lines ('0.0.0.0 domain') or adblock '||domain^'
    rules; skips comments, exceptions (@@), rules with options or paths, IPs, single
    labels and anything that is not a hostname."""
    out = set()
    for raw in io.StringIO(text):        # one line at a time: no list of every line
        line = raw.split("#", 1)[0].strip().lower()
        if not line or line.startswith(("!", "[")):
            continue
        if line.startswith("||"):
            if not line.endswith("^"):
                continue                      # a path or $options: not a whole-domain rule
            line = line[2:-1]
        parts = line.split()
        host = parts[-1] if len(parts) > 1 and _IPV4.match(parts[0]) else parts[0]
        host = host.rstrip(".")
        if "." not in host or _IPV4.match(host) or not _HOST.match(host):
            continue
        out.add(host)
    return out


def fetch(url: str, timeout: float = 90.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ghostwall-feed/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{url}: feed larger than {MAX_BYTES // (1024 * 1024)} MB, refusing")
    return data.decode("utf-8", "replace")


def source_for(url: str) -> Source:
    for s in DEFAULT_SOURCES:
        if s.url == url:
            return s
    return Source(urllib.parse.urlsplit(url).hostname or url, "", url)


# -------------------------------------------------------------- popularity guard
def parse_tranco(text: str, top: int) -> set[str]:
    """'rank,domain' lines (Tranco CSV) or bare domains; the first `top` only."""
    out = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        name = line.split(",", 1)[-1].strip().rstrip(".")
        if _HOST.match(name):
            out.add(name)
            if len(out) >= top:
                break
    return out


def fetch_popular(top: int, list_id: str | None = None) -> tuple[set[str], str]:
    """(top N Tranco domains, list id). Raises if the download looks wrong."""
    list_id = (list_id or fetch(TRANCO_ID_URL, timeout=30).strip()).upper()
    if not _TRANCO_ID.match(list_id):
        raise ValueError(f"unexpected Tranco list id {list_id[:20]!r}")
    names = parse_tranco(fetch(TRANCO_LIST_URL.format(id=list_id, n=top)), top)
    if len(names) < top * 0.9:
        raise ValueError(f"Tranco list {list_id}: only {len(names)} of {top} domains")
    return names, list_id


def load_popular(top: int, cache: str, list_id: str | None = None) -> set[str] | None:
    """Top N popular domains: downloaded (and cached), else the cached copy, else None."""
    try:
        names, lid = fetch_popular(top, list_id)
    except Exception as exc:  # noqa: BLE001
        print(f"[feed] popularity list download failed: {exc}", file=sys.stderr)
        try:
            with open(cache, encoding="utf-8") as f:
                names = parse_tranco(f.read(), top)
        except OSError:
            return None
        print(f"[feed] using the cached popularity list {cache} ({len(names)} domains)", file=sys.stderr)
        return names or None
    _write_atomic(cache, f"# Tranco list {lid}, top {top}, fetched {_today()}. Generated by update_feed.py.\n"
                  + "\n".join(sorted(names)) + "\n")
    print(f"[feed] popularity guard: Tranco list {lid}, top {len(names)}")
    return names


def is_popular(name: str, popular) -> bool:
    """The exact name (or name without www.) is a popular domain or a NEVER_LIST host."""
    bare = name[4:] if name.startswith("www.") else name
    return name in NEVER_LIST or bare in NEVER_LIST or name in popular or bare in popular


def guard(domains: set[str], popular) -> tuple[set[str], set[str]]:
    """(kept, dropped). Only exact names are dropped; subdomains of popular sites stay."""
    dropped = {d for d in domains if is_popular(d, popular)}
    return (domains - dropped if dropped else domains), dropped


# -------------------------------------------------------------- the feed file
def read_sections(path: str, only: str | None = None) -> dict[str, tuple[str, int, set[str]]]:
    """{url: (fetched date, count, domains)} from a feed file this script wrote earlier.
    Domains are collected for the `only` url (the one to carry over), the others just
    counted: holding the whole old file too would double the updater's memory. An old
    single-list file (no #@source lines) yields nothing."""
    out: dict[str, tuple[str, int, set[str]]] = {}
    url, fetched, n, doms = None, "", 0, set()
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#@source\t"):
                    if url:
                        out[url] = (fetched, n, doms)
                    parts = line.split("\t")
                    url, fetched, n, doms = (parts[1], parts[2], 0, set()) if len(parts) >= 3 else (None, "", 0, set())
                elif url and line and not line.startswith("#"):
                    n += 1
                    if url == only:
                        doms.add(line.strip())
    except OSError:
        pass
    if url:
        out[url] = (fetched, n, doms)
    return out


def _today() -> str:
    return datetime.date.today().isoformat()


def _age_days(fetched: str) -> int:
    try:
        return (datetime.date.today() - datetime.date.fromisoformat(fetched)).days
    except ValueError:
        return 10 ** 6


def _write_atomic(path: str, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".feed-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o644)  # mkstemp creates 0600; the feed is public data
    os.replace(tmp, path)


def render(sections: list[tuple[Source, str, set[str]]], total: int | None = None) -> str:
    """The feed file: one '#@source<TAB>url<TAB>date<TAB>name<TAB>kind' line per
    source, then its domains. Older readers skip the '#' lines and see one list."""
    if total is None:
        total = len(set().union(*(d for _, _, d in sections)))
    lines = [f"# Ghostwall threat feed, {total} domains from {len(sections)} sources. "
             "Generated by update_feed.py; do not edit."]
    for src, fetched, doms in sections:
        lines.append("\t".join(("#@source", src.url, fetched, src.name, src.kind)))
        lines.extend(sorted(doms))
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="update the Ghostwall threat feed")
    ap.add_argument("--out", default=os.path.join(HERE, "threat_feed.txt"))
    ap.add_argument("--feed", action="append", help="feed URL (repeatable)")
    ap.add_argument("--min", type=int, default=1000, help="refuse to write fewer domains than this")
    ap.add_argument("--popular-top", type=int,
                    default=int(os.environ.get("GHOSTWALL_FEED_POPULAR_TOP") or DEFAULT_POPULAR_TOP),
                    help="drop entries among the N most popular domains (Tranco); 0 = only NEVER_LIST")
    ap.add_argument("--tranco-id", default=os.environ.get("GHOSTWALL_TRANCO_ID") or None,
                    help="pin a Tranco list id instead of the latest")
    args = ap.parse_args(argv)

    urls = args.feed or os.environ.get("GHOSTWALL_FEEDS", "").split() or DEFAULT_FEEDS
    for url in urls:
        if not url.startswith("https://"):
            print(f"[feed] refusing {url}: only https:// feeds (a list fetched in clear text could be swapped)",
                  file=sys.stderr)
            return 1

    popular: set[str] = set()
    if args.popular_top > 0:
        cache = os.path.join(os.path.dirname(os.path.abspath(args.out)), "popular_domains.txt")
        got = load_popular(args.popular_top, cache, args.tranco_id)
        if got is None:
            print("[feed] no popularity list (no download, no cache); keeping existing feed. "
                  "--popular-top 0 skips this guard", file=sys.stderr)
            return 1
        popular = got

    previous = read_sections(args.out)
    sections: list[tuple[Source, str, set[str]]] = []
    failed = fresh = 0
    dropped_total: set[str] = set()
    for url in urls:
        src = source_for(url)
        prev = previous.get(url)          # (fetched, count, domains not loaded yet)
        try:
            got = parse_domains(fetch(url))
            if not got:
                raise ValueError("no domains in it")
            if prev and len(got) < SHRINK_RATIO * prev[1]:
                raise ValueError(f"only {len(got)} domains, {prev[1]} last time")
            fetched = _today()
            fresh += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            if prev and prev[1] and _age_days(prev[0]) <= MAX_CARRY_DAYS:
                print(f"[feed] FAILED {url}: {exc}; keeping its {prev[1]} domains from {prev[0]}",
                      file=sys.stderr)
                fetched, _, got = read_sections(args.out, only=url)[url]
            else:
                print(f"[feed] FAILED {url}: {exc}; nothing recent to keep, leaving it out", file=sys.stderr)
                continue
        kept, dropped = guard(got, popular)
        dropped_total |= dropped
        print(f"[feed] {src.label}: {len(got)} domains, {len(dropped)} dropped as popular, {len(kept)} kept")
        sections.append((src, fetched, kept))

    total = len(set().union(*(d for _, _, d in sections))) if sections else 0
    if not fresh:
        print("[feed] no source downloaded; keeping existing feed", file=sys.stderr)
        return 1
    if total < args.min:
        print(f"[feed] only {total} domains (< {args.min}); keeping existing feed", file=sys.stderr)
        return 1
    _write_atomic(args.out, render(sections, total))
    print(f"[feed] wrote {total} domains from {len(sections)} sources to {args.out}; "
          f"{len(dropped_total)} popular names dropped")
    if failed:
        print(f"[feed] WARNING: {failed} source(s) failed (see above); the others were updated",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
