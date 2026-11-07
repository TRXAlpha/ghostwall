#!/usr/bin/env python3
"""Download threat-intelligence domain lists into threat_feed.txt.

    python update_feed.py [--out threat_feed.txt] [--feed URL ...] [--min 1000]
                          [--popular-top 100000] [--cache-top 1000000] [--tranco-id ID]

Default sources: URLhaus (malware download hosts), Phishing Army (phishing) and
HaGeZi's Threat Intelligence Feeds, mini version (malware, C2, phishing, scams). With
DNS_BLOCK_FEED=on or dry-run (the DNS server blocks with this feed) the set grows:
HaGeZi TIF medium on a machine with about 2 GB of RAM or more, CERT Polska, OpenPhish
and, with a free abuse.ch key in THREATFOX_URL, ThreatFox (see feed_sources()). On
2026-11-07 that was 267,422 domains, 3.3 MiB in the resolver (sorted hashes) and a 150 MB
peak in this short-lived process, which also streams the Tranco top 1M to disk (64-bit, agents/dga_eval/results_feeds.md). Multi-million lists
are deliberately not the default: they would cost hundreds of MB on a Raspberry Pi.

False-positive guard: a feed that lists github.com or drive.google.com because someone
hosted malware there would break a household, so an entry is dropped when its exact
name (or the name without "www.") is among the most popular registrable domains (the
Tranco list, downloaded here and cached next to the feed, in rank order) or is one of the shared
platforms and service hosts in NEVER_LIST. Only the bare name is dropped:
evil.github.io is evidence about one host and stays. The resolver matches a listed
name and its subdomains, never its parents. The cache holds more names than this
guard uses (--cache-top, 1M by default): ghost-dns reads the whole of it for the DGA
rules' popular-domain guard, where a bigger list costs no detections
(agents/dga_eval/results_fp_independent.md), while the feed keeps its listed names
below the top 100k.

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
    url: str       # also the source's id in the feed file
    fmt: str = "domains"      # "urls": one full URL per line (OpenPhish); the host is kept
    secret_url: str = ""      # fetched instead of `url` when set: it carries a key, so it is
                              # never printed or written to the feed file

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

# The expanded set (research: agents/dga_eval/results_dns_block.md). Used when the DNS
# server blocks with the feed (DNS_BLOCK_FEED=on or dry-run), see feed_sources().
TIF_MINI = DEFAULT_SOURCES[2]
TIF_MEDIUM = Source("HaGeZi TIF", "malware, C2, phishing",   # GPL-3.0; downloaded, never redistributed
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt")
EXTRA_SOURCES = (
    # CERT Polska warning list: "may be used by any user for any purpose, including commercial",
    # no attribution required (https://cert.pl/en/warning-list/). Active domains only.
    Source("CERT Polska", "phishing, malware", "https://hole.cert.pl/domains/v2/domains.txt"),
    # OpenPhish community feed: free for non-commercial use (a home network), full URLs,
    # about 300 of them, refreshed every 12 hours.
    Source("OpenPhish", "phishing", "https://openphish.com/feed.txt", fmt="urls"),
)
# abuse.ch ThreatFox needs a free Auth-Key since 2025 (its keyless hostfile URLs answer
# 410 Gone). With THREATFOX_URL in ghostwall.env (the hostfile URL the abuse.ch portal
# shows you, key included) it joins the set; the key stays out of logs and the feed file.
THREATFOX_ID = "threatfox:hostfile"
MEDIUM_MIN_RAM_KB = 1_500_000    # a "2 GB" Pi reports about 1.8 million kB; a "1 GB" one 0.9 million


def total_ram_kb(meminfo: str = "/proc/meminfo") -> int:
    try:
        with open(meminfo, encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def feed_sources(env=None, ram_kb: int | None = None) -> tuple[Source, ...]:
    """The sources to download. GHOSTWALL_FEED_SET: "standard" (URLhaus, Phishing Army,
    HaGeZi TIF mini: what versions before 0.4 downloaded), "extended" (TIF medium on a
    machine with about 2 GB or more, else mini; CERT Polska; OpenPhish; ThreatFox if
    THREATFOX_URL is set), or "auto" (the default): extended when the DNS server blocks
    with the feed (DNS_BLOCK_FEED is on or dry-run), else standard. So an upgrade
    changes nothing until you choose blocking. GHOSTWALL_TIF=mini|medium overrides the
    RAM choice."""
    env = os.environ if env is None else env
    mode = (env.get("GHOSTWALL_FEED_SET") or "auto").strip().lower()
    if mode not in ("standard", "extended", "auto"):
        print(f"[feed] GHOSTWALL_FEED_SET={mode!r} is not standard, extended or auto; using auto", file=sys.stderr)
        mode = "auto"
    if mode == "auto":
        mode = "extended" if (env.get("DNS_BLOCK_FEED") or "off").strip().lower() in ("on", "dry-run") else "standard"
    if mode == "standard":
        return DEFAULT_SOURCES
    tif = (env.get("GHOSTWALL_TIF") or "").strip().lower()
    if tif not in ("mini", "medium"):
        tif = "medium" if (total_ram_kb() if ram_kb is None else ram_kb) >= MEDIUM_MIN_RAM_KB else "mini"
    out = list(DEFAULT_SOURCES[:2]) + [TIF_MEDIUM if tif == "medium" else TIF_MINI] + list(EXTRA_SOURCES)
    tf = (env.get("THREATFOX_URL") or "").strip()
    if tf and not tf.startswith("https://"):
        print("[feed] THREATFOX_URL must be an https:// URL; leaving ThreatFox out", file=sys.stderr)
    elif tf:
        out.append(Source("ThreatFox", "malware, C2", THREATFOX_ID, secret_url=tf))
    return tuple(out)

TRANCO_ID_URL = "https://tranco-list.eu/top-1m-id"
TRANCO_LIST_URL = "https://tranco-list.eu/download/{id}/{n}"
DEFAULT_POPULAR_TOP = 100000     # feed entries this popular are dropped
DEFAULT_CACHE_TOP = 1000000      # names cached for ghost-dns's DGA guard (popular_top_n)
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


def parse_url_hosts(text: str) -> set[str]:
    """Hostnames of a list of full URLs (OpenPhish): `http://www.evil.example/login` ->
    `www.evil.example`. Raw IP hosts, ports and userinfo are dealt with; junk is skipped."""
    out = set()
    for raw in io.StringIO(text):
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        try:
            host = urllib.parse.urlsplit(line if "//" in line else "//" + line).hostname or ""
        except ValueError:
            continue
        host = host.rstrip(".")
        if "." in host and not _IPV4.match(host) and _HOST.match(host):
            out.add(host)
    return out


def fetch(url: str, timeout: float = 90.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ghostwall-feed/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"feed larger than {MAX_BYTES // (1024 * 1024)} MB, refusing")
    return data.decode("utf-8", "replace")


def source_for(url: str, known=()) -> Source:
    for s in tuple(known) + DEFAULT_SOURCES + (TIF_MEDIUM,) + EXTRA_SOURCES:
        if s.url == url:
            return s
    return Source(urllib.parse.urlsplit(url).hostname or url, "", url)


# -------------------------------------------------------------- popularity guard
def parse_tranco(text: str, top: int) -> set[str]:
    """'rank,domain' lines (Tranco CSV) or bare domains; the first `top` only."""
    out = set()
    for name in _tranco_names(io.StringIO(text)):
        out.add(name)
        if len(out) >= top:
            break
    return out


def _env_int(name: str, default: int) -> int:
    """An integer setting from ghostwall.env; a typo ("100k") warns and uses the default
    instead of crashing every daily run."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(0, int(raw.replace("_", "")))
    except ValueError:
        print(f"[feed] {name}={raw!r} is not a number; using {default}", file=sys.stderr)
        return default


def _tranco_names(lines):
    """Domains of a Tranco CSV or of the cache, in file (rank) order."""
    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        name = line.split(",", 1)[-1].strip().rstrip(".")
        if _HOST.match(name):
            yield name


def fetch_popular(top: int, cache_top: int, cache: str, list_id: str | None = None) -> tuple[set[str], str]:
    """(top N Tranco domains, list id), and the top max(N, cache_top) written to `cache`
    in rank order, streamed: never a million names in memory at once. Raises if the
    download looks wrong (the cache is then left as it was)."""
    list_id = (list_id or fetch(TRANCO_ID_URL, timeout=30).strip()).upper()
    if not _TRANCO_ID.match(list_id):
        raise ValueError(f"unexpected Tranco list id {list_id[:20]!r}")
    n = max(top, cache_top)
    text = fetch(TRANCO_LIST_URL.format(id=list_id, n=n), timeout=180)
    names: set[str] = set()
    count = 0
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(cache)), prefix=".popular-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"# Tranco list {list_id}, top {n} in rank order, fetched {_today()}. "
                    "Generated by update_feed.py.\n")
            for name in _tranco_names(io.StringIO(text)):
                if count >= n:
                    break
                f.write(name + "\n")
                if count < top:
                    names.add(name)
                count += 1
            f.flush()
            os.fsync(f.fileno())
        del text
        if count < n * 0.9:
            raise ValueError(f"Tranco list {list_id}: only {count} of {n} domains")
        os.chmod(tmp, 0o644)
        os.replace(tmp, cache)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return names, list_id


def load_popular(top: int, cache: str, list_id: str | None = None, cache_top: int = 0) -> set[str] | None:
    """Top N popular domains: downloaded (and cached), else the cached copy, else None."""
    try:
        names, lid = fetch_popular(top, cache_top, cache, list_id)
    except Exception as exc:  # noqa: BLE001
        print(f"[feed] popularity list download failed: {exc}", file=sys.stderr)
        try:
            with open(cache, encoding="utf-8") as f:
                names = set()
                for name in _tranco_names(f):
                    if len(names) >= top:
                        break
                    names.add(name)
        except OSError:
            return None
        print(f"[feed] using the cached popularity list {cache} ({len(names)} domains)", file=sys.stderr)
        return names or None
    print(f"[feed] popularity guard: Tranco list {lid}, top {len(names)} "
          f"(top {max(top, cache_top)} cached for the DGA rules)")
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
    """Write, flush to disk, then rename: a power cut on a Pi's SD card leaves the old
    file or the new one, never half of one, and a failed write (disk full) leaves no
    temporary file behind."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".feed-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)  # mkstemp creates 0600; the feed is public data
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


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
                    default=_env_int("GHOSTWALL_FEED_POPULAR_TOP", DEFAULT_POPULAR_TOP),
                    help="drop entries among the N most popular domains (Tranco); 0 = only NEVER_LIST")
    ap.add_argument("--cache-top", type=int,
                    default=_env_int("GHOSTWALL_POPULAR_TOP", DEFAULT_CACHE_TOP),
                    help="how many popular domains to cache for ghost-dns's DGA guard (0 = only --popular-top)")
    ap.add_argument("--tranco-id", default=os.environ.get("GHOSTWALL_TRANCO_ID") or None,
                    help="pin a Tranco list id instead of the latest")
    args = ap.parse_args(argv)

    chosen = feed_sources()
    urls = args.feed or os.environ.get("GHOSTWALL_FEEDS", "").split() or [s.url for s in chosen]
    for url in urls:
        if not (url.startswith("https://") or source_for(url, chosen).secret_url.startswith("https://")):
            print(f"[feed] refusing {url}: only https:// feeds (a list fetched in clear text could be swapped)",
                  file=sys.stderr)
            return 1

    popular: set[str] = set()
    cache = os.path.join(os.path.dirname(os.path.abspath(args.out)), "popular_domains.txt")
    if args.popular_top > 0 or args.cache_top > 0:
        got = load_popular(args.popular_top, cache, args.tranco_id, args.cache_top)
        if got is None and args.popular_top > 0:
            print("[feed] no popularity list (no download, no cache); keeping existing feed. "
                  "--popular-top 0 skips this guard", file=sys.stderr)
            return 1
        popular = got or set()
    elif os.path.exists(cache):          # both off: don't leave an old list in use
        os.remove(cache)
        print(f"[feed] popularity lists turned off; removed {cache}")

    previous = read_sections(args.out)
    sections: list[tuple[Source, str, set[str]]] = []
    failed = fresh = 0
    dropped_total: set[str] = set()
    for url in urls:
        src = source_for(url, chosen)
        prev = previous.get(url)          # (fetched, count, domains not loaded yet)
        try:
            text = fetch(src.secret_url or url)
            got = parse_url_hosts(text) if src.fmt == "urls" else parse_domains(text)
            del text
            if not got:
                raise ValueError("no domains in it")
            # A sudden shrink looks like a broken download, but only while the old copy
            # is still worth keeping: after MAX_CARRY_DAYS the smaller list is the list.
            if prev and len(got) < SHRINK_RATIO * prev[1] and _age_days(prev[0]) <= MAX_CARRY_DAYS:
                raise ValueError(f"only {len(got)} domains, {prev[1]} last time")
            fetched = _today()
            fresh += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            exc = str(exc).replace(src.secret_url, "<key>") if src.secret_url else exc
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
