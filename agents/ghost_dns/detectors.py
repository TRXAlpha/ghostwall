"""Evidence- and behaviour-based DNS detectors.

The DGA model alone tops out at roughly 60% detection for 1% false positives
(measured on 2024/2025 labelled data), so it is the weakest signal here, not the
only one. These detectors add signals that do not depend on a label "looking
random":

  threat_feed  known-bad domains (malware, C2 and phishing feeds)
  doh_bypass   a device resolving a DNS-over-HTTPS provider (dodging your filter)
  dns_tunnel   many distinct, long, high-entropy subdomains under one apex
  dns_beacon   the same name queried at a near-constant interval (C2 call-home)
  dga_burst    one device hitting many *different* random-looking domains fast
  nx_burst     one device failing to resolve many *different* unregistered domains
  new_domain   a registered-days-ago domain (NRD list) that is also new to this network

Every stateful detector takes `now` as an argument (seconds) so tests can drive
time, and bounds its memory. Stdlib only.
"""
from __future__ import annotations

import datetime
import hashlib
import math
import os
import re
import statistics
import threading
import time
from array import array
from bisect import bisect_left
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field

import nrdfile
from tokenizer import PUBLIC_SUFFIXES, registrable_part

# DNS-over-HTTPS/TLS resolver hostnames. A LAN client resolving one of these is
# trying to skip the local resolver. "use-application-dns.net" is Firefox's
# canary query (not a bypass) and is deliberately absent.
DOH_HOSTS = frozenset("""
dns.google dns.google.com dns64.dns.google
cloudflare-dns.com mozilla.cloudflare-dns.com one.one.one.one 1dot1dot1dot1.cloudflare-dns.com
dns.quad9.net dns9.quad9.net dns10.quad9.net dns11.quad9.net
doh.opendns.com dns.opendns.com
dns.adguard.com dns.adguard-dns.com dns-family.adguard.com unfiltered.adguard-dns.com
dns.nextdns.io doh.cleanbrowsing.org dns.sb doh.dns.sb
dns.mullvad.net doh.mullvad.net adblock.doh.mullvad.net
doh.libredns.gr dnsforge.de doh.pub dns.alidns.com
doh.appliedprivacy.net dns.digitale-gesellschaft.ch dns.switch.ch
""".split())

# TLDs disproportionately used by throwaway/abusive domains.
RARE_TLDS = frozenset("""
top xyz click link work zip mov cam icu sbs cyou buzz rest bid loan men gq tk ml cf ga
monster quest cfd surf fit lol date racing stream download review accountant
""".split())

_DOMAIN_LINE = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")


@dataclass
class Hit:
    rule: str
    severity: str
    reasons: list[str]
    scores: dict = field(default_factory=dict)
    block: bool = False      # evidence strong enough to block when enforcing


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


INTERNAL_SUFFIXES = (".local", ".lan", ".home.arpa", ".internal", ".localdomain", ".ts.net",
                     ".in-addr.arpa", ".ip6.arpa", ".arpa")


def is_internal(host: str) -> bool:
    """Names that are not internet domains: single labels (`homepi`), mDNS/LAN/tailnet
    suffixes, reverse lookups, and `_service._proto` records. Scoring them as if they
    were DGA candidates only produces noise."""
    if "." not in host or host.endswith(INTERNAL_SUFFIXES):
        return True
    return any(label.startswith("_") for label in host.split("."))


# Names an IoT device may always look up (iot_new_domain). Clock sync only: a device with
# no time fails every TLS handshake, many firmwares rotate between these providers, and a
# time query carries no data. Matched as the name or a subdomain of it, so time.google.com
# is allowed while google.com as a whole is not. Connectivity checks are left out: a
# device that makes them does so every time, so it learns them.
IOT_BUILTIN_ALLOW = ("pool.ntp.org", "time.nist.gov", "time.google.com", "time.cloudflare.com",
                     "time.windows.com", "time.apple.com", "time.android.com")


def iot_builtin_allowed(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in IOT_BUILTIN_ALLOW)


def tld_of(host: str) -> str:
    return host.rsplit(".", 1)[-1] if "." in host else ""


def parents(host: str):
    """host, then each parent domain, never a bare TLD or public suffix."""
    labels = host.split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in PUBLIC_SUFFIXES or "." not in cand:
            continue
        yield cand


# --------------------------------------------------------------------------
def _hash64(name: str) -> int:
    return int.from_bytes(hashlib.blake2b(name.encode("utf-8"), digest_size=8).digest(), "big")


def _sorted_index(hashes: array, masks: array | None = None) -> tuple[array, array | None]:
    """Sort 64-bit name hashes (and the source bitmask that goes with each) and merge
    duplicates, in place. With numpy (always installed with the models) the work is done
    on the arrays' own buffers, so loading needs about twice the result, not the ten
    times a million Python ints would."""
    try:
        import numpy as np
    except ImportError:          # pragma: no cover - numpy ships with the models
        np = None
    if np is None or not len(hashes):
        if masks is None:
            return array("Q", sorted(set(hashes))), None
        merged: dict[int, int] = {}
        for k, v in zip(hashes, masks):
            merged[k] = merged.get(k, 0) | v
        keys = sorted(merged)
        return array("Q", keys), array("I", (merged[k] for k in keys))
    h = np.frombuffer(hashes, dtype=np.uint64)          # views: no copies
    if masks is None:
        h.sort()
        keep = np.empty(len(h), dtype=bool)
        keep[0] = True
        np.not_equal(h[1:], h[:-1], out=keep[1:])
        k = int(keep.sum())
        if k < len(h):
            h[:k] = h[keep]
        del h, keep
        del hashes[k:]
        return hashes, None
    m = np.frombuffer(masks, dtype=np.uint32)
    order = np.argsort(h, kind="stable")
    h[:] = h[order]
    m[:] = m[order]
    del order
    keep = np.empty(len(h), dtype=bool)
    keep[0] = True
    np.not_equal(h[1:], h[:-1], out=keep[1:])
    first = np.flatnonzero(keep)
    del keep
    k = len(first)
    if k < len(h):
        merged_masks = np.bitwise_or.reduceat(m, first)
        h[:k] = h[first]
        m[:k] = merged_masks
        del merged_masks
    del h, m, first
    del hashes[k:], masks[k:]
    return hashes, masks


def _find(index: array, h: int) -> int:
    """Position of hash h in a sorted index, or -1."""
    i = bisect_left(index, h)
    return i if i < len(index) and index[i] == h else -1


class _FileIndex:
    """A list loaded from a file and reloaded when the file changes (checked at most every
    `recheck` seconds), so a daily updater needs no restart. With background=True
    (inline mode, where a lookup sits on the answer path) every load runs in its own
    thread and lookups use the previous list meanwhile: a million names take seconds on
    a Pi, and no DNS answer should wait for that. Otherwise (shadow mode, replays) the
    load runs in the caller, so no logged query is checked against a half-loaded list."""

    def __init__(self, path: str | None, recheck_seconds: float = 300.0, background: bool = False):
        self.path = path
        self.recheck = recheck_seconds
        self.background = background
        self._mtime = 0.0
        self._checked = -1e18
        self._loading = False
        self._idle = threading.Event()
        self._idle.set()
        self._lock = threading.Lock()

    def info(self) -> tuple[int, float]:
        """(number of domains, file mtime or 0) for the status page: what is loaded now.
        Never loads or reloads itself: in shadow mode that ran in the request (about a
        minute for the top 1M on a Pi after each daily feed update) and `ghostwall
        status` timed out. The next scored query picks up a new file."""
        return self._size(), self._mtime

    def _size(self) -> int:
        raise NotImplementedError

    def wait_loaded(self, timeout: float | None = None) -> bool:
        """Block until no load is running (tests, and anything that must see the list)."""
        return self._idle.wait(timeout)

    def _enabled(self) -> bool:
        return bool(self.path)

    def _maybe_reload(self, now: float) -> None:
        if not self._enabled() or now - self._checked < self.recheck:
            return
        with self._lock:
            if now - self._checked < self.recheck or self._loading:
                return
            self._checked = now
            try:
                m = os.path.getmtime(self.path)
            except OSError:
                return               # keep what was loaded; a missing file at start means none
            if m == self._mtime:
                return
            self._loading = True
            self._idle.clear()
            if self.background:
                threading.Thread(target=self._load_and_swap, args=(m,), daemon=True,
                                 name=f"load-{os.path.basename(self.path)}").start()
                return
        self._load_and_swap(m)

    def _load_and_swap(self, mtime: float) -> None:
        try:
            if self._load():         # builds the new list, then swaps it in as one assignment
                self._mtime = mtime
        except Exception as exc:     # noqa: BLE001 - a bad file must never stop DNS
            print(f"[ghost-dns] could not load {self.path}: {exc}; keeping the previous list", flush=True)
        finally:
            self._loading = False
            self._idle.set()

    def _load(self) -> bool:
        raise NotImplementedError


class ThreatFeed(_FileIndex):
    """Known-bad domains loaded from a text file (one per line).

    update_feed.py writes each source under a '#@source' line; each name keeps a
    bitmask of the sources that list it, so the alert can say "on URLhaus (malware)".
    Names are held as sorted 64-bit hashes (8 bytes a name plus 4 for the sources: 3.3
    MiB for 267k names instead of 23 MiB as Python strings), so even while a new file
    loads beside the old one the resolver stays small on a Pi. A lookup hashes the
    name and each parent: the listed name in the alert is always the real string
    queried. A false match needs a 64-bit collision: about 1 in 10^14 per lookup."""

    MAX_SOURCES = 32               # bits in a mask; more sources still match, unnamed

    def __init__(self, path: str | None, recheck_seconds: float = 300.0, background: bool = False):
        super().__init__(path, recheck_seconds, background)
        self._feed: tuple[array, array, tuple[str, ...]] = (array("Q"), array("I"), ())   # swapped as one

    def __len__(self) -> int:
        self._maybe_reload(time.monotonic())   # report the real size, not a not-yet-loaded 0
        return self._size()

    def _size(self) -> int:
        return len(self._feed[0])

    def _load(self) -> bool:
        hashes, masks = array("Q"), array("I")
        labels: list[str] = []
        bit = 0                      # names before any '#@source' line: no source
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("#@source\t"):
                        parts = line.rstrip("\n").split("\t")
                        name, kind = (parts + ["", "", "", ""])[3:5]
                        label = f"{name} ({kind})" if name and kind else (name or "the threat feed")
                        if label not in labels:
                            labels.append(label)
                        i = labels.index(label)
                        bit = 1 << i if i < self.MAX_SOURCES else 0
                        continue
                    line = line.strip().lower()
                    if line and not line.startswith(("#", "!")) and _DOMAIN_LINE.match(line) and "." in line:
                        hashes.append(_hash64(line))
                        masks.append(bit)
        except OSError:
            return False             # keep what was loaded
        idx, msk = _sorted_index(hashes, masks)
        self._feed = (idx, msk, tuple(labels))
        return True

    def match(self, host: str, now: float = 0.0) -> tuple[str, bool] | None:
        """(listed_domain, exact) if host or a parent is listed, else None. Only
        parents: a listed evil.github.io never makes github.io itself a hit."""
        self._maybe_reload(now)
        idx = self._feed[0]
        if not idx:
            return None
        if _find(idx, _hash64(host)) >= 0:
            return host, True
        for cand in parents(host):
            if _find(idx, _hash64(cand)) >= 0:
                return cand, False
        return None

    def sources(self, listed: str) -> list[str]:
        """Which lists name `listed`, e.g. ["URLhaus (malware)"]; [] if unknown."""
        if not self._feed[0]:
            self._maybe_reload(time.monotonic())
        idx, msk, labels = self._feed
        i = _find(idx, _hash64(listed)) if idx else -1
        mask = msk[i] if i >= 0 else 0
        return [lab for j, lab in enumerate(labels) if mask >> j & 1]


class PopularDomains(_FileIndex):
    """Registrable domains of the most popular sites: the Tranco top list that
    update_feed.py downloads and caches, in rank order, as popular_domains.txt next to
    the threat feed. Their labels are brands and abbreviations, not algorithm output,
    so a random-looking score alone is no reason to alert on them. `top` takes the
    first N entries (the feed's own guard uses a smaller N from the same file).

    Kept as sorted 64-bit hashes of registrable_part(entry): 8 bytes a domain (8 MiB
    for the top 1M, 16 MiB peak while loading; a set of strings would be 84 MiB).
    No file or an unreadable one means no guard."""

    def __init__(self, path: str | None, recheck_seconds: float = 300.0, top: int = 1_000_000,
                 background: bool = False):
        super().__init__(path, recheck_seconds, background)
        self.top = int(top)
        self._hashes = array("Q")

    def __len__(self) -> int:
        self._maybe_reload(time.monotonic())
        return self._size()

    def _size(self) -> int:
        return len(self._hashes)

    def _enabled(self) -> bool:
        return bool(self.path) and self.top > 0

    def _load(self) -> bool:
        hashes, taken = array("Q"), 0
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    name = popular_entry(line)
                    if name is None:
                        continue
                    taken += 1
                    if taken > self.top:
                        break
                    # IP addresses and single labels are never scored as domains
                    if "." in name and not name.rsplit(".", 1)[1].isdigit():
                        hashes.append(_hash64(registrable_part(name)))
        except OSError:
            return False
        self._hashes = _sorted_index(hashes)[0]
        return True

    def match(self, host: str, now: float = 0.0) -> bool:
        """True if host's registrable domain (the part that is scored) is popular."""
        self._maybe_reload(now)
        if not self._hashes:
            return False
        return _find(self._hashes, _hash64(registrable_part(host))) >= 0


NRD_STALE_DAYS = 7     # a list built longer ago than this is not used: its ages would be wrong


def nrd_age_text(days: int) -> str:
    """What a band of the NRD list means: 7 -> "in the last 7 days", 14 -> "8 to 14 days ago"."""
    return f"in the last {days} days" if days <= nrdfile.BAND_DAYS else f"{days - nrdfile.BAND_DAYS + 1} to {days} days ago"


class NrdList(_FileIndex):
    """Domains registered in the last `days` days (HaGeZi's NRD lists, from Stamus Labs data),
    as update_nrd.py writes them to nrd_domains.bin. Sorted 64-bit hashes, one array per
    age band (7 days wide), 8 bytes a name: about 39 MiB for 14 days (4.9 million names)
    instead of some 400 MiB as strings. The file is hashes already, so loading is a read and
    a sort, not parsing text. A name is found by its registrable domain (or itself); the
    answer says which band, i.e. how young. No path, no file, a damaged file or one built
    more than NRD_STALE_DAYS ago means no hits: never an error on the answer path."""

    def __init__(self, path: str | None, days: int = 14, recheck_seconds: float = 300.0,
                 background: bool = False):
        super().__init__(path, recheck_seconds, background)
        self.days = nrdfile.window_days(days)
        self._bands: tuple[tuple[int, array], ...] = ()    # swapped as one
        self.built = ""
        self._built_epoch = 0.0
        self._warned = 0.0

    def __len__(self) -> int:
        self._maybe_reload(time.monotonic())
        return self._size()

    def _size(self) -> int:
        return sum(len(a) for _, a in self._bands)

    @property
    def stale(self) -> bool:
        return bool(self._bands) and time.time() - self._built_epoch > NRD_STALE_DAYS * 86400

    def _load(self) -> bool:
        try:
            head, bands = nrdfile.read(self.path, self.days)
        except OSError:
            return False             # keep what was loaded
        except ValueError as exc:    # damaged or half-copied: say so once per file version, keep the old list
            try:
                m = os.path.getmtime(self.path)
            except OSError:
                m = 0.0
            if m != self._warned:
                self._warned = m
                print(f"[ghost-dns] {self.path} is unusable ({exc}); keeping the previous list", flush=True)
            return False
        sorted_bands = tuple((d, _sorted_index(a)[0]) for d, a in bands)
        try:
            built = datetime.date.fromisoformat(head["built"])
            epoch = datetime.datetime(built.year, built.month, built.day, tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            epoch = 0.0
        self._bands, self.built, self._built_epoch = sorted_bands, head["built"], epoch
        return True

    def match(self, host: str, now: float = 0.0) -> tuple[int, str] | None:
        """(band days, listed name) if host's registrable domain (or host) is on the list, the
        youngest band first; else None."""
        self._maybe_reload(now)
        bands = self._bands
        if not bands or self.stale:
            return None
        reg = registrable_part(host)
        names = (reg,) if reg == host else (reg, host)
        for name in names:
            h = _hash64(name)
            for days, idx in bands:
                if _find(idx, h) >= 0:
                    return days, name
        return None


_POPULAR_HOST = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")


def popular_entry(line: str) -> str | None:
    """The domain on one line of a Tranco CSV ('rank,domain') or of the cache
    update_feed.py writes (one domain a line, '#' comments); None for anything else."""
    line = line.strip().lower()
    if not line or line.startswith("#"):
        return None
    name = line.split(",", 1)[-1].strip().rstrip(".")
    return name if _POPULAR_HOST.match(name) else None


# --------------------------------------------------------------------------
class DohDetector:
    def __init__(self, ignore_clients=()):
        self.ignore = set(ignore_clients)

    def check(self, client_ip: str, host: str) -> Hit | None:
        if client_ip in self.ignore:
            return None
        if host in DOH_HOSTS or (host.split(".", 1)[-1] in DOH_HOSTS):
            return Hit("doh_bypass", "warn",
                       [f"resolved DoH/DoT provider {host}", "this device may be bypassing your DNS filter",
                        "not a sign of infection by itself: phones (Private DNS) and browsers (secure DNS) "
                        "do this; Trust it if it is yours"])
        return None


# --------------------------------------------------------------------------
# Services malware likes because everyone else uses them too: bot APIs and chat CDNs
# for commands and payloads, paste sites, tunnels into home networks, anonymous file
# drops, "what is my IP" lookups that bots run first. Each is harmless on its own; what
# counts is a device that has never used one suddenly starting to.
ABUSED_SERVICES = {
    "Telegram bot API": "api.telegram.org",
    "Discord CDN (file hosting)": "cdn.discordapp.com media.discordapp.net",
    "Discord (webhooks)": "discord.com",
    "paste site": "pastebin.com paste.ee hastebin.com rentry.co rentry.org pastes.io justpaste.it "
                  "controlc.com dpaste.org ghostbin.co",
    "tunnel into a home network": "ngrok.io ngrok.app ngrok-free.app ngrok-free.dev trycloudflare.com loca.lt "
                                  "localtunnel.me serveo.net localhost.run lhr.life pinggy.io pinggy.link "
                                  "bore.pub playit.gg portmap.io",
    "anonymous file drop": "transfer.sh file.io gofile.io temp.sh catbox.moe pixeldrain.com anonfiles.com "
                           "bashupload.com oshi.at 0x0.st filebin.net uguu.se tmpfiles.org",
    "raw code download": "raw.githubusercontent.com gist.githubusercontent.com",
    "public-IP lookup": "ipify.org ipinfo.io icanhazip.com ifconfig.me ifconfig.co ip-api.com "
                        "checkip.amazonaws.com wtfismyip.com myexternalip.com ipecho.net ident.me api.ip.sb",
    "Tor web gateway": "onion.ws onion.ly onion.pet tor2web.org",
    "serverless relay": "workers.dev",
}
_SERVICE_OF = {host: label for label, hosts in ABUSED_SERVICES.items() for host in hosts.split()}


def abused_service(host: str) -> tuple[str, str] | None:
    """(matched service host, label) if host is one of ABUSED_SERVICES or under one."""
    parts = host.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in _SERVICE_OF:
            return cand, _SERVICE_OF[cand]
    return None


# --------------------------------------------------------------------------
class TunnelDetector:
    """DNS tunnelling/exfiltration looks like many distinct, long, random
    subdomains of ONE apex, usually via TXT/NULL/CNAME queries."""

    def __init__(self, window=600.0, min_distinct=30, min_avg_label=14.0, long_label=40, min_long=12,
                 cooldown=1800.0):
        self.window, self.min_distinct = window, min_distinct
        self.min_avg_label, self.long_label, self.min_long = min_avg_label, long_label, min_long
        self.cooldown = cooldown
        self._seen: dict[tuple, deque] = defaultdict(deque)   # (dev, apex) -> (t, host, labellen, entropy)
        self._flagged: dict[tuple, float] = {}

    def observe(self, device: str, host: str, now: float, popular=False) -> Hit | None:
        """popular: the apex is on the popular-domain list (a bool, or a callable asked
        only when the many-subdomains test would fire, so most queries never look it up). A tunnel needs a zone its
        operator runs, and a big site's own many word-based service names (one host
        per microservice) are long and distinct too, so there only the long random
        labels of real payload count."""
        apex = registrable_part(host)
        if host == apex:
            return None
        sub = host[: -(len(apex) + 1)]
        label = sub.split(".")[0]
        key = (device, apex)
        q = self._seen[key]
        q.append((now, host, len(sub), entropy(label)))
        while q and now - q[0][0] > self.window:
            q.popleft()
        if len(self._seen) > 5000:                      # bound memory
            for k in [k for k, v in self._seen.items() if not v or now - v[-1][0] > self.window][:2500]:
                self._seen.pop(k, None)
        if now - self._flagged.get(key, -1e18) < self.cooldown:
            return None
        distinct = {h for _, h, _, _ in q}
        n = len(distinct)
        avg = sum(l for _, _, l, _ in q) / len(q)
        long_hi = len({h for _, h, l, e in q if l >= self.long_label and e >= 3.2})   # DISTINCT long random hosts
        many = n >= self.min_distinct and avg >= self.min_avg_label
        if many and (popular() if callable(popular) else popular):
            many = False
        exfil = long_hi >= self.min_long
        if not (many or exfil):
            return None
        self._flagged[key] = now
        why = (f"{n} distinct subdomains of {apex} in {int(self.window // 60)} min (avg {avg:.0f} chars)"
               if many else f"{long_hi} very long high-entropy subdomains of {apex}")
        return Hit("dns_tunnel", "high", [why, "pattern matches DNS tunnelling/exfiltration"],
                   {"tunnel": min(1.0, max(n / (self.min_distinct * 2), long_hi / (self.min_long * 2)))})


# --------------------------------------------------------------------------
class BeaconDetector:
    """The same name queried every N seconds with little jitter."""

    def __init__(self, min_samples=8, min_interval=30.0, max_cv=0.12, max_age=7200.0, cooldown=3600.0):
        self.min_samples, self.min_interval, self.max_cv = min_samples, min_interval, max_cv
        self.max_age, self.cooldown = max_age, cooldown
        self._t: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=24))
        self._flagged: dict[tuple, float] = {}

    def observe(self, device: str, host: str, now: float, popular=False) -> Hit | None:
        """popular: the name's registrable domain is on the popular-domain list (a bool,
        or a callable asked only when the timing test would fire). Under a popular site a
        timer is someone's script or a polled page (weather, timetables, course sites),
        not a call-home: a C2 needs a domain its operator controls."""
        key = (device, host)
        q = self._t[key]
        # collapse retries of one lookup (resolvers re-ask within seconds)
        if q and now - q[-1] < 5.0:
            return None
        q.append(now)
        if len(self._t) > 20000:
            for k in [k for k, v in self._t.items() if v and now - v[-1] > self.max_age][:10000]:
                self._t.pop(k, None)
        if len(q) < self.min_samples or now - self._flagged.get(key, -1e18) < self.cooldown:
            return None
        ts = list(q)
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.fmean(gaps)
        if mean < self.min_interval or mean <= 0:
            return None
        cv = statistics.pstdev(gaps) / mean
        if cv > self.max_cv:
            return None
        if popular() if callable(popular) else popular:
            return None
        self._flagged[key] = now
        return Hit("dns_beacon", "warn",
                   [f"{host} queried every ~{mean:.0f}s (n={len(ts)}, jitter {cv:.2f})",
                    "regular call-home timing"], {"beacon": min(1.0, 1.0 - cv)})


# --------------------------------------------------------------------------
class DgaBurst:
    """One random-looking domain is noise. Five *different* ones from the same
    device within minutes is what a DGA-driven implant looks like."""

    def __init__(self, min_score=0.8, min_distinct=5, window=600.0, cooldown=1800.0):
        self.min_score, self.min_distinct = min_score, min_distinct
        self.window, self.cooldown = window, cooldown
        self._q: dict[str, deque] = defaultdict(deque)     # device -> (t, apex, score)
        self._flagged: dict[str, float] = {}

    def observe(self, device: str, host: str, score: float, now: float) -> Hit | None:
        if score < self.min_score:
            return None
        q = self._q[device]
        q.append((now, registrable_part(host), score))
        while q and now - q[0][0] > self.window:
            q.popleft()
        if len(self._q) > 5000:
            for k in [k for k, v in self._q.items() if not v or now - v[-1][0] > self.window][:2500]:
                self._q.pop(k, None)
        if self.recently_flagged(device, now):
            return None
        apexes = {a for _, a, _ in q}
        if len(apexes) < self.min_distinct:
            return None
        self._flagged[device] = now
        top = sorted(apexes)[:4]
        return Hit("dga_burst", "high",
                   [f"{len(apexes)} different random-looking domains in {int(self.window // 60)} min",
                    "e.g. " + ", ".join(top)],
                   {"dga": max(s for _, _, s in q), "burst": min(1.0, len(apexes) / (self.min_distinct * 2))})

    def recently_flagged(self, device: str, now: float) -> bool:
        """This device raised dga_burst within the cooldown (nx_burst then stays quiet:
        it is the same storm seen a second way)."""
        return now - self._flagged.get(device, -1e18) < self.cooldown


# --------------------------------------------------------------------------
# Suffixes that are never internet domains but that routers and OSes hand out as search
# domains (x.home, x.corp, x.fritz.box, ...), plus the reserved test names. An NXDOMAIN
# under one of these is a local name that didn't resolve, not an unregistered domain.
PRIVATE_TLDS = frozenset("""
home lan local localdomain internal intranet corp private priv router gateway box modem
domain workgroup test example invalid localhost onion alt arpa ip station
""".split())
def _load_tlds() -> frozenset:
    """Every TLD in the root zone (tlds.txt, IANA's list, refreshed with the code). A DGA
    can use any of them, cheap new gTLDs above all (.science, .party, .bond...)."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "tlds.txt"), encoding="ascii") as f:
            return frozenset(ln.strip() for ln in f if ln.strip() and not ln.startswith("#"))
    except OSError:
        return frozenset()


ROOT_TLDS = _load_tlds()


def real_tld(tld: str) -> bool:
    """A TLD that exists on the internet and is not used as a home or office suffix
    (fritz.box, .home, .corp...): only there can an NXDOMAIN mean "not registered"."""
    if tld in PRIVATE_TLDS:
        return False
    if ROOT_TLDS:
        return tld in ROOT_TLDS
    return (tld in PUBLIC_SUFFIXES or tld in RARE_TLDS or tld.startswith("xn--")      # no list: fall back
            or (len(tld) == 2 and tld.isascii() and tld.isalpha()))


def nx_countable(host: str) -> bool:
    """Can an NXDOMAIN for `host` mean "this whole domain is not registered"? Only for
    the registrable domain itself (or its www.): an NXDOMAIN for a deeper name is a typo,
    a telemetry probe, a dead tracker host or a search domain appended to something, and
    says nothing about its parent. Also not for local names, reverse lookups, service
    records, WPAD, Chrome's random intranet probes (single labels, or a single label
    plus the LAN's search suffix) or anything under a suffix that is not a real TLD."""
    if is_internal(host):          # single labels, .lan/.local/.home.arpa, reverse, _svc._tcp
        return False
    labels = host.split(".")
    if labels[0] in ("wpad", "isatap") or not real_tld(labels[-1]):
        return False
    reg = registrable_part(host)
    return host == reg or host == "www." + reg


class NxBurst:
    """A DGA implant tries dozens of generated domains to find the one its operator
    registered; almost all come back NXDOMAIN. Many *different* unregistered domains
    failing from one device within minutes is that search, whatever the names look like
    (dictionary DGAs such as suppobox or matsnu read like words and score low).

    The caller only feeds names that passed nx_countable() and whose domain this network
    has never resolved. A name is counted once per device: a device stuck on the same
    few dead domains (an old IoT update server) alerts at most once, a DGA keeps making
    new ones."""

    def __init__(self, min_distinct=10, window=600.0, cooldown=1800.0, max_per_device=512):
        self.min_distinct, self.window, self.cooldown = min_distinct, window, cooldown
        self.max_per_device = max_per_device
        # device -> {registrable: last failed}, oldest first. Keyed by name, so a device
        # hammering one dead domain can't push the others out of the window.
        self._q: dict[str, OrderedDict] = defaultdict(OrderedDict)
        self._reported: dict[str, set] = defaultdict(set)     # device -> names already alerted on
        self._flagged: dict[str, float] = {}

    def observe(self, device: str, host: str, now: float) -> Hit | None:
        reg = registrable_part(host)
        if reg in self._reported.get(device, ()):
            return None
        q = self._q[device]
        q[reg] = now
        q.move_to_end(reg)
        while q:
            oldest, t = next(iter(q.items()))
            if now - t <= self.window and len(q) <= self.max_per_device:
                break
            del q[oldest]
        if len(self._q) > 5000:   # bound memory: a LAN has far fewer devices
            for k in [k for k, v in self._q.items() if not v or now - next(reversed(v.values())) > self.window][:2500]:
                self._q.pop(k, None)
                self._reported.pop(k, None)
                self._flagged.pop(k, None)
        if now - self._flagged.get(device, -1e18) < self.cooldown:
            return None
        if len(q) < self.min_distinct:
            return None
        regs = list(q)                                   # distinct, oldest first
        self._flagged[device] = now
        span = now - min(q.values())
        seen = self._reported[device]
        if len(seen) > 4096:
            seen.clear()
        seen.update(regs)
        q.clear()
        return Hit("nx_burst", "high",
                   [f"{len(regs)} different unregistered domains failed to resolve (NXDOMAIN) "
                    f"within {max(1, math.ceil(span / 60))} min",
                    "e.g. " + ", ".join(regs[-4:]),
                    "malware that generates domain names (DGA) tries many until one answers",
                    "check what runs on this device; isolate it if you can't explain this"],
                   {"nx": min(1.0, len(regs) / (self.min_distinct * 2))})


# --------------------------------------------------------------------------
class Detectors:
    """Bundle configured from the resolver's cfg dict."""

    def __init__(self, cfg: dict):
        # Inline mode answers DNS: lists load beside the old ones, never on a query's path.
        bg = not cfg.get("shadow", True)
        self.threat_feed = ThreatFeed(cfg.get("threat_feed_path"), background=bg)
        self.popular = PopularDomains(cfg.get("popular_path"), top=int(cfg.get("popular_top_n", 1_000_000)),
                                      background=bg)
        # Newly registered domains (rule new_domain): off means the list is never read.
        nrd_on = str(cfg.get("nrd_mode", "off")).lower() != "off"
        self.nrd = NrdList(cfg.get("nrd_path") if nrd_on else None, days=int(cfg.get("nrd_days", 14)),
                           background=bg)
        if bg:                       # start loading now, not at the first query
            now = time.monotonic()
            self.threat_feed._maybe_reload(now)
            self.popular._maybe_reload(now)
            self.nrd._maybe_reload(now)
        self.doh = DohDetector(cfg.get("doh_ignore_clients",
                                       [ip for ip in ("127.0.0.1", "::1", cfg.get("pi_ip")) if ip]))
        self.tunnel = TunnelDetector(min_distinct=int(cfg.get("tunnel_min_distinct", 30)),
                                     min_long=int(cfg.get("tunnel_min_long", 12)))
        self.beacon = BeaconDetector(min_samples=int(cfg.get("beacon_min_samples", 8)))
        self.burst = DgaBurst(min_score=float(cfg.get("burst_min_score", 0.8)),
                              min_distinct=int(cfg.get("burst_min_distinct", 5)))
        self.nx = NxBurst(min_distinct=int(cfg.get("nx_burst_min_distinct", 10)),
                          window=float(cfg.get("nx_burst_window", 600)))
        self.lock = threading.Lock()

    def wait_loaded(self, timeout: float | None = None) -> bool:
        """True once the threat feed, the popular list and the NRD list have finished loading."""
        return (self.threat_feed.wait_loaded(timeout) and self.popular.wait_loaded(timeout)
                and self.nrd.wait_loaded(timeout))
