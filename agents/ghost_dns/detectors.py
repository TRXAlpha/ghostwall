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

Every stateful detector takes `now` as an argument (seconds) so tests can drive
time, and bounds its memory. Stdlib only.
"""
from __future__ import annotations

import math
import os
import re
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

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
class ThreatFeed:
    """Known-bad domains loaded from a text file (one per line). Reloads when
    the file changes, so a daily updater needs no restart.

    update_feed.py writes each source under a '#@source' line. The names are kept in a
    dict whose value is a bitmask of the sources that list them: the same memory as a
    frozenset (measured in agents/dga_eval/results_feeds.md), and the alert can say
    "on URLhaus (malware)" instead of just "on the threat feed"."""

    def __init__(self, path: str | None, recheck_seconds: float = 300.0):
        self.path = path
        self.recheck = recheck_seconds
        self._feed: tuple[dict[str, int], tuple[str, ...]] = ({}, ())   # swapped as one
        self._mtime = 0.0
        self._checked = -1e18
        self._lock = threading.Lock()

    def __len__(self) -> int:
        self._maybe_reload(time.monotonic())   # report the real size, not a not-yet-loaded 0
        return len(self._feed[0])

    def info(self) -> tuple[int, float]:
        """(number of domains, file mtime or 0) for the status page."""
        n = len(self)
        return n, self._mtime

    def _maybe_reload(self, now: float) -> None:
        if not self.path or now - self._checked < self.recheck:
            return
        with self._lock:
            self._checked = now
            try:
                m = os.path.getmtime(self.path)
            except OSError:
                return
            if m == self._mtime:
                return
            doms: dict[str, int] = {}
            labels: list[str] = []
            bit = 0                      # names before any '#@source' line: no source
            masks: dict[int, int] = {}   # one int object per distinct mask, not per name
            with open(self.path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("#@source\t"):
                        parts = line.rstrip("\n").split("\t")
                        name, kind = (parts + ["", "", "", ""])[3:5]
                        label = f"{name} ({kind})" if name and kind else (name or "the threat feed")
                        if label not in labels:
                            labels.append(label)
                        bit = 1 << labels.index(label)
                        continue
                    line = line.strip().lower()
                    if line and not line.startswith(("#", "!")) and _DOMAIN_LINE.match(line) and "." in line:
                        v = doms.get(line, 0) | bit
                        doms[line] = masks.setdefault(v, v)
            self._feed = (doms, tuple(labels))
            self._mtime = m

    def match(self, host: str, now: float = 0.0) -> tuple[str, bool] | None:
        """(listed_domain, exact) if host or a parent is listed, else None. Only
        parents: a listed evil.github.io never makes github.io itself a hit."""
        self._maybe_reload(now)
        doms = self._feed[0]
        if not doms:
            return None
        if host in doms:
            return host, True
        for cand in parents(host):
            if cand in doms:
                return cand, False
        return None

    def sources(self, listed: str) -> list[str]:
        """Which lists name `listed`, e.g. ["URLhaus (malware)"]; [] if unknown."""
        if not self._feed[0]:
            self._maybe_reload(time.monotonic())
        doms, labels = self._feed
        mask = doms.get(listed, 0)
        return [lab for i, lab in enumerate(labels) if mask >> i & 1]


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

    def observe(self, device: str, host: str, now: float) -> Hit | None:
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

    def observe(self, device: str, host: str, now: float) -> Hit | None:
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
        if now - self._flagged.get(device, -1e18) < self.cooldown:
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


# --------------------------------------------------------------------------
# Suffixes that are never internet domains but that routers and OSes hand out as search
# domains (x.home, x.corp, x.fritz.box, ...), plus the reserved test names. An NXDOMAIN
# under one of these is a local name that didn't resolve, not an unregistered domain.
PRIVATE_TLDS = frozenset("""
home lan local localdomain internal intranet corp private priv router gateway box modem
domain workgroup test example invalid localhost onion alt arpa ip station
""".split())
# Real top-level domains outside tokenizer.PUBLIC_SUFFIXES and RARE_TLDS that DGAs use.
# Two-letter TLDs (country codes) are accepted as a whole.
EXTRA_TLDS = frozenset("""
website space wtf rent live life world today email cloud digital network systems services
solutions company group news blog page fun host press center global
""".split())


def real_tld(tld: str) -> bool:
    if tld in PRIVATE_TLDS:
        return False
    return (tld in PUBLIC_SUFFIXES or tld in RARE_TLDS or tld in EXTRA_TLDS or tld.startswith("xn--")
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
        self._q: dict[str, deque] = defaultdict(deque)        # device -> (t, registrable)
        self._reported: dict[str, set] = defaultdict(set)     # device -> names already alerted on
        self._flagged: dict[str, float] = {}

    def observe(self, device: str, host: str, now: float) -> Hit | None:
        reg = registrable_part(host)
        if reg in self._reported.get(device, ()):
            return None
        q = self._q[device]
        q.append((now, reg))
        while q and (now - q[0][0] > self.window or len(q) > self.max_per_device):
            q.popleft()
        if len(self._q) > 5000:   # bound memory: a LAN has far fewer devices
            for k in [k for k, v in self._q.items() if not v or now - v[-1][0] > self.window][:2500]:
                self._q.pop(k, None)
                self._reported.pop(k, None)
        if now - self._flagged.get(device, -1e18) < self.cooldown:
            return None
        regs = list(dict.fromkeys(r for _, r in q))     # distinct, oldest first
        if len(regs) < self.min_distinct:
            return None
        self._flagged[device] = now
        span = now - q[0][0]
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
        self.threat_feed = ThreatFeed(cfg.get("threat_feed_path"))
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
