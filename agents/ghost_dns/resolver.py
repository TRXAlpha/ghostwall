"""The decision-maker: score every DNS query, decide allow / recommend / block,
forward or sinkhole, emit events, and trigger a pcap freeze on real alerts.

`decide()` is pure (no sockets) and is where all the policy lives, so the whole
rule set is unit-testable without a network. `handle_packet()` wraps it with the
DNS wire format and upstream forwarding. `serve_forever()` is the UDP loop.

Blocking policy (deliberately conservative -- the models over-flag; full order in
docs/ARCHITECTURE.md):
  * allowlisted domain            -> ALLOW, no event
  * blocklisted domain            -> BLOCK (sinkhole), event rule=blocklist
    (the blocklist is dga_high's own blocks plus every containment in force: `contain`
     puts the destination behind a threat_feed / dns_tunnel / new dga_high alert there
     for contain_days, for every device; see _contain)
  * dga >= block_threshold
        AND domain is new
        AND learning mode is off   -> BLOCK, promote to blocklist, event action=block
     (otherwise the same score      -> RECOMMEND: forwarded, event action=recommend)
  * dga >= recommend_threshold     -> RECOMMEND (forwarded), event action=recommend
  (a name whose registrable domain is on the popular list, Tranco top N, gets neither:
   its score alone raises nothing, nor does a timer on it (dns_beacon); the feed, tunnel
   and nx_burst rules still apply)
  * a device marked "profile": "iot", after iot_learn_days, looking up a registrable
    domain outside what it learned -> RECOMMEND, event rule=iot_new_domain (BLOCK with
    iot_enforce "on", inline mode, learning off); only when no other rule alerted
  * nrd_mode "alert"/"block": a name whose registrable domain is on the newly registered
    domains list, first seen on this network within novelty_days, not popular, not
    allowlisted -> RECOMMEND, event rule=new_domain (severity high with a second signal: a
    random-looking score or a risky TLD; BLOCK with nrd_mode "block", inline mode, learning
    off; an IoT device follows iot_enforce); only when no other rule alerted
  * everything else                -> ALLOW, no event
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import queue
import socket
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone

import struct
import sys

import dnsmsg
import events as events_mod
from detectors import (RARE_TLDS, Detectors, abused_service, is_internal, iot_builtin_allowed, nrd_age_text,
                       nx_countable, tld_of)
from tokenizer import is_public_suffix, registrable_part


# Letters of other alphabets (Cyrillic, Greek) that look like Latin ones: what a lookalike
# domain is built from. Deliberately short: only near-identical shapes.
CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
    "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u04bb": "h", "\u0501": "d",
    "\u051b": "q", "\u051d": "w", "\u043a": "k", "\u043c": "m", "\u043d": "h", "\u0442": "t",
    "\u0432": "b", "\u0491": "r",
    "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03c1": "p", "\u03c4": "t", "\u03b9": "i",
    "\u03ba": "k", "\u03c5": "u", "\u03b5": "e", "\u03c7": "x",
}

# Lookups a web page can make a browser send (HTTPS/SVCB: type 65/64, asked alongside A).
ADDRESS_QTYPES = frozenset({"A", "AAAA", "HTTPS", "SVCB", "TYPE64", "TYPE65"})


def _blockable_ip(ip: str) -> bool:
    """A public IPv4 address (the gateway's blocked_ip set holds IPv4; it forwards no IPv6)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_global


def _prune(d: dict, cutoff: float, cap: int) -> dict:
    """Drop entries older than cutoff; if that is not enough, keep the newest half of cap.
    (Filtering by age alone keeps everything during a flood, then re-filters on every
    insert: quadratic.)"""
    kept = {k: v for k, v in d.items() if v >= cutoff}
    if len(kept) > cap // 2:
        kept = dict(sorted(kept.items(), key=lambda kv: kv[1])[-(cap // 2):])
    return kept


@dataclass
class Decision:
    action: str            # "allow" | "recommend" | "block"
    reason: str
    event: dict | None = None


class Resolver:
    def __init__(self, cfg, state, scorer, enforcer, device_map, event_log,
                 capture=None, neighbours=None):
        self.cfg = cfg
        self.neighbours = neighbours         # neighbours.Neighbours: which MAC is at an IP
        self.state = state
        self.scorer = scorer
        self.enforcer = enforcer
        self.devices = device_map
        self.events = event_log
        self.capture = capture
        self._resolved_lock = threading.Lock()
        self._query_lock = threading.Lock()
        self._recent_ip: dict[str, float] = {}   # ip -> monotonic last-written
        self._events_lock = threading.Lock()
        self._alert_times: dict[str, list[float]] = {}  # device -> monotonic times of written alerts
        self._primary_down_until = 0.0   # monotonic; skip a dead primary upstream until then
        self._stop = threading.Event()
        self._socks: list = []
        self._later: queue.Queue | None = None   # inline + learning: scored after the answer
        self._later_lock = threading.Lock()
        # Shadow mode: scoring a log of queries someone else already answered.
        # Nothing here can block, so decisions are only ever recommendations.
        self.shadow = bool(cfg.get("shadow", False))
        self.source = None                   # shadow: "adguard" or "pihole", set by app.py
        self.clock = time.monotonic          # overridable, so tests can drive time
        self.det = Detectors(cfg)            # threat feed, DoH, tunnel, beacon, DGA burst
        # device names or IPs whose failed lookups never count for nx_burst
        self._nx_ignored = frozenset(str(x) for x in (cfg.get("nx_burst_ignore_devices") or ()))
        self.last_seen: dict[str, str] = {}  # client ip -> ISO time of its latest query
        self.current_ip: dict[str, str] = {} # named device -> the address it last queried from
        self.stats = {"queries": 0, "blocked": 0, "recommended": 0, "suppressed": 0,
                      "forwarded": 0, "errors": 0, "fallbacks": 0, "failopen": 0,
                      "rate_limited": 0, "blocked_upstream": 0, "popular": 0,
                      "auto_isolated": 0}
        self._iso_lock = threading.Lock()   # auto_isolate: check the cap and isolate as one step
        # contain: which addresses each name answered with lately (to drop them at the gateway),
        # and which registrable domains share an address (a shared address is never dropped).
        self._contain_lock = threading.Lock()
        self._ips_lock = threading.Lock()
        self._host_ips: OrderedDict = OrderedDict()      # host -> addresses of its latest answer
        self._ip_regs: dict[str, set] = {}               # address -> registrable domains seen on it
        # confirm_seconds: findings a web page or an email can cause with one lookup act only
        # once they continue. (device, domain family, rule, action) -> first sighting (wall
        # clock), or None once it has been used.
        self._pending_lock = threading.Lock()
        self._pending: OrderedDict = OrderedDict()
        self._qtypes: OrderedDict = OrderedDict()        # (device, apex) -> [lookups, non-address lookups]
        self._contained_ips: dict[str, str] = {ip: name for name, c in state.contained_list().items()
                                               for ip in c["ips"]}
        self.stats["contained"] = 0

    # -- policy (pure, no I/O except event log + state + enforcer) --------
    def decide(self, client_ip: str, domain: str, qtype: str, upstream_blocked: bool = False,
               rcode: str | None = None, nx_zone: str | None = None,
               when: float | None = None) -> Decision:
        """upstream_blocked: the DNS server (AdGuard) already refused this name, so no
        connection happened: a single random-looking score is then not worth an alert
        (most of those are ad and tracker junk). Bursts and every other rule still count.

        rcode: the answer's response code ("NOERROR", "NXDOMAIN", ...) when it is known
        (shadow mode, or inline mode scoring after the answer); None when not. nx_zone:
        the SOA owner of an NXDOMAIN answer, if it carried one. Both feed nx_burst only.

        when: the time the query was made, on self.clock()'s scale, when it is known and
        differs from now (shadow mode reads queries in batches, after the fact). The
        timing rules (tunnel, beacon, nx_burst, dga_burst) use it; None means now.

        rcode "FILTERED": the upstream resolver (Quad9, Cloudflare security) blocked the
        name itself. It is treated like a name the DNS server blocked: not an
        unregistered domain for nx_burst, and one `upstream_block` info event says so."""
        domain = domain.rstrip(".").lower()
        by_upstream = rcode == "FILTERED" and not upstream_blocked
        if by_upstream:
            upstream_blocked = True
        if not domain:
            return Decision("allow", "empty")
        dev = self._device(client_ip)
        now = self.clock()
        t = now if when is None else when    # when the query happened, for timing rules
        if len(self.last_seen) > 10000:      # a LAN has far fewer clients; bound it anyway
            self.last_seen.clear()
        self.last_seen[client_ip] = events_mod.now_iso()
        if dev.name != client_ip:
            self.current_ip[dev.name] = client_ip

        # Evidence that is checked BEFORE the allowlist: a known-bad host (an exact
        # feed match wins even over a trusted parent domain) and DoH bypass. Trusting the
        # listed name itself does count: the list names some shorteners and apps as a
        # whole (phishing runs through them), and you must be able to say "not for me".
        feed = self.det.threat_feed.match(domain, now)
        if feed and not self.state.trusts(feed[0]) and (feed[1] or not self.state.is_allowed(domain)):
            listed, exact = feed
            enforce = (not self.state.learning) and not self.shadow
            on = " and ".join(self.det.threat_feed.sources(listed)) or "the threat feed"
            why = [f"{listed} is on {on}" if exact else f"{domain} is under {listed}, which is on {on}",
                   f"a service you know? sudo ghostwall allow {listed}"]
            if upstream_blocked:    # the DNS server's own filtering did the blocking
                why.append("blocked by your upstream DNS filter" if by_upstream else "blocked by your DNS server")
            elif not enforce:
                why.append("not blocked (" + ("shadow mode" if self.shadow else "learning mode") + ")")
            evt = self._event(dev, domain, rule="threat_feed",
                              action="block" if enforce else "recommend",
                              severity="high", scores={"feed": 1.0}, reasons=why,
                              isolate_hold=self._feed_hold(domain, listed, exact, now), contain=listed)
            return Decision("block" if enforce else "recommend", "threat_feed", evt)
        hit = self.det.doh.check(client_ip, domain)
        if hit and domain not in self.state.allowlist:   # trusted by exact name: a DoH you chose
            return Decision("recommend", hit.rule, self._emit_hit(dev, domain, hit))

        # A device starting to use a service malware favours (bot APIs, paste sites,
        # tunnels, file drops...). Checked before the allowlist: the starter list trusts
        # discordapp.com and githubusercontent.com as a whole, which is where payloads sit.
        svc = self._abused_service(client_ip, dev, domain)
        if svc:
            return svc

        if by_upstream:
            self.stats["upstream_filtered"] = self.stats.get("upstream_filtered", 0) + 1
            self._event(dev, domain, rule="upstream_block", action="allow", severity="info",
                        reasons=["blocked by your upstream DNS filter (Quad9 or Cloudflare security), "
                                 "not by Ghostwall; no connection was made"])
        # IoT default-deny (a device marked "profile": "iot"). Before the allowlist on
        # purpose: the allowlist is network-wide (and its starter file trusts whole clouds),
        # an IoT device's set is its own; Trust on its alert adds to that set. A refusal
        # is final here. Otherwise the alert is raised only if no other rule below
        # alerts on the same lookup: one lookup, one alert.
        iot = self._iot_check(client_ip, dev, domain, rcode, upstream_blocked)
        if iot is not None and iot["block"]:
            return self._iot_alert(dev, domain, iot)

        # A containment in force wins over the allowlist (its starter file trusts whole
        # clouds, which is where contained hosts sit), unless you trusted that very name.
        held = self.state.contained_by(domain)
        if held and (self.state.trusts(held) or self.state.trusts(domain)):
            held = None
        if not held and self.state.is_allowed(domain):
            return self._iot_alert(dev, domain, iot) or Decision("allow", "allowlist")

        if is_internal(domain):          # homepi, *.ts.net, *.local, _svc._tcp... not internet names
            return Decision("allow", "internal")

        if held or self.state.is_blocked(domain):
            why = "on confirmed blocklist"
            if held:
                c = self.state.contained_list().get(held) or {}
                why = (f"{held} is contained: blocked for every device after {c.get('rule') or 'an alert'}"
                       f" on {c.get('device') or 'a device'}; undo: sudo ghostwall uncontain {held}")
            evt = self._event(dev, domain, rule="blocklist",
                              action="recommend" if self.shadow else "block",
                              severity="high",
                              reasons=[why]
                              + (["blocked by your DNS server" if upstream_blocked else
                                  "shadow mode: Ghostwall itself does not block"] if self.shadow else []))
            return Decision("recommend" if self.shadow else "block", "blocklist", evt)

        look = self._lookalike(domain, now)
        if look:
            evt = self._event(dev, domain, rule="lookalike", action="recommend", severity="high",
                              reasons=[f"{look[0]} is written with letters from another alphabet that look "
                                       f"like {look[1]}, a popular site: the usual trick of a phishing link",
                                       f"really yours? sudo ghostwall allow {registrable_part(domain)}"])
            return Decision("recommend", "lookalike", evt)

        first_seen = self.state.note_seen(domain)
        is_new = self.state.is_new(domain, int(self.cfg["novelty_days"]))
        sc = self.scorer.score_one(domain)
        dga = sc["dga"]
        reasons = [f"dga score {dga:.2f}"]
        if is_new:
            reasons.append("first seen" if first_seen else "recently seen")
        nrd = self._nrd_check(domain, now, is_new, upstream_blocked, rcode)
        if nrd:      # the score rules below say so too; new_domain itself speaks only when they do not
            reasons.append(f"also on the newly registered domains list ({nrd['age']})")

        # Behavioural detectors (not allowlisted names only).
        # Tunnelling stands on its own. A regular timer, though, is what EVERY app does
        # (updaters, telemetry, sync), so a beacon only counts when the name itself is
        # also odd: it scores as random-looking, or sits on a rarely-legitimate TLD.
        behaviour = None
        self._count_qtype(dev.name, domain, qtype)
        with self.det.lock:
            tun = self.det.tunnel.observe(dev.name, domain, t,
                                          popular=lambda: self.det.popular.match(domain, now))
            bea = self.det.beacon.observe(dev.name, domain, t,
                                          popular=lambda: self.det.popular.match(domain, now))
        if bea and not (dga >= float(self.cfg.get("beacon_min_dga", 0.5)) or tld_of(domain) in RARE_TLDS):
            bea = None
        for hit in (tun, bea):
            if hit and behaviour is None:
                behaviour = Decision("recommend", hit.rule, self._emit_hit(dev, domain, hit))

        # Many DIFFERENT random-looking domains from one device is a far stronger
        # signal than any single score. Many different unregistered ones is too, even
        # when they read like words.
        # One storm raises one alert: dga_burst wins when both fire. A popular site's
        # name (Tranco top N) never feeds dga_burst: a portal loading qq.com, gtimg.cn and
        # qpic.cn is not malware, and no public DGA name is on the list.
        nx = None if upstream_blocked else self._nx_observe(dev, domain, rcode, nx_zone, t)
        burst_score = dga
        if dga >= self.det.burst.min_score and self.det.popular.match(domain, now):
            burst_score = 0.0
        with self.det.lock:
            burst = self.det.burst.observe(dev.name, domain, burst_score, t)
        if burst:
            return Decision("recommend", burst.rule, self._emit_hit(dev, domain, burst))
        if nx and not self.det.burst.recently_flagged(dev.name, t):
            return Decision("recommend", nx.rule, self._emit_hit(dev, domain, nx))

        block_thr = float(self.cfg["block_threshold"])
        rec_thr = float(self.cfg["recommend_threshold"])
        corr_thr = float(self.cfg.get("corroborated_threshold", 0.80))
        if upstream_blocked and dga >= min(rec_thr, corr_thr):
            self.stats["blocked_upstream"] += 1
            return behaviour or Decision("allow", "blocked_upstream")

        # A name of one of the most popular sites (Tranco top N) looks random because it
        # is a brand or an abbreviation (qq.com, 1e100.net): its score alone raises
        # nothing. It already counted above for the feed, tunnel, beacon, dga_burst and
        # nx_burst rules.
        if dga >= min(rec_thr, corr_thr) and self.det.popular.match(domain, now):
            self.stats["popular"] += 1
            return behaviour or self._iot_alert(dev, domain, iot) or Decision("allow", "popular")

        if dga >= block_thr:
            can_block = (not self.state.learning) and is_new and not self.shadow
            if can_block:
                self.state.add_block(domain)
                self.enforcer_block_hook(domain)
                evt = self._event(dev, domain, rule="dga_high", action="block",
                                  severity="high", scores=sc, reasons=reasons)
                return Decision("block", f"dga>={block_thr}", evt)
            # High score but either established, or learning mode -> recommend.
            why = ("shadow mode" if self.shadow else
                   "learning mode" if self.state.learning else "established domain")
            reasons.append(f"not blocked ({why})")
            evt = self._event(dev, domain, rule="dga_high", action="recommend",
                              severity="high" if is_new else "warn",
                              scores=sc, reasons=reasons)
            return Decision("recommend", "dga_high", evt)

        # A random-looking name that this network has already used for days has
        # proven itself; alerting on it again is the bulk of the noise. Only names
        # new to the network (within novelty_days) raise a plain "suspect" alert.
        if dga >= rec_thr and (is_new or not self.cfg.get("suspect_only_new", True)):
            evt = self._event(dev, domain, rule="dga_suspect", action="recommend",
                              severity="warn", scores=sc, reasons=reasons)
            return Decision("recommend", "dga_suspect", evt)

        # A middling score is not enough alone (it is where the noise lives), but it
        # is worth an alert when something else about the name is also off.
        if dga >= corr_thr and tld_of(domain) in RARE_TLDS:
            evt = self._event(dev, domain, rule="dga_corroborated", action="recommend",
                              severity="warn", scores=sc,
                              reasons=reasons + [f"rarely-legitimate TLD .{tld_of(domain)}"])
            return Decision("recommend", "dga_corroborated", evt)

        return (behaviour or self._iot_alert(dev, domain, iot)
                or self._nrd_alert(client_ip, dev, domain, nrd, sc, first_seen)
                or Decision("allow", "clean"))

    def _lookalike(self, domain: str, now: float) -> tuple[str, str] | None:
        """(the name as displayed, the popular site it imitates) when the registrable label
        is an internationalised name made only of ASCII plus letters of another alphabet
        that look like Latin ones, and reading them as Latin gives a popular site. Names
        with ordinary accents are left alone (companies register those themselves)."""
        if "xn--" not in domain or not self.cfg.get("lookalike_enabled", True):
            return None
        reg = registrable_part(domain)
        label, _, rest = reg.partition(".")
        if not label.startswith("xn--") or not rest:
            return None
        try:
            shown = label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            return None
        latin = "".join(CONFUSABLES.get(c, c) for c in shown)
        if latin == shown or not latin.isascii() or not all(c.isascii() or c in CONFUSABLES for c in shown):
            return None
        target = f"{latin}.{rest}"
        return (f"{shown}.{rest}", target) if self.det.popular.match(target, now) else None

    def _nrd_check(self, domain: str, now: float, is_new: bool, upstream_blocked: bool,
                   rcode: str | None) -> dict | None:
        """new_domain, the finding without its alert: the name's registrable domain is on the
        newly registered list, this network met it within novelty_days, and it is not a
        popular site (a top-1M name is never new). Not for names your DNS server or upstream
        already refused (no connection followed) or that do not exist (nx_burst's job).
        Allowlisted, internal and blocklisted names never get here."""
        if not is_new or upstream_blocked or rcode == "NXDOMAIN":
            return None
        if str(self.cfg.get("nrd_mode", "off")).lower() == "off":
            return None
        hit = self.det.nrd.match(domain, now)
        if hit is None or self.det.popular.match(domain, now):
            return None
        return {"days": hit[0], "listed": hit[1], "age": f"registered {nrd_age_text(hit[0])}"}

    def _nrd_alert(self, client_ip: str, dev, domain: str, nrd: dict | None, sc: dict, first_seen: bool):
        """The Decision for a _nrd_check() finding, alert included (None without one). Severity
        is high when a second signal agrees (a score of corroborated_threshold or more, or a
        rarely-legitimate TLD), else warn. One alert per device and domain family
        (rule_dedupe_seconds); a refused name is refused on every retry, its alert is not
        repeated. nrd_mode "block" refuses in inline mode with learning off; an IoT device's
        lookup is refused only with iot_enforce "on" (iot_enforce "dry-run": the alert says it
        would be); shadow mode answers nothing, so never."""
        if nrd is None:
            return None
        reg = registrable_part(domain)
        dga = float(sc.get("dga", 0.0))
        also = []
        if dga >= float(self.cfg.get("corroborated_threshold", 0.80)):
            also.append(f"dga score {dga:.2f}")
        if tld_of(domain) in RARE_TLDS:
            also.append(f"rarely-legitimate TLD .{tld_of(domain)}")
        mode = str(self.cfg.get("nrd_mode", "off")).lower()
        iot = str(dev.profile).lower() == "iot" and client_ip != self.cfg.get("pi_ip")
        iot_mode = str(self.cfg.get("iot_enforce", "off")).lower()
        applies = mode == "block" and (not iot or iot_mode in ("on", "dry-run"))
        block = applies and (not iot or iot_mode == "on") and not self.shadow and not self.state.learning
        why = [f"{reg} is on the newly registered domains list ({nrd['age']})",
               "first seen on your network" if first_seen
               else f"first seen on your network in the last {int(self.cfg['novelty_days'])} days"]
        why += also
        why.append(f"a site you know? Trust, or sudo ghostwall allow {reg}")
        if mode == "block" and not block:
            if iot and iot_mode != "on":
                why.append(f'not blocked (an IoT device follows iot_enforce, which is "{iot_mode}")')
            else:
                why.append("not blocked (" + ("shadow mode" if self.shadow else "learning mode") + ")")
        if block and self._is_repeat(dev.name, domain, "new_domain"):
            self.stats["blocked"] += 1
            return Decision("block", "new_domain")
        action = "block" if block else "recommend"
        hold = None if also else ("a newly registered domain alone is not proof about this device; "
                                  "it needs a second signal (a random-looking name or a risky TLD)")
        evt = self._event(dev, domain, rule="new_domain", action=action,
                          severity="high" if also else "warn", scores=sc, reasons=why,
                          trust=reg if reg != domain else None,
                          would_block=applies and not block, isolate_hold=hold)
        return Decision(action, "new_domain", evt)

    def _device(self, client_ip: str):
        mac = self.neighbours.mac(client_ip) if self.neighbours is not None else None
        return self.devices.device_for_ip(client_ip, mac)

    def _nx_burst(self, dev, domain: str, rcode: str | None, nx_zone: str | None, now: float):
        hit = self._nx_observe(dev, domain, rcode, nx_zone, now)
        return Decision("recommend", hit.rule, self._emit_hit(dev, domain, hit)) if hit else None

    def _nx_observe(self, dev, domain: str, rcode: str | None, nx_zone: str | None, now: float):
        """Feed one upstream answer to nx_burst. Callers have already dropped allowlisted,
        internal and blocklisted names. A NOERROR anywhere in a domain family proves the
        domain is registered; so does an NXDOMAIN whose SOA names that domain (or a zone
        inside it): only the one name is missing. What is left counts if nx_countable()
        says the name is the registrable domain itself, on a real TLD."""
        if not rcode or not self.cfg.get("nx_burst_enabled", True):
            return None
        if dev.name in self._nx_ignored:      # a link checker, a mail filter: fails lookups on purpose
            return None
        if rcode == "NOERROR":
            self.state.note_resolved(domain)
            return None
        if rcode != "NXDOMAIN":
            return None   # SERVFAIL/REFUSED say nothing about registration
        reg = registrable_part(domain)
        if nx_zone is not None and (nx_zone == reg or nx_zone.endswith("." + reg)):
            self.state.note_resolved(domain)
            return None
        if not nx_countable(domain) or self.state.has_resolved(domain):
            return None
        with self.det.lock:
            return self.det.nx.observe(dev.name, domain, now)

    def note_answer(self, client_ip: str, domain: str, rcode: str | None, nx_zone: str | None = None):
        """Inline mode, when decide() ran before the answer existed (blocking on, or the
        score-later queue was full): give nx_burst the answer's rcode. Trusted and
        blocklisted names are skipped, as in decide(); nx_countable() drops local ones."""
        domain = domain.rstrip(".").lower()
        if not rcode or not domain or self.state.is_allowed(domain) or self.state.is_blocked(domain):
            return None
        return self._nx_burst(self._device(client_ip), domain, rcode, nx_zone, self.clock())

    def _abused_service(self, client_ip: str, dev, domain: str):
        if client_ip in self.det.doh.ignore:          # this box itself (fw_bot uses Telegram)
            return None
        self.state.note_device(dev.name)
        match = abused_service(domain)
        if not match:
            return None
        host, label = match
        if domain in self.state.allowlist or host in self.state.allowlist:
            return None   # trusted by name (Trust button, `ghostwall allow`)
        first = self.state.first_service_use(dev.name, host, float(self.cfg.get("service_baseline_days", 3)))
        if not first:
            return None   # used before, or still learning what this device normally does
        evt = self._event(dev, domain, rule="abused_service", action="recommend", severity="warn",
                          reasons=[f"first use of a {label} ({host}) by this device",
                                   "malware uses these for commands, payloads or stolen data; "
                                   "trust it if you know why this device started"])
        return Decision("recommend", "abused_service", evt)

    def _iot_check(self, client_ip: str, dev, domain: str, rcode: str | None,
                   upstream_blocked: bool) -> dict | None:
        """iot_new_domain, the finding without its alert. A device marked "profile": "iot"
        talks to a small, stable set of domains. During iot_learn_days from its first
        lookup they are learned (hashed, in state.json); after that a registrable domain
        outside the set is a finding, and with iot_enforce "on" a refusal (inline mode,
        learning off; shadow mode answers nothing, so never). Callers have already let the
        threat feed, DoH and abused-service rules speak: those names are never learned."""
        if str(dev.profile).lower() != "iot" or client_ip == self.cfg.get("pi_ip"):
            return None
        if upstream_blocked or rcode == "NXDOMAIN":
            return None    # no connection followed (your DNS server refused it, or no such name)
        if is_internal(domain) or iot_builtin_allowed(domain) or abused_service(domain):
            return None    # LAN names; clock sync; abused services keep their own rule
        if self.state.is_blocked(domain):
            return None    # the blocklist rule refuses it anyway; never learned either
        days = float(self.cfg.get("iot_learn_days", 7))
        if self.state.iot_observe(dev.name, domain, days) != "new":
            return None
        mode = str(self.cfg.get("iot_enforce", "off")).strip().lower()
        block = mode == "on" and not self.shadow and not self.state.learning
        reg = registrable_part(domain)
        why = [f"{dev.name} normally talks to {self.state.iot_count(dev.name)} domains; {reg} is not one of them",
               f"allow it for this device only: Trust, or sudo ghostwall allow {reg} --device {dev.name}"]
        if mode == "on" and not block:
            why.append("not blocked (" + ("shadow mode" if self.shadow else "learning mode") + ")")
        elif mode == "dry-run":
            why.append('iot_enforce is "dry-run": it would be refused')
        return {"block": block, "would_block": mode in ("on", "dry-run") and not block,
                "reasons": why, "trust": reg}

    def _iot_alert(self, dev, domain: str, iot: dict | None):
        """The Decision for an _iot_check() finding, alert included (None without one).
        One alert per device and domain family (rule_dedupe_seconds); a refused name
        is refused on every retry, its alert is not repeated."""
        if iot is None:
            return None
        if iot["block"] and self._is_repeat(dev.name, domain, "iot_new_domain"):
            self.stats["blocked"] += 1
            return Decision("block", "iot_new_domain")
        action = "block" if iot["block"] else "recommend"
        evt = self._event(dev, domain, rule="iot_new_domain", action=action, severity="warn",
                          reasons=iot["reasons"], trust=iot["trust"], would_block=iot["would_block"])
        return Decision(action, "iot_new_domain", evt)

    def _emit_hit(self, dev, domain, hit) -> dict:
        # A tunnel uses a new subdomain for every query: trusting the one name in the
        # alert would never match the next, so Trust means the zone it goes to.
        trust = registrable_part(domain) if hit.rule == "dns_tunnel" else None
        return self._event(dev, domain, rule=hit.rule, action="recommend", severity=hit.severity,
                           scores=hit.scores or None, reasons=hit.reasons, trust=trust)

    def enforcer_block_hook(self, domain: str) -> None:
        """Domain blocks are enforced at the resolver (sinkhole); no kernel
        change needed. Hook kept for symmetry / future IP-level escalation."""
        return None

    def _event(self, dev, domain, *, rule, action, severity, scores=None,
               reasons=None, trust=None, would_block=False, isolate_hold=None, contain=None) -> dict:
        """isolate_hold: why this finding, though its rule is in auto_isolate_rules, must
        not isolate the device (said in the event when auto_isolate is on or dry-run).
        contain: the name to contain for this finding (default: the registrable domain)."""
        evt = events_mod.make_event(
            device=dev.name, ip=dev.ip, mac=dev.mac, domain=domain,
            rule=rule, action=action, severity=severity, scores=scores,
            reasons=reasons, trust=trust, would_block=would_block)
        # Any web page can make a browser look up thousands of made-up names, so one
        # device's alerts are capped per minute (a block still happens; only its alert
        # is dropped). The flood itself still shows up as a dga_burst alert.
        # Findings that can isolate or contain have a budget of their own: a device flooding
        # junk lookups must not be able to push the one alert that matters over the cap
        # (and skip the isolation with it).
        acting = rule in (self.cfg.get("auto_isolate_rules") or ()) or rule in (self.cfg.get("contain_rules") or ())
        rate_key = dev.name + ("|acting" if acting else "")
        if self._over_rate(rate_key):
            self.stats["rate_limited"] += 1
            return evt
        # A device re-querying the same domain family is one finding, not fifty.
        # Blocks are always recorded; only repeat recommendations are suppressed.
        if (action == "recommend" or rule == "upstream_block") and self._is_repeat(dev.name, domain, rule) \
                and not self._confirm_due(dev.name, domain, rule):
            self.stats["suppressed"] += 1
            return evt
        self._count_alert(rate_key)
        self._auto_isolate(dev, evt, isolate_hold)   # before the write: the alert says what happened
        self._contain(dev, evt, contain)
        self.events.write(evt)
        self.state.record_event(evt)
        if action == "block":
            self.stats["blocked"] += 1
        elif action == "recommend":
            self.stats["recommended"] += 1
        self._maybe_freeze(dev, evt)
        return evt

    # -- containment: what one device was caught reaching, refused for every device ----
    def _contain(self, dev, evt, name: str | None = None) -> None:
        """Opt-in (contain): the destination behind a high-confidence alert is refused for the
        whole network for contain_days: by Ghostwall itself in inline mode, by AdGuard Home /
        Pi-hole through ghostwall-dnsblock, and (gateway mode) the addresses it answered with
        are dropped in both directions. Dry-run, and "on" while learning, only say
        "would_contain". Never raises. Never a trusted name, a popular site, a shared platform
        or an internal name; at most contain_max_per_day new ones a day."""
        mode = self.cfg.get("contain", "off")
        rule = evt["rule"]
        if mode not in ("dry-run", "on") or rule not in (self.cfg.get("contain_rules") or ()):
            return
        reasons = evt.setdefault("reasons", [])
        try:
            domain = evt["domain"]
            name = (name or registrable_part(domain)).rstrip(".").lower()
            skip = self._contain_skip(domain, name, evt)
            if skip:
                reasons.append(f"not blocked for every device: {skip}")
                return
            days = float(self.cfg.get("contain_days", 7))
            if rule == "dns_tunnel" and self._web_like(dev.name, domain) and not self.state.contained_by(name):
                wait = self._confirm_hold(dev.name, domain, rule, "contain")
                if wait:
                    evt["would_contain"] = name
                    reasons.append(f"not blocked for every device yet: {wait}; it is if this continues")
                    return
            with self._contain_lock:
                if self.state.contained_by(name):
                    self.state.contain(self.state.contained_by(name), rule, dev.name, days)   # extends it
                    reasons.append(f"{name} is already blocked for every device (contained)")
                    return
                dry = "contain is dry-run" if mode == "dry-run" else \
                    "learning mode (alerts only): sudo ghostwall learning off" if self.state.learning else None
                if dry:
                    evt["would_contain"] = name
                    reasons.append(f"would block {name} for every device ({rule}); not blocked: {dry}")
                    return
                cap = int(self.cfg.get("contain_max_per_day", 20))
                # a listed name does not count: blocking it harms nobody, and junk lookups of
                # listed names must not be able to use the cap up before the real thing
                if rule != "threat_feed" and self.state.containments_within(86400, skip_rule="threat_feed") >= cap:
                    evt["would_contain"] = name
                    reasons.append(f"not blocked for every device: {cap} containment(s) in the last day is "
                                   "the cap (contain_max_per_day)")
                    return
                ips = self._contain_block_ips(name, days)
                self.state.contain(name, rule, dev.name, days, ips)
                self.stats["contained"] += 1
                evt["contained"] = name
                where = "your DNS server refuses it once ghostwall-dnsblock has pushed it (DNS_BLOCK_FEED=on)" \
                    if self.shadow else "Ghostwall refuses it, and so does your DNS server if ghostwall-dnsblock is on"
                text = f"blocked {name} for every device for {days:g} days ({rule}): {where}"
                if ips:
                    text += (f"; {len(ips)} address(es) it answered with are dropped at the gateway, "
                             "to and from")
                reasons.append(text + f"; undo: sudo ghostwall uncontain {name}")
            print(f"[ghost-dns] contained {name} ({rule} on {dev.name}, event {evt['event_id']}, "
                  f"{len(ips)} address(es))", file=sys.stderr, flush=True)
        except Exception as exc:  # noqa: BLE001 (a bug here must never cost the alert)
            evt.pop("contained", None)
            reasons.append(f"blocking it for every device FAILED ({str(exc).strip()[:200] or type(exc).__name__})")
            print(f"[ghost-dns] contain failed for {evt.get('domain')}: {exc!r}", file=sys.stderr, flush=True)

    def _contain_skip(self, domain: str, name: str, evt) -> str | None:
        """Why this finding must not become a network-wide block, or None."""
        if "." not in name or is_internal(name) or is_public_suffix(name):
            return f"{name} is not one site's own domain"
        if evt["rule"] == "dga_high" and evt.get("severity") != "high":
            return "the name is not new to this network"
        if evt["rule"] != "threat_feed" and self._web_like(str(evt.get("device")), domain) \
                and not self.state.is_new(name, int(self.cfg["novelty_days"])):
            # Evidence a web page can produce (address lookups only) never takes away a site
            # the household already uses. Evidence a page cannot produce (a tunnel carrying
            # TXT / NULL / CNAME / MX queries) still does: otherwise malware would only have
            # to look its server up once and wait novelty_days to be left alone for good.
            return (f"{name} is not new to this network (in use for {self.cfg['novelty_days']}+ days) and "
                    "every lookup was one a web page can cause")
        # your own Trust counts; the starter allowlist (whole clouds) does not: a listed or
        # tunnelling host under one of those is exactly what containment is for
        if self.state.trusts(name) or self.state.user_trusts(registrable_part(name)):
            return f"you trust {name}"
        if abused_service(domain) or abused_service(name):
            return "it is on a shared service (other people's pages live there too)"
        reg = registrable_part(name)
        if name == reg and self.det.popular.match(name, self.clock()):
            return f"{name} is a popular site; one alert is not enough to block it for everyone"
        return None

    # -- confirmation: one lookup is something any web page or email can cause ----------
    def _count_qtype(self, device: str, domain: str, qtype: str) -> None:
        apex = registrable_part(domain)
        if apex == domain:
            return
        key = (device, apex)
        with self._pending_lock:
            c = self._qtypes.get(key)
            if c is None:
                c = self._qtypes[key] = [0, 0]
                while len(self._qtypes) > 5000:
                    self._qtypes.popitem(last=False)
            c[0] += 1
            if str(qtype).upper() not in ADDRESS_QTYPES:
                c[1] += 1

    def _web_like(self, device: str, domain: str) -> bool:
        """True if every lookup this device made under the domain's apex was an address
        lookup (A, AAAA, HTTPS): the only kind a web page can make a browser send. A real
        tunnel tool carries its data in TXT, NULL, CNAME or MX queries."""
        with self._pending_lock:
            c = self._qtypes.get((device, registrable_part(domain)))
        return c is None or c[1] == 0

    def _confirm_hold(self, device: str, domain: str, rule: str, what: str) -> str | None:
        """Why this finding may not act yet (the first sighting, or one within
        confirm_seconds of it), or None once it has continued past that. Used once: after
        None the same finding does not come back until event_dedupe_seconds has passed."""
        wait = float(self.cfg.get("confirm_seconds", 300))
        if wait <= 0:
            return None
        key = (device, registrable_part(domain), rule, what)
        now = self.state.clock().timestamp()
        text = (f"one sighting is something any web page or email can cause, so this waits until it "
                f"is seen again {wait / 60:g}+ minutes later (confirm_seconds)")
        with self._pending_lock:
            first = self._pending.get(key, 0.0)
            if first is None:                       # already used
                return text
            if not first or now - first > 86400 or now < first:
                self._pending[key] = now
                while len(self._pending) > 5000:
                    self._pending.popitem(last=False)
                return text
            if now - first < wait:
                return text
            self._pending[key] = None
            return None

    def _confirm_due(self, device: str, domain: str, rule: str) -> bool:
        """A finding waiting for confirmation has continued long enough: its repeat is an
        alert of its own (not suppressed), so the action and its reason are on record."""
        wait = float(self.cfg.get("confirm_seconds", 300))
        reg, now = registrable_part(domain), self.state.clock().timestamp()
        with self._pending_lock:
            return any(first and wait <= now - first <= 86400
                       for what in ("isolate", "contain")
                       for first in (self._pending.get((device, reg, rule, what)),))

    def _contain_block_ips(self, name: str, days: float) -> list[str]:
        """Gateway mode: drop the public IPv4 addresses `name` (or a name under it) answered
        with lately, unless another domain answered with the same address (shared hosting,
        a CDN). Returns the addresses now in the firewall's blocked_ip set."""
        if not self._ip_block_ready():
            return []
        reg = registrable_part(name)
        with self._ips_lock:
            cand = [ip for host, ips in self._host_ips.items() if host == name or host.endswith("." + name)
                    for ip in ips]
            shared = {ip for ip in cand if any(r != reg and self.state.contained_by(r) is None
                                               for r in self._ip_regs.get(ip, ()))}
        out = []
        timeout = f"{max(1, int(days * 24))}h"
        limit = int(self.cfg.get("contain_max_ips", 8))
        for ip in dict.fromkeys(cand):
            if ip in shared or not _blockable_ip(ip) or self._is_this_box(ip):
                continue
            if self._protected_ip(ip):
                # whoever runs the bad domain chooses what it resolves to: it must never be
                # able to point this firewall at a DNS resolver or at something you named
                print(f"[ghost-dns] not dropping {ip} for {name}: a protected address "
                      "(a DNS resolver, this box's upstream, or contain_protect)", file=sys.stderr, flush=True)
                continue
            if len(out) >= limit:
                break
            try:
                self.enforcer.block_ip(ip, timeout=timeout)
            except Exception as exc:  # noqa: BLE001 (no ghostwall table: the DNS block still holds)
                print(f"[ghost-dns] could not drop {ip} for {name}: {exc!r}", file=sys.stderr, flush=True)
                continue
            out.append(ip)
            self._contained_ips[ip] = name
        return out

    def _protected_ip(self, ip: str) -> bool:
        """Addresses a containment never drops: this box's DNS upstreams and system
        resolvers, the public DNS resolvers in netconf/doh_ips.txt (your DNS server's
        upstream is almost certainly one of them), and the networks in contain_protect."""
        nets = getattr(self, "_protected_nets", None)
        if nets is None:
            cands = [h for h, _ in self._upstreams()] + [str(x) for x in (self.cfg.get("contain_protect") or ())]
            for path in ("/etc/resolv.conf", os.path.join(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__))), "netconf", "doh_ips.txt")):
                try:
                    with open(path, encoding="utf-8", errors="replace") as f:
                        for line in f:
                            cands += line.split("#", 1)[0].replace("nameserver", " ").split()
                except OSError:
                    pass
            nets = []
            for c in cands:
                try:
                    nets.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    continue
            self._protected_nets = nets
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(a.version == n.version and a in n for n in nets)

    def _ip_block_ready(self) -> bool:
        return (self.cfg.get("contain") == "on" and bool(self.cfg.get("contain_ips", True))
                and getattr(self.enforcer.backend, "name", "") == "nft")

    def note_ips(self, host: str, ips) -> None:
        """An answer for `host` carried these addresses. Kept (bounded) so a containment can
        drop them; and if one is an address dropped for a contained name while `host` is not
        contained, the address is shared: it is let through again at once."""
        if not ips or not self._ip_block_ready():
            return
        host = host.rstrip(".").lower()
        reg = registrable_part(host)
        with self._ips_lock:
            self._host_ips[host] = tuple(ips)
            self._host_ips.move_to_end(host)
            while len(self._host_ips) > 20000:
                self._host_ips.popitem(last=False)
            if len(self._ip_regs) > 100000:
                self._ip_regs.clear()
            for ip in ips:
                regs = self._ip_regs.setdefault(ip, set())
                if len(regs) < 8:
                    regs.add(reg)
            hit = [ip for ip in ips if ip in self._contained_ips]
        if hit and self.state.contained_by(host) is None:
            for ip in hit:
                self.release_ip(ip, f"{host} answers with it too (a shared address)")

    def release_ip(self, ip: str, why: str = "") -> None:
        self._contained_ips.pop(ip, None)
        self.state.uncontain_ip(ip)
        try:
            self.enforcer.unblock_ip(ip)
        except Exception as exc:  # noqa: BLE001
            print(f"[ghost-dns] could not unblock {ip}: {exc!r}", file=sys.stderr, flush=True)
            return
        if why:
            print(f"[ghost-dns] no longer dropping {ip}: {why}", file=sys.stderr, flush=True)

    def uncontain(self, name: str) -> bool:
        """End a containment (the CLI, the control API, Trust). False if there was none."""
        ips = self.state.uncontain(name)
        if ips is None:
            return False
        for ip in ips:
            self._contained_ips.pop(ip, None)
            try:
                self.enforcer.unblock_ip(ip)
            except Exception as exc:  # noqa: BLE001
                print(f"[ghost-dns] could not unblock {ip}: {exc!r}", file=sys.stderr, flush=True)
        return True

    def _feed_hold(self, domain: str, listed: str, exact: bool, now: float) -> str | None:
        """Why a threat_feed hit is not proof enough to cut a device off, or None. Checked
        only for auto_isolate; the alert and the block are unchanged."""
        if not exact:
            return f"{domain} only matched {listed}, a parent domain on the list"
        if self.det.popular.match(domain, now):
            return f"{registrable_part(domain)} is a popular site (a shared platform or CDN)"
        if abused_service(domain):
            return "it is on a shared service malware abuses, not proof about this device"
        labels = self.det.threat_feed.sources(listed)
        need = int(self.cfg.get("auto_isolate_min_sources", 2))
        if labels and len(labels) < need:
            return (f"only {len(labels)} list names it ({labels[0]}); some lists take submissions from "
                    f"anyone, so cutting a device off needs {need} (auto_isolate_min_sources)")
        if labels and all(lab.endswith("(phishing)") for lab in labels):
            return "only phishing lists name it (someone opened a link; the device is not infected)"
        return None

    def _auto_isolate(self, dev, evt, hold: str | None = None) -> None:
        """Opt-in (auto_isolate): cut off the device behind a high-confidence alert, the way
        POST /isolate does, record it in state.json, and say so in the event. Dry-run, and
        "on" while learning, in shadow mode, without nft or without pi_ip, only say
        "would_isolate". Never raises: a failure here must not cost the alert, and says so
        in the event ("auto_isolate_failed"). The Pi, loopback, exempt and unnamed devices
        are never isolated; nor is one past the hourly cap (kept across restarts), nor one
        you released from an isolation for the same finding."""
        mode = self.cfg.get("auto_isolate", "off")
        rule = evt["rule"]
        if mode not in ("dry-run", "on") or rule not in (self.cfg.get("auto_isolate_rules") or ()):
            return
        reasons = evt.setdefault("reasons", [])
        name = dev.name
        try:
            skip = hold or self._iso_skip(dev)
            ip = None if skip else self._iso_address(dev)
            if not skip and ip is None:
                skip = f"{name} has no IPv4 LAN address to isolate (the isolated set holds IPv4 only)"
            if skip:
                reasons.append(f"not isolated automatically: {skip}")
                return
            if rule == "threat_feed" or (rule == "dns_tunnel" and self._web_like(name, evt["domain"])):
                wait = self._confirm_hold(name, evt["domain"], rule, "isolate")
                if wait:
                    evt["would_isolate"] = True
                    reasons.append(f"not isolated yet: {wait}; {name} is isolated if it keeps reaching for this")
                    return
            with self._iso_lock:   # decide() runs on many threads: one check-and-isolate at a time
                if self.state.is_isolated(name):
                    reasons.append(f"{name} is already isolated")
                    return
                dry = self._iso_dry(mode)
                if dry:
                    evt["would_isolate"] = True
                    reasons.append(f"would isolate {name} automatically ({rule}); not isolated: {dry}")
                    return
                window = float(self.cfg.get("event_dedupe_seconds", 86400))
                key = f"{name}|{registrable_part(evt['domain'])}|{rule}|isolated"
                if window > 0 and self.state.recently(key, window):
                    reasons.append(f"not isolated again: {name} was isolated for this finding and "
                                   "then released (until event_dedupe_seconds passes)")
                    return
                cap = int(self.cfg.get("auto_isolate_max_per_hour", 2))
                if self.state.auto_isolations_within(3600) >= cap:
                    evt["would_isolate"] = True
                    reasons.append(f"not isolated: {cap} automatic isolation(s) in the last hour is the "
                                   f"cap (auto_isolate_max_per_hour); isolate by hand if you agree: "
                                   f"/fw isolate {name}")
                    return
                try:
                    self.enforcer.isolate(ip)
                except Exception as exc:  # noqa: BLE001 (nft failed, table missing...)
                    self._iso_failed(evt, name, exc)
                    return
                try:
                    self.state.isolate(name, ip)
                except Exception as exc:  # noqa: BLE001 (state.json unwritable): undo the kernel side
                    try:
                        self.enforcer.release(ip)
                    except Exception:  # noqa: BLE001
                        pass
                    self._iso_failed(evt, name, exc)
                    return
                if window > 0:
                    self.state.seen_alert(key, window)   # records it: a release sticks
                self.state.note_auto_isolation()
                self.stats["auto_isolated"] += 1
                evt["auto_isolated"] = True
                reasons.append(f"isolated {name} ({ip}) automatically: {rule}; undo: the Release button, "
                               f"the dashboard or sudo ghostwall release {name}")
            print(f"[ghost-dns] auto-isolated {name} at {ip} ({rule}, event {evt['event_id']})",
                  file=sys.stderr, flush=True)
        except Exception as exc:  # noqa: BLE001 (a bug here must never cost the alert)
            self._iso_failed(evt, name, exc)

    def _iso_failed(self, evt, name, exc) -> None:
        evt.pop("auto_isolated", None)
        evt["would_isolate"] = True
        evt["auto_isolate_failed"] = True
        evt.setdefault("reasons", []).append(
            f"automatic isolation FAILED ({str(exc).strip()[:200] or type(exc).__name__}); "
            f"isolate by hand: /fw isolate {name}")
        print(f"[ghost-dns] auto-isolate of {name} failed: {exc!r}", file=sys.stderr, flush=True)

    def _iso_dry(self, mode: str) -> str | None:
        """Why "on" can only be a dry run right now, or None (it may isolate)."""
        if mode == "dry-run":
            return "auto_isolate is dry-run"
        if self.shadow:
            return "shadow mode only watches"
        if self.state.learning:
            return "learning mode is on"
        if self.enforcer.backend.name != "nft":
            return 'enforcement is off (needs gateway mode and "enforce": "nft")'
        if not self.cfg.get("pi_ip"):
            return 'set "pi_ip" first, so this box can never isolate itself'
        if self.cfg.get("auto_isolate_need_antispoof", True) and not self.enforcer.antispoof_active():
            return ('the firewall\'s anti-spoofing is off, so another device could send lookups under '
                    'this one\'s address to get it cut off: set "antispoof": "on" in netconf/config.json, '
                    're-run gen.py and reload (or "auto_isolate_need_antispoof": false to accept that)')
        return None

    def _iso_skip(self, dev) -> str | None:
        """Devices that are never isolated, whatever the mode: unnamed (/release works on
        names, so it could not be undone), exempt, and this box itself."""
        name = dev.name
        named = self.devices.device_for_name(name)
        if named is None:
            return f"{name} has no name yet (sudo ghostwall name {name} NAME)"
        exempt = set(self.cfg.get("auto_isolate_exempt") or ())
        if name in exempt or dev.ip in exempt or named.ip in exempt:
            return f"{name} is exempt (auto_isolate_exempt)"
        if self._is_this_box(dev.ip) or self._is_this_box(named.ip):
            return f"{name} is this box"
        return None

    def _iso_address(self, dev) -> str | None:
        """The address to put in the isolated set: where it queried from, or (queried over
        IPv6) its address in devices.json. Only a private IPv4 address, never the Pi's."""
        named = self.devices.device_for_name(dev.name)
        for ip in (dev.ip, named.ip if named is not None else None):
            try:
                a = ipaddress.ip_address(str(ip))
            except ValueError:
                continue
            if (a.version == 4 and a.is_private and not (a.is_loopback or a.is_link_local
                                                         or a.is_unspecified or a.is_multicast)
                    and not self._is_this_box(str(a))):
                return str(a)
        return None

    def _is_this_box(self, ip: str) -> bool:
        """The Pi itself (pi_ip) and loopback are never isolated, whatever the exempt list
        says."""
        if ip == self.cfg.get("pi_ip"):
            return True
        try:
            return ipaddress.ip_address(ip).is_loopback
        except ValueError:
            return True   # not an address we could put in an nft set

    def _over_rate(self, device: str) -> bool:
        limit = int(self.cfg.get("alert_rate_per_device", 30))
        if limit <= 0:
            return False
        now = self.clock()
        with self._events_lock:
            times = [t for t in self._alert_times.get(device, []) if now - t < 60.0]
            self._alert_times[device] = times
            return len(times) >= limit

    def _count_alert(self, device: str) -> None:
        with self._events_lock:
            if len(self._alert_times) > 10000:  # bound memory: a LAN has far fewer devices
                self._alert_times.clear()
            self._alert_times.setdefault(device, []).append(self.clock())

    def _is_repeat(self, device: str, domain: str, rule: str = "") -> bool:
        """True if this device already got this kind of alert for this registrable
        domain within event_dedupe_seconds. Records the sighting otherwise (in state.json,
        so restarts don't repeat alerts)."""
        window = float((self.cfg.get("rule_dedupe_seconds") or {}).get(
            rule, self.cfg.get("event_dedupe_seconds", 86400)))
        if window <= 0:
            return False
        return self.state.seen_alert(f"{device}|{registrable_part(domain)}|{rule}", window)

    def _maybe_freeze(self, dev, evt) -> None:
        order = {"info": 0, "warn": 1, "high": 2, "critical": 3}
        want = order.get(self.cfg.get("freeze_severity", "high"), 2)
        if self.capture and order.get(evt["severity"], 1) >= want:
            self.capture.freeze(dev.name, evt["event_id"],
                                dns_history=[evt["domain"]])

    # -- wire handling ----------------------------------------------------
    def handle_packet(self, client_ip: str, packet: bytes, tcp: bool = False) -> bytes:
        self.stats["queries"] += 1
        q = dnsmsg.parse_question(packet)
        if q is None:
            # Not a question we understand; just forward it blindly.
            up = self._forward(packet, tcp)
            return up if up is not None else packet
        self._log_query(client_ip, q)
        later = self._score_after_answer(q)
        if later:
            decision = Decision("allow", "scored after the answer")
        else:
            try:
                decision = self.decide(client_ip, q.name, q.qtype_name)
            except Exception as exc:  # noqa: BLE001
                # FAIL OPEN: a bug in scoring/state must never take DNS down.
                self.stats["failopen"] += 1
                print(f"[ghost-dns] decide() failed for {q.name}: {exc!r}; forwarding", file=sys.stderr, flush=True)
                decision = Decision("allow", "failopen")
        if decision.action != "block" and self.state.isolated and \
                self.state.is_isolated(self._device(client_ip).name):
            # isolated means isolated: its lookups are still scored and logged above, but
            # nothing is resolved for it (a recursive answer is a way out, a few bytes a time)
            self.stats["isolated_refused"] = self.stats.get("isolated_refused", 0) + 1
            decision = Decision("block", "isolated")
        if decision.action == "block":
            if self.cfg.get("block_response") == "nxdomain":
                return dnsmsg.build_nxdomain(packet, q.end)
            return dnsmsg.build_sinkhole(packet, q, self.cfg["sinkhole_ip4"],
                                         self.cfg.get("sinkhole_ip6"))
        up = self._forward(packet, tcp)
        rcode = dnsmsg.reply_status(up) if up is not None else None
        zone = dnsmsg.negative_zone(up) if rcode == "NXDOMAIN" else None
        if later:
            self._queue_later(client_ip, q, rcode, zone)
        elif rcode:
            try:
                self.note_answer(client_ip, q.name, rcode, zone)
            except Exception as exc:  # noqa: BLE001 - the answer must still go out
                print(f"[ghost-dns] note_answer() failed for {q.name}: {exc!r}", file=sys.stderr, flush=True)
        if up is None:
            self.stats["errors"] += 1
            return dnsmsg.build_servfail(packet, q.end)
        self.stats["forwarded"] += 1
        self._record_resolved(client_ip, q.name, up)
        if self._ip_block_ready():
            self.note_ips(q.name, dnsmsg.extract_answer_ips(up))
        return up

    def _score_after_answer(self, q) -> bool:
        """Learning mode (alerts only) can block nothing but names on the confirmed
        blocklist, a set lookup. So a new name doesn't wait for the models (milliseconds
        each, more on a Pi) before its answer: it is queued once the answer is in (so its
        rcode goes along, for nx_burst) and scored right after, and alerts come out the
        same. Returns False (score now) when blocking is on, for a blocklisted name, or
        with score_after_answer off."""
        if self.shadow or not self.cfg.get("score_after_answer", True) or not self.state.learning:
            return False
        return not self.state.is_blocked(q.name.rstrip(".").lower())

    def _queue_later(self, client_ip: str, q, rcode: str | None, zone: str | None) -> None:
        if self._later is None:
            with self._later_lock:
                if self._later is None:
                    self._later = queue.Queue(maxsize=4096)
                    threading.Thread(target=self._score_worker, name="ghost-dns-score", daemon=True).start()
        try:
            self._later.put_nowait((client_ip, q.name, q.qtype_name, rcode, zone))
        except queue.Full:   # a flood: score in line again, slower answers but no lost alerts
            try:
                self.decide(client_ip, q.name, q.qtype_name, rcode=rcode, nx_zone=zone)
            except Exception as exc:  # noqa: BLE001 - FAIL OPEN, as in handle_packet
                self.stats["failopen"] += 1
                print(f"[ghost-dns] decide() failed for {q.name}: {exc!r}", file=sys.stderr, flush=True)

    def _score_worker(self) -> None:
        while True:
            client_ip, name, qtype, rcode, zone = self._later.get()
            try:
                self.decide(client_ip, name, qtype, rcode=rcode, nx_zone=zone)
            except Exception as exc:  # noqa: BLE001 (the answer went out; say why no alert)
                self.stats["failopen"] += 1
                print(f"[ghost-dns] decide() failed for {name}: {exc!r}", file=sys.stderr, flush=True)
            finally:
                self._later.task_done()

    def drain(self) -> None:
        """Wait until every query answered before scoring has been scored."""
        if self._later is not None:
            self._later.join()

    def _upstreams(self) -> list[tuple[str, int]]:
        """Primary first, then fallbacks. A primary that just failed is skipped
        for a few seconds so a dead upstream costs one timeout, not one per query."""
        primary = (self.cfg["upstream"], int(self.cfg["upstream_port"]))
        fallbacks = []
        for f in self.cfg.get("upstream_fallbacks") or []:
            host, _, port = str(f).partition(":")
            fallbacks.append((host, int(port) if port else 53))
        if fallbacks and time.monotonic() < self._primary_down_until:
            return fallbacks + [primary]
        return [primary] + fallbacks

    def _forward(self, packet: bytes, tcp: bool = False) -> bytes | None:
        ups = self._upstreams()
        for i, (host, port) in enumerate(ups):
            reply = self._ask(packet, host, port, tcp)
            if reply is not None:
                if (host, port) != (self.cfg["upstream"], int(self.cfg["upstream_port"])):
                    self.stats["fallbacks"] += 1
                return reply
            if i == 0 and (host, port) == (self.cfg["upstream"], int(self.cfg["upstream_port"])):
                self._primary_down_until = time.monotonic() + float(self.cfg.get("primary_retry_seconds", 10))
        return None

    def _ask(self, packet: bytes, host: str, port: int, tcp: bool) -> bytes | None:
        timeout = float(self.cfg["dns_timeout"])
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        try:
            if tcp:
                with socket.socket(family, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((host, port))
                    s.sendall(struct.pack(">H", len(packet)) + packet)
                    head = _recv_exact(s, 2)
                    if head is None:
                        return None
                    return _recv_exact(s, struct.unpack(">H", head)[0])
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(packet, (host, port))
                return s.recvfrom(65535)[0]
        except (OSError, socket.timeout, struct.error):
            return None

    def _log_query(self, client_ip: str, q) -> None:
        path = self.cfg.get("query_log")
        if not path:
            return
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        line = f"{ts} ghost-dns[{self.stats['queries']}]: query[{q.qtype_name}] {q.name} from {client_ip}\n"
        try:
            with self._query_lock:
                self._append(path, line)
        except OSError:
            pass

    def _append(self, path: str, text: str) -> None:
        """Append to an inline-mode log. Past log_max_bytes the file is moved to
        <path>.1 (replacing the previous one) and started again, so it can't fill the disk."""
        try:
            if os.path.getsize(path) > int(self.cfg.get("log_max_bytes", 16 * 2**20)):
                os.replace(path, path + ".1")
        except OSError:
            pass  # no file yet
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)

    def _record_resolved(self, client_ip: str, domain: str, reply: bytes) -> None:
        path = self.cfg.get("resolved_ips_path")
        if not path:
            return
        ips = dnsmsg.extract_answer_ips(reply)
        if not ips:
            return
        ts = events_mod.now_iso()
        window = float(self.cfg.get("resolved_dedupe_seconds", 300))
        now = time.monotonic()
        with self._resolved_lock:
            # Dedupe within a short window so the file does not grow a line per
            # answer forever, while still re-writing an actively-used IP often
            # enough that ghost-flow's TTL never expires it.
            fresh = []
            for ip in ips:
                last = self._recent_ip.get(ip)
                if last is not None and now - last < window:
                    continue
                self._recent_ip[ip] = now
                fresh.append(ip)
            if len(self._recent_ip) > 50000:  # bound the dedupe map too
                self._recent_ip = _prune(self._recent_ip, now - window, 50000)
            if not fresh:
                return
            try:
                self._append(path, "".join(
                    json.dumps({"time": ts, "ip": ip, "domain": domain, "client": client_ip},
                               separators=(",", ":")) + "\n" for ip in fresh))
            except OSError:
                pass

    # -- server loop ------------------------------------------------------
    @staticmethod
    def _client_ip(addr) -> str:
        return str(addr[0]).split("%", 1)[0]  # drop an IPv6 scope id

    def _udp_reply(self, sock, packet, addr) -> None:
        try:
            reply = self.handle_packet(self._client_ip(addr), packet)
            sock.sendto(reply, addr)
        except Exception:  # noqa: BLE001 - one bad query must not kill DNS
            self.stats["errors"] += 1

    def _tcp_conn(self, conn, addr) -> None:
        """Serve DNS-over-TCP: 2-byte length prefix, several queries per connection."""
        try:
            conn.settimeout(float(self.cfg.get("tcp_timeout", 5)))
            for _ in range(16):
                head = _recv_exact(conn, 2)
                if head is None:
                    break
                packet = _recv_exact(conn, struct.unpack(">H", head)[0])
                if packet is None:
                    break
                reply = self.handle_packet(self._client_ip(addr), packet, tcp=True)
                conn.sendall(struct.pack(">H", len(reply)) + reply)
        except (OSError, socket.timeout, struct.error):
            pass
        except Exception:  # noqa: BLE001
            self.stats["errors"] += 1
        finally:
            conn.close()

    def _bind(self, family: int, kind: int, host: str, port: int):
        sock = socket.socket(family, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)  # own the v6 side only
        sock.bind((host, port))
        if kind == socket.SOCK_STREAM:
            sock.listen(128)
        return sock

    def _udp_loop(self, sock, pool) -> None:
        while not self._stop.is_set():
            try:
                packet, addr = sock.recvfrom(65535)
            except OSError:
                break
            pool.submit(self._udp_reply, sock, packet, addr)

    def _tcp_loop(self, sock, pool) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except OSError:
                break
            pool.submit(self._tcp_conn, conn, addr)

    def start(self) -> None:
        """Bind UDP+TCP on IPv4 and (when available) IPv6, then serve until stop().

        Listeners that cannot bind (e.g. no IPv6) are skipped with a warning;
        the IPv4 UDP listener is mandatory."""
        port = int(self.cfg["dns_port"])
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=int(self.cfg.get("workers", 16)))
        self._pool = pool
        plans = [("udp4", socket.AF_INET, socket.SOCK_DGRAM, self.cfg["dns_host"], self._udp_loop, True),
                 ("tcp4", socket.AF_INET, socket.SOCK_STREAM, self.cfg["dns_host"], self._tcp_loop, False)]
        host6 = self.cfg.get("dns_host6")
        if host6:
            plans += [("udp6", socket.AF_INET6, socket.SOCK_DGRAM, host6, self._udp_loop, False),
                      ("tcp6", socket.AF_INET6, socket.SOCK_STREAM, host6, self._tcp_loop, False)]
        self.listening: list[str] = []
        for name, fam, kind, host, loop, mandatory in plans:
            try:
                sock = self._bind(fam, kind, host, port)
            except OSError as exc:
                if mandatory:
                    raise
                print(f"[ghost-dns] {name} listener skipped: {exc}", file=sys.stderr, flush=True)
                continue
            self._socks.append(sock)
            self.listening.append(name)
            threading.Thread(target=loop, args=(sock, pool), daemon=True, name=f"dns-{name}").start()

    def stop(self) -> None:
        self._stop.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        try:
            self._pool.shutdown(wait=False)
        except AttributeError:
            pass
        self.state.flush()

    def serve_forever(self) -> None:
        self.start()
        try:
            self._stop.wait()
        finally:
            self.stop()


def _recv_exact(sock, n: int) -> bytes | None:
    """Read exactly n bytes, or None if the peer closes/times out first."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (OSError, socket.timeout):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf
