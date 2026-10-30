"""The decision-maker: score every DNS query, decide allow / recommend / block,
forward or sinkhole, emit events, and trigger a pcap freeze on real alerts.

`decide()` is pure (no sockets) and is where all the policy lives, so the whole
rule set is unit-testable without a network. `handle_packet()` wraps it with the
DNS wire format and upstream forwarding. `serve_forever()` is the UDP loop.

Blocking policy (deliberately conservative -- the models over-flag; full order in
docs/ARCHITECTURE.md):
  * allowlisted domain            -> ALLOW, no event
  * blocklisted domain            -> BLOCK (sinkhole), event rule=blocklist
  * dga >= block_threshold
        AND domain is new
        AND learning mode is off   -> BLOCK, promote to blocklist, event action=block
     (otherwise the same score      -> RECOMMEND: forwarded, event action=recommend)
  * dga >= recommend_threshold     -> RECOMMEND (forwarded), event action=recommend
  * everything else                -> ALLOW, no event
"""
from __future__ import annotations

import concurrent.futures
import json
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import struct
import sys

import dnsmsg
import events as events_mod
from detectors import RARE_TLDS, Detectors, is_internal, tld_of
from tokenizer import registrable_part


@dataclass
class Decision:
    action: str            # "allow" | "recommend" | "block"
    reason: str
    event: dict | None = None


class Resolver:
    def __init__(self, cfg, state, scorer, enforcer, device_map, event_log,
                 capture=None):
        self.cfg = cfg
        self.state = state
        self.scorer = scorer
        self.enforcer = enforcer
        self.devices = device_map
        self.events = event_log
        self.capture = capture
        self._resolved_lock = threading.Lock()
        self._query_lock = threading.Lock()
        self._recent_ip: dict[str, float] = {}   # ip -> monotonic last-written
        self._recent_events: dict[tuple, float] = {}  # (device, registrable) -> monotonic
        self._events_lock = threading.Lock()
        self._primary_down_until = 0.0   # monotonic; skip a dead primary upstream until then
        self._stop = threading.Event()
        self._socks: list = []
        # Shadow mode: scoring a log of queries someone else already answered.
        # Nothing here can block, so decisions are only ever recommendations.
        self.shadow = bool(cfg.get("shadow", False))
        self.clock = time.monotonic          # overridable, so tests can drive time
        self.det = Detectors(cfg)            # threat feed, DoH, tunnel, beacon, DGA burst
        self.stats = {"queries": 0, "blocked": 0, "recommended": 0, "suppressed": 0,
                      "forwarded": 0, "errors": 0, "fallbacks": 0, "failopen": 0}

    # -- policy (pure, no I/O except event log + state + enforcer) --------
    def decide(self, client_ip: str, domain: str, qtype: str) -> Decision:
        domain = domain.rstrip(".").lower()
        if not domain:
            return Decision("allow", "empty")
        dev = self.devices.device_for_ip(client_ip)
        now = self.clock()

        # Evidence that is checked BEFORE the allowlist: a known-bad host (an exact
        # feed match wins even over a trusted parent domain) and DoH bypass.
        feed = self.det.threat_feed.match(domain, now)
        if feed and (feed[1] or not self.state.is_allowed(domain)):
            listed, exact = feed
            enforce = (not self.state.learning) and not self.shadow
            why = [f"{listed} is on the threat feed"
                   + ("" if exact else f" (parent of {domain})")]
            if not enforce:
                why.append("not blocked (" + ("shadow mode" if self.shadow else "learning mode") + ")")
            evt = self._event(dev, domain, rule="threat_feed",
                              action="block" if enforce else "recommend",
                              severity="high", scores={"feed": 1.0}, reasons=why)
            return Decision("block" if enforce else "recommend", "threat_feed", evt)
        hit = self.det.doh.check(client_ip, domain)
        if hit:
            return Decision("recommend", hit.rule, self._emit_hit(dev, domain, hit))

        if self.state.is_allowed(domain):
            return Decision("allow", "allowlist")

        if is_internal(domain):          # homepi, *.ts.net, *.local, _svc._tcp... not internet names
            return Decision("allow", "internal")

        if self.state.is_blocked(domain):
            evt = self._event(dev, domain, rule="blocklist",
                              action="recommend" if self.shadow else "block",
                              severity="high",
                              reasons=["on confirmed blocklist"]
                              + (["shadow mode: not enforced"] if self.shadow else []))
            return Decision("recommend" if self.shadow else "block", "blocklist", evt)

        first_seen = self.state.note_seen(domain)
        is_new = self.state.is_new(domain, int(self.cfg["novelty_days"]))
        sc = self.scorer.score_one(domain)
        dga = sc["dga"]
        reasons = [f"dga score {dga:.2f}"]
        if is_new:
            reasons.append("first seen" if first_seen else "recently seen")

        # Behavioural detectors (not allowlisted names only).
        # Tunnelling stands on its own. A regular timer, though, is what EVERY app does
        # (updaters, telemetry, sync), so a beacon only counts when the name itself is
        # also odd: it scores as random-looking, or sits on a rarely-legitimate TLD.
        behaviour = None
        with self.det.lock:
            tun = self.det.tunnel.observe(dev.name, domain, now)
            bea = self.det.beacon.observe(dev.name, domain, now)
        if bea and not (dga >= float(self.cfg.get("beacon_min_dga", 0.5)) or tld_of(domain) in RARE_TLDS):
            bea = None
        for hit in (tun, bea):
            if hit and behaviour is None:
                behaviour = Decision("recommend", hit.rule, self._emit_hit(dev, domain, hit))

        # Many DIFFERENT random-looking domains from one device is a far stronger
        # signal than any single score.
        with self.det.lock:
            burst = self.det.burst.observe(dev.name, domain, dga, now)
        if burst:
            return Decision("recommend", burst.rule, self._emit_hit(dev, domain, burst))

        block_thr = float(self.cfg["block_threshold"])
        rec_thr = float(self.cfg["recommend_threshold"])

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
        corr_thr = float(self.cfg.get("corroborated_threshold", 0.80))
        if dga >= corr_thr and tld_of(domain) in RARE_TLDS:
            evt = self._event(dev, domain, rule="dga_corroborated", action="recommend",
                              severity="warn", scores=sc,
                              reasons=reasons + [f"rarely-legitimate TLD .{tld_of(domain)}"])
            return Decision("recommend", "dga_corroborated", evt)

        return behaviour or Decision("allow", "clean")

    def _emit_hit(self, dev, domain, hit) -> dict:
        return self._event(dev, domain, rule=hit.rule, action="recommend", severity=hit.severity,
                           scores=hit.scores or None, reasons=hit.reasons)

    def enforcer_block_hook(self, domain: str) -> None:
        """Domain blocks are enforced at the resolver (sinkhole); no kernel
        change needed. Hook kept for symmetry / future IP-level escalation."""
        return None

    def _event(self, dev, domain, *, rule, action, severity, scores=None,
               reasons=None) -> dict:
        evt = events_mod.make_event(
            device=dev.name, ip=dev.ip, mac=dev.mac, domain=domain,
            rule=rule, action=action, severity=severity, scores=scores,
            reasons=reasons)
        # A device re-querying the same domain family is one finding, not fifty.
        # Blocks are always recorded; only repeat recommendations are suppressed.
        if action == "recommend" and self._is_repeat(dev.name, domain, rule):
            self.stats["suppressed"] += 1
            return evt
        self.events.write(evt)
        self.state.record_event(evt)
        if action == "block":
            self.stats["blocked"] += 1
        elif action == "recommend":
            self.stats["recommended"] += 1
        self._maybe_freeze(dev, evt)
        return evt

    def _is_repeat(self, device: str, domain: str, rule: str = "") -> bool:
        """True if this device already got this kind of alert for this registrable
        domain within event_dedupe_seconds. Records the sighting otherwise."""
        window = float(self.cfg.get("event_dedupe_seconds", 86400))
        if window <= 0:
            return False
        key = (device, registrable_part(domain), rule)
        now = time.monotonic()
        with self._events_lock:
            last = self._recent_events.get(key)
            if last is not None and now - last < window:
                return True
            self._recent_events[key] = now
            if len(self._recent_events) > 20000:  # bound memory
                cutoff = now - window
                self._recent_events = {k: v for k, v in self._recent_events.items() if v >= cutoff}
        return False

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
        try:
            decision = self.decide(client_ip, q.name, q.qtype_name)
        except Exception as exc:  # noqa: BLE001
            # FAIL OPEN: a bug in scoring/state must never take DNS down.
            self.stats["failopen"] += 1
            print(f"[ghost-dns] decide() failed for {q.name}: {exc!r}; forwarding", file=sys.stderr, flush=True)
            decision = Decision("allow", "failopen")
        if decision.action == "block":
            if self.cfg.get("block_response") == "nxdomain":
                return dnsmsg.build_nxdomain(packet, q.end)
            return dnsmsg.build_sinkhole(packet, q, self.cfg["sinkhole_ip4"],
                                         self.cfg.get("sinkhole_ip6"))
        up = self._forward(packet, tcp)
        if up is None:
            self.stats["errors"] += 1
            return dnsmsg.build_servfail(packet, q.end)
        self.stats["forwarded"] += 1
        self._record_resolved(client_ip, q.name, up)
        return up

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
            with self._query_lock, open(path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass

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
                cutoff = now - window
                self._recent_ip = {k: v for k, v in self._recent_ip.items() if v >= cutoff}
            if not fresh:
                return
            try:
                with open(path, "a", encoding="utf-8") as f:
                    for ip in fresh:
                        f.write(json.dumps({"time": ts, "ip": ip, "domain": domain,
                                            "client": client_ip},
                                           separators=(",", ":")) + "\n")
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
