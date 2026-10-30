"""The connection-level decision-maker.

Sees every forwarded first-packet (via NFQUEUE on the Pi, or a replay source in
tests), and raises recommendations for:
  * raw_ip  -- a new connection to a public IP ghost-dns never resolved
  * beacon  -- near-constant-interval repeat connections (C2 call-home)
and enriches TLS flows with a JA4 fingerprint.

Safety: the NFQUEUE verdict is ACCEPT for everything. ghost-flow NEVER drops a
packet or blackholes a destination unless enforcement is explicitly turned on
(enforce=nft) AND auto-block is opted in AND learning mode is off -- matching
policy: auto-blocking is off; recommendations are always human-reviewed.
"""
from __future__ import annotations

import os
import sys
import time

import beacon as beacon_mod  # noqa: F401 (type hint only)
import packet as packet_mod
import tls as tls_mod
from ja4 import ja4 as compute_ja4

# ghost-flow is an accessory to the ghost-dns core: reuse its events writer,
# enforcement bridge and device map rather than duplicating the contracts.
GHOST_DNS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "ghost_dns")
sys.path.insert(0, GHOST_DNS)
import events as events_mod          # noqa: E402

_PSEUDO = {"raw_ip": "raw-ip.flow.ghostwall", "beacon": "beacon.flow.ghostwall"}
_ALERT_COOLDOWN = 300.0  # seconds; don't re-raise the same (src,dst,rule)


class Inspector:
    def __init__(self, cfg, resolved, rawip, beacon, device_map, event_log,
                 enforcer=None, capture=None, autoblock: bool = False):
        self.cfg = cfg
        self.resolved = resolved
        self.rawip = rawip
        self.beacon = beacon
        self.devices = device_map
        self.events = event_log
        self.enforcer = enforcer
        self.capture = capture
        self.autoblock = autoblock
        self.learning = bool(cfg.get("learning", True))
        self._ja4: dict[tuple, str] = {}
        self._last_alert: dict[tuple, float] = {}
        self.stats = {"packets": 0, "new_conns": 0, "raw_ip": 0, "beacon": 0,
                      "tls": 0, "blocked": 0}

    def inspect(self, raw: bytes, when: float | None = None) -> str:
        """Process one raw packet; return the NFQUEUE verdict ('accept'/'drop')."""
        now = when if when is not None else time.time()
        self.stats["packets"] += 1
        pkt = packet_mod.parse(raw)
        if pkt is None:
            return "accept"

        # TLS ClientHello enrichment (a later packet in the flow, not the SYN).
        if pkt.proto == packet_mod.PROTO_TCP and pkt.payload[:1] == b"\x16":
            ch = tls_mod.parse_client_hello(pkt.payload)
            if ch is not None:
                self.stats["tls"] += 1
                self._ja4[(pkt.src, pkt.dst)] = compute_ja4(ch)

        is_new = pkt.is_syn_only or pkt.proto == packet_mod.PROTO_UDP
        if not is_new:
            return "accept"
        self.stats["new_conns"] += 1

        reasons: list[str] = []
        rule: str | None = None
        severity = "warn"

        raw_reason = self.rawip.check(pkt.dst)
        if raw_reason:
            reasons.append(raw_reason)
            rule = "raw_ip"
            self.stats["raw_ip"] += 1

        beacon_reason = self.beacon.observe(pkt.src, pkt.dst, pkt.dport, now)
        if beacon_reason:
            reasons.append(beacon_reason)
            rule = "beacon"           # beacon outranks raw_ip for the rule name
            severity = "high"
            self.stats["beacon"] += 1

        if rule is None:
            return "accept"

        key = (pkt.src, pkt.dst, rule)
        last = self._last_alert.get(key)
        if last is not None and now - last < _ALERT_COOLDOWN:
            return "accept"
        self._last_alert[key] = now

        verdict = "accept"
        action = "recommend"
        do_block = (self.autoblock and not self.learning and rule == "beacon"
                    and self.enforcer is not None)
        if do_block:
            try:
                self.enforcer.block_ip(pkt.dst)
                action = "block"
                verdict = "drop"
                self.stats["blocked"] += 1
            except Exception:  # noqa: BLE001 - enforcement failure => stay in recommend
                action = "recommend"

        self._emit(pkt, rule, action, severity, reasons)
        return verdict

    def _emit(self, pkt, rule, action, severity, reasons) -> None:
        dev = self.devices.device_for_ip(pkt.src)
        domain = self.resolved.domain_for(pkt.dst) or _PSEUDO.get(rule, "flow.ghostwall")
        ja4 = self._ja4.get((pkt.src, pkt.dst))
        evt = events_mod.make_event(
            device=dev.name, ip=dev.ip, mac=dev.mac, domain=domain,
            dst_ip=pkt.dst, ja4=ja4, rule=rule, action=action,
            severity=severity, reasons=reasons,
            capture=f"dst {pkt.dst}:{pkt.dport}")
        self.events.write(evt)
        order = {"info": 0, "warn": 1, "high": 2, "critical": 3}
        want = order.get(self.cfg.get("freeze_severity", "high"), 2)
        if self.capture and order.get(severity, 1) >= want:
            self.capture.freeze(dev.name, evt["event_id"], dns_history=[domain])
