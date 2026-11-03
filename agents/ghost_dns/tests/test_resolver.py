"""Tests for resolver.decide() and the block wire path (no network needed)."""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
# fw_bot only for validate_events (no `config` dep); append so ghost_dns's
# own `config` still wins the import.
sys.path.append(os.path.join(os.path.dirname(HERE), "fw_bot"))
import config as config_mod
import dnsmsg
import socket
import struct
import validate_events as V
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from state import GhostState


class FakeScorer:
    def __init__(self, dga):
        self._dga = dga

    def score_one(self, domain):
        return {"dga": self._dga, "dga_trm": self._dga, "dga_lr": self._dga}


def build_query(name, qtype=1):
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + q + struct.pack(">HH", qtype, 1)


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "state.json"),
            "events_path": os.path.join(self.dir, "events.jsonl"),
            "query_log": os.path.join(self.dir, "q.log"),
            "resolved_ips_path": os.path.join(self.dir, "resolved.jsonl"),
            # policy tests pin their own thresholds; the shipped defaults are tested elsewhere
            "recommend_threshold": 0.60, "block_threshold": 0.90,
            "threat_feed_path": None, "allowlist_path": None,
        })
        self.devices = DeviceMap.from_json(
            [{"name": "dell", "ip": "192.168.1.30", "mac": "aa:bb:cc:dd:ee:01"}])
        self.events = EventLog(self.cfg["events_path"])

    def _resolver(self, dga, learning):
        state = GhostState(self.cfg["state_path"], learning_default=learning)
        return Resolver(self.cfg, state, FakeScorer(dga),
                        Enforcer(NullBackend()), self.devices, self.events), state

    def test_alerts_name_the_device_by_mac_not_by_address(self):
        state = GhostState(self.cfg["state_path"], learning_default=True)
        arp = {"192.168.1.31": "aa:bb:cc:dd:ee:01",      # dell, moved by DHCP
               "192.168.1.30": "02:00:00:00:00:99"}      # its old address: someone else now
        neigh = type("N", (), {"mac": lambda self, ip: arp.get(ip)})()
        r = Resolver(self.cfg, state, FakeScorer(0.7), Enforcer(NullBackend()), self.devices,
                     self.events, neighbours=neigh)
        self.assertEqual(r.decide("192.168.1.31", "suspect-one.example", "A").event["device"], "dell")
        other = r.decide("192.168.1.30", "suspect-two.example", "A").event
        self.assertEqual(other["device"], "192.168.1.30")
        self.assertEqual(other["mac"], "02:00:00:00:00:99")
        self.assertEqual(r.current_ip, {"dell": "192.168.1.31"})

    def test_trust_on_a_tunnel_alert_trusts_its_zone(self):
        # Every tunnel query is a new subdomain: Trust on the one in the alert would never
        # match the next. The event names the zone to trust, and trusting it works.
        r, s = self._resolver(0.1, learning=True)
        evt = None
        for i in range(40):
            d = r.decide("192.168.1.30", f"{i:02d}q8f3k2m9x7v1z4p6w0r5t.exfil.example", "TXT")
            evt = evt or d.event
        self.assertEqual(evt["rule"], "dns_tunnel")
        self.assertEqual(evt["trust"], "exfil.example")
        s.allow(evt["trust"])
        r2, _ = self._resolver(0.1, learning=True)
        quiet = [r2.decide("192.168.1.30", f"{i:02d}z9y8x7w6v5u4t3s2r1q0p.exfil.example", "TXT")
                 for i in range(40)]
        self.assertTrue(all(d.event is None for d in quiet))

    def test_ordinary_alert_has_no_separate_trust_target(self):
        r, _ = self._resolver(0.7, learning=False)
        self.assertNotIn("trust", r.decide("192.168.1.30", "suspect.example", "A").event)

    def test_allowlisted(self):
        r, s = self._resolver(0.99, learning=False)
        s.allow("good.example")
        d = r.decide("192.168.1.30", "good.example", "A")
        self.assertEqual(d.action, "allow")
        self.assertIsNone(d.event)

    def test_blocklisted(self):
        r, s = self._resolver(0.0, learning=False)
        s.add_block("bad.example")
        d = r.decide("192.168.1.30", "bad.example", "A")
        self.assertEqual(d.action, "block")
        self.assertEqual(d.event["rule"], "blocklist")

    def test_high_score_new_domain_blocks_when_not_learning(self):
        r, s = self._resolver(0.95, learning=False)
        d = r.decide("192.168.1.30", "dga-new.example", "A")
        self.assertEqual(d.action, "block")
        self.assertTrue(s.is_blocked("dga-new.example"))

    def test_high_score_only_recommends_in_learning_mode(self):
        r, s = self._resolver(0.95, learning=True)
        d = r.decide("192.168.1.30", "dga-new.example", "A")
        self.assertEqual(d.action, "recommend")
        self.assertFalse(s.is_blocked("dga-new.example"))

    def test_high_score_established_domain_recommends(self):
        r, s = self._resolver(0.95, learning=False)
        # make it "old": seed first_seen far in the past
        s.set_first_seen("estab.example", "2000-01-01T00:00:00Z")
        d = r.decide("192.168.1.30", "estab.example", "A")
        self.assertEqual(d.action, "recommend")

    def test_mid_score_recommends(self):
        r, s = self._resolver(0.7, learning=False)
        d = r.decide("192.168.1.30", "suspect.example", "A")
        self.assertEqual(d.action, "recommend")
        self.assertEqual(d.event["rule"], "dga_suspect")

    def test_low_score_allows(self):
        r, s = self._resolver(0.1, learning=False)
        d = r.decide("192.168.1.30", "clean.example", "A")
        self.assertEqual(d.action, "allow")
        self.assertIsNone(d.event)

    def test_block_wire_path_sinkhole(self):
        r, s = self._resolver(0.0, learning=False)
        s.add_block("bad.example")
        resp = r.handle_packet("192.168.1.30", build_query("bad.example"))
        # sinkhole default -> 1 answer with the sinkhole ip
        self.assertEqual(struct.unpack(">H", resp[6:8])[0], 1)

    def test_resolved_ip_deduped(self):
        r, s = self._resolver(0.0, learning=True)
        pkt = build_query("example.com")
        q = dnsmsg.parse_question(pkt)
        header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        reply = (header + pkt[12:q.end]
                 + struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4)
                 + socket.inet_aton("93.184.216.34"))
        r._record_resolved("192.168.1.30", "example.com", reply)
        r._record_resolved("192.168.1.30", "example.com", reply)  # within window
        with open(self.cfg["resolved_ips_path"], encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        self.assertEqual(len(lines), 1)  # deduped, not two

    def test_emitted_events_validate(self):
        r, s = self._resolver(0.95, learning=False)
        r.decide("192.168.1.30", "dga-new.example", "A")
        with open(self.cfg["events_path"], encoding="utf-8") as f:
            import json
            for line in f:
                self.assertEqual(V.validate_event(json.loads(line)), [])


if __name__ == "__main__":
    unittest.main()
