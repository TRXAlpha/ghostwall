"""Tests for inspector.py (raw-IP, beacon, JA4, verdicts, dedupe)."""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, TESTS)
sys.path.append(os.path.join(os.path.dirname(HERE), "fw_bot"))  # validate_events
import config as flow_config          # ghost_flow config (bind before app flips path)
import app                             # imports inspector (adds ghost_dns to path)
import validate_events as V
from _helpers import ipv4_tcp, client_hello, SYN, PSH_ACK

PUB = "8.8.8.8"
BEAC = "185.199.108.153"


class InspectorTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = flow_config.load_config(None, {
            "events_path": os.path.join(self.dir, "events.jsonl"),
            "resolved_ips_path": os.path.join(self.dir, "resolved.jsonl"),
            "devices_json": os.path.join(os.path.dirname(HERE), "netconf", "devices.example.json"),
            # huge TTL so entries seeded with a synthetic timestamp aren't purged
            "resolved_ttl_seconds": 10 ** 12,
        })
        (self.resolved, self.rawip, self.beacon, self.devices,
         self.events, self.enforcer, self.insp) = app.build(self.cfg)

    def _events(self):
        p = self.cfg["events_path"]
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def test_raw_ip_recommend_and_accept(self):
        v = self.insp.inspect(ipv4_tcp("192.168.1.30", PUB, 51000, 443, SYN), when=1.0)
        self.assertEqual(v, "accept")
        evs = self._events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["rule"], "raw_ip")
        self.assertEqual(evs[0]["action"], "recommend")
        self.assertEqual(evs[0]["dst_ip"], PUB)

    def test_known_ip_no_alert(self):
        self.resolved.add(PUB, domain="dns.google", when=1.0)
        v = self.insp.inspect(ipv4_tcp("192.168.1.30", PUB, 51000, 443, SYN), when=1.0)
        self.assertEqual(v, "accept")
        self.assertEqual(self._events(), [])

    def test_beacon_high_severity(self):
        self.resolved.add(BEAC, domain="cdn.example", when=1.0)
        for k in range(5):
            self.insp.inspect(ipv4_tcp("192.168.1.30", BEAC, 52000 + k, 443, SYN),
                              when=2000.0 + 60 * k)
        beacons = [e for e in self._events() if e["rule"] == "beacon"]
        self.assertEqual(len(beacons), 1)
        self.assertEqual(beacons[0]["severity"], "high")
        self.assertEqual(beacons[0]["domain"], "cdn.example")

    def test_cooldown_dedupes(self):
        # two raw-ip SYNs to the same dst within the cooldown -> one event
        self.insp.inspect(ipv4_tcp("192.168.1.30", PUB, 51000, 443, SYN), when=1.0)
        self.insp.inspect(ipv4_tcp("192.168.1.30", PUB, 51001, 443, SYN), when=2.0)
        self.assertEqual(len([e for e in self._events() if e["rule"] == "raw_ip"]), 1)

    def test_ja4_enrichment(self):
        self.insp.inspect(ipv4_tcp("192.168.1.30", PUB, 51000, 443, SYN), when=1.0)
        self.insp.inspect(ipv4_tcp("192.168.1.30", PUB, 51000, 443, PSH_ACK,
                                   client_hello()), when=1.1)
        self.assertIn(("192.168.1.30", PUB), self.insp._ja4)
        self.assertTrue(self.insp._ja4[("192.168.1.30", PUB)].startswith("t13d"))

    def test_never_blocks_by_default(self):
        # autoblock off => verdict always accept, stats.blocked stays 0
        for k in range(6):
            self.insp.inspect(ipv4_tcp("192.168.1.30", PUB, 52000 + k, 443, SYN),
                              when=3000.0 + 60 * k)
        self.assertEqual(self.insp.stats["blocked"], 0)

    def test_all_events_valid(self):
        self.insp.inspect(ipv4_tcp("192.168.1.30", PUB, 51000, 443, SYN), when=1.0)
        for e in self._events():
            self.assertEqual(V.validate_event(e), [])


if __name__ == "__main__":
    unittest.main()
