"""End-to-end: drive the inspector from source.replay and a .pcap file."""
import json
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, TESTS)
sys.path.append(os.path.join(os.path.dirname(HERE), "fw_bot"))
import config as flow_config
import app
import source
import validate_events as V
from _helpers import ipv4_tcp, SYN


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))  # raw IP
        for fr in frames:
            f.write(struct.pack("<IIII", 0, 0, len(fr), len(fr)))
            f.write(fr)


class E2ETests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = flow_config.load_config(None, {
            "events_path": os.path.join(self.dir, "events.jsonl"),
            "resolved_ips_path": os.path.join(self.dir, "resolved.jsonl"),
            "devices_json": os.path.join(os.path.dirname(HERE), "netconf", "devices.example.json"),
        })
        (self.resolved, _, _, _, _, _, self.insp) = app.build(self.cfg)

    def _events(self):
        with open(self.cfg["events_path"], encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def test_replay_scenario(self):
        pkts, ts = [], []
        pkts.append(ipv4_tcp("192.168.1.30", "8.8.8.8", 51000, 443, SYN)); ts.append(1.0)
        for k in range(5):
            pkts.append(ipv4_tcp("192.168.1.30", "185.199.108.153", 52000 + k, 443, SYN))
            ts.append(2000.0 + 60 * k)
        verdicts = source.replay(pkts, self.insp.inspect, ts)
        self.assertTrue(all(v == "accept" for v in verdicts))
        rules = {e["rule"] for e in self._events()}
        self.assertIn("raw_ip", rules)
        self.assertIn("beacon", rules)
        for e in self._events():
            self.assertEqual(V.validate_event(e), [])

    def test_read_pcap_roundtrip(self):
        path = os.path.join(self.dir, "x.pcap")
        frames = [ipv4_tcp("192.168.1.30", "8.8.8.8", 51000, 443, SYN)]
        write_pcap(path, frames)
        got = list(source.read_pcap(path))
        self.assertEqual(got, frames)


if __name__ == "__main__":
    unittest.main()
