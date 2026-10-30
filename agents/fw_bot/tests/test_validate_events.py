"""Tests for validate_events.py"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(HERE))
from validate_events import validate_event

GOOD = {"time": "2026-10-20T21:04:05Z", "device": "laptop",
        "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10",
        "domain": "xkjqwehz.biz", "dst_ip": "203.0.113.7",
        "ja4": "t13d1516h2_8daaf6152771_b186095e22b6", "scores": {"dga": 0.93},
        "rule": "dga_high", "action": "block", "severity": "high",
        "reasons": ["dga score 0.93"], "capture": "pcap rotated 21:04",
        "event_id": "evt_01abc"}


class ValidatorTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_event(GOOD), [])
        minimal = {k: GOOD[k] for k in ("time", "device", "domain", "rule",
                                        "action", "event_id")}
        self.assertEqual(validate_event(minimal), [])

    def test_missing_required(self):
        for f in ("time", "device", "domain", "rule", "action", "event_id"):
            evt = {k: v for k, v in GOOD.items() if k != f}
            errs = validate_event(evt)
            self.assertTrue(any(f in e for e in errs), f)

    def test_bad_values(self):
        self.assertTrue(validate_event(dict(GOOD, time="21:04:05")))
        self.assertTrue(validate_event(dict(GOOD, domain="XKJ.BIZ")))
        self.assertTrue(validate_event(dict(GOOD, domain="xkjqwehz.biz.")))
        self.assertTrue(validate_event(dict(GOOD, mac="AA:BB:CC:DD:EE:FF")))
        self.assertTrue(validate_event(dict(GOOD, scores={"dga": 1.5})))
        self.assertTrue(validate_event(dict(GOOD, scores={"dga": "high"})))
        self.assertTrue(validate_event(dict(GOOD, action="drop")))
        self.assertTrue(validate_event(dict(GOOD, severity="emergency")))
        self.assertTrue(validate_event(dict(GOOD, event_id="bad id!")))
        self.assertTrue(validate_event(["not", "a", "dict"]))

    def test_cli_exit_codes(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            import json
            f.write(json.dumps(GOOD) + "\n")
            f.write(json.dumps(GOOD, event_id := None) if False else json.dumps(dict(GOOD, action="nope")) + "\n")
            path = f.name
        try:
            r = subprocess.run([sys.executable, os.path.join(HERE, "..", "validate_events.py"), path],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("line 2", r.stdout)
            self.assertIn("action", r.stdout)
        finally:
            os.unlink(path)

    def test_cli_valid_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps(GOOD) + "\n\n")
            path = f.name
        try:
            r = subprocess.run([sys.executable, os.path.join(HERE, "..", "validate_events.py"), path],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertIn("all lines valid", r.stdout)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
