"""Tests for resolved.py"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from resolved import ResolvedIPs


class ResolvedTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "resolved.jsonl")

    def _write(self, *recs):
        with open(self.path, "a", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")

    def test_tail_and_know(self):
        self._write({"time": "2026-10-22T10:00:00Z", "ip": "8.8.8.8", "domain": "dns.google"})
        r = ResolvedIPs(self.path, ttl_seconds=10_000_000_000)
        self.assertTrue(r.knows("8.8.8.8"))
        self.assertEqual(r.domain_for("8.8.8.8"), "dns.google")

    def test_incremental(self):
        r = ResolvedIPs(self.path, ttl_seconds=10_000_000_000)
        self.assertFalse(r.knows("1.2.3.4"))
        self._write({"time": "2026-10-22T10:00:00Z", "ip": "1.2.3.4", "domain": "x.example"})
        self.assertTrue(r.knows("1.2.3.4"))  # picked up on next refresh

    def test_ttl_expiry(self):
        old = "2000-01-01T00:00:00Z"
        self._write({"time": old, "ip": "9.9.9.9", "domain": "quad9"})
        r = ResolvedIPs(self.path, ttl_seconds=60)
        self.assertFalse(r.knows("9.9.9.9"))  # far older than ttl

    def test_add_direct(self):
        r = ResolvedIPs(self.path, ttl_seconds=10_000)
        r.add("5.5.5.5", domain="five.example", when=time.time())
        self.assertTrue(r.knows("5.5.5.5"))
        self.assertEqual(r.domain_for("5.5.5.5"), "five.example")

    def test_missing_file_ok(self):
        r = ResolvedIPs(os.path.join(self.dir, "nope.jsonl"))
        self.assertFalse(r.knows("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
