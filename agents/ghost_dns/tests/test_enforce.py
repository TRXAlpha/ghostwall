"""Tests for enforce.py (null backend only -- no real nft on the dev box)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from enforce import Enforcer, NullBackend


class EnforceTests(unittest.TestCase):
    def setUp(self):
        self.backend = NullBackend()
        self.e = Enforcer(self.backend)

    def test_isolate_records_valid_ip(self):
        self.e.isolate("192.168.1.30")
        self.assertTrue(any("isolated_dev" in c for c in self.backend.calls))

    def test_invalid_ip_rejected(self):
        with self.assertRaises(ValueError):
            self.e.isolate("not-an-ip")
        with self.assertRaises(ValueError):
            self.e.block_ip("999.1.1.1")

    def test_block_ip_has_timeout(self):
        self.e.block_ip("1.2.3.4", timeout="1h")
        call = [c for c in self.backend.calls if "blocked_ip" in c][0]
        self.assertIn("timeout", call)
        self.assertIn("1h", call)

    def test_lockdown_toggle(self):
        self.assertTrue(self.e.set_lockdown(True))
        self.assertTrue(self.e.lockdown)
        # second call to turn on is a no-op (stays on, no extra insert)
        inserts = [c for c in self.backend.calls if c[0] == "insert"]
        self.e.set_lockdown(True)
        self.assertEqual(len([c for c in self.backend.calls if c[0] == "insert"]),
                         len(inserts))
        self.assertFalse(self.e.set_lockdown(False))
        self.assertFalse(self.e.lockdown)

    def test_null_backend_touches_nothing(self):
        # NullBackend just appends to .calls; no subprocess / network.
        self.e.isolate("10.0.0.5")
        self.e.release("10.0.0.5")
        self.assertEqual(self.backend.name, "null")


if __name__ == "__main__":
    unittest.main()
