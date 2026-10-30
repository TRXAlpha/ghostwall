"""Tests for rawip.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from rawip import RawIPDetector, is_local
from resolved import ResolvedIPs


class _Res:
    def __init__(self, known):
        self._known = set(known)

    def knows(self, ip):
        return ip in self._known


class RawIpTests(unittest.TestCase):
    def test_is_local(self):
        for ip in ("192.168.1.5", "10.0.0.1", "127.0.0.1", "169.254.1.1",
                   "224.0.0.1", "203.0.113.5"):
            self.assertTrue(is_local(ip), ip)
        for ip in ("8.8.8.8", "185.199.108.153", "1.1.1.1"):
            self.assertFalse(is_local(ip), ip)

    def test_unknown_public_flagged(self):
        d = RawIPDetector(_Res(set()))
        self.assertIsNotNone(d.check("8.8.8.8"))

    def test_known_public_ok(self):
        d = RawIPDetector(_Res({"8.8.8.8"}))
        self.assertIsNone(d.check("8.8.8.8"))

    def test_local_ignored(self):
        d = RawIPDetector(_Res(set()))
        self.assertIsNone(d.check("192.168.1.5"))

    def test_exceptions_ignored(self):
        d = RawIPDetector(_Res(set()), exceptions={"8.8.8.8"})
        self.assertIsNone(d.check("8.8.8.8"))

    def test_unparseable_not_flagged(self):
        d = RawIPDetector(_Res(set()))
        self.assertIsNone(d.check("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
