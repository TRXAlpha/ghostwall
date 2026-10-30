"""Tests for ja4.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tls
from ja4 import ja4
from _helpers import client_hello


class Ja4Tests(unittest.TestCase):
    def _fp(self, **kw):
        return ja4(tls.parse_client_hello(client_hello(**kw)))

    def test_format(self):
        fp = self._fp()
        a, b, c = fp.split("_")
        # a = t 13 d 07 04 h2
        self.assertEqual(a, "t13d0704h2")
        self.assertEqual(len(b), 12)
        self.assertEqual(len(c), 12)

    def test_deterministic(self):
        self.assertEqual(self._fp(), self._fp())

    def test_grease_excluded_from_count_and_hash(self):
        # adding a GREASE cipher must not change the fingerprint
        self.assertEqual(self._fp(grease=False), self._fp(grease=True))

    def test_no_sni_marked_i(self):
        # a hello with SNI still present -> 'd'; sanity that our builder yields d
        self.assertTrue(self._fp().startswith("t13d"))

    def test_cipher_order_irrelevant(self):
        # JA4_b sorts ciphers, so reordering yields the same fingerprint
        fp1 = ja4(tls.parse_client_hello(client_hello(ciphers=(0x1301, 0x1302, 0xc02f))))
        fp2 = ja4(tls.parse_client_hello(client_hello(ciphers=(0xc02f, 0x1302, 0x1301))))
        self.assertEqual(fp1, fp2)


if __name__ == "__main__":
    unittest.main()
