"""Tests for tls.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tls
from _helpers import client_hello


class TlsTests(unittest.TestCase):
    def test_parse_basic(self):
        ch = tls.parse_client_hello(client_hello())
        self.assertIsNotNone(ch)
        self.assertEqual(ch.sni, "example.com")
        self.assertEqual(ch.alpns, ["h2", "http/1.1"])
        self.assertIn(0x0304, ch.supported_versions)
        self.assertEqual(ch.sig_algs, [0x0403, 0x0804])
        self.assertIn(0x1301, ch.ciphers)

    def test_extensions_in_order(self):
        ch = tls.parse_client_hello(client_hello())
        self.assertEqual(ch.extensions, [0x0000, 0x0010, 0x002b, 0x000d])

    def test_not_tls_returns_none(self):
        self.assertIsNone(tls.parse_client_hello(b"GET / HTTP/1.1\r\n"))
        self.assertIsNone(tls.parse_client_hello(b""))

    def test_sni_ascii_only_never_raises(self):
        # a ClientHello whose SNI has odd bytes must not raise
        ch = tls.parse_client_hello(client_hello(sni=b"xn--bad\xff"))
        self.assertIsNotNone(ch)


if __name__ == "__main__":
    unittest.main()
