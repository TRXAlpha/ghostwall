"""Tests for tokenizer.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tokenizer as T


class TokenizerTests(unittest.TestCase):
    def test_registrable_part(self):
        self.assertEqual(T.registrable_part("www.google.com"), "google.com")
        self.assertEqual(T.registrable_part("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(T.registrable_part("example.com"), "example.com")
        self.assertEqual(T.registrable_part("EXAMPLE.COM."), "example.com")
        self.assertEqual(T.registrable_part(""), "")

    def test_registrable_label(self):
        self.assertEqual(T.registrable_label("www.google.com"), "google")
        self.assertEqual(T.registrable_label("xkjqwehz.biz"), "xkjqwehz")
        self.assertEqual(T.registrable_label("a.b.example.co.uk"), "example")

    def test_encode_shape_and_pad(self):
        toks = T.encode(["abc", "a"])
        self.assertEqual(toks.shape, (2, T.MAX_LEN))
        # 'a' -> id 2, 'b' -> 3, 'c' -> 4; trailing pad is 0
        self.assertEqual(list(toks[0, :4]), [2, 3, 4, 0])
        self.assertEqual(list(toks[1, :2]), [2, 0])

    def test_encode_keeps_last_bytes(self):
        long = "z" * 100
        toks = T.encode([long])
        # last 64 kept, all 'z' -> same id, no pad in the row
        self.assertTrue((toks[0] != 0).all())

    def test_unknown_char_maps_to_unk(self):
        toks = T.encode(["a/b"])  # '/' not in vocab
        self.assertEqual(toks[0, 1], T.UNK)

    def test_strip_dot(self):
        toks = T.encode(["ab.cd"])
        stripped = T.strip_dot(toks)
        # 'a','b' kept, '.' and after zeroed
        self.assertEqual(list(stripped[0, :4]), [2, 3, 0, 0])
        # original not mutated
        self.assertNotEqual(list(toks[0, :4]), [2, 3, 0, 0])


if __name__ == "__main__":
    unittest.main()


class SuffixTests(unittest.TestCase):
    """The scored label must be the part someone chose, not a provider's name."""

    def test_dynamic_dns_hosts_are_scored_by_their_own_label(self):
        from tokenizer import registrable_label, registrable_part
        self.assertEqual(registrable_label("cvyh1po636avyrsxebwbkn7.ddns.net"), "cvyh1po636avyrsxebwbkn7")
        self.assertEqual(registrable_part("a.b.cvyh1po636.duckdns.org"), "cvyh1po636.duckdns.org")
        self.assertEqual(registrable_label("bqlqscpqwsh.mooo.com"), "bqlqscpqwsh")

    def test_country_second_levels(self):
        from tokenizer import registrable_label
        self.assertEqual(registrable_label("shop.example.com.ua"), "example")
        self.assertEqual(registrable_label("www.portal.gov.br"), "portal")
        self.assertEqual(registrable_label("xpunqr.com.hn"), "xpunqr")

    def test_unchanged_cases(self):
        from tokenizer import registrable_label, registrable_part
        self.assertEqual(registrable_part("www.example.com"), "example.com")
        self.assertEqual(registrable_part("a.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(registrable_part("example.com"), "example.com")
        # hosting/CDN names stay grouped under the provider: their hosts are machine-made
        self.assertEqual(registrable_label("d1a2b3c4d5e6f7.cloudfront.net"), "cloudfront")
