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
