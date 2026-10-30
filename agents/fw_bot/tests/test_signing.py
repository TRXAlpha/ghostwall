"""Tests for signing.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from signing import CallbackError, make_callback, parse_callback

SECRET = b"s3cret"


class SigningTests(unittest.TestCase):
    def test_roundtrip_all_actions(self):
        for action in ("unblock", "keep", "isolate", "details"):
            data = make_callback(action, "evt_01abc", SECRET)
            self.assertLessEqual(len(data), 64)
            self.assertEqual(parse_callback(data, SECRET), (action, "evt_01abc"))

    def test_tampered_signature_rejected(self):
        data = make_callback("unblock", "evt_01", SECRET)
        tampered = data[:-2] + ("AA" if not data.endswith("AA") else "BB")
        with self.assertRaises(CallbackError):
            parse_callback(tampered, SECRET)

    def test_wrong_secret_rejected(self):
        data = make_callback("unblock", "evt_01", SECRET)
        with self.assertRaises(CallbackError):
            parse_callback(data, b"other")

    def test_swapped_action_rejected(self):
        data = make_callback("unblock", "evt_01", SECRET)
        code, eid, sig = data.split(".")
        forged = f"k.{eid}.{sig}"  # same sig, different action
        with self.assertRaises(CallbackError):
            parse_callback(forged, SECRET)

    def test_malformed_inputs(self):
        for bad in ("", "x", "u.evt", "z.evt.abcdef0123456789", "u..abcdef0123456789"):
            with self.assertRaises(CallbackError):
                parse_callback(bad, SECRET)
        with self.assertRaises(ValueError):
            make_callback("bogus", "evt", SECRET)
        with self.assertRaises(ValueError):
            make_callback("unblock", "bad id!", SECRET)

    def test_deterministic_and_unique(self):
        a = make_callback("unblock", "evt_01", SECRET)
        b = make_callback("unblock", "evt_01", SECRET)
        self.assertEqual(a, b)
        c = make_callback("keep", "evt_01", SECRET)
        self.assertNotEqual(a, c)
        d = make_callback("unblock", "evt_02", SECRET)
        self.assertNotEqual(a, d)


if __name__ == "__main__":
    unittest.main()
