"""Tests for alerts.py (formatting + keyboard, no network)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from alerts import format_alert, group_text, inline_keyboard
from signing import parse_callback

SECRET = b"s3cret"
EVENT = {
    "time": "2026-10-20T21:04:05Z", "device": "laptop", "domain": "xkjqwehz.biz",
    "dst_ip": "203.0.113.7", "rule": "dga_high", "action": "block",
    "severity": "high", "reasons": ["dga score 0.93", "never seen before"],
    "capture": "pcap rotated 21:04", "event_id": "evt_01abc",
}


class FormatTests(unittest.TestCase):
    def test_format_alert_shape(self):
        text = format_alert(EVENT)
        lines = text.split("\n")
        self.assertEqual(lines[0], "BLOCKED · laptop")
        self.assertEqual(lines[1], "xkjqwehz.biz → 203.0.113.7")
        self.assertEqual(lines[2], "Why: dga score 0.93; never seen before")
        self.assertEqual(lines[3], "Capture: pcap rotated 21:04")

    def test_format_missing_fields(self):
        text = format_alert({"device": "phone", "domain": "a.b", "event_id": "e1"})
        self.assertIn("BLOCKED · phone", text)
        self.assertIn("Capture: none", text)
        self.assertIn("Why: rule fired", text)

    def test_keyboard_buttons_signed(self):
        kb = inline_keyboard(EVENT, SECRET)
        row = kb[0]
        self.assertEqual([b["text"] for b in row],
                         ["Unblock", "Keep blocked", "Isolate device", "Details"])
        for b in row:
            action, eid = parse_callback(b["callback_data"], SECRET)
            self.assertEqual(eid, "evt_01abc")
        actions = [parse_callback(b["callback_data"], SECRET)[0] for b in row]
        self.assertEqual(actions, ["unblock", "keep", "isolate", "details"])

    def test_keyboard_forgery_rejected(self):
        kb = inline_keyboard(EVENT, SECRET)
        bad = kb[0][0]["callback_data"][:-1] + ("9" if kb[0][0]["callback_data"][-1] != "9" else "8")
        with self.assertRaises(Exception):
            parse_callback(bad, SECRET)

    def test_group_text_counter(self):
        base = format_alert(EVENT)
        g1 = group_text(base, 2)
        self.assertIn("(x2)", g1.split("\n")[0])
        g2 = group_text(g1, 3)
        self.assertIn("(x3)", g2.split("\n")[0])
        self.assertNotIn("(x2)", g2.split("\n")[0])


if __name__ == "__main__":
    unittest.main()
