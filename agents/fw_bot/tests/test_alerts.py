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
        self.assertEqual(text.split("\n")[:2], ["ALERT · phone", "a.b"])
        self.assertNotIn("Capture", text)
        self.assertIn("Why: rule fired", text)

    def test_shadow_alert_is_not_called_blocked(self):
        # Shadow and learning mode only flag; the message must not claim a block.
        evt = dict(EVENT, action="recommend", dst_ip=None, capture=None)
        lines = format_alert(evt).split("\n")
        self.assertEqual(lines[0], "ALERT · laptop")
        self.assertEqual(lines[1], "xkjqwehz.biz")
        kb = inline_keyboard(evt, SECRET)[0]
        self.assertEqual([b["text"] for b in kb], ["Trust domain", "Details"])
        self.assertEqual([parse_callback(b["callback_data"], SECRET)[0] for b in kb], ["trust", "details"])

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


class TrustButtonTests(unittest.TestCase):
    def test_iot_alert_offers_allow_for_the_device_even_when_refused(self):
        for action in ("recommend", "block"):
            evt = {"event_id": "evt_1", "rule": "iot_new_domain", "action": action}
            labels = [b["text"] for row in inline_keyboard(evt, b"k") for b in row]
            self.assertEqual(labels, ["Allow for this device", "Isolate device", "Details"])

    def test_no_trust_button_for_phishing_feed_hits(self):
        evt = {"event_id": "evt_1", "rule": "threat_feed", "action": "recommend"}
        labels = [b["text"] for row in inline_keyboard(evt, b"k") for b in row]
        self.assertNotIn("Trust domain", labels)
        evt["rule"] = "doh_bypass"
        self.assertIn("Trust domain", [b["text"] for row in inline_keyboard(evt, b"k") for b in row])

    def test_no_trust_button_for_a_burst(self):
        # A burst is many different random names; trusting the one in the alert is a placebo.
        evt = {"event_id": "evt_1", "rule": "dga_burst", "action": "recommend"}
        self.assertEqual([b["text"] for row in inline_keyboard(evt, b"k") for b in row], ["Details"])
