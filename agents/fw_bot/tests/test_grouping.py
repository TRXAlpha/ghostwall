"""Tests for grouping.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from grouping import AlertGrouper, group_key, severity_of


def evt(device="laptop", rule="dga_high", severity="high", domain="x.biz", **kw):
    d = {"time": "2026-10-20T21:04:05Z", "device": device, "domain": domain,
         "rule": rule, "action": "block", "severity": severity,
         "event_id": "evt_" + domain, "reasons": ["dga score 0.9"]}
    d.update(kw)
    return d


class GroupingTests(unittest.TestCase):
    def test_severity_defaults(self):
        self.assertEqual(severity_of({}), "warn")
        self.assertEqual(severity_of({"severity": "critical"}), "critical")
        self.assertEqual(severity_of({"severity": "bogus"}), "warn")

    def test_group_key(self):
        self.assertEqual(group_key(evt()), ("laptop", "dga_high", "high"))
        self.assertNotEqual(group_key(evt()), group_key(evt(device="phone")))

    def test_grouping_within_window(self):
        g = AlertGrouper(window_minutes=10, clock=lambda: 1000.0)
        kind, grp = g.feed(evt())
        self.assertEqual(kind, "new")
        self.assertEqual(grp.count, 1)
        kind, grp = g.feed(evt(domain="y.biz"))
        self.assertEqual(kind, "update")
        self.assertEqual(grp.count, 2)

    def test_rate_limit_new_window(self):
        t = [1000.0]
        g = AlertGrouper(window_minutes=10, clock=lambda: t[0])
        g.feed(evt())
        t[0] += 9 * 60  # still inside window
        kind, _ = g.feed(evt())
        self.assertEqual(kind, "update")
        t[0] += 2 * 60  # past window -> new message
        kind, grp = g.feed(evt())
        self.assertEqual(kind, "new")
        self.assertEqual(grp.count, 1)

    def test_info_goes_to_digest(self):
        g = AlertGrouper(window_minutes=10, clock=lambda: 0)
        kind, payload = g.feed(evt(severity="info"))
        self.assertEqual(kind, "digest")
        self.assertEqual(payload["domain"], "x.biz")

    def test_different_devices_not_collapsed(self):
        g = AlertGrouper(window_minutes=10, clock=lambda: 0)
        k1, _ = g.feed(evt())
        k2, _ = g.feed(evt(device="phone"))
        self.assertEqual((k1, k2), ("new", "new"))

    def test_latest_event_displayed(self):
        g = AlertGrouper(window_minutes=10, clock=lambda: 0)
        _, grp = g.feed(evt(domain="a.biz"))
        _, grp = g.feed(evt(domain="b.biz"))
        self.assertEqual(grp.event["domain"], "b.biz")
        self.assertEqual(g.counters()[group_key(evt())], 2)


if __name__ == "__main__":
    unittest.main()
