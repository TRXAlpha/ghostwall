"""Tests for dispatch.py (no network, fake control API)."""
import json, os, sys, tempfile, unittest
from datetime import datetime, timezone
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import dispatch
from config import Config


class FakeClient:
    def __init__(self):
        self.calls = []

    def status(self):
        self.calls.append("status")
        return {"lockdown": False, "learning": True, "devices": [{"name": "dell", "ip": "1.2.3.4"}]}

    def isolate(self, name):
        self.calls.append(("isolate", name))
        return {"name": name}

    def learning(self, enabled):
        self.calls.append(("learning", enabled))
        return {"learning": enabled}


def ev(i, action="recommend", rule="dga_high", t="2026-10-26T10:00:00Z", score=0.99):
    return {"time": t, "device": "dell", "domain": f"d{i}.example", "action": action,
            "rule": rule, "severity": "high", "event_id": f"evt_{i}", "scores": {"dga": score}}


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "events.jsonl")
        with open(self.path, "w", encoding="utf-8") as f:
            for i in range(1, 6):
                f.write(json.dumps(ev(i)) + "\n")
        self.client = FakeClient()
        cfg = Config(owner_chat_id=42, telegram_token="x", secret=b"s", labels_path=os.path.join(self.dir, "l.jsonl"))
        self.d = dispatch.Dispatcher(cfg, self.path, "http://x", api=None)
        self.d.client = self.client

    def test_help(self):
        self.assertIn("/fw log", self.d.text("/fw help"))
        self.assertIn("/fw log", self.d.text("/fw"))

    def test_log_newest_first_and_limit(self):
        out = self.d.text("/fw log 2")
        self.assertIn("d5.example", out)
        self.assertIn("d4.example", out)
        self.assertNotIn("d3.example", out)
        self.assertLess(out.index("d5"), out.index("d4"))

    def test_log_bad_number(self):
        self.assertEqual(self.d.text("/fw log abc"), "usage: /fw log [n]")

    def test_log_capped(self):
        self.assertIn("d1.example", self.d.text("/fw log 999"))

    def test_status_and_isolate_route_to_control(self):
        self.assertIn("ghostwall status", self.d.text("/fw status"))
        self.d.text("/fw isolate dell")
        self.assertIn(("isolate", "dell"), self.client.calls)

    def test_learning_route(self):
        self.d.text("/fw learning off")
        self.assertIn(("learning", False), self.client.calls)

    def test_summary_counts_recent_only(self):
        now = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
        out = dispatch.format_summary(
            [ev(1), ev(2, action="block", rule="blocklist", t="2020-01-01T00:00:00Z")], now=now)
        self.assertIn("last 24h: 1 decisions", out)
        self.assertIn("recommend 1", out)

    def test_summary_empty(self):
        self.assertEqual(dispatch.format_summary([]), "No decisions in the last 24h.")

    def test_read_events_skips_garbage(self):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("garbage\n")
        self.assertEqual(len(dispatch.read_events(self.path)), 5)

    def test_event_index_lookup(self):
        self.assertEqual(dispatch.EventIndex(self.path).get("evt_3")["domain"], "d3.example")
        self.assertIsNone(dispatch.EventIndex(self.path).get("nope"))


if __name__ == "__main__":
    unittest.main()
