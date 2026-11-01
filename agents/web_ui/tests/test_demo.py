"""The demo shows only what the detector really does: demo_events.json must match a
fresh run of make_demo.py (the real resolver, models and thresholds)."""
import importlib.util
import json
import os
import re
import sys
import unittest
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import demo  # noqa: E402

# Only look: importing onnxruntime here would start it before scoring.py turns its telemetry off.
HAVE_MODELS = all(importlib.util.find_spec(m) for m in ("numpy", "onnxruntime"))


def shape(e):
    return (e["minutes_ago"], e["device"], e["domain"], e["rule"], e["action"], e["severity"],
            [re.sub(r"\d+(\.\d+)?", "#", r) for r in e.get("reasons", [])])


class DemoTests(unittest.TestCase):
    @unittest.skipUnless(HAVE_MODELS, "needs numpy and onnxruntime")
    def test_demo_events_come_from_the_real_detector(self):
        import make_demo
        fresh = make_demo.generate()
        committed = demo.load_demo()
        self.assertEqual(fresh["queries"], committed["queries"])
        self.assertEqual([shape(e) for e in fresh["events"]], [shape(e) for e in committed["events"]],
                         "the detector changed: run agents/web_ui/make_demo.py and commit demo_events.json")
        for a, b in zip(fresh["events"], committed["events"]):
            for k, v in (b.get("scores") or {}).items():
                self.assertAlmostEqual(a["scores"][k], v, delta=0.01)

    def test_every_rule_is_shown_once_or_more(self):
        rules = {e["rule"] for e in demo.load_demo()["events"]}
        self.assertTrue({"threat_feed", "dga_burst", "dga_high", "dga_suspect", "dga_corroborated",
                         "doh_bypass", "dns_tunnel", "dns_beacon"} <= rules)

    def test_sample_events_are_timestamped_oldest_first(self):
        now = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
        evs = demo.sample_events(now)
        times = [e["time"] for e in evs]
        self.assertEqual(times, sorted(times))
        self.assertTrue(all("minutes_ago" not in e and e["event_id"].startswith("evt_demo") for e in evs))
        json.dumps(evs)


if __name__ == "__main__":
    unittest.main()
