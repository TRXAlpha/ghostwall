"""A flood of made-up names (any web page can make a browser send one) must not
turn into a flood of alerts, a state.json rewrite per query, or quadratic work."""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config as config_mod
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver, _prune
from state import GhostState


class Scorer:
    def score_one(self, domain):
        return {"dga": 0.99, "dga_trm": 0.99, "dga_lr": 0.99}


class FloodTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "state.json"),
            "events_path": os.path.join(self.dir, "events.jsonl"),
            "query_log": None, "resolved_ips_path": None,
            "threat_feed_path": None, "allowlist_path": None,
            "alert_rate_per_device": 5,
        })
        self.state = GhostState(self.cfg["state_path"], learning_default=True)
        self.r = Resolver(self.cfg, self.state, Scorer(), Enforcer(NullBackend()),
                          DeviceMap.from_json([{"name": "dell", "ip": "192.168.1.30"}]),
                          EventLog(self.cfg["events_path"]))
        self.t = [1000.0]
        self.r.clock = lambda: self.t[0]

    def _alerts(self):
        with open(self.cfg["events_path"]) as f:
            return [json.loads(l) for l in f]

    def test_alerts_capped_per_device_per_minute(self):
        for i in range(200):
            self.r.decide("192.168.1.30", f"q{i}zx8kfj3v.top", "A")
        self.assertEqual(len(self._alerts()), 5)
        self.assertGreater(self.r.stats["rate_limited"], 0)
        self.t[0] += 61
        self.r.decide("192.168.1.30", "next9qz2kx7.top", "A")
        self.assertEqual(len(self._alerts()), 6)

    def test_cap_zero_means_no_cap(self):
        self.cfg["alert_rate_per_device"] = 0
        for i in range(40):
            self.r.decide("192.168.1.30", f"q{i}zx8kfj3v.top", "A")
        self.assertEqual(len(self._alerts()), 40)

    def test_state_not_rewritten_per_alert(self):
        self.state.save()
        writes = []
        real = self.state._save_locked
        self.state._save_locked = lambda: (writes.append(1), real())[1]
        for i in range(100):
            self.r.decide("192.168.1.30", f"w{i}zx8kfj3v.top", "A")
        self.assertLessEqual(len(writes), 1)
        self.state.flush()  # ...and nothing is lost on a clean shutdown
        with open(self.cfg["state_path"]) as f:
            self.assertGreaterEqual(len(json.load(f)["first_seen"]), 100)

    def test_prune_is_bounded_when_everything_is_recent(self):
        d = {i: 100.0 + i for i in range(1000)}
        out = _prune(d, cutoff=0.0, cap=1000)
        self.assertEqual(len(out), 500)
        self.assertEqual(min(out.values()), 600.0)  # the newest half survives
        start = time.monotonic()
        for i in range(30000):  # would be quadratic without the cap
            self.r._is_repeat("dell", f"x{i}.example", "r")
        self.assertLess(time.monotonic() - start, 10)


class BrokenStateTests(unittest.TestCase):
    def test_broken_state_is_kept_not_silently_dropped(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "state.json")
        with open(p, "w") as f:
            f.write('{"allowlist": ["a.example"')  # cut off by a power loss
        s = GhostState(p)
        self.assertEqual(s.allowlist, set())
        kept = [n for n in os.listdir(d) if n.startswith("state.json.broken-")]
        self.assertEqual(len(kept), 1)


if __name__ == "__main__":
    unittest.main()


class NoOnnxTests(unittest.TestCase):
    """Without onnxruntime the TRM score is None; alerts must still be written.
    (Until this fix, every score-based alert raised TypeError there.)"""

    def test_alert_with_one_model_missing(self):
        d = tempfile.mkdtemp()
        cfg = config_mod.load_config(None, {
            "state_path": os.path.join(d, "s.json"), "events_path": os.path.join(d, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "threat_feed_path": None, "allowlist_path": None})

        class LrOnly:
            def score_one(self, domain):
                return {"dga": 0.999, "dga_trm": None, "dga_lr": 0.999}

        r = Resolver(cfg, GhostState(cfg["state_path"]), LrOnly(), Enforcer(NullBackend()),
                     DeviceMap.from_json([]), EventLog(cfg["events_path"]))
        dec = r.decide("192.168.1.30", "xk2qv9zr7wpl3mfa.top", "A")
        self.assertEqual(dec.reason, "dga_high")
        self.assertEqual(dec.event["scores"], {"dga": 0.999, "dga_lr": 0.999})


class PresetTests(unittest.TestCase):
    def test_v3_public_preset(self):
        cfg = config_mod.load_config(None, {"models": "v3-public"})
        self.assertIsNone(cfg["onnx_model"])
        self.assertTrue(cfg["lr_coef"].endswith("lr_v3_public.npy"))
        with open(cfg["lr_meta"]) as f:
            thr = json.load(f)["thresholds"]
        self.assertEqual(cfg["recommend_threshold"], thr["recommend_threshold"])

    def test_preset_keeps_what_the_user_set(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "c.json")
        with open(p, "w") as f:
            json.dump({"models": "v3-public", "recommend_threshold": 0.99}, f)
        cfg = config_mod.load_config(p)
        self.assertEqual(cfg["recommend_threshold"], 0.99)

    def test_unknown_preset_refused(self):
        with self.assertRaises(ValueError):
            config_mod.load_config(None, {"models": "v9"})

    def test_shipped_v3_public_model_loads_and_ranks(self):
        import scoring
        cfg = config_mod.load_config(None, {"models": "v3-public"})
        s = scoring.Scorer(cfg["onnx_model"], cfg["lr_coef"], cfg["lr_meta"])
        self.assertEqual(s.backend, "lr")
        self.assertLess(s.score_one("wikipedia.org")["dga"], 0.5)
        self.assertGreater(s.score_one("kjqwehdzxklqwpe.biz")["dga"], cfg["recommend_threshold"])
