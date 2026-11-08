"""Newly registered domains (rule new_domain): the list file, the updater, NrdList, and the
rule in Resolver.decide. Made-up example names and 192.168.1.x addresses only."""
import contextlib
import datetime
import io
import json
import os
import sys
import tempfile
import unittest
from array import array

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config as config_mod
import detectors as D
import nrdfile
import update_nrd as U
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from state import GhostState

DEV, CAM = "192.168.1.30", "192.168.1.40"
TODAY = datetime.date.today().isoformat()


def hashes(*names):
    return array("Q", (nrdfile.hash64(n) for n in names))


def write_list(path, week1=(), week2=(), built=TODAY):
    nrdfile.write(path, [(7, hashes(*week1)), (14, hashes(*week2))], built, "test")


class FileTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "nrd_domains.bin")

    def test_round_trip_and_window(self):
        write_list(self.path, ["fresh.example"], ["older.example"])
        head, bands = nrdfile.read(self.path)
        self.assertEqual([d for d, _ in bands], [7, 14])
        self.assertEqual(len(nrdfile.read(self.path, 7)[1]), 1)       # only the first week
        self.assertEqual(nrdfile.window_days(1), 7)
        self.assertEqual(nrdfile.window_days(8), 14)
        self.assertEqual(nrdfile.window_days(99), 35)

    def test_hash_is_the_detectors_hash(self):
        self.assertEqual(nrdfile.hash64("fresh.example"), D._hash64("fresh.example"))

    def test_truncated_or_foreign_file_refused(self):
        write_list(self.path, ["a.example", "b.example"])
        with open(self.path, "rb") as f:
            data = f.read()
        with open(self.path, "wb") as f:
            f.write(data[:-4])
        with self.assertRaises(ValueError):
            nrdfile.read(self.path)
        with open(self.path, "wb") as f:
            f.write(b"not a list\n")
        with self.assertRaises(ValueError):
            nrdfile.read(self.path)


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.out = os.path.join(tempfile.mkdtemp(), "nrd_domains.bin")

    def fake(self, sizes):
        def fetch(name):
            n = sizes[name]
            if isinstance(n, Exception):
                raise n
            return array("Q", range(1, n + 1)), n
        return fetch

    def run_update(self, sizes, days=14):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = U.update(self.out, days, fetch=self.fake(sizes))
        return rc, err.getvalue()

    def test_writes_the_bands_the_window_needs(self):
        rc, _ = self.run_update({"nrd7": 300, "nrd14-8": 200})
        self.assertEqual(rc, 0)
        head, bands = nrdfile.read(self.out)
        self.assertEqual([(d, len(h)) for d, h in bands], [(7, 300), (14, 200)])

    def test_a_failed_band_keeps_the_old_list(self):
        self.run_update({"nrd7": 300, "nrd14-8": 200})
        before = os.path.getmtime(self.out)
        rc, err = self.run_update({"nrd7": 300, "nrd14-8": OSError("HTTP 503")})
        self.assertEqual(rc, 1)
        self.assertIn("keeping the existing list", err)
        self.assertEqual(os.path.getmtime(self.out), before)

    def test_a_band_that_shrank_by_half_keeps_the_old_list(self):
        self.run_update({"nrd7": 300, "nrd14-8": 200})
        rc, err = self.run_update({"nrd7": 100, "nrd14-8": 200})
        self.assertEqual(rc, 1)
        self.assertIn("looks broken", err)

    def test_off_downloads_nothing_and_removes_an_old_list(self):
        write_list(self.out, ["x.example"])
        cfg = os.path.join(os.path.dirname(self.out), "cfg.json")
        with open(cfg, "w") as f:
            json.dump({"nrd_mode": "off"}, f)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(U.main(["--out", self.out, "--config", cfg]), 0)
        self.assertFalse(os.path.exists(self.out))


class NrdListTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "nrd_domains.bin")

    def test_match_by_registrable_domain_with_its_age(self):
        write_list(self.path, ["fresh.example"], ["older.example"])
        n = D.NrdList(self.path, days=14)
        self.assertEqual(n.match("login.fresh.example"), (7, "fresh.example"))
        self.assertEqual(n.match("older.example"), (14, "older.example"))
        self.assertIsNone(n.match("established.example"))
        self.assertEqual(len(n), 2)
        self.assertIsNone(D.NrdList(self.path, days=7).match("older.example"))   # outside the window

    def test_stale_missing_or_damaged_list_gives_no_hits(self):
        write_list(self.path, ["fresh.example"], built="2020-01-01")
        self.assertIsNone(D.NrdList(self.path).match("fresh.example"))
        self.assertIsNone(D.NrdList(self.path + ".missing").match("fresh.example"))
        with open(self.path, "wb") as f:
            f.write(b"garbage")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(D.NrdList(self.path).match("fresh.example"))


class FakeScorer:
    def __init__(self, dga=0.05):
        self.dga = dga

    def score_one(self, domain):
        return {"dga": self.dga, "dga_trm": self.dga, "dga_lr": self.dga}


class RuleTests(unittest.TestCase):
    def build(self, dga=0.05, popular="brand.example\n", **over):
        self.dir = tempfile.mkdtemp()
        feed = os.path.join(self.dir, "threat_feed.txt")
        with open(feed, "w") as f:
            f.write("listed-bad.example\n")
        with open(os.path.join(self.dir, "popular_domains.txt"), "w") as f:
            f.write(popular)
        write_list(os.path.join(self.dir, "nrd_domains.bin"),
                   ["fresh.example", "brand.example", "risky.top", "listed-bad.example"], ["older.example"])
        cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "s.json"), "events_path": os.path.join(self.dir, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "allowlist_path": None,
            "threat_feed_path": feed, "nrd_mode": "alert", **over})
        self.cfg = cfg
        self.state = GhostState(cfg["state_path"], learning_default=cfg.get("learning", True))
        dm = DeviceMap.from_json([{"name": "laptop", "ip": DEV},
                                  {"name": "cam-1", "ip": CAM, "profile": "iot"}])
        self.now = 1_000_000.0
        self.r = Resolver(cfg, self.state, FakeScorer(dga), Enforcer(NullBackend()), dm,
                          EventLog(cfg["events_path"]))
        self.assertTrue(self.r.det.wait_loaded(10))
        self.r.clock = lambda: self.now
        return self.r

    def events(self, rule="new_domain"):
        p = self.cfg["events_path"]
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [e for e in (json.loads(x) for x in f if x.strip()) if rule is None or e["rule"] == rule]

    def test_alerts_once_for_a_new_name_on_the_list(self):
        r = self.build()
        d = r.decide(DEV, "login.fresh.example", "A", rcode="NOERROR")
        self.assertEqual((d.action, d.reason), ("recommend", "new_domain"))
        e = self.events()[0]
        self.assertEqual(e["severity"], "warn")
        self.assertIn("newly registered", " ".join(e["reasons"]))
        self.assertEqual(e["trust"], "fresh.example")
        r.decide(DEV, "www.fresh.example", "A", rcode="NOERROR")
        self.assertEqual(len(self.events()), 1)                          # dedupe per domain family

    def test_not_for_unlisted_popular_or_nonexistent_names(self):
        r = self.build()
        for name, rcode in (("established.example", "NOERROR"), ("brand.example", "NOERROR"),
                            ("fresh.example", "NXDOMAIN")):
            self.assertNotEqual(r.decide(DEV, name, "A", rcode=rcode).reason, "new_domain", name)
        self.assertEqual(self.events(), [])

    def test_not_once_the_network_knows_the_domain(self):
        r = self.build(novelty_days=7)
        self.state.note_seen("fresh.example")
        self.state.first_seen[next(iter(self.state.first_seen))] = "2020-01-01"   # met long ago
        r.decide(DEV, "fresh.example", "A", rcode="NOERROR")
        self.assertEqual(self.events(), [])

    def test_high_with_a_second_signal(self):
        r = self.build()
        r.decide(DEV, "risky.top", "A", rcode="NOERROR")
        self.assertEqual(self.events()[0]["severity"], "high")

    def test_threat_feed_wins_one_alert_per_lookup(self):
        r = self.build()
        r.decide(DEV, "listed-bad.example", "A", rcode="NOERROR")
        self.assertEqual([e["rule"] for e in self.events(None)], ["threat_feed"])

    def test_off_reads_nothing(self):
        r = self.build(nrd_mode="off")
        r.decide(DEV, "fresh.example", "A", rcode="NOERROR")
        self.assertEqual(self.events(), [])
        self.assertEqual(len(r.det.nrd), 0)

    def test_block_only_inline_with_learning_off(self):
        r = self.build(nrd_mode="block", shadow=False)
        self.state.learning = True
        d = r.decide(DEV, "fresh.example", "A", rcode="NOERROR")
        self.assertEqual(d.action, "recommend")
        self.assertIn("learning mode", " ".join(self.events()[-1]["reasons"]))
        self.state.learning = False
        self.assertEqual(r.decide(DEV, "older.example", "A", rcode="NOERROR").action, "block")
        r = self.build(nrd_mode="block", shadow=True)
        self.state.learning = False
        self.assertEqual(r.decide(DEV, "fresh.example", "A", rcode="NOERROR").action, "recommend")

    def test_iot_device_follows_iot_enforce(self):
        r = self.build(nrd_mode="block", shadow=False, iot_enforce="off")
        self.state.learning = False
        self.assertEqual(r.decide(CAM, "fresh.example", "A", rcode="NOERROR").action, "recommend")
        r = self.build(nrd_mode="block", shadow=False, iot_enforce="on")
        self.state.learning = False
        self.assertEqual(r.decide(CAM, "fresh.example", "A", rcode="NOERROR").action, "block")

    def test_bad_mode_is_refused(self):
        with self.assertRaises(ValueError):
            config_mod.load_config(None, {"nrd_mode": "on"})
        with self.assertRaises(ValueError):
            config_mod.load_config(None, {"nrd_days": 0})


if __name__ == "__main__":
    unittest.main()
