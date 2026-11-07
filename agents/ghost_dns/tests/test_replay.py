"""replay_querylog.py: it must replay with *your* settings and the installed lists.

v0.3.0b2's replay ignored /etc/ghostwall/ghost_dns.json (so a raised threshold changed
nothing in it), had no way to try another value, and on installs upgraded from before
v0.2.0b2 it picked the stale feed left next to the code, which also hid the popular list
(it looked for popular_domains.txt beside that stale copy).

All names are synthetic; all addresses are 192.168.1.x LAN.
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replay_querylog as rq
from test_nx_burst import INFECTED, adguard_row, dga_names, nx


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


class Settings(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.wd = os.path.join(self.dir, "wd")
        os.mkdir(self.wd)
        self.lists = os.path.join(self.dir, "lib")
        os.mkdir(self.lists)
        self.feed = write(os.path.join(self.lists, "threat_feed.txt"), "evil-feed-example.com\n")
        write(os.path.join(self.lists, "popular_domains.txt"), "# in rank order\nexample.com\n")

    def test_parse_set(self):
        self.assertEqual(rq.parse_set(["a=8", "b=0.9", "c=true", "d=hello", 'e=["x"]']),
                         {"a": 8, "b": 0.9, "c": True, "d": "hello", "e": ["x"]})
        with self.assertRaises(SystemExit):
            rq.parse_set(["no-equals-sign"])

    def test_uses_your_config_but_never_its_files(self):
        cfg_path = write(os.path.join(self.dir, "ghost_dns.json"), json.dumps({
            "threat_feed_path": self.feed, "nx_burst_min_distinct": 7, "recommend_threshold": 0.99,
            "state_path": "/var/lib/ghostwall/state.json", "events_path": "/var/lib/ghostwall/events.jsonl",
            "capture_enabled": True}))
        cfg = rq.replay_config(cfg_path, "", "", {}, self.wd)
        self.assertEqual(cfg["nx_burst_min_distinct"], 7)
        self.assertEqual(cfg["recommend_threshold"], 0.99)
        self.assertEqual(cfg["threat_feed_path"], self.feed)
        self.assertEqual(cfg["popular_path"], os.path.join(self.lists, "popular_domains.txt"))
        self.assertTrue(cfg["state_path"].startswith(self.wd))
        self.assertTrue(cfg["events_path"].startswith(self.wd))
        self.assertTrue(cfg["shadow"])
        self.assertFalse(cfg["capture_enabled"])

    def test_set_beats_config_but_not_the_throwaway_files(self):
        cfg_path = write(os.path.join(self.dir, "ghost_dns.json"),
                         json.dumps({"threat_feed_path": self.feed, "nx_burst_min_distinct": 7}))
        cfg = rq.replay_config(cfg_path, "", "", {"nx_burst_min_distinct": 15, "popular_top_n": 100000,
                                                  "events_path": "/tmp/live.jsonl"}, self.wd)
        self.assertEqual(cfg["nx_burst_min_distinct"], 15)
        self.assertEqual(cfg["popular_top_n"], 100000)
        self.assertTrue(cfg["events_path"].startswith(self.wd))

    def test_installed_feed_beats_the_stale_copy_next_to_the_code(self):
        code = os.path.join(self.dir, "code")
        os.mkdir(code)
        write(os.path.join(code, "threat_feed.txt"), "stale-example.com\n")
        with mock.patch.object(rq, "HERE", code), mock.patch.object(rq, "INSTALLED_FEED", self.feed):
            cfg = rq.replay_config(None, "", "", {}, self.wd)
        self.assertEqual(cfg["threat_feed_path"], self.feed)
        self.assertEqual(cfg["popular_path"], os.path.join(self.lists, "popular_domains.txt"))

    def test_explicit_feed_and_popular_win(self):
        other = write(os.path.join(self.dir, "other_feed.txt"), "x-example.com\n")
        pop = write(os.path.join(self.dir, "pop.txt"), "example.org\n")
        cfg = rq.replay_config(None, other, pop, {}, self.wd)
        self.assertEqual((cfg["threat_feed_path"], cfg["popular_path"]), (other, pop))


class EndToEnd(unittest.TestCase):
    """A storm of 12 unregistered names: an nx_burst with your 10, none with --set 15."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        rows = []
        for i, name in enumerate(dga_names(12)):
            row = json.loads(adguard_row(INFECTED, name, nx(name)))
            row["T"] = f"2026-11-05T10:{i:02d}:10.000000000Z"
            rows.append(json.dumps(row))
        self.log = write(os.path.join(self.dir, "querylog.json"), "\n".join(rows) + "\n")
        self.feed = write(os.path.join(self.dir, "threat_feed.txt"), "evil-feed-example.com\n")

    def replay(self, *extra):
        out = os.path.join(self.dir, "alerts.jsonl")
        args = ["--querylog", self.log, "--no-config", "--devices", "", "--no-allowlist",
                "--feed", self.feed, "--events-out", out, *extra]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(rq.main(args), 0)
        with open(out, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()], buf.getvalue()

    def test_default_threshold_alerts_once(self):
        evs, text = self.replay()
        self.assertEqual([e["rule"] for e in evs if e["rule"] == "nx_burst"], ["nx_burst"])
        self.assertIn("replayed 12 queries", text)

    def test_alert_time_is_the_query_time(self):
        evs, text = self.replay()
        burst = [e for e in evs if e["rule"] == "nx_burst"][0]
        self.assertEqual(burst["time"], "2026-11-05T10:09:10Z")   # the 10th name's query
        self.assertIn("alerts per day: {'2026-11-05':", text)

    def test_set_raises_the_threshold(self):
        evs, text = self.replay("--set", "nx_burst_min_distinct=15")
        self.assertEqual([e for e in evs if e["rule"] == "nx_burst"], [])
        self.assertIn("nx_burst_min_distinct=15", text)

    def test_leaves_no_temporary_directory(self):
        before = set(os.listdir(tempfile.gettempdir()))
        self.replay()
        left = {d for d in set(os.listdir(tempfile.gettempdir())) - before if d.startswith("ghostwall-replay-")}
        self.assertEqual(left, set())


if __name__ == "__main__":
    unittest.main()
