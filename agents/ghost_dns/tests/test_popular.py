"""Tests for the popular-domain guard of the DGA rules (detectors.PopularDomains and its
use in Resolver.decide), reading the Tranco cache update_feed.py writes (no network)."""
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config as config_mod
import detectors as D
import update_feed as U
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from state import GhostState

DEV = "192.168.1.30"


def write(path, text, mode="w"):
    with open(path, mode) as f:
        f.write(text)


class PopularDomainsTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "popular_domains.txt")
        write(self.path, "# Tranco list TEST1, top 5\nabc.ddns.net\nbrand.example\nddns.net\nqq.test\n"
                         "www.shop.co.uk\n")

    def test_registrable_domain_and_subdomains_match(self):
        p = D.PopularDomains(self.path)
        for host in ("brand.example", "cdn.edge.brand.example", "qq.test", "shop.co.uk", "img.shop.co.uk"):
            self.assertTrue(p.match(host), host)
        for host in ("brand.test", "notbrand.example", "co.uk", "other.co.uk"):
            self.assertFalse(p.match(host), host)
        self.assertEqual(len(p), 5)

    def test_dynamic_dns_names_stay_separate(self):
        # A listed provider must not vouch for every name under it: those are scored
        # by their own label (tokenizer.DYNAMIC_DNS_SUFFIXES).
        p = D.PopularDomains(self.path)
        self.assertTrue(p.match("abc.ddns.net"))
        self.assertTrue(p.match("www.abc.ddns.net"))
        self.assertFalse(p.match("kq7zx2wvplmh.ddns.net"))

    def test_tranco_csv_format_is_read_too(self):
        write(self.path, "1,brand.example\r\n2,qq.test\r\n")
        self.assertTrue(D.PopularDomains(self.path).match("x.qq.test"))

    def test_missing_file_or_no_path_means_no_guard(self):
        self.assertFalse(D.PopularDomains(os.path.join(self.dir, "none.txt")).match("brand.example"))
        self.assertFalse(D.PopularDomains(None).match("brand.example"))
        self.assertFalse(D.PopularDomains("").match("brand.example"))

    def test_garbled_file_keeps_only_hostnames(self):
        write(self.path, b"\x00\xff\xfe garbage\nnot a domain!\n\xc3(\n,,,\n192.0.2.7\nbrand.example\n", "wb")
        p = D.PopularDomains(self.path)
        self.assertTrue(p.match("brand.example"))
        self.assertEqual(len(p), 1)
        write(self.path, b"\x00\x01\x02\xff" * 1000, "wb")
        self.assertFalse(D.PopularDomains(self.path).match("brand.example"))

    def test_reloads_when_file_changes(self):
        p = D.PopularDomains(self.path, recheck_seconds=0)
        self.assertFalse(p.match("new.example", now=1))
        write(self.path, "new.example\n")
        os.utime(self.path, (time.time() + 5, time.time() + 5))
        self.assertTrue(p.match("new.example", now=2))
        self.assertFalse(p.match("brand.example", now=3))

    def test_deleted_file_keeps_the_loaded_list(self):
        p = D.PopularDomains(self.path, recheck_seconds=0)
        self.assertTrue(p.match("brand.example", now=1))
        os.remove(self.path)
        self.assertTrue(p.match("brand.example", now=2))

    def test_reads_the_cache_update_feed_writes(self):
        out = os.path.join(self.dir, "threat_feed.txt")
        pages = {U.TRANCO_ID_URL: "TEST1\n",
                 U.TRANCO_LIST_URL.format(id="TEST1", n=3): "1,brand.example\r\n2,qq.test\r\n3,shop.co.uk\r\n",
                 "https://feed.example/list.txt": "".join(f"bad{i}.example\n" for i in range(3))}
        with mock.patch.object(U, "fetch", lambda url, timeout=90.0: pages[url]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = U.main(["--out", out, "--feed", "https://feed.example/list.txt", "--min", "1",
                         "--popular-top", "3"])
        self.assertEqual(rc, 0)
        cfg = config_mod.load_config(None, {"threat_feed_path": out})
        self.assertEqual(cfg["popular_path"], os.path.join(self.dir, "popular_domains.txt"))
        p = D.PopularDomains(cfg["popular_path"])
        for host in ("brand.example", "img.qq.test", "www.shop.co.uk"):
            self.assertTrue(p.match(host), host)
        self.assertFalse(p.match("bad0.example"))


class ConfigTests(unittest.TestCase):
    def test_popular_path_defaults_next_to_the_feed(self):
        cfg = config_mod.load_config(None, {"threat_feed_path": "/var/lib/ghostwall/threat_feed.txt"})
        self.assertEqual(cfg["popular_path"], "/var/lib/ghostwall/popular_domains.txt")
        cfg = config_mod.load_config(None, {"popular_path": "/elsewhere/top.csv"})
        self.assertEqual(cfg["popular_path"], "/elsewhere/top.csv")
        cfg = config_mod.load_config(None, {"popular_path": ""})          # off
        self.assertEqual(cfg["popular_path"], "")


class FakeScorer:
    def __init__(self, dga=0.0):
        self.dga = dga

    def score_one(self, domain):
        return {"dga": self.dga, "dga_trm": self.dga, "dga_lr": self.dga}


class ResolverGuardTests(unittest.TestCase):
    def build(self, dga, popular="brand.example\nqq.test\n", feed="", **over):
        self.dir = tempfile.mkdtemp()
        pop, fd = os.path.join(self.dir, "popular_domains.txt"), os.path.join(self.dir, "feed.txt")
        write(pop, popular)
        write(fd, feed)
        cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "s.json"), "events_path": os.path.join(self.dir, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "allowlist_path": None,
            "threat_feed_path": fd, **over})
        if "popular_path" not in over:          # found next to the feed by default
            self.assertEqual(cfg["popular_path"], pop)
        self.cfg = cfg
        self.state = GhostState(cfg["state_path"], learning_default=cfg.get("learning", True))
        dm = DeviceMap.from_json([{"name": "dell", "ip": DEV}])
        self.now = 1000.0
        self.r = Resolver(cfg, self.state, FakeScorer(dga), Enforcer(NullBackend()), dm,
                          EventLog(cfg["events_path"]))
        self.r.clock = lambda: self.now
        return self.r

    def rules(self):
        p = self.cfg["events_path"]
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return [json.loads(l)["rule"] for l in f if l.strip()]

    def test_guard_silences_dga_suspect_for_popular_domain_and_subdomains(self):
        r = self.build(0.97)
        for host in ("qq.test", "img.cdn.qq.test"):
            self.assertEqual(r.decide(DEV, host, "A").reason, "popular", host)
        self.assertEqual(r.decide(DEV, "kq7zx2wvplmh.test", "A").reason, "dga_suspect")
        self.assertEqual(self.rules(), ["dga_suspect"])
        self.assertEqual(r.stats["popular"], 2)

    def test_guard_stops_score_blocks_and_corroborated(self):
        r = self.build(0.999, learning=False)
        self.state.set_learning(False)
        self.assertEqual(r.decide(DEV, "brand.example", "A").action, "allow")
        self.assertFalse(self.state.is_blocked("brand.example"))
        self.assertEqual(r.decide(DEV, "unlisted.example", "A").action, "block")
        r = self.build(0.85, popular="brand.xyz\n")
        self.assertEqual(r.decide(DEV, "brand.xyz", "A").reason, "popular")
        self.assertEqual(r.decide(DEV, "other.xyz", "A").reason, "dga_corroborated")

    def test_threat_feed_still_wins(self):
        r = self.build(0.99, feed="bad.qq.test\n")
        self.assertEqual(r.decide(DEV, "bad.qq.test", "A").reason, "threat_feed")
        self.assertEqual(r.decide(DEV, "fine.qq.test", "A").reason, "popular")

    def test_popular_names_still_count_for_a_burst(self):
        popular = "".join(f"qx{i}zk.test\n" for i in range(5))
        r = self.build(0.97, popular=popular)
        reasons = []
        for i in range(5):
            self.now += 5
            reasons.append(r.decide(DEV, f"qx{i}zk.test", "A").reason)
        self.assertEqual(reasons, ["popular"] * 4 + ["dga_burst"])
        self.assertEqual(self.rules(), ["dga_burst"])

    def test_no_list_is_todays_behaviour(self):
        r = self.build(0.97, popular_path=os.path.join(tempfile.mkdtemp(), "missing.txt"))
        self.assertEqual(r.decide(DEV, "qq.test", "A").reason, "dga_suspect")
        r = self.build(0.97, popular_path="")
        self.assertEqual(r.decide(DEV, "qq.test", "A").reason, "dga_suspect")

    def test_low_score_never_consults_the_list(self):
        r = self.build(0.1)
        with mock.patch.object(r.det.popular, "match", side_effect=AssertionError("looked up")):
            self.assertEqual(r.decide(DEV, "qq.test", "A").reason, "clean")


if __name__ == "__main__":
    unittest.main()
