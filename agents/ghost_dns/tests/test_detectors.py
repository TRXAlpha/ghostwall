"""Tests for detectors.py and their wiring in Resolver.decide()."""
import json
import os
import random
import string
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config as config_mod
import detectors as D
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from state import GhostState


class ThreatFeedTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "feed.txt")
        with open(self.path, "w") as f:
            f.write("# comment\nevil.example\nphish.bad-site.com\nco.uk\nnot a domain!\n")

    def test_exact_and_parent_match(self):
        feed = D.ThreatFeed(self.path)
        self.assertEqual(feed.match("evil.example"), ("evil.example", True))
        self.assertEqual(feed.match("a.b.evil.example"), ("evil.example", False))
        self.assertEqual(feed.match("phish.bad-site.com"), ("phish.bad-site.com", True))
        self.assertIsNone(feed.match("bad-site.com"))      # parent of a listed host is NOT listed
        self.assertIsNone(feed.match("google.com"))

    def test_public_suffix_never_matches(self):
        feed = D.ThreatFeed(self.path)
        self.assertIsNone(feed.match("anything.co.uk"))

    def test_garbage_lines_ignored(self):
        self.assertEqual(len(D.ThreatFeed(self.path)), 3)  # evil.example, phish..., co.uk

    def test_reloads_when_file_changes(self):
        feed = D.ThreatFeed(self.path, recheck_seconds=0)
        self.assertIsNone(feed.match("new-bad.example", now=1))
        time.sleep(0.05)
        with open(self.path, "a") as f:
            f.write("new-bad.example\n")
        os.utime(self.path, (time.time() + 5, time.time() + 5))
        self.assertIsNotNone(feed.match("new-bad.example", now=2))

    def test_missing_file_is_empty(self):
        self.assertIsNone(D.ThreatFeed(os.path.join(self.dir, "none.txt")).match("evil.example"))


class InternalNameTests(unittest.TestCase):
    def test_internal_names(self):
        for h in ("homepi", "_8080._https.homepi", "homepi.tail1234ab.ts.net", "printer.local",
                  "1.1.168.192.in-addr.arpa", "nas.home.arpa", "_dns-sd._udp.lan"):
            self.assertTrue(D.is_internal(h), h)

    def test_real_domains_are_not_internal(self):
        for h in ("example.com", "cdn.fbsbx.com", "xkqzjw.top", "a.b.co.uk"):
            self.assertFalse(D.is_internal(h), h)


class DohTests(unittest.TestCase):
    def test_flags_doh_provider(self):
        h = D.DohDetector(ignore_clients=["127.0.0.1"]).check("192.168.1.50", "dns.google")
        self.assertEqual(h.rule, "doh_bypass")

    def test_subdomain_of_provider(self):
        self.assertIsNotNone(D.DohDetector().check("192.168.1.50", "x.dns.quad9.net"))

    def test_ignores_pi_and_firefox_canary_and_normal(self):
        d = D.DohDetector(ignore_clients=["192.168.1.20"])
        self.assertIsNone(d.check("192.168.1.20", "dns.google"))
        self.assertIsNone(d.check("192.168.1.50", "use-application-dns.net"))
        self.assertIsNone(d.check("192.168.1.50", "google.com"))


def rand_label(seed, n=50):
    """A high-entropy label, like the payload chunks a DNS tunnel sends."""
    return "".join(random.Random(seed).choices(string.ascii_lowercase + string.digits, k=n))


class TunnelTests(unittest.TestCase):
    def test_many_distinct_long_subdomains(self):
        t = D.TunnelDetector(min_distinct=30)
        hit = None
        for i in range(35):
            hit = t.observe("dell", f"{'a1b2c3d4e5f6g7h8i9'}{i:03d}.t.tunnel.example", i) or hit
        self.assertEqual(hit.rule, "dns_tunnel")
        self.assertEqual(hit.severity, "high")

    def test_normal_subdomain_use_not_flagged(self):
        t = D.TunnelDetector()
        for i in range(200):
            self.assertIsNone(t.observe("dell", f"www{i % 3}.example.com", i))

    def test_many_short_subdomains_not_flagged(self):
        t = D.TunnelDetector(min_distinct=30, min_avg_label=14)
        for i in range(60):
            self.assertIsNone(t.observe("dell", f"h{i}.cdn.example.com", i))

    def test_exfil_long_random_labels(self):
        t = D.TunnelDetector(min_long=12)
        hit = None
        for i in range(14):
            lab = rand_label(i)
            hit = t.observe("dell", f"{lab}.exfil.example", i) or hit
        self.assertIsNotNone(hit)

    def test_a_few_long_random_labels_are_normal_web_traffic(self):
        """Fraud-fingerprinting, ad-safeframe and cloud-function hosts look like this."""
        t = D.TunnelDetector(min_long=12)
        for i in range(5):
            lab = rand_label(i)
            self.assertIsNone(t.observe("dell", f"{lab}.online-metrix.example", i))

    def test_same_long_host_repeated_is_not_distinct(self):
        t = D.TunnelDetector(min_long=3)
        lab = rand_label(99)
        for i in range(20):
            self.assertIsNone(t.observe("dell", f"{lab}.cdn.example", i))

    def test_cooldown_prevents_repeat(self):
        t = D.TunnelDetector(min_distinct=5, min_avg_label=1)
        hits = [t.observe("d", f"sub{i}xxxxxxxxxxxxxxxx.t.example", i) for i in range(40)]
        self.assertEqual(sum(1 for h in hits if h), 1)

    def test_apex_itself_ignored(self):
        self.assertIsNone(D.TunnelDetector().observe("d", "example.com", 0))


class BeaconTests(unittest.TestCase):
    def test_regular_interval_flagged(self):
        b = D.BeaconDetector(min_samples=8, min_interval=30)
        hit = None
        for k in range(10):
            hit = b.observe("dell", "c2.example", 1000 + 60 * k) or hit
        self.assertEqual(hit.rule, "dns_beacon")

    def test_jittery_not_flagged(self):
        b = D.BeaconDetector()
        for k, t in enumerate([0, 40, 190, 230, 500, 520, 900, 1500, 1520, 2300]):
            self.assertIsNone(b.observe("dell", "x.example", t))

    def test_fast_repeats_not_a_beacon(self):
        b = D.BeaconDetector(min_interval=30)
        for k in range(30):
            self.assertIsNone(b.observe("dell", "chatty.example", k * 10))

    def test_retries_collapse(self):
        b = D.BeaconDetector(min_samples=3)
        for t in (0, 1, 2, 3):                 # one lookup retried
            self.assertIsNone(b.observe("dell", "x.example", t))

    def test_per_device(self):
        b = D.BeaconDetector(min_samples=8)
        for k in range(10):
            self.assertIsNone(b.observe(f"dev{k}", "c2.example", 60 * k))  # 1 sample per device


class BurstTests(unittest.TestCase):
    def test_five_different_domains(self):
        d = D.DgaBurst(min_distinct=5)
        hit = None
        for i in range(5):
            hit = d.observe("dell", f"xk{i}qzvw.biz", 0.9, i * 10) or hit
        self.assertEqual(hit.rule, "dga_burst")

    def test_same_domain_repeated_is_not_a_burst(self):
        d = D.DgaBurst(min_distinct=5)
        for i in range(30):
            self.assertIsNone(d.observe("dell", "a.xkqzvw.biz", 0.95, i))

    def test_low_scores_ignored(self):
        d = D.DgaBurst(min_distinct=3)
        for i in range(10):
            self.assertIsNone(d.observe("dell", f"d{i}.example", 0.5, i))

    def test_window_expires(self):
        d = D.DgaBurst(min_distinct=5, window=600)
        for i in range(4):
            d.observe("dell", f"x{i}.biz", 0.9, i)
        self.assertIsNone(d.observe("dell", "x9.biz", 0.9, 5000))   # old ones expired


class FakeScorer:
    def __init__(self, dga=0.0):
        self.dga = dga

    def score_one(self, domain):
        return {"dga": self.dga, "dga_trm": self.dga, "dga_lr": self.dga}


class ResolverWiringTests(unittest.TestCase):
    def build(self, feed_lines=(), allow=(), **over):
        self.dir = tempfile.mkdtemp()
        feed = os.path.join(self.dir, "feed.txt")
        with open(feed, "w") as f:
            f.write("\n".join(feed_lines) + "\n")
        cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "s.json"), "events_path": os.path.join(self.dir, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "allowlist_path": None,
            "threat_feed_path": feed, **over})
        self.cfg = cfg
        self.state = GhostState(cfg["state_path"], learning_default=cfg.get("learning", True))
        for a in allow:
            self.state.allow(a)
        dm = DeviceMap.from_json([{"name": "dell", "ip": "192.168.1.30"}])
        self.now = 1000.0
        self.r = Resolver(cfg, self.state, FakeScorer(0.0), Enforcer(NullBackend()), dm, EventLog(cfg["events_path"]))
        self.r.clock = lambda: self.now
        return self.r

    def events(self):
        p = self.cfg["events_path"]
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def test_shipped_default_thresholds_are_the_measured_ones(self):
        cfg = config_mod.load_config(None)
        self.assertEqual(cfg["recommend_threshold"], 0.96)
        self.assertEqual(cfg["block_threshold"], 0.995)

    def test_feed_hit_recommends_in_learning(self):
        r = self.build(["evil.example"])
        d = r.decide("192.168.1.30", "evil.example", "A")
        self.assertEqual((d.action, d.reason), ("recommend", "threat_feed"))
        self.assertEqual(self.events()[0]["rule"], "threat_feed")

    def test_feed_hit_blocks_when_enforcing(self):
        r = self.build(["evil.example"], learning=False)
        self.state.set_learning(False)
        d = r.decide("192.168.1.30", "evil.example", "A")
        self.assertEqual(d.action, "block")

    def test_feed_hit_never_blocks_in_shadow(self):
        r = self.build(["evil.example"], shadow=True)
        self.state.set_learning(False)
        r.shadow = True
        self.assertEqual(r.decide("192.168.1.30", "evil.example", "A").action, "recommend")

    def test_exact_feed_match_beats_allowlist_but_parent_match_respects_it(self):
        r = self.build(["bad.cdn.example", "partner.test"], allow=["cdn.example", "partner.test"])
        self.assertEqual(r.decide("192.168.1.30", "bad.cdn.example", "A").reason, "threat_feed")
        self.assertEqual(r.decide("192.168.1.30", "x.partner.test", "A").action, "allow")

    def test_doh_bypass_alert(self):
        r = self.build()
        d = r.decide("192.168.1.30", "dns.google", "A")
        self.assertEqual(d.reason, "doh_bypass")

    def test_dga_burst_alert_via_resolver(self):
        r = self.build()
        r.scorer = FakeScorer(0.85)          # below recommend_threshold (0.96): no single alert
        reasons = []
        for i in range(5):
            self.now += 5
            reasons.append(r.decide("192.168.1.30", f"qx{i}zk.top", "A").reason)
        self.assertEqual(reasons[:4].count("dga_burst"), 0)
        self.assertEqual(reasons[4], "dga_burst")

    def test_corroborated_needs_rare_tld(self):
        r = self.build()
        r.scorer = FakeScorer(0.85)
        self.assertEqual(r.decide("192.168.1.30", "plainname.com", "A").action, "allow")
        self.assertEqual(r.decide("192.168.1.30", "plainname.xyz", "A").reason, "dga_corroborated")

    def test_established_domain_does_not_raise_plain_suspect(self):
        r = self.build()
        r.scorer = FakeScorer(0.97)                          # between recommend (0.96) and block (0.995)
        self.state.first_seen["longtime.example"] = "2020-01-01T00:00:00Z"   # seen for years
        self.assertEqual(r.decide("192.168.1.30", "longtime.example", "A").action, "allow")
        self.assertEqual(r.decide("192.168.1.30", "brandnew.example", "A").reason, "dga_suspect")

    def test_suspect_only_new_can_be_turned_off(self):
        r = self.build(suspect_only_new=False)
        r.scorer = FakeScorer(0.97)
        self.state.first_seen["longtime.example"] = "2020-01-01T00:00:00Z"
        self.assertEqual(r.decide("192.168.1.30", "longtime.example", "A").reason, "dga_suspect")

    def test_internal_names_are_never_scored_or_beaconed(self):
        r = self.build()
        r.scorer = FakeScorer(0.99)                 # would be flagged if it were scored
        for k in range(12):
            self.now = 1000 + 60 * k
            d = r.decide("192.168.1.30", "_8080._https.homepi", "HTTPS")
        self.assertEqual((d.action, d.reason), ("allow", "internal"))
        self.assertEqual(self.events(), [])

    def test_beacon_on_odd_looking_name_alerts(self):
        r = self.build()
        r.scorer = FakeScorer(0.6)           # looks somewhat random
        for k in range(10):
            self.now = 1000 + 60 * k
            r.decide("192.168.1.30", "call-home.example", "A")
        self.assertIn("dns_beacon", [e["rule"] for e in self.events()])

    def test_beacon_on_ordinary_name_is_ignored(self):
        """Apps poll on timers all day (updaters, telemetry): timing alone is not evidence."""
        r = self.build()
        r.scorer = FakeScorer(0.05)
        for k in range(20):
            self.now = 1000 + 300 * k
            r.decide("192.168.1.30", "catalog.example", "A")
        self.assertNotIn("dns_beacon", [e["rule"] for e in self.events()])

    def test_beacon_on_rare_tld_alerts_even_with_low_score(self):
        r = self.build()
        r.scorer = FakeScorer(0.05)
        for k in range(10):
            self.now = 1000 + 60 * k
            r.decide("192.168.1.30", "updates.example.top", "A")
        self.assertIn("dns_beacon", [e["rule"] for e in self.events()])


if __name__ == "__main__":
    unittest.main()
