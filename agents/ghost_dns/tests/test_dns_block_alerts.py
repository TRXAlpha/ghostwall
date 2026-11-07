"""What Ghostwall does with answers that a protective upstream or its own DNS-server blocklist
produced: no nx_burst, an honest alert text, Trust and unblock reaching the exception list, and
the expanded feed set. Example names only."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import update_feed as U
from shadow import QueryLogFollower
from state import GhostState
from test_nx_burst import INFECTED, Base, adguard_row, dga_names, reply


class UpstreamBlockedNotCounted(Base):
    def test_filtered_answers_never_raise_nx_burst(self):
        names = dga_names(14)
        self.nx_storm(INFECTED, names, zone="tld")           # control: real NXDOMAINs do
        self.assertEqual(len(self.events("nx_burst")), 1)
        r = self.build()
        for n in dga_names(14, seed=3):
            r.decide(INFECTED, n, "A", rcode="FILTERED")
            self.now += 5
        self.assertEqual(self.events("nx_burst"), [])
        self.assertEqual(r.stats["upstream_filtered"], 14)

    def test_each_filtered_name_is_marked_blocked_upstream_in_events(self):
        r = self.build()
        r.decide(INFECTED, "bad.example.net", "A", rcode="FILTERED")
        r.decide(INFECTED, "bad.example.net", "AAAA", rcode="FILTERED")     # same family, same day: once
        ev = self.events("upstream_block")
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["severity"], ev[0]["action"], ev[0]["domain"]), ("info", "allow", "bad.example.net"))
        self.assertIn("upstream DNS filter", ev[0]["reasons"][0])

    def log_follow(self, quad9):
        r = self.build(shadow=True, protective_upstream="quad9" if quad9 else "off")
        log = os.path.join(self.dir, "querylog.json")
        open(log, "w").close()
        fol = QueryLogFollower(r, log, fmt="adguard")
        with open(log, "a") as f:
            for n in dga_names(14, seed=5):                  # Quad9's block: NXDOMAIN with no SOA
                f.write(adguard_row(INFECTED, n, reply(n, 3)) + "\n")
        fol.poll_once()
        return r

    def test_quad9_nxdomain_without_soa_is_read_as_a_block_when_the_upstream_is_quad9(self):
        r = self.log_follow(quad9=True)
        self.assertEqual(self.events("nx_burst"), [])
        self.assertEqual(r.stats["upstream_filtered"], 14)

    def test_the_same_log_without_the_setting_still_counts_for_nx_burst(self):
        self.log_follow(quad9=False)
        self.assertEqual(len(self.events("nx_burst")), 1)

    def test_cloudflare_zero_address_is_read_without_any_setting(self):
        r = self.build(shadow=True)
        log = os.path.join(self.dir, "querylog.json")
        open(log, "w").close()
        fol = QueryLogFollower(r, log, fmt="adguard")
        with open(log, "a") as f:
            for n in dga_names(14, seed=6):
                f.write(adguard_row(INFECTED, n, reply(n, 0, ip="0.0.0.0")) + "\n")
        fol.poll_once()
        self.assertEqual(r.stats["upstream_filtered"], 14)
        self.assertEqual(self.events("nx_burst"), [])


class ThreatFeedAlertText(Base):
    def setUp(self):
        self.feed = os.path.join(tempfile.mkdtemp(), "threat_feed.txt")
        with open(self.feed, "w") as f:
            f.write("#@source\thttps://x.example/a\t2026-11-07\tURLhaus\tmalware\nevil.example.com\n")
        self.build(threat_feed_path=self.feed, shadow=True)

    def reasons(self, **kw):
        self.r.decide(INFECTED, "evil.example.com", "A", **kw)
        ev = self.events("threat_feed")
        return ev[-1]["reasons"] if ev else []

    def test_says_blocked_by_your_dns_server_when_it_was(self):
        why = self.reasons(upstream_blocked=True)
        self.assertIn("blocked by your DNS server", why)
        self.assertFalse([w for w in why if w.startswith("not blocked")])
        self.assertIn("evil.example.com is on URLhaus (malware)", why[0])

    def test_still_says_not_blocked_when_nothing_blocked_it(self):
        why = self.reasons()
        self.assertIn("not blocked (shadow mode)", why)
        self.assertNotIn("blocked by your DNS server", why)

    def test_upstream_filter_is_named_as_such(self):
        self.assertIn("blocked by your upstream DNS filter", self.reasons(rcode="FILTERED"))


class TrustAndUnblockReachTheView(unittest.TestCase):
    def test_view_file_follows_trust_untrust_and_unblock(self):
        d = tempfile.mkdtemp()
        al = os.path.join(d, "allowlist.txt")
        with open(al, "w") as f:
            f.write("starter.example.com\n")
        st = GhostState(os.path.join(d, "state.json"))
        st.load_allowlist_file(al)
        view = lambda: json.load(open(os.path.join(d, "dns_view.json")))
        st.allow("mine.example.com")
        self.assertEqual((view()["trusted"], view()["starter"]), (["mine.example.com"], ["starter.example.com"]))
        st.set_dns_exception("ads.example.com")
        self.assertEqual(view()["exceptions"], ["ads.example.com"])
        self.assertFalse(st.set_dns_exception("ads.example.com"))
        st.untrust("mine.example.com")
        st.set_dns_exception("ads.example.com", False)
        self.assertEqual((view()["trusted"], view()["exceptions"]), ([], []))
        st.set_dns_exception("keep.example.com")
        self.assertEqual(GhostState(os.path.join(d, "state.json")).dns_exceptions, {"keep.example.com"})


class ExpandedFeedSet(unittest.TestCase):
    def test_default_is_unchanged_until_you_choose_blocking(self):
        self.assertEqual(U.feed_sources({}, ram_kb=8_000_000), U.DEFAULT_SOURCES)
        self.assertEqual(U.feed_sources({"DNS_BLOCK_FEED": "off"}, ram_kb=8_000_000), U.DEFAULT_SOURCES)

    def test_blocking_picks_the_set_by_ram(self):
        big = U.feed_sources({"DNS_BLOCK_FEED": "on"}, ram_kb=1_900_000)
        small = U.feed_sources({"DNS_BLOCK_FEED": "dry-run"}, ram_kb=900_000)
        self.assertIn("tif.medium", " ".join(s.url for s in big))
        self.assertIn("tif.mini", " ".join(s.url for s in small))
        for got in (big, small):
            self.assertEqual([s.name for s in got if s.name in ("CERT Polska", "OpenPhish")], ["CERT Polska", "OpenPhish"])
        self.assertIn("tif.mini", " ".join(s.url for s in U.feed_sources(
            {"DNS_BLOCK_FEED": "on", "GHOSTWALL_TIF": "mini"}, ram_kb=8_000_000)))
        self.assertEqual(U.feed_sources({"DNS_BLOCK_FEED": "on", "GHOSTWALL_FEED_SET": "standard"}, 8_000_000),
                         U.DEFAULT_SOURCES)

    def test_openphish_urls_become_hosts(self):
        txt = "https://www.evil.example.com/login?x=1\nhttp://bad.example.net:8080/a\nhttp://192.0.2.9/x\nnot a url\n"
        self.assertEqual(U.parse_url_hosts(txt), {"www.evil.example.com", "bad.example.net"})

    def test_threatfox_key_stays_out_of_the_feed_file_and_the_log(self):
        key = "tf-key-sentinel-123"
        url = f"https://threatfox-api.example.net/v2/files/exports/{key}/hostfile.txt"
        env = {"DNS_BLOCK_FEED": "on", "THREATFOX_URL": url}
        srcs = U.feed_sources(env, ram_kb=900_000)
        self.assertEqual(srcs[-1].url, U.THREATFOX_ID)
        fetched = []

        def fake(u, timeout=90.0):
            fetched.append(u)
            if u == url:
                raise OSError(f"HTTP Error 401 for {url}")
            return "".join(f"h{i}.example.org\n" for i in range(5))
        d = tempfile.mkdtemp()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env), mock.patch.object(U, "fetch", fake), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = U.main(["--out", os.path.join(d, "f.txt"), "--min", "3", "--popular-top", "0", "--cache-top", "0"])
        self.assertEqual(rc, 0)
        self.assertIn(url, fetched)
        self.assertNotIn(key, out.getvalue() + err.getvalue())
        self.assertIn("FAILED " + U.THREATFOX_ID, err.getvalue())
        with open(os.path.join(d, "f.txt")) as f:
            self.assertNotIn(key, f.read())

    def test_threatfox_hostfile_lines_parse(self):
        self.assertEqual(U.parse_domains("# c\n127.0.0.1 c2.example.org\n127.0.0.1\tload.example.net\n"),
                         {"c2.example.org", "load.example.net"})


if __name__ == "__main__":
    unittest.main()
