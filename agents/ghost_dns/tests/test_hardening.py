"""Fixes from a review of nx_burst, the threat feed updater and the popular guard. Each
test fails on the code before its fix. Synthetic names and 192.168.1.x addresses only."""
import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detectors as D
import dnsmsg
import update_feed as U
from shadow import adguard_rcode, pihole_reply
from test_nx_burst import INFECTED, Base, adguard_row, dga_names, nx, qname, reply


def cname_to_missing(name, target):
    """NXDOMAIN whose answer section is a CNAME from `name` to a name that is gone."""
    out = struct.pack(">HHHHHH", 0x4242, 0x8183, 1, 1, 0, 0) + qname(name) + struct.pack(">HH", 1, 1)
    rdata = qname(target)
    return out + struct.pack(">HHHIH", 0xC00C, 5, 1, 60, len(rdata)) + rdata


class ReplyStatusTests(unittest.TestCase):
    def test_empty_noerror_is_nodata_and_cname_to_nothing_is_noerror(self):
        self.assertEqual(dnsmsg.reply_status(reply("a.example", 0, ip="192.0.2.1")), "NOERROR")
        self.assertEqual(dnsmsg.reply_status(reply("a.example", 0)), "NODATA")
        self.assertEqual(dnsmsg.reply_status(nx("brothernerveplace.net")), "NXDOMAIN")
        self.assertEqual(dnsmsg.reply_status(cname_to_missing("shop.example", "gone.platform.example")), "NOERROR")
        self.assertEqual(dnsmsg.reply_status(reply("a.example", 2)), "SERVFAIL")
        self.assertIsNone(dnsmsg.reply_status(b"\x00" * 5))

    def test_adguard_and_pihole_report_nodata(self):
        row = __import__("json").loads(adguard_row(INFECTED, "x.example", reply("x.example", 0, qtype=28), qtype="AAAA"))
        self.assertEqual(adguard_rcode(row, "x.example", False)[0], "NODATA")
        self.assertEqual(pihole_reply("Nov  5 10:00:01 dnsmasq[812]: reply x.example is NODATA-IPv6"),
                         ("x.example", "NODATA"))


class NxBurstReviewTests(Base):
    def test_made_up_empty_aaaa_does_not_mark_a_dga_domain_registered(self):
        # AdGuard with IPv6 resolving off answers AAAA itself, empty, before the A query's
        # NXDOMAIN comes back. That must not teach "this domain exists".
        for n in dga_names(15):
            self.r.decide(INFECTED, n, "AAAA", rcode="NODATA")
            self.r.decide(INFECTED, n, "A", rcode="NXDOMAIN", nx_zone=n.rsplit(".", 1)[-1])
            self.now += 5
        self.assertEqual(len(self.events()), 1)

    def test_cname_to_a_missing_name_is_not_an_unregistered_domain(self):
        for i, n in enumerate(dga_names(15)):
            self.r.decide(INFECTED, n, "A", rcode=dnsmsg.reply_status(cname_to_missing(n, f"x{i}.gone.example")))
            self.now += 5
        self.assertEqual(self.events(), [])

    def test_repeating_one_dead_name_cannot_hide_the_rest(self):
        # 5 lookups a second of one dead domain, plus a new DGA name every 20 s.
        names = iter(dga_names(40, seed=2))
        for step in range(30 * 60 * 5):
            self.now += 0.2
            self.r.decide(INFECTED, "deadvendor.com", "A", rcode="NXDOMAIN", nx_zone="com")
            if step % 100 == 0:
                n = next(names)
                self.r.decide(INFECTED, n, "A", rcode="NXDOMAIN", nx_zone=n.rsplit(".", 1)[-1])
            if self.events():
                break
        self.assertEqual(len(self.events()), 1)

    def test_cheap_new_gtlds_count(self):
        for tld in ("science", "party", "bond", "vip", "pics", "support", "ltd"):
            self.assertTrue(D.nx_countable(f"qwhdjske.{tld}"), tld)
        for name in ("printer.fritz.box", "nas.home", "pc.corp", "x.localdomain", "a.notatld"):
            self.assertFalse(D.nx_countable(name), name)

    def test_one_storm_one_alert(self):
        class High:
            def score_one(self, domain):
                return {"dga": 0.9, "dga_trm": 0.9, "dga_lr": 0.9}
        self.r.scorer = High()
        self.nx_storm(INFECTED, dga_names(30))
        self.assertEqual(len(self.events(rule=None)), 1)


class UpdaterReviewTests(unittest.TestCase):
    def test_typo_in_env_uses_the_default(self):
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"GHOSTWALL_FEED_POPULAR_TOP": "100k"}), contextlib.redirect_stderr(err):
            self.assertEqual(U._env_int("GHOSTWALL_FEED_POPULAR_TOP", 7), 7)
        self.assertIn("not a number", err.getvalue())
        with mock.patch.dict(os.environ, {"GHOSTWALL_FEED_POPULAR_TOP": "1_000"}):
            self.assertEqual(U._env_int("GHOSTWALL_FEED_POPULAR_TOP", 7), 1000)

    def test_failed_write_leaves_no_temp_file(self):
        d = tempfile.mkdtemp()
        with mock.patch.object(U.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                U._write_atomic(os.path.join(d, "threat_feed.txt"), "x.example\n")
        self.assertEqual(os.listdir(d), [])

    def test_both_lists_off_removes_the_old_cache(self):
        d = tempfile.mkdtemp()
        out, cache = os.path.join(d, "threat_feed.txt"), os.path.join(d, "popular_domains.txt")
        with open(cache, "w") as f:
            f.write("old.example\n")
        page = "".join(f"bad{i}.example\n" for i in range(5))
        with mock.patch.object(U, "fetch", lambda url, timeout=90: page), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = U.main(["--out", out, "--feed", "https://a.example/l.txt", "--min", "1",
                         "--popular-top", "0", "--cache-top", "0"])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(cache))

    def test_after_the_carry_period_a_smaller_list_is_accepted(self):
        import datetime
        d = tempfile.mkdtemp()
        out = os.path.join(d, "threat_feed.txt")
        url = "https://a.example/l.txt"
        old = (datetime.date.today() - datetime.timedelta(days=U.MAX_CARRY_DAYS + 1)).isoformat()
        with open(out, "w") as f:
            f.write(f"#@source\t{url}\t{old}\ta.example\t\n" + "".join(f"old{i}.example\n" for i in range(10)))
        with mock.patch.object(U, "fetch", lambda u, timeout=90: "new0.example\nnew1.example\n"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = U.main(["--out", out, "--feed", url, "--min", "1", "--popular-top", "0", "--cache-top", "0"])
        self.assertEqual(rc, 0)
        f = D.ThreatFeed(out)
        self.assertIsNotNone(f.match("new1.example"))
        self.assertIsNone(f.match("old3.example"))


if __name__ == "__main__":
    unittest.main()
