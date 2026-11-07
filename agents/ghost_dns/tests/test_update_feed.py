"""Tests for update_feed (no network: fetch is replaced by a fake)."""
import contextlib
import datetime
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import detectors as D
import update_feed as U


class ParseTests(unittest.TestCase):
    def test_plain_and_hosts_formats(self):
        txt = "# c\nEvil.Example\n0.0.0.0 bad.example.org\n127.0.0.1\tother.test\n!adblock\n\n"
        self.assertEqual(U.parse_domains(txt), {"evil.example", "bad.example.org", "other.test"})

    def test_rejects_ips_single_labels_and_junk(self):
        txt = "1.2.3.4\nlocalhost\nnot a domain\nhttp://x.com/path\nok.example\n-bad-.example\n"
        self.assertEqual(U.parse_domains(txt), {"ok.example"})

    def test_inline_comment_and_trailing_dot(self):
        self.assertEqual(U.parse_domains("a.example. # note\n"), {"a.example"})

    def test_empty(self):
        self.assertEqual(U.parse_domains(""), set())

    def test_adblock_rules(self):
        txt = ("[Adblock Plus]\n! Title: x\n||evil.example^\n||Bad.Example.org^\n"
               "@@||good.example^\n||opt.example^$important\n||path.example/x^\n|http://x.example|\n")
        self.assertEqual(U.parse_domains(txt), {"evil.example", "bad.example.org"})

    def test_tranco_csv(self):
        txt = "1,popular.example\n2,www.gov.test\r\n3,third.example\n"
        self.assertEqual(U.parse_tranco(txt, 2), {"popular.example", "www.gov.test"})
        self.assertEqual(U.parse_tranco("# cache\nb.example\na.example\n", 10), {"a.example", "b.example"})


class GuardTests(unittest.TestCase):
    def test_drops_popular_exact_names_keeps_hosts_under_them(self):
        popular = {"popular.example", "shared-host.example"}
        doms = {"github.com", "www.github.com", "github.io", "evil.github.io", "evil.blogspot.com",
                "abc.duckdns.org", "drive.google.com", "popular.example", "www.popular.example",
                "evil.shared-host.example", "bad.example"}
        kept, dropped = U.guard(doms, popular)
        self.assertEqual(dropped, {"github.com", "www.github.com", "github.io", "drive.google.com",
                                   "popular.example", "www.popular.example"})
        self.assertEqual(kept, {"evil.github.io", "evil.blogspot.com", "abc.duckdns.org",
                                "evil.shared-host.example", "bad.example"})

    def test_never_list_applies_without_a_popularity_list(self):
        kept, dropped = U.guard({"github.com", "bad.example"}, set())
        self.assertEqual((kept, dropped), ({"bad.example"}, {"github.com"}))


A, B = "https://a.example/list.txt", "https://b.example/hosts"
TRANCO = "1,popular.example\n2,second.example\n"


def lines(n, prefix):
    return "".join(f"{prefix}{i}.example\n" for i in range(n))


class MainTests(unittest.TestCase):
    """update_feed.main end to end with a fake fetch."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.out = os.path.join(self.dir, "threat_feed.txt")
        self.pages = {U.TRANCO_ID_URL: "TEST1\n", U.TRANCO_LIST_URL.format(id="TEST1", n=2): TRANCO}

    def fake_fetch(self, url, timeout=90.0):
        page = self.pages.get(url)
        if page is None or isinstance(page, Exception):
            raise page or OSError(f"no route to {url}")
        return page

    def run_main(self, *extra):
        err, out = io.StringIO(), io.StringIO()
        with mock.patch.object(U, "fetch", self.fake_fetch), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            rc = U.main(["--out", self.out, "--feed", A, "--feed", B, "--min", "3", "--popular-top", "2", *extra])
        return rc, out.getvalue() + err.getvalue()

    def feed(self):
        return D.ThreatFeed(self.out)

    def test_writes_both_sources_and_drops_popular(self):
        self.pages[A] = lines(3, "a") + "popular.example\nevil.github.io\n"
        self.pages[B] = "0.0.0.0 b0.example\n0.0.0.0 github.com\n0.0.0.0 a0.example\n"
        rc, log = self.run_main()
        self.assertEqual(rc, 0, log)
        self.assertIn("2 popular names dropped", log)
        self.assertIn("a.example: 5 domains, 1 dropped as popular, 4 kept", log)
        f = self.feed()
        self.assertEqual(len(f), 5)
        self.assertIsNone(f.match("popular.example"))
        self.assertIsNone(f.match("github.com"))
        self.assertEqual(f.match("evil.github.io"), ("evil.github.io", True))
        self.assertIsNone(f.match("github.io"))          # a listed child never makes the parent a hit
        self.assertEqual(f.sources("a0.example"), ["a.example", "b.example"])
        self.assertEqual(f.sources("b0.example"), ["b.example"])
        self.assertEqual(f.sources("nope.example"), [])
        with open(os.path.join(self.dir, "popular_domains.txt")) as fh:
            self.assertIn("popular.example", fh.read())

    def test_known_source_gets_its_label(self):
        url = U.DEFAULT_SOURCES[0].url
        self.pages[url] = lines(4, "m")
        err = io.StringIO()
        with mock.patch.object(U, "fetch", self.fake_fetch), contextlib.redirect_stdout(err):
            self.assertEqual(U.main(["--out", self.out, "--feed", url, "--min", "3", "--popular-top", "2"]), 0)
        self.assertEqual(self.feed().sources("m1.example"), ["URLhaus (malware)"])

    def test_failed_source_keeps_its_previous_contents(self):
        self.pages[A], self.pages[B] = lines(3, "a"), lines(3, "b")
        self.assertEqual(self.run_main()[0], 0)
        self.pages[A] = lines(4, "x")
        self.pages[B] = OSError("HTTP Error 410: Gone")
        rc, log = self.run_main()
        self.assertEqual(rc, 0)                         # the file was written...
        self.assertIn("WARNING: 1 source(s) failed", log)  # ...and the failure is reported
        self.assertIn("keeping its 3 domains from", log)
        f = self.feed()                                 # ...but the good source was updated
        self.assertIsNotNone(f.match("x3.example"))
        self.assertIsNone(f.match("a0.example"))
        self.assertIsNotNone(f.match("b2.example"))
        self.assertEqual(f.sources("b2.example"), ["b.example"])

    def test_source_that_shrank_keeps_its_previous_contents(self):
        self.pages[A], self.pages[B] = lines(10, "a"), lines(10, "b")
        self.run_main()
        self.pages[B] = lines(2, "new")
        rc, log = self.run_main()
        self.assertEqual(rc, 0)
        self.assertIn("only 2 domains, 10 last time", log)
        self.assertIsNotNone(self.feed().match("b9.example"))
        self.assertIsNone(self.feed().match("new0.example"))

    def test_stale_carried_source_is_dropped(self):
        old = (datetime.date.today() - datetime.timedelta(days=U.MAX_CARRY_DAYS + 1)).isoformat()
        with open(self.out, "w") as f:
            f.write(f"#@source\t{B}\t{old}\tb.example\t\nold.example\n")
        self.pages[A], self.pages[B] = lines(3, "a"), OSError("down")
        rc, log = self.run_main()
        self.assertEqual(rc, 0)
        self.assertIn("nothing recent to keep", log)
        self.assertIsNone(self.feed().match("old.example"))
        self.assertIsNotNone(self.feed().match("a1.example"))

    def test_first_run_with_one_source_down_writes_the_other(self):
        self.pages[A], self.pages[B] = lines(3, "a"), OSError("down")
        rc, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.feed()), 3)

    def test_everything_down_keeps_the_existing_file(self):
        with open(self.out, "w") as f:
            f.write("kept.example\n")
        rc, log = self.run_main()
        self.assertEqual(rc, 1)
        self.assertIn("keeping existing feed", log)
        with open(self.out) as f:
            self.assertEqual(f.read(), "kept.example\n")

    def test_min_guard_keeps_the_existing_file(self):
        with open(self.out, "w") as f:
            f.write("kept.example\n")
        self.pages[A], self.pages[B] = lines(1, "a"), lines(1, "b")
        rc, log = self.run_main("--min", "100")
        self.assertEqual(rc, 1)
        self.assertIn("only 2 domains (< 100)", log)
        with open(self.out) as f:
            self.assertEqual(f.read(), "kept.example\n")

    def test_popularity_list_falls_back_to_cache_then_refuses(self):
        self.pages[A], self.pages[B] = lines(3, "a") + "popular.example\n", lines(3, "b")
        self.assertEqual(self.run_main()[0], 0)          # downloads and caches the list
        del self.pages[U.TRANCO_ID_URL]
        rc, log = self.run_main()
        self.assertEqual(rc, 0, log)
        self.assertIn("using the cached popularity list", log)
        self.assertIsNone(self.feed().match("popular.example"))
        os.remove(os.path.join(self.dir, "popular_domains.txt"))
        before = os.path.getmtime(self.out)
        rc, log = self.run_main()
        self.assertEqual(rc, 1)
        self.assertIn("no popularity list", log)
        self.assertEqual(os.path.getmtime(self.out), before)
        rc, log = self.run_main("--popular-top", "0")    # explicitly without Tranco
        self.assertEqual(rc, 0, log)

    def test_pinned_tranco_id(self):
        self.pages[A], self.pages[B] = lines(3, "a"), lines(3, "b")
        self.pages[U.TRANCO_LIST_URL.format(id="PIN9", n=2)] = TRANCO
        del self.pages[U.TRANCO_ID_URL]
        rc, log = self.run_main("--tranco-id", "pin9")
        self.assertEqual(rc, 0, log)
        self.assertIn("Tranco list PIN9", log)

    def test_old_single_list_file_is_replaced_cleanly(self):
        with open(self.out, "w") as f:
            f.write("# Ghostwall threat feed, 1 domains.\nold.example\n")
        self.pages[A], self.pages[B] = lines(3, "a"), lines(3, "b")
        self.assertEqual(self.run_main()[0], 0)
        self.assertIsNone(self.feed().match("old.example"))


class FeedSourceTests(unittest.TestCase):
    def test_env_feeds_used_and_plain_http_refused(self):
        out = os.path.join(tempfile.mkdtemp(), "feed.txt")
        os.environ["GHOSTWALL_FEEDS"] = "http://feeds.example/list.txt"
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(U.main(["--out", out]), 1)
            self.assertIn("only https://", err.getvalue())
            self.assertFalse(os.path.exists(out))
        finally:
            del os.environ["GHOSTWALL_FEEDS"]

    def test_defaults_are_https(self):
        self.assertTrue(all(s.url.startswith("https://") for s in U.DEFAULT_SOURCES))
        self.assertEqual(U.source_for("https://lists.example/x.txt").label, "lists.example")


if __name__ == "__main__":
    unittest.main()
