"""IP reputation for gateway mode: update_ipfeed.py, the nft transaction that fills
drop_net4 / drop_net6, and ghost-dns' loader. Documentation ranges and example data only."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import app
import enforce
import update_ipfeed as U

# Public test-like networks (not the RFC 5737 ranges: those are not "global", so the
# guard rightly refuses them; see test_refuses_private_bogon_and_too_wide).
SPAMHAUS = ('{"cidr":"11.22.0.0/16","sblid":"SBL1","rir":"arin"}\n'
            '{"cidr":"31.13.200.0/22","sblid":"SBL2","rir":"ripencc"}\n'
            '{"type":"metadata","timestamp":1,"records":2}\n')
PLAIN = "# comment\n45.33.10.20\n45.33.10.21 # c2\n"


class ParseTests(unittest.TestCase):
    def test_spamhaus_ndjson_and_plain_lists(self):
        self.assertEqual(U.parse_nets(SPAMHAUS)[0], {"11.22.0.0/16", "31.13.200.0/22"})
        self.assertEqual(U.parse_nets(PLAIN)[0], {"45.33.10.20/32", "45.33.10.21/32"})

    def test_refuses_private_bogon_and_too_wide(self):
        nets, refused = U.parse_nets("192.168.1.0/24\n10.0.0.0/8\n0.0.0.0/0\n11.0.0.0/7\n192.0.2.1\n"
                                     "2001:db8::/32\n2a00::/16\nnot-an-ip\n11.22.33.0/24\n")
        self.assertEqual(nets, {"11.22.33.0/24"})
        self.assertEqual(refused, 8)


class MainTests(unittest.TestCase):
    def setUp(self):
        self.out = os.path.join(tempfile.mkdtemp(), "ip_blocklist.txt")

    def run_main(self, pages, *extra):
        def fake(url, timeout=60.0):
            page = pages.get(url)
            if isinstance(page, Exception) or page is None:
                raise page or OSError("no route")
            return page
        err = io.StringIO()
        with mock.patch.object(U, "fetch", fake), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err):
            rc = U.main(["--out", self.out, "--min", "2", *extra])
        return rc, err.getvalue()

    def test_writes_sections_and_keeps_a_failed_source(self):
        drop, ssl = U.SOURCES[0][1], U.SOURCES[2][1]
        rc, _ = self.run_main({drop: SPAMHAUS, ssl: PLAIN})
        self.assertEqual(rc, 0)
        v4, _ = U.read_networks(self.out)
        self.assertEqual(len(v4), 4)
        rc, log = self.run_main({drop: OSError("down"), ssl: PLAIN})
        self.assertEqual(rc, 0)
        self.assertIn("keeping its 2 networks", log)
        self.assertIn("11.22.0.0/16", U.read_networks(self.out)[0])

    def test_too_few_keeps_the_existing_file(self):
        with open(self.out, "w") as f:
            f.write("#@source\tx\t2026-01-01\n11.22.0.0/16\n")
        rc, log = self.run_main({U.SOURCES[0][1]: '{"cidr":"11.23.0.0/16"}\n'}, "--min", "5")
        self.assertEqual(rc, 1)
        with open(self.out) as f:
            self.assertIn("11.22.0.0/16", f.read())

    def test_read_networks_checks_the_file_again(self):
        with open(self.out, "w") as f:
            f.write("11.22.0.0/16\n192.168.0.0/16\n0.0.0.0/0\n2a03:2880::/32\ngarbage; drop\n")
        self.assertEqual(U.read_networks(self.out), (["11.22.0.0/16"], ["2a03:2880::/32"]))


class ScriptTests(unittest.TestCase):
    def test_one_transaction_flushes_then_adds_merged_networks(self):
        s = enforce.drop_nets_script(["11.22.0.0/17", "11.22.128.0/17", "45.33.10.20/32"], ["2a03:2880::/32"])
        lines = s.splitlines()
        self.assertEqual(lines[0], "flush set inet ghostwall drop_net4")
        self.assertIn("add element inet ghostwall drop_net4 { 11.22.0.0/16, 45.33.10.20/32 }", lines)
        self.assertIn("flush set inet ghostwall drop_net6", lines)
        self.assertIn("add element inet ghostwall drop_net6 { 2a03:2880::/32 }", lines)

    def test_large_lists_are_chunked_and_wrong_family_refused(self):
        many = [f"11.{i // 256}.{i % 256}.1/32" for i in range(1200)]
        adds = [ln for ln in enforce.drop_nets_script(many, []).splitlines() if ln.startswith("add")]
        self.assertEqual(len(adds), 3)
        with self.assertRaises(ValueError):
            enforce.drop_nets_script(["2a03:2880::/32"], [])

    def test_null_backend_does_nothing(self):
        self.assertFalse(enforce.Enforcer(enforce.NullBackend()).load_drop_nets(["11.22.0.0/16"], []))


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "ip_blocklist.txt")
        with open(self.path, "w") as f:
            f.write("#@source\tSpamhaus DROP\t2026-11-07\n11.22.0.0/16\n")

    def nft_enforcer(self, fail=False):
        calls = []

        class Backend:
            name = "nft"

            def run_script(self, text):
                calls.append(text)
                if fail:
                    raise OSError("nft: table ghostwall not found")
        return enforce.Enforcer(Backend()), calls

    def test_loads_once_then_again_when_the_file_changes(self):
        enf, calls = self.nft_enforcer()
        loader = app.IpBlocklistLoader(self.path, enf, log=lambda *a, **k: None)
        self.assertTrue(loader.check())
        self.assertFalse(loader.check())
        os.utime(self.path, (1, 1))
        self.assertTrue(loader.check())
        self.assertEqual(len(calls), 2)
        self.assertIn("11.22.0.0/16", calls[0])

    def test_failure_is_reported_once_and_retried(self):
        enf, calls = self.nft_enforcer(fail=True)
        logged = []
        loader = app.IpBlocklistLoader(self.path, enf, log=lambda *a, **k: logged.append(a[0]))
        self.assertFalse(loader.check())
        self.assertFalse(loader.check())
        self.assertEqual(len(calls), 2)          # retried
        self.assertEqual(len(logged), 1)         # reported once

    def test_no_nft_or_no_file_means_nothing(self):
        loader = app.IpBlocklistLoader(self.path, enforce.Enforcer(enforce.NullBackend()))
        self.assertFalse(loader.check())
        enf, calls = self.nft_enforcer()
        self.assertFalse(app.IpBlocklistLoader(self.path + ".missing", enf).check())
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
