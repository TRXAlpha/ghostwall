"""Tests for update_feed.parse_domains (no network)."""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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


if __name__ == "__main__":
    unittest.main()
