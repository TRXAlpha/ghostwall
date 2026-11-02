"""FW_BOT_PRIVACY=minimal: nothing sent to Telegram names a domain, IP or MAC."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import alerts      # noqa: E402
import commands    # noqa: E402
import dispatch    # noqa: E402

EVT = {"time": "2026-11-02T10:00:00Z", "device": "laptop", "ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01",
       "domain": "secret-site.example", "dst_ip": "203.0.113.9", "rule": "abused_service",
       "action": "recommend", "severity": "warn", "event_id": "evt_1",
       "reasons": ["first use of a paste site (secret-site.example)"], "scores": {"dga": 0.4}}
LEAKS = ("secret-site", "192.168.1.10", "aa:bb:cc", "203.0.113.9")


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        os.environ["FW_BOT_PRIVACY"] = "minimal"

    def tearDown(self):
        os.environ.pop("FW_BOT_PRIVACY", None)

    def assertClean(self, text):
        for leak in LEAKS:
            self.assertNotIn(leak, text)

    def test_alert_text(self):
        t = alerts.format_alert(EVT)
        self.assertClean(t)
        self.assertIn("laptop", t)
        self.assertIn("service malware favours", t)

    def test_log_and_summary(self):
        self.assertClean(dispatch.format_log([EVT]))
        self.assertClean(dispatch.format_summary([EVT]) if hasattr(dispatch, "format_summary") else "")

    def test_status_and_device(self):
        st = {"devices": [{"name": "laptop", "ip": "192.168.1.10", "blocked_domains": ["secret-site.example"]}]}
        self.assertClean(commands._fmt_status(st))
        self.assertClean(commands._fmt_device({"name": "laptop", "ip": "192.168.1.10",
                                               "mac": "aa:bb:cc:dd:ee:01", "blocked_domains": ["secret-site.example"]}))

    def test_details_button(self):
        from callbacks import CallbackHandler
        h = CallbackHandler.__new__(CallbackHandler)
        self.assertClean(h._details("evt_1", EVT))

    def test_full_mode_unchanged(self):
        os.environ.pop("FW_BOT_PRIVACY")
        self.assertIn("secret-site.example", alerts.format_alert(EVT))


if __name__ == "__main__":
    unittest.main()
