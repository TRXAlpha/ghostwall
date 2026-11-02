"""abused_service: an established device starting to use a service malware favours."""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config as config_mod  # noqa: E402
from detectors import abused_service  # noqa: E402
from devices import DeviceMap  # noqa: E402
from enforce import Enforcer, NullBackend  # noqa: E402
from events import EventLog  # noqa: E402
from resolver import Resolver  # noqa: E402
from state import GhostState  # noqa: E402


class Low:
    def score_one(self, domain):
        return {"dga": 0.01, "dga_trm": 0.01, "dga_lr": 0.01}


def ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


class AbusedServiceTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(d, "s.json"), "events_path": os.path.join(d, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "threat_feed_path": None,
            "allowlist_path": os.path.join(HERE, "allowlist.txt"), "pi_ip": "192.168.1.2"})
        self.state = GhostState(self.cfg["state_path"])
        self.state.load_allowlist_file(self.cfg["allowlist_path"])
        self.r = Resolver(self.cfg, self.state, Low(), Enforcer(NullBackend()),
                          DeviceMap.from_json([{"name": "camera", "ip": "192.168.1.40"}]),
                          EventLog(self.cfg["events_path"]))

    def q(self, host, ip="192.168.1.40"):
        return self.r.decide(ip, host, "A")

    def test_matching(self):
        self.assertEqual(abused_service("api.telegram.org"), ("api.telegram.org", "Telegram bot API"))
        self.assertEqual(abused_service("abc123.ngrok-free.app")[0], "ngrok-free.app")
        self.assertIsNone(abused_service("telegram.org"))       # the website, not the bot API
        self.assertIsNone(abused_service("example.com"))

    def test_new_device_learns_quietly(self):
        for _ in range(3):  # a device seen for the first time is still in its baseline
            self.assertNotEqual(self.q("api.telegram.org").reason, "abused_service")

    def test_established_device_alerts_once_per_service(self):
        self.q("example.com")
        self.state.device_since["camera"] = ago(5)
        d = self.q("abc123.trycloudflare.com")
        self.assertEqual(d.reason, "abused_service")
        self.assertIn("tunnel", d.event["reasons"][0])
        self.assertNotEqual(self.q("def456.trycloudflare.com").reason, "abused_service")  # same service

    def test_services_used_during_baseline_never_alert(self):
        self.q("api.ipify.org")                           # day 0: learned
        self.state.device_since["camera"] = ago(5)
        self.assertNotEqual(self.q("api.ipify.org").reason, "abused_service")
        self.assertEqual(self.q("pastebin.com").reason, "abused_service")

    def test_payload_hosts_under_allowlisted_parents_still_alert(self):
        # the starter allowlist trusts discordapp.com and githubusercontent.com
        self.state.device_since["camera"] = ago(5)
        self.assertEqual(self.q("cdn.discordapp.com").reason, "abused_service")
        self.assertEqual(self.q("raw.githubusercontent.com").reason, "abused_service")

    def test_user_trust_silences_it(self):
        self.state.device_since["camera"] = ago(5)
        self.state.allow("api.telegram.org")
        self.assertNotEqual(self.q("api.telegram.org").reason, "abused_service")

    def test_this_box_is_ignored(self):
        self.state.device_since["192.168.1.2"] = ago(5)
        self.assertNotEqual(self.q("api.telegram.org", ip="192.168.1.2").reason, "abused_service")

    def test_baseline_survives_restart(self):
        self.q("example.com")
        self.state.save()
        s2 = GhostState(self.cfg["state_path"])
        self.assertIn("camera", s2.device_since)


if __name__ == "__main__":
    unittest.main()


class TrustTests(AbusedServiceTests):
    def test_trusting_a_doh_host_stops_the_alert(self):
        self.assertEqual(self.q("cloudflare-dns.com").reason, "doh_bypass")
        self.state.allow("cloudflare-dns.com")      # the dashboard's Trust button
        self.assertNotEqual(self.q("cloudflare-dns.com").reason, "doh_bypass")


class ClockTests(unittest.TestCase):
    """The history replay drives the state's clock from the log's timestamps."""

    def _resolver(self, d):
        cfg = config_mod.load_config(None, {
            "state_path": os.path.join(d, "s.json"), "events_path": os.path.join(d, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "threat_feed_path": None, "allowlist_path": None})
        st = GhostState(cfg["state_path"])
        return Resolver(cfg, st, Low(), Enforcer(NullBackend()),
                        DeviceMap.from_json([{"name": "tv", "ip": "192.168.1.50"}]), EventLog(cfg["events_path"])), st

    def test_baseline_follows_log_time(self):
        r, st = self._resolver(tempfile.mkdtemp())
        t = {"now": datetime(2026, 10, 1, tzinfo=timezone.utc)}
        st.clock = lambda: t["now"]
        r.decide("192.168.1.50", "example.com", "A")               # day 0 in the log
        t["now"] += timedelta(days=4)                                 # four log-days later
        self.assertEqual(r.decide("192.168.1.50", "abc.ngrok-free.app", "A").reason, "abused_service")

    def test_dedupe_survives_a_restart(self):
        d = tempfile.mkdtemp()
        r, st = self._resolver(d)
        self.assertFalse(r._is_repeat("tv", "x.example.com", "dga_suspect"))
        st.flush()
        r2, _ = self._resolver(d)                                     # ghost-dns restarted
        self.assertTrue(r2._is_repeat("tv", "y.example.com", "dga_suspect"))   # same family, same day
