"""iot_new_domain: default-deny for devices marked "profile": "iot" in devices.json."""
import json
import os
import struct
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(os.path.dirname(HERE), "fw_bot"))   # validate_events only
import config as config_mod  # noqa: E402
import dnsmsg  # noqa: E402
import validate_events  # noqa: E402
from devices import DeviceMap  # noqa: E402
from enforce import Enforcer, NullBackend  # noqa: E402
from events import EventLog  # noqa: E402
from resolver import Resolver  # noqa: E402
from state import GhostState  # noqa: E402

CAM, TV, LAPTOP = "192.168.1.40", "192.168.1.41", "192.168.1.30"
DEVICES = [{"name": "cam-1", "ip": CAM, "mac": "aa:bb:cc:dd:ee:40", "profile": "iot"},
           {"name": "tv-box", "ip": TV, "mac": "aa:bb:cc:dd:ee:41", "profile": "iot"},
           {"name": "laptop", "ip": LAPTOP, "mac": "aa:bb:cc:dd:ee:30"}]


class Low:
    """Every name scores as ordinary, except the made-up random-looking ones in HIGH."""
    HIGH = ("xkqzvwpt.example",)

    def score_one(self, domain):
        v = 0.99 if any(domain.endswith(h) for h in self.HIGH) else 0.01
        return {"dga": v, "dga_trm": v, "dga_lr": v}


def build_query(name, qtype=1):
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + q + struct.pack(">HH", qtype, 1)


class IotBase(unittest.TestCase):
    extra: dict = {}
    shadow = False

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.start()

    def start(self):
        """(Re)build the whole stack on the same state.json, like a restart."""
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "s.json"), "events_path": os.path.join(self.dir, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "threat_feed_path": self.feed_path(),
            "allowlist_path": os.path.join(HERE, "allowlist.txt"), "pi_ip": "192.168.1.2",
            "shadow": self.shadow, **self.extra})
        self.state = GhostState(self.cfg["state_path"], learning_default=bool(self.cfg["learning"]))
        self.r = Resolver(self.cfg, self.state, Low(), Enforcer(NullBackend()),
                          DeviceMap.from_json(DEVICES), EventLog(self.cfg["events_path"]))
        self.assertTrue(self.r.det.wait_loaded(10))   # inline mode loads the feed in the background

    def feed_path(self):
        return None

    def events(self):
        try:
            with open(self.cfg["events_path"], encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def iot_events(self):
        return [e for e in self.events() if e["rule"] == "iot_new_domain"]

    def q(self, host, ip=CAM, **kw):
        return self.r.decide(ip, host, "A", **kw)

    def age(self, days, device="cam-1"):
        """Pretend the device was first seen `days` ago (its learning window moves with it)."""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        self.state.iot[device]["since"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    def learn(self, *hosts, device_ip=CAM, device="cam-1"):
        for h in hosts:
            self.q(h, ip=device_ip)
        self.age(8, device)


class LearningTests(IotBase):
    def test_learning_window_is_quiet_and_learns(self):
        for h in ("api.cam-cloud.example", "stream.cam-cloud.example", "updates.example.org"):
            self.assertNotEqual(self.q(h).reason, "iot_new_domain")
        self.assertEqual(self.state.iot_count("cam-1"), 2)       # registrable domains, not names
        self.age(6.9)
        self.assertNotEqual(self.q("late.example.net").reason, "iot_new_domain")   # still learning
        self.assertEqual(self.iot_events(), [])

    def test_alert_after_learning(self):
        self.learn("api.cam-cloud.example", "updates.example.org")
        self.assertNotEqual(self.q("other.cam-cloud.example").reason, "iot_new_domain")   # same family
        d = self.q("c2.badhost.example")
        self.assertEqual((d.action, d.reason), ("recommend", "iot_new_domain"))
        evt = self.iot_events()[0]
        self.assertEqual((evt["device"], evt["severity"], evt["trust"]), ("cam-1", "warn", "badhost.example"))
        self.assertNotIn("would_block", evt)
        why = " ".join(evt["reasons"])
        self.assertIn("2 domains", why)
        self.assertIn("ghostwall allow badhost.example --device cam-1", why)
        self.assertNotIn("cam-cloud", why)          # a count, not names
        self.assertEqual(self.state.iot_count("cam-1"), 2)   # alerting does not learn

    def test_dedupe_one_alert_per_device_and_domain(self):
        self.learn("api.cam-cloud.example")
        for _ in range(3):
            self.q("c2.badhost.example")
            self.q("x.badhost.example")             # same family
        self.assertEqual(len(self.iot_events()), 1)
        self.q("c2.other-bad.example")
        self.assertEqual(len(self.iot_events()), 2)

    def test_per_device_sets(self):
        self.learn("api.cam-cloud.example")
        self.q("tv.example.org", ip=TV)
        self.age(8, "tv-box")
        self.assertEqual(self.q("tv.example.org").reason, "iot_new_domain")       # not the camera's
        self.assertNotEqual(self.q("tv.example.org", ip=TV).reason, "iot_new_domain")

    def test_hashed_storage_and_persistence(self):
        self.learn("api.cam-cloud.example", "updates.example.org")
        self.q("c2.badhost.example")
        self.state.save()
        with open(self.cfg["state_path"], encoding="utf-8") as f:
            raw = f.read()
        for name in ("cam-cloud", "updates.example.org"):
            self.assertNotIn(name, raw)               # learned names are nowhere in the file
        self.assertNotIn("badhost", json.dumps(json.loads(raw)["iot"]))
        self.assertEqual(len(json.loads(raw)["iot"]["cam-1"]["domains"]), 2)
        self.start()                                  # restart
        self.assertEqual(self.state.iot_count("cam-1"), 2)
        self.assertNotEqual(self.q("api.cam-cloud.example").reason, "iot_new_domain")
        self.assertEqual(self.q("c2.badhost.example").reason, "iot_new_domain")   # window is not restarted
        self.assertEqual(len(self.iot_events()), 1)    # ...and the day's alert is not repeated

    def test_set_is_bounded(self):
        for i in range(600):
            self.q(f"host.dom{i}.example")
        self.assertEqual(self.state.iot_count("cam-1"), 512)

    def test_builtin_allow_internal_and_unknown_clients(self):
        self.learn("api.cam-cloud.example")
        for host in ("0.pool.ntp.org", "time.google.com", "time.cloudflare.com", "cam-1.local", "homepi"):
            self.assertNotEqual(self.q(host).reason, "iot_new_domain", host)
        self.assertEqual(self.q("www.google.com").reason, "iot_new_domain")   # only time.google.com is built in
        self.assertEqual(self.state.iot_count("cam-1"), 1)    # built-ins are not learned either

    def test_nxdomain_and_abused_services_are_not_learned(self):
        self.q("typo.nowhere.example", rcode="NXDOMAIN")
        self.q("api.telegram.org")
        self.assertEqual(self.state.iot_count("cam-1"), 0)

    def test_non_iot_devices_unaffected(self):
        self.q("a.example.com", ip=LAPTOP)
        self.assertNotIn("laptop", self.state.iot)
        self.assertNotEqual(self.q("zz.example.net", ip=LAPTOP).reason, "iot_new_domain")
        self.assertNotEqual(self.q("zz.example.net", ip="192.168.1.99").reason, "iot_new_domain")  # unknown client

    def test_global_allowlist_does_not_exempt(self):
        self.learn("api.cam-cloud.example")
        self.state.allow("badhost.example")
        self.assertEqual(self.q("c2.badhost.example").reason, "iot_new_domain")

    def test_other_rules_still_run(self):
        self.learn("api.cam-cloud.example")
        self.state.add_block("evil.example")
        self.assertEqual(self.q("evil.example").reason, "blocklist")


    def test_events_match_the_schema(self):
        self.learn("api.cam-cloud.example")
        self.q("c2.badhost.example")
        for e in self.events():
            self.assertEqual(validate_events.validate_event(e), [], e)

    def test_one_lookup_raises_one_alert(self):
        # a random-looking new name from an IoT device: the score rule speaks, not both
        self.learn("api.cam-cloud.example")
        d = self.q("a.xkqzvwpt.example")
        self.assertIn(d.reason, ("dga_high", "dga_suspect"))
        self.assertEqual([e["rule"] for e in self.events()], [d.reason])

    def test_refused_upstream_is_neither_learned_nor_alerted(self):
        self.q("ads.tracker.example", upstream_blocked=True)
        self.q("api.cam-cloud.example")
        self.assertEqual(self.state.iot_count("cam-1"), 1)
        self.age(8)
        self.assertNotEqual(self.q("ads.tracker.example", upstream_blocked=True).reason, "iot_new_domain")
        self.assertEqual(self.iot_events(), [])

    def test_blocklisted_names_are_not_learned(self):
        self.state.add_block("evil.example")
        self.q("evil.example")
        self.assertEqual(self.state.iot_count("cam-1"), 0)

    def test_relearn_and_forget(self):
        self.learn("api.cam-cloud.example")
        self.state.iot_allow("cam-1", "partner.example")
        self.assertTrue(self.state.iot_forget("cam-1", "x.partner.example"))   # by family
        self.assertFalse(self.state.iot_forget("cam-1", "partner.example"))
        self.assertEqual(self.q("x.partner.example").reason, "iot_new_domain")
        self.assertTrue(self.state.iot_relearn("cam-1"))
        self.assertNotEqual(self.q("y.other.example").reason, "iot_new_domain")   # learning again
        self.assertEqual(self.state.iot_count("cam-1"), 1)


class FeedTests(IotBase):
    def feed_path(self):
        path = os.path.join(self.dir, "threat_feed.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("phish.example\n")
        return path

    def test_threat_feed_still_wins_and_is_never_learned(self):
        d = self.q("login.phish.example")                   # in the learning window
        self.assertEqual(d.reason, "threat_feed")
        self.assertEqual(self.state.iot_count("cam-1"), 0)
        self.q("api.cam-cloud.example")
        self.age(8)
        self.assertEqual(self.q("login.phish.example").reason, "threat_feed")
        self.assertEqual({e["rule"] for e in self.events()}, {"threat_feed"})

    def test_threat_feed_blocks_first_with_enforcement_on(self):
        self.extra = {"learning": False, "iot_enforce": "on"}
        self.start()
        self.learn("api.cam-cloud.example")
        d = self.q("login.phish.example")
        self.assertEqual((d.action, d.reason), ("block", "threat_feed"))
        self.assertEqual([(e["rule"], e["severity"]) for e in self.events()], [("threat_feed", "high")])


class ConfigTests(unittest.TestCase):
    def test_iot_enforce_must_be_a_known_mode(self):
        for good in ("off", "dry-run", "on"):
            self.assertEqual(config_mod.load_config(None, {"iot_enforce": good})["iot_enforce"], good)
        for bad in ("true", "enforce", True):
            with self.assertRaises(ValueError):
                config_mod.load_config(None, {"iot_enforce": bad})


class TrustTests(IotBase):
    def test_trust_adds_to_that_device_only(self):
        self.learn("api.cam-cloud.example")
        self.q("c2.partner.example")
        self.state.iot_allow("cam-1", "partner.example")
        self.assertNotEqual(self.q("x.partner.example").reason, "iot_new_domain")
        self.assertFalse(self.state.is_allowed("partner.example"))     # not the global allowlist
        self.assertEqual(self.state.iot_count("cam-1"), 2)
        self.q("a.example.org", ip=TV)
        self.age(8, "tv-box")
        self.assertEqual(self.q("x.partner.example", ip=TV).reason, "iot_new_domain")
        self.state.save()
        self.start()
        self.assertNotEqual(self.q("x.partner.example").reason, "iot_new_domain")   # survives restart


class EnforceTests(IotBase):
    extra = {"learning": False}

    def test_off_never_blocks(self):
        self.learn("api.cam-cloud.example")
        d = self.q("c2.badhost.example")
        self.assertEqual(d.action, "recommend")
        self.assertNotIn("would_block", self.iot_events()[0])

    def test_dry_run_says_would_block(self):
        self.extra = {"learning": False, "iot_enforce": "dry-run"}
        self.start()
        self.learn("api.cam-cloud.example")
        d = self.q("c2.badhost.example")
        self.assertEqual(d.action, "recommend")
        evt = self.iot_events()[0]
        self.assertIs(evt["would_block"], True)
        self.assertEqual(evt["action"], "recommend")

    def test_on_refuses_in_inline_mode(self):
        self.extra = {"learning": False, "iot_enforce": "on"}
        self.start()
        self.learn("api.cam-cloud.example")
        self.assertEqual(self.q("api.cam-cloud.example").action, "allow")
        d = self.q("c2.badhost.example")
        self.assertEqual((d.action, d.reason), ("block", "iot_new_domain"))
        self.assertEqual(self.iot_events()[0]["action"], "block")
        self.assertNotIn("would_block", self.iot_events()[0])
        for _ in range(3):                      # a retrying device: refused every time, alerted once
            self.assertEqual(self.q("c2.badhost.example").action, "block")
        self.assertEqual(len(self.iot_events()), 1)
        self.assertEqual(self.q("c2.badhost.example", ip=LAPTOP).action, "allow")   # normal device
        self.state.iot_allow("cam-1", "badhost.example")
        self.assertEqual(self.q("c2.badhost.example").action, "allow")

    def test_on_sinkholes_on_the_wire(self):
        self.extra = {"learning": False, "iot_enforce": "on"}
        self.start()
        self.learn("api.cam-cloud.example")
        resp = self.r.handle_packet(CAM, build_query("c2.badhost.example"))
        self.assertEqual(dnsmsg.reply_status(resp), "NOERROR")
        self.assertIn(bytes([0, 0, 0, 0]), resp[-4:])          # sinkhole_ip4 0.0.0.0 as the answer

    def test_on_with_learning_on_only_alerts(self):
        self.extra = {"learning": True, "iot_enforce": "on"}
        self.start()
        self.learn("api.cam-cloud.example")
        d = self.q("c2.badhost.example")
        self.assertEqual(d.action, "recommend")
        evt = self.iot_events()[0]
        self.assertIs(evt["would_block"], True)
        self.assertIn("not blocked (learning mode)", evt["reasons"])


class ShadowTests(IotBase):
    extra = {"learning": False, "iot_enforce": "on"}
    shadow = True

    def test_shadow_never_blocks(self):
        self.learn("api.cam-cloud.example")
        d = self.q("c2.badhost.example")
        self.assertEqual((d.action, d.reason), ("recommend", "iot_new_domain"))
        evt = self.iot_events()[0]
        self.assertEqual(evt["action"], "recommend")
        self.assertIs(evt["would_block"], True)
        self.assertIn("not blocked (shadow mode)", evt["reasons"])


if __name__ == "__main__":
    unittest.main()
