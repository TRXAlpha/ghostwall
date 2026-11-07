"""auto_isolate: off / dry-run / on, exemptions, the hourly cap, null backend, learning mode,
event fields, and that the control API's own isolate/release is unchanged."""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(os.path.dirname(HERE), "fw_bot"))
import config as config_mod
import validate_events as V
from control_api import ControlServer
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from state import GhostState

LAPTOP, TV, PI = "192.168.1.10", "192.168.1.20", "192.168.1.2"


class FakeScorer:
    def score_one(self, domain):
        return {"dga": 0.0, "dga_trm": 0.0, "dga_lr": 0.0}


class NftLike(NullBackend):
    """Records calls like NullBackend but reports itself as the real backend."""

    @property
    def name(self):
        return "nft"


class Base(unittest.TestCase):
    def build(self, backend=NftLike, learning=False, feed=("evil.example",), **over):
        self.dir = tempfile.mkdtemp()
        fpath = os.path.join(self.dir, "feed.txt")
        with open(fpath, "w") as f:
            f.write("\n".join(feed) + "\n")
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "s.json"), "events_path": os.path.join(self.dir, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "allowlist_path": None,
            "threat_feed_path": fpath, "pi_ip": PI, "auto_isolate": "on", **over})
        self.state = GhostState(self.cfg["state_path"], learning_default=learning)
        self.backend = backend()
        self.enforcer = Enforcer(self.backend)
        self.devices = DeviceMap.from_json([
            {"name": "laptop", "ip": LAPTOP}, {"name": "tv-box", "ip": TV}, {"name": "homepi", "ip": PI}])
        self.r = Resolver(self.cfg, self.state, FakeScorer(), self.enforcer, self.devices,
                          EventLog(self.cfg["events_path"]))
        self.assertTrue(self.r.det.wait_loaded(10))
        self.now = 1000.0
        self.r.clock = lambda: self.now
        return self.r

    def isolations(self):
        return [c for c in self.backend.calls if "isolated_dev" in c]

    def hit(self, ip=TV, domain="evil.example"):
        return self.r.decide(ip, domain, "A").event

    def tunnel(self, ip=TV, apex="exfil.example"):
        evt = None
        for i in range(40):
            d = self.r.decide(ip, f"{i:02d}q8f3k2m9x7v1z4p6w0r5t.{apex}", "TXT")
            evt = evt or d.event
        return evt


class AutoIsolateTests(Base):
    def test_off_is_the_default_and_changes_nothing(self):
        self.assertEqual(config_mod.DEFAULTS["auto_isolate"], "off")
        self.build(auto_isolate="off")
        evt = self.hit()
        self.assertNotIn("auto_isolated", evt)
        self.assertNotIn("would_isolate", evt)
        self.assertEqual(self.isolations(), [])
        self.assertFalse(self.state.is_isolated("tv-box"))

    def test_default_rules_are_the_conservative_set(self):
        self.assertEqual(config_mod.DEFAULTS["auto_isolate_rules"], ["threat_feed", "dns_tunnel"])
        self.assertEqual(config_mod.DEFAULTS["auto_isolate_max_per_hour"], 2)
        with self.assertRaises(ValueError):
            config_mod.load_config(None, {"auto_isolate": "yes"})

    def test_on_isolates_like_the_api_and_says_so(self):
        self.build()
        evt = self.hit()
        self.assertTrue(evt["auto_isolated"])
        self.assertNotIn("would_isolate", evt)
        self.assertEqual(self.isolations(), [("add", "element", "inet", "ghostwall", "isolated_dev", "{", TV, "}")])
        self.assertTrue(self.state.is_isolated("tv-box"))
        last = evt["reasons"][-1]
        self.assertIn("isolated automatically: threat_feed", last)
        self.assertIn("Release button", last)
        self.assertIn("sudo ghostwall release tv-box", last)
        self.assertEqual(self.r.stats["auto_isolated"], 1)
        self.assertEqual(V.validate_event(evt), [])
        with open(self.cfg["events_path"], encoding="utf-8") as f:   # the written line has it too
            self.assertTrue(json.loads(f.readline())["auto_isolated"])

    def test_dry_run_only_says_would_isolate(self):
        self.build(auto_isolate="dry-run")
        evt = self.hit()
        self.assertTrue(evt["would_isolate"])
        self.assertNotIn("auto_isolated", evt)
        self.assertIn("would isolate automatically: threat_feed", evt["reasons"][-1])
        self.assertEqual(self.isolations(), [])
        self.assertFalse(self.state.is_isolated("tv-box"))
        self.assertEqual(V.validate_event(evt), [])

    def test_null_backend_is_would_isolate_only(self):
        self.build(backend=NullBackend)
        evt = self.hit()
        self.assertTrue(evt["would_isolate"])
        self.assertIn("enforcement is off", evt["reasons"][-1])
        self.assertEqual(self.isolations(), [])
        self.assertFalse(self.state.is_isolated("tv-box"))

    def test_learning_mode_behaves_as_dry_run(self):
        self.build(learning=True)
        evt = self.hit()
        self.assertTrue(evt["would_isolate"])
        self.assertIn("learning mode is on", evt["reasons"][-1])
        self.assertEqual(self.isolations(), [])
        self.state.set_learning(False)
        self.assertTrue(self.hit(domain="x.evil.example") is not None)   # same family: deduped, no new event
        self.assertEqual(self.isolations(), [])

    def test_rule_not_in_the_list_is_left_alone(self):
        self.build(auto_isolate_rules=["dns_tunnel"])
        evt = self.hit()
        self.assertNotIn("would_isolate", evt)
        self.assertNotIn("auto_isolated", evt)
        self.assertEqual(self.isolations(), [])

    def test_dns_tunnel_isolates(self):
        self.build()
        evt = self.tunnel()
        self.assertEqual(evt["rule"], "dns_tunnel")
        self.assertTrue(evt["auto_isolated"])
        self.assertTrue(self.state.is_isolated("tv-box"))

    def test_parent_domain_feed_match_never_isolates(self):
        self.build()
        evt = self.hit(domain="x.evil.example")
        self.assertEqual(evt["rule"], "threat_feed")
        self.assertIn("is under evil.example", evt["reasons"][0])
        self.assertNotIn("auto_isolated", evt)
        self.assertNotIn("would_isolate", evt)
        self.assertEqual(self.isolations(), [])

    def test_exempt_device_is_never_isolated(self):
        self.build(auto_isolate_exempt=["laptop"])
        evt = self.hit(ip=LAPTOP)
        self.assertEqual(evt["device"], "laptop")
        self.assertNotIn("auto_isolated", evt)
        self.assertNotIn("would_isolate", evt)
        self.assertEqual(self.isolations(), [])

    def test_the_pi_itself_is_always_exempt(self):
        self.build()
        evt = self.hit(ip=PI)
        self.assertEqual(evt["device"], "homepi")
        self.assertNotIn("auto_isolated", evt)
        self.assertEqual(self.isolations(), [])

    def test_loopback_is_always_exempt(self):
        self.build()
        self.devices = DeviceMap.from_json([{"name": "local", "ip": "127.0.0.1"}])
        self.r.devices = self.devices
        evt = self.hit(ip="127.0.0.1")
        self.assertNotIn("auto_isolated", evt)
        self.assertEqual(self.isolations(), [])

    def test_unnamed_address_is_not_isolated_and_says_how_to_name_it(self):
        self.build()
        evt = self.hit(ip="192.168.1.99")
        self.assertNotIn("auto_isolated", evt)
        self.assertIn("sudo ghostwall name 192.168.1.99 NAME", evt["reasons"][-1])
        self.assertEqual(self.isolations(), [])

    def test_hourly_cap_alerts_only_and_says_why(self):
        self.build(auto_isolate_max_per_hour=1)
        first = self.hit(ip=TV)
        second = self.hit(ip=LAPTOP)
        self.assertTrue(first["auto_isolated"])
        self.assertNotIn("auto_isolated", second)
        self.assertTrue(second["would_isolate"])
        self.assertIn("cap of 1", second["reasons"][-1])
        self.assertFalse(self.state.is_isolated("laptop"))
        self.assertEqual(len(self.isolations()), 1)

    def test_cap_window_slides(self):
        self.build(auto_isolate_max_per_hour=1, feed=("evil.example", "evil2.example"))
        self.assertTrue(self.hit(ip=TV)["auto_isolated"])
        self.now += 3601
        self.assertTrue(self.hit(ip=LAPTOP, domain="evil2.example")["auto_isolated"])

    def test_cap_zero_never_isolates(self):
        self.build(auto_isolate_max_per_hour=0)
        evt = self.hit()
        self.assertTrue(evt["would_isolate"])
        self.assertEqual(self.isolations(), [])

    def test_backend_failure_keeps_the_alert(self):
        class Boom(NftLike):
            def _run(self, *a):
                raise OSError("nft exploded")
        self.build(backend=Boom)
        evt = self.hit()
        self.assertTrue(evt["would_isolate"])
        self.assertNotIn("auto_isolated", evt)
        self.assertIn("automatic isolation failed", evt["reasons"][-1])
        self.assertFalse(self.state.is_isolated("tv-box"))
        self.assertEqual(self.r.stats["auto_isolated"], 0)

    def test_released_device_is_not_isolated_again_by_a_repeat(self):
        self.build()
        self.assertTrue(self.hit()["auto_isolated"])
        self.state.release("tv-box")
        self.hit()      # same device, same family within the dedupe window: no new alert
        self.assertFalse(self.state.is_isolated("tv-box"))
        self.assertEqual(len(self.isolations()), 1)


class ControlApiUnchangedTests(Base):
    def test_manual_isolate_and_release_still_work_and_undo_an_auto_isolation(self):
        self.build()
        self.assertTrue(self.hit()["auto_isolated"])
        server = ControlServer(dict(self.cfg, control_port=0), self.state, self.enforcer,
                               self.devices, resolver=self.r)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.httpd.server_address[1]}"

        def call(path, body):
            req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.loads(r.read())
        try:
            self.assertTrue(call("/device", {"name": "tv-box"})["isolated"])
            self.assertFalse(call("/release", {"name": "tv-box"})["isolated"])
            self.assertFalse(self.state.is_isolated("tv-box"))
            self.assertEqual(call("/isolate", {"name": "laptop"})["isolated"], True)
            self.assertTrue(self.state.is_isolated("laptop"))
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
