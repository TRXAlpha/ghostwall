"""auto_isolate: off / dry-run / on, learning and shadow mode, which findings are proof
enough (exact feed matches only, never a popular site, a shared service or a phishing-only
listing), who is never isolated (the Pi, loopback, exempt, unnamed, no IPv4), the hourly
cap (kept across restarts), nft and state failures, threads, and that the control API's
isolate/release (idempotent now) undoes an automatic isolation."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(os.path.dirname(HERE), "fw_bot"))
import config as config_mod
import resolver as resolver_mod
import validate_events as V
from app import restore_isolations
from control_api import ControlServer
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from state import GhostState

LAPTOP, TV, CAM, PLUG, PI = "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40", "192.168.1.2"
TV_MAC = "aa:bb:cc:dd:ee:20"
ENOENT = "Error: Could not process rule: No such file or directory"
DEVICES = [{"name": "laptop", "ip": LAPTOP}, {"name": "tv-box", "ip": TV, "mac": TV_MAC},
           {"name": "cam-1", "ip": CAM}, {"name": "plug-1", "ip": PLUG}, {"name": "homepi", "ip": PI}]


class FakeScorer:
    def score_one(self, domain):
        return {"dga": 0.0, "dga_trm": 0.0, "dga_lr": 0.0}


class NftSet(NullBackend):
    """Behaves like the nft backend for the isolated set: keeps its members, and a delete of
    an address that is not in it fails the way nft does (ENOENT)."""

    def __init__(self):
        super().__init__()
        self.members: set[str] = set()
        self.fail_add: Exception | None = None
        self.fail_delete: Exception | None = None

    @property
    def name(self):
        return "nft"

    def _run(self, *args):
        self.calls.append(args)
        if "isolated_dev" not in args:
            return
        ip = args[args.index("{") + 1]
        if args[0] == "add":
            if self.fail_add:
                raise self.fail_add
            self.members.add(ip)
        elif args[0] == "delete":
            if self.fail_delete:
                raise self.fail_delete
            if ip not in self.members:
                raise subprocess.CalledProcessError(1, ["nft"], stderr=ENOENT)
            self.members.discard(ip)


class Neigh:
    """neighbours.Neighbours stand-in: which MAC is at an address."""

    def __init__(self, table):
        self.table = table

    def mac(self, ip):
        return self.table.get(ip)


class Base(unittest.TestCase):
    def build(self, backend=NftSet, learning=False, feed=("evil.example",), popular=(), dir=None,
              neighbours=None, **over):
        self.dir = dir or tempfile.mkdtemp()
        fpath = os.path.join(self.dir, "feed.txt")
        with open(fpath, "w") as f:
            f.write("\n".join(feed) + "\n")
        with open(os.path.join(self.dir, "popular_domains.txt"), "w") as f:
            f.write("\n".join(popular) + "\n")
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "s.json"), "events_path": os.path.join(self.dir, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "allowlist_path": None,
            "threat_feed_path": fpath, "pi_ip": PI, "auto_isolate": "on", "confirm_seconds": 0, "auto_isolate_min_sources": 1,
            "auto_isolate_need_antispoof": False, **over})
        self.state = GhostState(self.cfg["state_path"], learning_default=learning)
        self.wall = getattr(self, "wall", 1_800_000_000.0)
        self.state.clock = lambda: datetime.fromtimestamp(self.wall, timezone.utc)
        self.backend = backend()
        self.enforcer = Enforcer(self.backend)
        self.devices = DeviceMap.from_json(DEVICES)
        self.r = Resolver(self.cfg, self.state, FakeScorer(), self.enforcer, self.devices,
                          EventLog(self.cfg["events_path"]), neighbours=neighbours)
        self.assertTrue(self.r.det.wait_loaded(10))
        self.now = 1000.0
        self.r.clock = lambda: self.now
        return self.r

    def isolations(self):
        return [c for c in self.backend.calls if "isolated_dev" in c and c[0] == "add"]

    def hit(self, ip=TV, domain="evil.example"):
        return self.r.decide(ip, domain, "A").event

    def tunnel(self, ip=TV, apex="exfil.example"):
        evt = None
        for i in range(40):
            d = self.r.decide(ip, f"{i:02d}q8f3k2m9x7v1z4p6w0r5t.{apex}", "TXT")
            evt = evt or d.event
        return evt

    def written(self):
        with open(self.cfg["events_path"], encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def assertNotIsolated(self, evt, why=None):
        self.assertNotIn("auto_isolated", evt)
        self.assertEqual(self.isolations(), [])
        self.assertEqual(self.state.isolated, set())
        if why:
            self.assertIn(why, evt["reasons"][-1])


class ModeTests(Base):
    def test_off_is_the_default_and_changes_nothing(self):
        self.assertEqual(config_mod.DEFAULTS["auto_isolate"], "off")
        self.build(auto_isolate="off")
        evt = self.hit()
        self.assertNotIsolated(evt)
        self.assertNotIn("would_isolate", evt)
        self.assertFalse(any("isolat" in r for r in evt["reasons"]))

    def test_default_rules_are_the_conservative_set(self):
        self.assertEqual(config_mod.DEFAULTS["auto_isolate_rules"], ["threat_feed", "dns_tunnel"])
        self.assertEqual(config_mod.DEFAULTS["auto_isolate_max_per_hour"], 2)
        self.assertEqual(config_mod.DEFAULTS["auto_isolate_exempt"], [])

    def test_config_is_checked(self):
        for bad in ({"auto_isolate": "yes"}, {"auto_isolate": True},
                    {"auto_isolate_rules": "threat_feed"}, {"auto_isolate_rules": ["raw_ip"]},
                    {"auto_isolate_rules": ["threat_fed"]}, {"auto_isolate_exempt": "laptop"},
                    {"auto_isolate_max_per_hour": -1}, {"auto_isolate_max_per_hour": True},
                    {"auto_isolate_max_per_hour": "2"}):
            with self.assertRaises(ValueError, msg=bad):
                config_mod.load_config(None, bad)
        with self.assertRaisesRegex(ValueError, "ghost-flow"):
            config_mod.load_config(None, {"auto_isolate_rules": ["threat_feed", "beacon"]})
        config_mod.load_config(None, {"auto_isolate": "dry-run", "auto_isolate_rules": ["nx_burst"],
                                      "auto_isolate_max_per_hour": 0, "auto_isolate_exempt": ["laptop"]})

    def test_on_isolates_like_the_api_and_says_so(self):
        self.build()
        d = self.r.decide(TV, "evil.example", "A")
        self.assertEqual(d.action, "block")
        evt = d.event
        self.assertTrue(evt["auto_isolated"])
        self.assertNotIn("would_isolate", evt)
        self.assertNotIn("auto_isolate_failed", evt)
        self.assertEqual(self.isolations(), [("add", "element", "inet", "ghostwall", "isolated_dev", "{", TV, "}")])
        self.assertEqual(self.backend.members, {TV})
        self.assertTrue(self.state.is_isolated("tv-box"))
        self.assertEqual(self.state.isolated_addresses("tv-box"), [TV])
        last = evt["reasons"][-1]
        self.assertIn(f"isolated tv-box ({TV}) automatically: threat_feed", last)
        self.assertIn("Release button", last)
        self.assertIn("sudo ghostwall release tv-box", last)
        self.assertNotIn("—", last)
        self.assertEqual(self.r.stats["auto_isolated"], 1)
        self.assertEqual(V.validate_event(evt), [])
        self.assertTrue(self.written()[0]["auto_isolated"])   # the written line has it too
        with open(self.cfg["state_path"], encoding="utf-8") as f:   # and state.json, at once
            saved = json.load(f)
        self.assertEqual(saved["isolated"], ["tv-box"])
        self.assertEqual(saved["isolated_ips"], {"tv-box": [TV]})
        self.assertEqual(len(saved["auto_isolations"]), 1)

    def test_dry_run_only_says_would_isolate(self):
        self.build(auto_isolate="dry-run")
        evt = self.hit()
        self.assertTrue(evt["would_isolate"])
        self.assertNotIsolated(evt, "not isolated: auto_isolate is dry-run")
        self.assertIn("would isolate tv-box automatically (threat_feed)", evt["reasons"][-1])
        self.assertEqual(V.validate_event(evt), [])
        self.assertEqual(self.state.auto_isolations_within(3600), 0)   # a dry run uses no cap

    def test_null_backend_is_would_isolate_only(self):
        self.build(backend=NullBackend)
        evt = self.hit()
        self.assertTrue(evt["would_isolate"])
        self.assertIn("enforcement is off", evt["reasons"][-1])
        self.assertEqual(self.state.isolated, set())
        self.assertEqual([c for c in self.backend.calls if "isolated_dev" in c], [])

    def test_learning_mode_behaves_as_dry_run(self):
        self.build(learning=True)
        evt = self.hit()
        self.assertEqual(evt["action"], "recommend")
        self.assertTrue(evt["would_isolate"])
        self.assertNotIsolated(evt, "learning mode is on")
        self.state.set_learning(False)
        self.assertTrue(self.hit(domain="evil.example")["auto_isolated"])   # blocking on: it acts

    def test_shadow_mode_behaves_as_dry_run(self):
        self.build()
        self.r.shadow = True
        evt = self.hit()
        self.assertTrue(evt["would_isolate"])
        self.assertNotIsolated(evt, "shadow mode only watches")

    def test_without_pi_ip_it_is_a_dry_run(self):
        self.build(pi_ip=None)
        evt = self.hit()
        self.assertTrue(evt["would_isolate"])
        self.assertNotIsolated(evt, 'set "pi_ip" first')

    def test_rule_not_in_the_list_is_left_alone(self):
        self.build(auto_isolate_rules=["dns_tunnel"])
        evt = self.hit()
        self.assertNotIn("would_isolate", evt)
        self.assertNotIsolated(evt)

    def test_dns_tunnel_isolates(self):
        self.build()
        evt = self.tunnel()
        self.assertEqual(evt["rule"], "dns_tunnel")
        self.assertEqual(evt["action"], "recommend")
        self.assertTrue(evt["auto_isolated"])
        self.assertTrue(self.state.is_isolated("tv-box"))


class WhichFindingsTests(Base):
    def test_parent_domain_feed_match_never_isolates(self):
        self.build()
        evt = self.hit(domain="x.evil.example")
        self.assertEqual(evt["rule"], "threat_feed")
        self.assertIn("is under evil.example", evt["reasons"][0])
        self.assertNotIn("would_isolate", evt)
        self.assertNotIsolated(evt, "only matched evil.example, a parent domain")

    def test_parent_match_on_a_big_platform_never_isolates(self):
        # the list names one host on a shared platform; a device using another host there
        self.build(feed=("bad-user.platform.example",), popular=("platform.example",))
        evt = self.hit(domain="cdn.bad-user.platform.example")
        self.assertEqual(evt["rule"], "threat_feed")
        self.assertNotIsolated(evt, "parent domain")

    def test_exact_match_under_a_popular_site_never_isolates(self):
        self.build(feed=("cdn.platform.example",), popular=("platform.example",))
        evt = self.hit(domain="cdn.platform.example")
        self.assertEqual(evt["action"], "block")          # still blocked and alerted
        self.assertNotIsolated(evt, "platform.example is a popular site")

    def test_exact_match_on_an_abused_service_never_isolates(self):
        self.build(feed=("drop.paste.example",))
        fake = lambda host: ("paste.example", "paste site") if host.endswith("paste.example") else None  # noqa: E731
        with mock.patch.object(resolver_mod, "abused_service", fake):
            evt = self.hit(domain="drop.paste.example")
        self.assertNotIsolated(evt, "shared service malware abuses")

    def test_phishing_only_listing_never_isolates(self):
        feed = ("#@source\thttps://lists.example/p.txt\t2026-11-01\tPhish List\tphishing", "login-bank.example",
                "#@source\thttps://lists.example/m.txt\t2026-11-01\tMal List\tmalware, C2, phishing", "c2.example")
        self.build(feed=feed)
        evt = self.hit(domain="login-bank.example")
        self.assertIn("Phish List (phishing)", evt["reasons"][0])
        self.assertNotIsolated(evt, "only phishing lists name it")
        evt = self.hit(ip=LAPTOP, domain="c2.example")    # a mixed list with malware: proof enough
        self.assertTrue(evt["auto_isolated"])


class WhoTests(Base):
    def test_exempt_device_is_never_isolated(self):
        self.build(auto_isolate_exempt=["laptop", CAM])
        evt = self.hit(ip=LAPTOP)
        self.assertEqual(evt["device"], "laptop")
        self.assertNotIn("would_isolate", evt)
        self.assertNotIsolated(evt, "laptop is exempt")
        self.assertNotIsolated(self.hit(ip=CAM), "cam-1 is exempt")    # by address too

    def test_the_pi_itself_is_always_exempt(self):
        self.build(auto_isolate_exempt=[])
        evt = self.hit(ip=PI)
        self.assertEqual(evt["device"], "homepi")
        self.assertNotIsolated(evt, "homepi is this box")

    def test_loopback_is_always_exempt(self):
        self.build()
        self.r.devices = self.devices = DeviceMap.from_json([{"name": "local", "ip": "127.0.0.1"}])
        self.assertNotIsolated(self.hit(ip="127.0.0.1"), "local is this box")

    def test_unnamed_address_is_not_isolated_and_says_how_to_name_it(self):
        self.build()
        evt = self.hit(ip="192.168.1.99")
        self.assertNotIsolated(evt, "sudo ghostwall name 192.168.1.99 NAME")

    def test_a_named_device_over_ipv6_is_isolated_at_its_ipv4_address(self):
        v6 = "fd00::20"
        self.build(neighbours=Neigh({v6: TV_MAC}))
        evt = self.hit(ip=v6)
        self.assertEqual(evt["device"], "tv-box")
        self.assertTrue(evt["auto_isolated"])
        self.assertEqual(self.backend.members, {TV})

    def test_no_ipv4_lan_address_is_not_isolated(self):
        self.build()
        self.r.devices = self.devices = DeviceMap.from_json([{"name": "v6-only", "ip": "fd00::50"}])
        evt = self.hit(ip="fd00::50")
        self.assertNotIsolated(evt, "no IPv4 LAN address")

    def test_already_isolated_is_left_alone(self):
        self.build()
        self.state.isolate("tv-box", TV)
        evt = self.hit()
        self.assertNotIn("auto_isolated", evt)
        self.assertIn("already isolated", evt["reasons"][-1])
        self.assertEqual(self.isolations(), [])


class CapTests(Base):
    def test_hourly_cap_alerts_only_and_says_why(self):
        self.build(auto_isolate_max_per_hour=1)
        first = self.hit(ip=TV)
        second = self.hit(ip=LAPTOP)
        self.assertTrue(first["auto_isolated"])
        self.assertNotIn("auto_isolated", second)
        self.assertTrue(second["would_isolate"])
        self.assertIn("1 automatic isolation(s) in the last hour is the cap", second["reasons"][-1])
        self.assertIn("/fw isolate laptop", second["reasons"][-1])
        self.assertFalse(self.state.is_isolated("laptop"))
        self.assertEqual(len(self.isolations()), 1)

    def test_cap_survives_a_restart(self):
        self.build(auto_isolate_max_per_hour=1)
        self.assertTrue(self.hit(ip=TV)["auto_isolated"])
        self.build(auto_isolate_max_per_hour=1, dir=self.dir)    # ghost-dns restarted (or crashed)
        evt = self.hit(ip=LAPTOP)
        self.assertNotIn("auto_isolated", evt)
        self.assertIn("is the cap", evt["reasons"][-1])

    def test_cap_window_slides(self):
        self.build(auto_isolate_max_per_hour=1, feed=("evil.example", "evil2.example"))
        self.assertTrue(self.hit(ip=TV)["auto_isolated"])
        self.wall += 3601
        self.assertTrue(self.hit(ip=LAPTOP, domain="evil2.example")["auto_isolated"])

    def test_a_clock_that_went_back_still_counts(self):
        # a Pi has no clock battery: if its time steps back, the cap must not reset
        self.build(auto_isolate_max_per_hour=1, feed=("evil.example", "evil2.example"))
        self.assertTrue(self.hit(ip=TV)["auto_isolated"])
        self.wall -= 7200
        self.assertNotIn("auto_isolated", self.hit(ip=LAPTOP, domain="evil2.example"))

    def test_cap_zero_never_isolates(self):
        self.build(auto_isolate_max_per_hour=0)
        evt = self.hit()
        self.assertTrue(evt["would_isolate"])
        self.assertNotIsolated(evt, "is the cap")

    def test_concurrent_findings_respect_the_cap(self):
        # the answer-first score worker and the DNS threads all call decide()
        self.build(auto_isolate_max_per_hour=2)
        slow = self.backend._run

        def run(*a):          # nft takes a moment: widen the window for a race
            threading.Event().wait(0.01)
            return slow(*a)
        self.backend._run = run
        ips = [TV, LAPTOP, CAM, PLUG] * 4
        out, threads = [], []
        for ip in ips:
            t = threading.Thread(target=lambda ip=ip: out.append(self.hit(ip=ip)))
            threads.append(t)
            t.start()
        for t in threads:
            t.join(10)
        self.assertEqual(len(out), len(ips))
        self.assertEqual(sum(1 for e in out if e.get("auto_isolated")), 2)
        self.assertEqual(len(self.isolations()), 2)
        self.assertEqual(len(self.state.isolated), 2)


class FailureTests(Base):
    def test_nft_failure_keeps_the_alert_and_says_isolation_failed(self):
        self.build()
        self.backend.fail_add = subprocess.CalledProcessError(1, ["nft"], stderr=ENOENT)
        d = self.r.decide(TV, "evil.example", "A")     # does not raise
        self.assertEqual(d.action, "block")
        evt = d.event
        self.assertTrue(evt["auto_isolate_failed"])
        self.assertTrue(evt["would_isolate"])
        self.assertNotIn("auto_isolated", evt)
        self.assertIn("automatic isolation FAILED", evt["reasons"][-1])
        self.assertIn("/fw isolate tv-box", evt["reasons"][-1])
        self.assertFalse(self.state.is_isolated("tv-box"))
        self.assertEqual(self.r.stats["auto_isolated"], 0)
        self.assertEqual(self.state.auto_isolations_within(3600), 0)
        self.assertEqual(V.validate_event(evt), [])
        self.assertTrue(self.written()[0]["auto_isolate_failed"])
        self.backend.fail_add = None          # fixed: the next sighting isolates
        self.assertTrue(self.hit()["auto_isolated"])

    def test_state_failure_undoes_the_kernel_side(self):
        self.build()
        with mock.patch.object(self.state, "isolate", side_effect=OSError("disk full")):
            evt = self.hit()
        self.assertTrue(evt["auto_isolate_failed"])
        self.assertIn("disk full", evt["reasons"][-1])
        self.assertEqual(self.backend.members, set())

    def test_a_bug_in_the_policy_never_costs_the_alert(self):
        self.build()
        with mock.patch.object(self.r, "_iso_address", side_effect=RuntimeError("oops")):
            evt = self.hit()
        self.assertTrue(evt["auto_isolate_failed"])
        self.assertEqual(len(self.written()), 1)


class ReleaseTests(Base):
    def serve(self):
        server = ControlServer(dict(self.cfg, control_port=0), self.state, self.enforcer,
                               self.devices, resolver=self.r)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.httpd.server_address[1]}"

        def call(path, body):
            req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())
        return call

    def test_release_undoes_it_is_idempotent_and_sticks(self):
        self.build(feed=("evil.example", "evil2.example"))
        self.assertTrue(self.hit()["auto_isolated"])
        call = self.serve()
        self.assertTrue(call("/device", {"name": "tv-box"})[1]["isolated"])
        self.assertEqual(call("/release", {"name": "tv-box"}), (200, {"ok": True, "name": "tv-box", "isolated": False}))
        self.assertEqual(self.backend.members, set())
        self.assertFalse(self.state.is_isolated("tv-box"))
        # a second press (or the dashboard after the Telegram button) is fine
        self.assertEqual(call("/release", {"name": "tv-box"})[0], 200)
        # the same finding again does not cut it off again...
        evt = self.hit()
        self.assertNotIn("auto_isolated", evt)
        self.assertIn("then released", evt["reasons"][-1])
        self.assertEqual(self.backend.members, set())
        # ...a new one does
        self.assertTrue(self.hit(domain="evil2.example")["auto_isolated"])
        # and manual isolate still works
        self.assertTrue(call("/isolate", {"name": "laptop"})[1]["isolated"])
        self.assertEqual(self.backend.members, {TV, LAPTOP})

    def test_release_finds_the_address_after_the_device_moved(self):
        self.build(neighbours=Neigh({"192.168.1.77": TV_MAC, "192.168.1.78": TV_MAC}))
        self.assertTrue(self.hit(ip="192.168.1.77")["auto_isolated"])
        self.r.decide("192.168.1.78", "example.com", "A")       # DHCP moved it
        call = self.serve()
        self.assertEqual(call("/release", {"name": "tv-box"})[0], 200)
        self.assertEqual(self.backend.members, set())

    def test_a_real_nft_failure_on_release_keeps_it_isolated(self):
        self.build()
        self.assertTrue(self.hit()["auto_isolated"])
        self.backend.fail_delete = subprocess.CalledProcessError(1, ["nft"], stderr="Operation not permitted")
        code, body = self.serve()("/release", {"name": "tv-box"})
        self.assertEqual(code, 500)
        self.assertIn("could not release tv-box", body["error"])
        self.assertTrue(self.state.is_isolated("tv-box"))

    def test_restart_puts_isolations_back(self):
        self.build()
        self.assertTrue(self.hit()["auto_isolated"])
        self.state.isolate("laptop")                 # isolated by an older version: no address kept
        fresh = NftSet()                             # a reboot emptied the set
        logs = []
        n = restore_isolations(GhostState(self.cfg["state_path"]), Enforcer(fresh), self.devices,
                               log=lambda *a, **k: logs.append(a[0]))
        self.assertEqual(n, 2)
        self.assertEqual(fresh.members, {TV, LAPTOP})
        self.assertTrue(any("sudo ghostwall release tv-box" in m for m in logs))
        self.assertEqual(restore_isolations(self.state, Enforcer(NullBackend()), self.devices), 0)
        fresh.fail_add = OSError("no table")         # never fatal
        self.assertEqual(restore_isolations(self.state, Enforcer(fresh), self.devices, log=lambda *a, **k: None), 0)


if __name__ == "__main__":
    unittest.main()
