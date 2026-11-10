"""contain: what one device was caught reaching is refused for every device. Off / dry-run /
on, learning, the guards (trusted, popular, shared platforms, established names), the daily
cap, expiry, undo (CLI route, Trust), the gateway address block (both directions are the
firewall's job; here: which addresses go in, shared ones never, self-healing), restart, and
the push to AdGuard Home / Pi-hole. Made-up example names; 192.168.1.x and public test-like
addresses only."""
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

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(os.path.dirname(HERE), "fw_bot"))
import config as config_mod
import dns_block as B
import shadow
import validate_events as V
from app import restore_contained
from control_api import ControlServer
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from events import EventLog
from resolver import Resolver
from state import GhostState

LAPTOP, TV, PI = "192.168.1.10", "192.168.1.20", "192.168.1.2"
DEVICES = [{"name": "laptop", "ip": LAPTOP}, {"name": "tv-box", "ip": TV}, {"name": "homepi", "ip": PI}]
BAD_IP, BAD_IP2, SHARED_IP = "45.33.10.20", "45.33.10.21", "31.13.200.7"
ENOENT = "Error: Could not process rule: No such file or directory"
RANDOM = "xk7qz2vb9w4m.example"          # FakeScorer calls anything starting "xk" random-looking


class FakeScorer:
    def score_one(self, domain):
        v = 0.999 if domain.split(".")[-2].startswith("xk") else 0.0
        return {"dga": v, "dga_trm": v, "dga_lr": v}


class NftSet(NullBackend):
    """The nft backend's blocked_ip set: members, and ENOENT when deleting an absent one."""

    def __init__(self):
        super().__init__()
        self.blocked: dict[str, str] = {}

    @property
    def name(self):
        return "nft"

    def _run(self, *args):
        self.calls.append(args)
        if "blocked_ip" not in args:
            return
        ip = args[args.index("{") + 1]
        if args[0] == "add":
            self.blocked[ip] = args[args.index("timeout") + 1]
        elif ip not in self.blocked:
            raise subprocess.CalledProcessError(1, ["nft"], stderr=ENOENT)
        else:
            del self.blocked[ip]


class Base(unittest.TestCase):
    def build(self, backend=NullBackend, learning=False, shadow_mode=True, feed=("evil.example",),
              popular=("brand.example",), dir=None, **over):
        self.dir = dir or tempfile.mkdtemp()
        fpath = os.path.join(self.dir, "feed.txt")
        with open(fpath, "w") as f:
            f.write("\n".join(feed) + "\n")
        with open(os.path.join(self.dir, "popular_domains.txt"), "w") as f:
            f.write("\n".join(popular) + "\n")
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "s.json"), "events_path": os.path.join(self.dir, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "allowlist_path": None, "shadow": shadow_mode,
            "threat_feed_path": fpath, "pi_ip": PI, "contain": "on", **over})
        self.state = GhostState(self.cfg["state_path"], learning_default=learning)
        self.wall = getattr(self, "wall", 1_800_000_000.0)
        self.state.clock = lambda: datetime.fromtimestamp(self.wall, timezone.utc)
        self.backend = backend()
        self.enforcer = Enforcer(self.backend)
        self.devices = DeviceMap.from_json(DEVICES)
        self.r = Resolver(self.cfg, self.state, FakeScorer(), self.enforcer, self.devices,
                          EventLog(self.cfg["events_path"]))
        self.assertTrue(self.r.det.wait_loaded(10))
        self.now = 1000.0
        self.r.clock = lambda: self.now
        return self.r

    def hit(self, ip=TV, domain="evil.example"):
        return self.r.decide(ip, domain, "A", rcode="NOERROR").event

    def tunnel(self, ip=TV, apex="exfil.example"):
        evt = None
        for i in range(40):
            d = self.r.decide(ip, f"{i:02d}q8f3k2m9x7v1z4p6w0r5t.{apex}", "TXT")
            evt = evt or d.event
        return evt


class ModeTests(Base):
    def test_off_does_nothing(self):
        self.build(contain="off")
        evt = self.hit()
        self.assertNotIn("contained", evt)
        self.assertNotIn("would_contain", evt)
        self.assertEqual(self.state.contained_list(), {})

    def test_dry_run_says_what_it_would_block(self):
        self.build(contain="dry-run")
        evt = self.hit()
        self.assertEqual(evt["would_contain"], "evil.example")
        self.assertIn("would block evil.example for every device", evt["reasons"][-1])
        self.assertEqual(self.state.contained_list(), {})
        self.assertEqual(V.validate_event(evt), [])

    def test_on_while_learning_is_a_dry_run(self):
        self.build(learning=True)
        evt = self.hit()
        self.assertEqual(evt["would_contain"], "evil.example")
        self.assertIn("learning mode", evt["reasons"][-1])
        self.assertFalse(self.state.is_blocked("evil.example"))

    def test_feed_hit_contains_the_listed_name_for_every_device(self):
        self.build()
        evt = self.hit()
        self.assertEqual(evt["contained"], "evil.example")
        self.assertIn("undo: sudo ghostwall uncontain evil.example", evt["reasons"][-1])
        self.assertEqual(V.validate_event(evt), [])
        c = self.state.contained_list()["evil.example"]
        self.assertEqual((c["rule"], c["device"]), ("threat_feed", "tv-box"))
        self.assertAlmostEqual(c["until"] - c["since"], 7 * 86400)
        self.assertTrue(self.state.is_blocked("login.evil.example"))      # and everything under it
        self.assertEqual(self.r.stats["contained"], 1)
        again = self.hit(LAPTOP)                                           # another device: already held
        self.assertIn("already blocked for every device", " ".join(again["reasons"]))
        self.assertEqual(len(self.state.contained_list()), 1)

    def test_behaviour_finding_blocks_the_zone_for_the_next_device(self):
        self.build()
        evt = self.tunnel()
        self.assertEqual((evt["rule"], evt["contained"]), ("dns_tunnel", "exfil.example"))
        d = self.r.decide(LAPTOP, "www.exfil.example", "A")
        self.assertEqual((d.reason, d.action), ("blocklist", "recommend"))   # shadow: the DNS server blocks
        self.assertIn("exfil.example is contained", d.event["reasons"][0])

    def test_inline_mode_refuses_it_for_the_next_device(self):
        self.build(shadow_mode=False)
        evt = self.hit(TV, RANDOM)
        self.assertEqual((evt["rule"], evt["action"], evt["contained"]), ("dga_high", "block", RANDOM))
        self.assertEqual(self.r.decide(LAPTOP, "cdn." + RANDOM, "A").action, "block")

    def test_written_event_carries_it(self):
        self.build()
        self.hit()
        with open(self.cfg["events_path"]) as f:
            evt = json.loads(f.readline())
        self.assertEqual(evt["contained"], "evil.example")


class GuardTests(Base):
    def assertNotContained(self, evt, why):
        self.assertNotIn("contained", evt)
        self.assertIn(why, " ".join(evt["reasons"]))
        self.assertEqual(self.state.contained_list(), {})

    def test_never_a_popular_site(self):
        self.build(feed=("brand.example",))
        self.assertNotContained(self.hit(domain="brand.example"), "popular site")

    def test_a_listed_host_under_a_popular_site_is_contained_alone(self):
        self.build(feed=("phish.brand.example",))
        self.assertEqual(self.hit(domain="phish.brand.example")["contained"], "phish.brand.example")
        self.assertFalse(self.state.is_blocked("www.brand.example"))

    def test_never_a_shared_platform(self):
        self.build(feed=("abc123.ngrok.io",))
        evt = self.hit(domain="abc123.ngrok.io")
        if evt["rule"] == "threat_feed":
            self.assertNotContained(evt, "shared service")

    def test_never_an_established_name(self):
        self.build(novelty_days=7)
        self.state.note_seen(RANDOM)
        self.state.first_seen[next(iter(self.state.first_seen))] = "2020-01-01"
        evt = self.hit(domain=RANDOM)
        self.assertEqual(evt["rule"], "dga_high")
        self.assertNotContained(evt, "not new to this network")

    def test_rules_outside_contain_rules_do_not_contain(self):
        self.build(contain_rules=["dns_tunnel"])
        self.assertNotIn("contained", self.hit())

    def test_daily_cap(self):
        self.build(feed=("a.example", "b.example", "c.example"), contain_max_per_day=2)
        self.assertIn("contained", self.hit(domain="a.example"))
        self.assertIn("contained", self.hit(domain="b.example"))
        evt = self.hit(domain="c.example")
        self.assertEqual(evt["would_contain"], "c.example")
        self.assertIn("cap", evt["reasons"][-1])
        self.assertEqual(len(self.state.contained_list()), 2)

    def test_expires_and_survives_a_restart_until_then(self):
        self.build(contain_rules=["dns_tunnel"])
        self.tunnel()
        self.state.flush()
        again = GhostState(self.cfg["state_path"], learning_default=False)
        again.clock = self.state.clock
        self.assertTrue(again.is_blocked("x.exfil.example"))
        self.wall += 8 * 86400
        self.assertFalse(again.is_blocked("x.exfil.example"))
        self.assertEqual(again.contained_list(), {})

    def test_bad_settings_are_refused(self):
        for over in ({"contain": "yes"}, {"contain_rules": ["nx_burst"]}, {"contain_rules": "threat_feed"},
                     {"contain_days": 0}, {"contain_max_per_day": -1}):
            with self.assertRaises(ValueError, msg=over):
                config_mod.load_config(None, over)


class AddressTests(Base):
    def test_addresses_it_answered_with_are_dropped(self):
        self.build(backend=NftSet)
        self.r.note_ips("evil.example", [BAD_IP, "192.168.1.99", "2a03:2880::1"])   # only public IPv4 counts
        self.r.note_ips("c2.evil.example", [BAD_IP2])
        evt = self.hit()
        self.assertEqual(self.backend.blocked, {BAD_IP: "168h", BAD_IP2: "168h"})
        self.assertIn("2 address(es)", evt["reasons"][-1])
        self.assertEqual(self.state.contained_list()["evil.example"]["ips"], [BAD_IP, BAD_IP2])

    def test_an_address_another_domain_uses_is_never_dropped(self):
        self.build(backend=NftSet)
        self.r.note_ips("evil.example", [BAD_IP, SHARED_IP])
        self.r.note_ips("www.innocent.example", [SHARED_IP])
        self.hit()
        self.assertEqual(set(self.backend.blocked), {BAD_IP})

    def test_a_dropped_address_is_let_through_when_another_domain_answers_with_it(self):
        self.build(backend=NftSet)
        self.r.note_ips("evil.example", [BAD_IP])
        self.hit()
        self.r.note_ips("c2.evil.example", [BAD_IP])            # the contained name itself: stays
        self.assertIn(BAD_IP, self.backend.blocked)
        self.r.note_ips("www.innocent.example", [BAD_IP])       # shared hosting after all
        self.assertEqual(self.backend.blocked, {})
        self.assertEqual(self.state.contained_list()["evil.example"]["ips"], [])
        self.assertTrue(self.state.is_blocked("evil.example"))  # the name is still refused

    def test_no_gateway_means_no_address_block_and_no_claim(self):
        self.build()                                             # NullBackend
        self.r.note_ips("evil.example", [BAD_IP])
        evt = self.hit()
        self.assertNotIn("address(es)", evt["reasons"][-1])
        self.assertEqual(self.backend.calls, [])

    def test_contain_ips_off(self):
        self.build(backend=NftSet, contain_ips=False)
        self.r.note_ips("evil.example", [BAD_IP])
        self.hit()
        self.assertEqual(self.backend.blocked, {})

    def test_uncontain_takes_the_addresses_out_even_if_they_timed_out(self):
        self.build(backend=NftSet)
        self.r.note_ips("evil.example", [BAD_IP, BAD_IP2])
        self.hit()
        del self.backend.blocked[BAD_IP2]                        # the kernel timed it out
        self.assertTrue(self.r.uncontain("evil.example"))
        self.assertEqual(self.backend.blocked, {})
        self.assertFalse(self.state.is_blocked("evil.example"))
        self.assertFalse(self.r.uncontain("evil.example"))

    def test_restart_puts_addresses_back_for_the_time_left(self):
        self.build(backend=NftSet)
        self.r.note_ips("evil.example", [BAD_IP])
        self.hit()
        self.backend.blocked.clear()                             # a reboot emptied the set
        self.wall += 2 * 86400
        self.assertEqual(restore_contained(self.state, self.enforcer, log=lambda *a, **k: None), 1)
        self.assertEqual(self.backend.blocked, {BAD_IP: "120h"})
        self.assertEqual(restore_contained(self.state, Enforcer(NullBackend())), 0)

    def test_adguard_log_line_gives_the_answers_addresses(self):
        import base64
        import dnsmsg
        import struct
        q = b"\x04evil\x07example\x00\x00\x01\x00\x01"
        msg = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + q + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" \
            + bytes(int(x) for x in BAD_IP.split("."))
        self.assertEqual(dnsmsg.extract_answer_ips(msg), [BAD_IP])
        line = {"QH": "evil.example", "Answer": base64.b64encode(msg).decode(), "Result": {}}
        self.assertEqual(shadow.adguard_answer_ips(json.dumps(line)), ("evil.example", [BAD_IP]))
        line["Result"] = {"IsFiltered": True, "Reason": 3}       # AdGuard's own block: not an address
        self.assertIsNone(shadow.adguard_answer_ips(json.dumps(line)))
        self.assertIsNone(shadow.adguard_answer_ips("not json"))


class ControlTests(Base):
    def api(self):
        server = ControlServer(dict(self.cfg, control_port=0), self.state, self.enforcer,
                               self.devices, resolver=self.r)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.httpd.server_address[1]}"

        def call(path, body=None):
            req = urllib.request.Request(base + path, data=json.dumps(body or {}).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())
        return call

    def test_list_and_undo(self):
        self.build(backend=NftSet, control_token_path=None)
        self.r.note_ips("evil.example", [BAD_IP])
        self.hit()
        call = self.api()
        code, body = call("/contained")
        self.assertEqual((code, body["mode"]), (200, "on"))
        row = body["contained"][0]
        self.assertEqual((row["domain"], row["rule"], row["device"], row["ips"]),
                         ("evil.example", "threat_feed", "tv-box", [BAD_IP]))
        self.assertEqual(call("/status")[1]["contain"], {"mode": "on", "contained": 1})
        self.assertEqual(call("/uncontain", {"domain": "www.evil.example"})[1]["domain"], "evil.example")
        self.assertEqual(self.backend.blocked, {})
        self.assertEqual(call("/uncontain", {"domain": "evil.example"})[0], 404)
        self.assertEqual(call("/uncontain", {"domain": "bad name"})[0], 400)

    def test_trust_ends_a_containment(self):
        self.build(contain_rules=["dns_tunnel"], control_token_path=None)
        self.tunnel()
        code, body = self.api()("/allow", {"domain": "exfil.example"})
        self.assertEqual((code, body.get("uncontained")), (200, "exfil.example"))
        self.assertFalse(self.state.is_blocked("exfil.example"))


class DnsServerTests(unittest.TestCase):
    """ghostwall-dnsblock: contained names become rules of their own, in force at once."""

    def setUp(self):
        import test_dns_block as T
        self.T = T
        self.d = tempfile.mkdtemp()
        self.feed = os.path.join(self.d, "threat_feed.txt")
        with open(self.feed, "w") as f:
            f.write(T.FEED)

    def syncer(self, http, **kw):
        env = {"DNS_SOURCE": "adguard", "DNS_BLOCK_FEED": "on", "ADGUARD_USER": "admin",
               "ADGUARD_PASSWORD": self.T.AG_PASS, "PIHOLE_PASSWORD": self.T.PH_PASS,
               "ADGUARD_URL": "http://127.0.0.1:3000", "PIHOLE_URL": "http://127.0.0.1", **kw}
        s = B.load_settings(env)
        s.update(feed_path=self.feed, state_path=os.path.join(self.d, "state.json"), data=self.d,
                 events_path=os.path.join(self.d, "events.jsonl"), allowlist_path=None)
        return B.Syncer(s, http, log=lambda m: None, serve=False)

    def view(self, contained=(), trusted=()):
        with open(os.path.join(self.d, "dns_view.json"), "w") as f:
            json.dump({"trusted": list(trusted), "exceptions": [], "blocked": [], "starter": [],
                       "contained": list(contained)}, f)

    def test_adguard_gets_a_rule_and_loses_it_again(self):
        ag = self.T.FakeAdGuard()
        ag.rules = ["||mine.example^"]
        self.view(contained=["exfil.example"])
        self.assertTrue(self.syncer(ag).sync_once())
        self.assertIn("||exfil.example^", ag.rules)
        self.assertIn("||mine.example^", ag.rules)               # the user's own rules stay
        self.view()
        self.assertTrue(self.syncer(ag).sync_once())
        self.assertEqual(ag.rules, ["||mine.example^"])

    def test_a_trusted_name_is_not_pushed(self):
        ag = self.T.FakeAdGuard()
        self.view(contained=["exfil.example", "x.trusted.example"], trusted=["trusted.example"])
        self.assertTrue(self.syncer(ag).sync_once())
        self.assertIn("||exfil.example^", ag.rules)
        self.assertNotIn("||x.trusted.example^", ag.rules)

    def test_pihole_gets_a_deny_rule_without_a_gravity_run_for_it(self):
        ph = self.T.FakePiHole()
        self.view()
        self.assertTrue(self.syncer(ph, DNS_SOURCE="pihole").sync_once())
        runs = ph.gravity
        self.view(contained=["exfil.example"])
        self.assertTrue(self.syncer(ph, DNS_SOURCE="pihole").sync_once())
        self.assertEqual(list(ph.deny), [B.pihole_regex("exfil.example")])
        self.assertTrue(ph.deny[B.pihole_regex("exfil.example")]["comment"].startswith(B.CONTAINED))
        self.assertEqual(ph.gravity, runs)
        self.view()
        self.assertTrue(self.syncer(ph, DNS_SOURCE="pihole").sync_once())
        self.assertEqual(ph.deny, {})


if __name__ == "__main__":
    unittest.main()
