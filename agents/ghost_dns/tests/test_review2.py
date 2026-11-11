"""Second design review: who chooses what gets blocked, and who can frame whom. The owner of
a bad domain chooses its addresses; any LAN device can forge a lookup's sender; a flood can
push an alert over the cap; a trusted cloud can hide a contained host; a Pi boots with the
wrong time; a lookalike name. Example names, 192.168.1.x and public test-like addresses."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config as config_mod
import test_auto_isolate as A
import test_contain as C
from enforce import Enforcer, NullBackend
from state import GhostState


class WhoChoosesTheTarget(C.Base):
    def test_a_bad_domain_cannot_point_the_firewall_at_a_dns_resolver(self):
        self.build(backend=C.NftSet, upstream_fallbacks=["9.9.9.9"], contain_protect=["203.0.113.0/24"])
        self.r.note_ips("evil.example", ["9.9.9.9", "1.1.1.1", "203.0.113.7", C.BAD_IP])
        self.hit()
        self.assertEqual(set(self.backend.blocked), {C.BAD_IP})     # resolvers and protected networks stay

    def test_at_most_contain_max_ips_addresses(self):
        self.build(backend=C.NftSet, contain_max_ips=2)
        self.r.note_ips("evil.example", [f"45.33.10.{i}" for i in range(20, 30)])
        self.hit()
        self.assertEqual(len(self.backend.blocked), 2)

    def test_containment_wins_over_a_trusted_cloud_but_not_over_your_own_trust(self):
        d = self.build(shadow_mode=False, feed=("bad.bigcloud.example",), popular=()).state
        d.allowlist.add("bigcloud.example")
        d.static_allow.add("bigcloud.example")                       # as the starter allowlist does
        self.hit(C.TV, "bad.bigcloud.example")
        self.assertEqual(self.state.contained_by("x.bad.bigcloud.example"), "bad.bigcloud.example")
        self.assertEqual(self.r.decide(C.LAPTOP, "x.bad.bigcloud.example", "A").reason, "blocklist")
        self.assertEqual(self.r.decide(C.LAPTOP, "www.bigcloud.example", "A").reason, "allowlist")
        self.state.allow("bad.bigcloud.example")                     # the owner says it is fine
        self.assertNotEqual(self.r.decide(C.LAPTOP, "x.bad.bigcloud.example", "A").action, "block")

    def test_bad_settings_refused(self):
        for over in ({"contain_protect": ["not-a-network"]}, {"contain_protect": "9.9.9.9"},
                     {"contain_max_ips": -1}, {"auto_isolate_min_sources": 0}):
            with self.assertRaises(ValueError, msg=over):
                config_mod.load_config(None, over)

    def test_a_containment_made_before_the_clock_was_set_does_not_vanish(self):
        self.build(contain_rules=["dns_tunnel"])
        self.tunnel()
        self.state.flush()
        again = GhostState(self.cfg["state_path"], learning_default=False)
        boot = self.wall - 400 * 86400                                # no clock battery: an old time
        again.clock = lambda: __import__("datetime").datetime.fromtimestamp(boot, __import__("datetime").timezone.utc)
        self.assertTrue(again.is_blocked("x.exfil.example"))
        again.contain("late.example", "dns_tunnel", "tv-box", 7)      # made with the old time
        again.clock = self.state.clock                                # the clock is set
        self.assertTrue(again.is_blocked("late.example"))

    def test_lookalike_of_a_popular_site(self):
        self.build(popular=("paypal.example",), contain="off")
        fake = "xn--" + "p\u0430yp\u0430l".encode("punycode").decode() + ".example"   # Cyrillic a
        d = self.r.decide(C.TV, "login." + fake, "A")
        self.assertEqual((d.reason, d.event["severity"]), ("lookalike", "high"))
        self.assertIn("paypal.example", d.event["reasons"][0])
        accent = "xn--" + "p\u00e4ypal".encode("punycode").decode() + ".example"        # an ordinary accent
        self.assertNotEqual(self.r.decide(C.TV, accent, "A").reason, "lookalike")
        other = "xn--" + "\u0430\u0435\u043e".encode("punycode").decode() + ".example"  # imitates nothing popular
        self.assertNotEqual(self.r.decide(C.TV, other, "A").reason, "lookalike")


class WhoCanFrameWhom(A.Base):
    def test_no_isolation_while_lookups_can_be_forged(self):
        self.build(shadow=False, auto_isolate_need_antispoof=True)
        evt = self.hit()
        self.assertNotIsolated(evt, "anti-spoofing is off")
        self.assertTrue(evt["would_isolate"])

    def test_isolation_once_the_firewall_binds_addresses_to_macs(self):
        self.build(shadow=False, auto_isolate_need_antispoof=True)
        self.backend.chain_text = lambda chain: (
            'iifname "eth0" ip saddr @named_dev ip saddr . ether saddr != @named_mac counter drop\n')
        self.assertTrue(self.hit()["auto_isolated"])
        self.assertFalse(Enforcer(NullBackend()).antispoof_active())

    def test_one_list_is_not_enough_to_cut_a_device_off(self):
        self.build(shadow=False, auto_isolate_min_sources=2, feed=(
            "#@source\tone\t2026-11-01\tOpen list\tmalware", "evil.example",
            "#@source\ttwo\t2026-11-01\tSecond list\tmalware", "evil.example", "worse.example"))
        self.assertNotIsolated(self.hit(A.CAM, "worse.example"), "only 1 list names it")
        self.assertTrue(self.hit(A.TV, "evil.example")["auto_isolated"])

    def test_a_flood_of_junk_alerts_cannot_hide_the_one_that_isolates(self):
        self.build(shadow=False, alert_rate_per_device=5, recommend_threshold=0.0, block_threshold=2.0,
                   suspect_only_new=False)
        for i in range(40):                                           # junk: one score alert each
            self.r.decide(A.TV, f"junk{i}.example", "A")
        self.assertGreater(self.r.stats["rate_limited"], 0)
        self.assertTrue(self.hit()["auto_isolated"])

    def test_an_isolated_device_gets_no_answers(self):
        import dnsmsg
        self.build(shadow=False)
        self.r._forward = lambda packet, tcp=False: self.fail("an isolated device's lookup was forwarded")
        self.state.isolate("tv-box", A.TV)
        q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05quiet\x07example\x00\x00\x10\x00\x01"
        reply = self.r.handle_packet(A.TV, q)
        self.assertNotEqual(dnsmsg.reply_status(reply), None)
        self.assertEqual(self.r.stats["isolated_refused"], 1)


if __name__ == "__main__":
    unittest.main()
