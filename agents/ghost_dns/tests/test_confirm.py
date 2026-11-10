"""confirm_seconds: a finding one lookup can cause (a web page or an email can make a device
look a listed name up, or send dozens of made-up subdomains) does not cut a device off or
block a site until it is seen again later. Example names and 192.168.1.x only."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config as config_mod
import test_auto_isolate as A
import test_contain as C


class IsolateTests(A.Base):
    def test_one_listed_lookup_does_not_isolate_a_repeat_later_does(self):
        self.build(confirm_seconds=300, shadow=False)
        evt = self.hit()
        self.assertNotIsolated(evt, "any web page or email can cause")
        self.assertTrue(evt["would_isolate"])
        self.wall += 60
        self.assertNotIn("auto_isolated", self.hit())            # too soon: could be the same page
        self.wall += 300
        evt = self.hit()
        self.assertTrue(evt["auto_isolated"])
        self.assertEqual(len(self.isolations()), 1)

    def test_another_device_starts_its_own_wait(self):
        self.build(confirm_seconds=300, shadow=False)
        self.hit(A.TV)
        self.wall += 400
        self.assertNotIn("auto_isolated", self.hit(A.CAM))
        self.assertTrue(self.hit(A.TV)["auto_isolated"])

    def test_a_tunnel_of_address_lookups_waits_one_with_txt_does_not(self):
        self.build(confirm_seconds=300, shadow=False, auto_isolate_max_per_hour=5)
        evt = None
        for i in range(40):                                       # what a page full of <img> tags can do
            d = self.r.decide(A.CAM, f"{i:02d}q8f3k2m9x7v1z4p6w0r5t.pagemade.example", "A")
            evt = evt or d.event
        self.assertEqual(evt["rule"], "dns_tunnel")
        self.assertNotIn("auto_isolated", evt)
        self.assertIn("not isolated yet", " ".join(evt["reasons"]))
        self.assertTrue(self.tunnel(A.TV)["auto_isolated"])       # TXT queries: a tunnel tool

    def test_zero_acts_on_the_first_sighting(self):
        self.build(confirm_seconds=0, shadow=False)
        self.assertTrue(self.hit()["auto_isolated"])

    def test_bad_value_refused(self):
        with self.assertRaises(ValueError):
            config_mod.load_config(None, {"confirm_seconds": -1})


class ContainTests(C.Base):
    def page_tunnel(self, ip=C.TV, apex="smallshop.example"):
        evt = None
        for i in range(40):
            d = self.r.decide(ip, f"{i:02d}q8f3k2m9x7v1z4p6w0r5t.{apex}", "A")
            evt = evt or d.event
        return evt

    def test_a_page_cannot_get_a_site_blocked_for_the_house(self):
        self.build(contain_rules=["dns_tunnel"])
        evt = self.page_tunnel()
        self.assertEqual((evt["rule"], evt.get("would_contain")), ("dns_tunnel", "smallshop.example"))
        self.assertNotIn("contained", evt)
        self.assertFalse(self.state.is_blocked("www.smallshop.example"))

    def test_it_is_contained_when_it_continues(self):
        self.build(contain_rules=["dns_tunnel"])
        self.page_tunnel()
        self.wall += 3600
        self.now += 3600                                          # past the detector's cooldown
        evt = self.page_tunnel()
        self.assertEqual(evt.get("contained"), "smallshop.example")

    def test_a_site_the_household_already_uses_is_never_contained_by_behaviour(self):
        self.build(contain_rules=["dns_tunnel"], novelty_days=7)
        self.state.note_seen("www.oldfriend.example")
        self.state.first_seen[next(iter(self.state.first_seen))] = "2020-01-01"
        evt = self.tunnel(apex="oldfriend.example")               # even with TXT queries
        self.assertNotIn("contained", evt)
        self.assertNotIn("would_contain", evt)
        self.assertIn("not new to this network", " ".join(evt["reasons"]))

    def test_a_feed_hit_is_contained_at_once(self):
        self.build()
        self.assertEqual(self.hit()["contained"], "evil.example")


if __name__ == "__main__":
    unittest.main()
