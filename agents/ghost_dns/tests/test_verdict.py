"""First-contact verdict (verdict.py) and its dry-run wiring in resolver.decide().

The pure rules run on Evidence objects. The wiring runs real Resolver stacks and checks that
"dry-run" never changes a decision or the events written, that "off" does nothing, that stats
count the judged lookups, and that a crash inside the verdict is swallowed.
"""
import dataclasses
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from collections import Counter
from datetime import datetime, timedelta, timezone
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(os.path.dirname(HERE), "fw_bot"))   # validate_events only
import config as config_mod  # noqa: E402
import replay_querylog  # noqa: E402
import state as state_mod  # noqa: E402
import validate_events  # noqa: E402
import verdict as V  # noqa: E402
from devices import DeviceMap  # noqa: E402
from enforce import Enforcer, NullBackend  # noqa: E402
from events import EventLog  # noqa: E402
from resolver import Resolver  # noqa: E402
from state import GhostState  # noqa: E402

TH = V.Thresholds(recommend_dga=0.96, corroborated_dga=0.80, block_dga=0.995, young_days=7)


def ev(**kw):
    base = {"domain": "site.example", "new_to_network": True}
    base.update(kw)
    return V.Evidence(**base)


def judged(**kw):
    return V.judge(ev(**kw), TH)


# -- the pure rules --------------------------------------------------------------------------

class FamilyTests(unittest.TestCase):
    def test_nothing_risky_allows(self):
        v = judged(new_to_network=False)
        self.assertEqual((v.outcome, v.score), ("allow", 0))
        self.assertEqual(set(v.families.values()), {"none"})

    def test_strong_name_alone_holds_a_normal_device(self):
        v = judged(dga=0.997)
        self.assertEqual((v.outcome, v.score), ("hold", 1))
        self.assertEqual(v.families["name"], "strong")

    def test_weak_name_alone_does_not_hold_a_normal_device(self):
        self.assertEqual(judged(dga=0.97, new_to_network=False).outcome, "allow")
        self.assertEqual(judged(dga=0.97).outcome, "allow")      # new to the network is weak too: two weak, not counted
        self.assertEqual(judged(dga=0.97).families["name"], "weak")

    def test_iot_holds_on_one_risky_family(self):
        self.assertEqual(judged(iot=True).outcome, "hold")       # new to the network: its one family
        iot = judged(dga=0.97, iot=True)                         # ...and a weak name is a second family
        self.assertEqual((iot.outcome, iot.score), ("block", 2))

    def test_rare_tld_is_weak_and_needs_a_score_to_be_strong(self):
        self.assertEqual(judged(rare_tld=True).families["name"], "weak")
        self.assertEqual(judged(rare_tld=True).outcome, "allow")
        corroborated = judged(dga=0.85, rare_tld=True)
        self.assertEqual((corroborated.families["name"], corroborated.outcome), ("strong", "hold"))
        self.assertEqual(judged(dga=0.85).families["name"], "none")   # a middling score alone is nothing

    def test_lookalike_is_strong(self):
        v = judged(lookalike=True)
        self.assertEqual((v.outcome, v.families["name"]), ("hold", "strong"))

    def test_young_domain_is_strong_within_novelty_days(self):
        self.assertEqual(judged(young_days=3).families["age"], "strong")
        self.assertEqual(judged(young_days=3).outcome, "hold")
        old = judged(young_days=20)
        self.assertEqual((old.families["age"], old.outcome), ("weak", "allow"))
        self.assertEqual(judged(young_days=20, iot=True).outcome, "block")   # weak age and weak history

    def test_list_exact_hit_is_proof_grade_and_blocks_alone(self):
        v = judged(list_hit="exact", list_name="bad.example")
        self.assertEqual((v.outcome, v.proof), ("block", True))
        self.assertIn("bad.example", v.reasons[0])

    def test_list_parent_hit_is_weak_and_not_proof(self):
        v = judged(list_hit="parent", list_name="p.example")
        self.assertEqual((v.outcome, v.families["list"], v.proof), ("allow", "weak", False))
        self.assertEqual(judged(list_hit="parent", list_name="p.example", iot=True).outcome, "block")

    def test_list_hit_on_a_shared_service_is_not_proof(self):
        v = judged(list_hit="exact", list_name="x.example", shared_service="paste site")
        self.assertEqual((v.outcome, v.proof, v.families["list"]), ("hold", False, "strong"))

    def test_service_is_weak(self):
        self.assertEqual(judged(shared_service="paste site").outcome, "allow")
        self.assertEqual(judged(shared_service="paste site", iot=True).outcome, "block")

    def test_history_is_strong_only_for_iot_outside_its_set_and_new(self):
        self.assertEqual(judged(new_to_network=False).families["history"], "none")   # the network knows it
        self.assertEqual(judged().families["history"], "weak")                        # new to the network
        strong = judged(iot=True, iot_outside_set=True, new_to_network=True)
        self.assertEqual((strong.families["history"], strong.outcome), ("strong", "hold"))
        # an IoT device outside its set, on a destination the network has used: established, so allowed
        established = judged(iot=True, iot_outside_set=True, new_to_network=False)
        self.assertEqual(established.outcome, "allow")
        self.assertIn("novelty_days", established.reasons[0])


class FamilyRuleTests(unittest.TestCase):
    def test_only_the_five_families_exist(self):
        self.assertEqual(V.FAMILIES, ("name", "age", "list", "history", "service"))

    def test_evidence_has_no_fingerprint_companion_or_idle_fields(self):
        names = {f.name for f in dataclasses.fields(V.Evidence)}
        for banned in ("ja4", "tls", "fingerprint", "companion", "idle", "last_seen", "sni"):
            self.assertFalse(any(banned in n for n in names), banned)

    def test_two_different_families_block(self):
        v = judged(dga=0.997, young_days=2)
        self.assertEqual((v.outcome, v.score), ("block", 2))
        self.assertFalse(v.proof)

    def test_same_family_signals_do_not_count_twice(self):
        # a random name, a rare TLD and a lookalike are all the name family: one family, a hold
        v = judged(dga=0.997, rare_tld=True, lookalike=True)
        self.assertEqual((v.outcome, v.score), ("hold", 1))

    def test_weak_families_do_not_add_up_for_a_normal_device(self):
        self.assertEqual(judged(dga=0.97, young_days=20).outcome, "allow")
        iot = judged(dga=0.97, young_days=20, iot=True)            # name, age and history, all weak
        self.assertEqual((iot.outcome, iot.score), ("block", 3))   # IoT counts weak families


class GuardTests(unittest.TestCase):
    def test_guards_allow_whatever_the_evidence(self):
        risky = dict(dga=0.997, young_days=2)
        for guard in ("local_name", "trusted", "known_to_device", "popular", "no_connection"):
            self.assertEqual(judged(**{guard: True}, **risky).outcome, "allow", guard)

    def test_popular_site_is_allowed_even_on_an_exact_list_hit(self):
        self.assertEqual(judged(popular=True, list_hit="exact", list_name="x.example").outcome, "allow")

    def test_established_destination_only_an_exact_list_hit_can_act(self):
        self.assertEqual(judged(new_to_network=False, dga=0.997, young_days=2).outcome, "allow")
        self.assertEqual(judged(new_to_network=False, list_hit="exact", list_name="bad.example").outcome, "block")

    def test_missing_feed_or_newly_registered_list_still_judges(self):
        # no feed hit, no list age: the other families decide alone
        self.assertEqual(judged(list_hit="", young_days=None, dga=0.997).outcome, "hold")
        self.assertEqual(judged(list_hit="", young_days=None).outcome, "allow")


class ThresholdAndTextTests(unittest.TestCase):
    def test_thresholds_come_from_the_arguments(self):
        lower = V.Thresholds(recommend_dga=0.5, corroborated_dga=0.8, block_dga=0.9, young_days=7)
        self.assertEqual(V.judge(ev(dga=0.95), lower).families["name"], "strong")
        self.assertEqual(judged(dga=0.97).families["name"], "weak")
        self.assertEqual(V.judge(ev(dga=0.97), lower).families["name"], "strong")

    def test_reasons_are_plain_and_have_no_dashes(self):
        cases = [judged(dga=0.997, young_days=2), judged(list_hit="exact", list_name="bad.example"),
                 judged(popular=True), judged(new_to_network=False, dga=0.997)]
        for v in cases:
            for r in v.reasons:
                self.assertNotIn("—", r)
                self.assertNotIn("–", r)
        self.assertTrue(judged(dga=0.997).line.startswith("dry-run verdict: would hold: "))
        self.assertTrue(judged(list_hit="exact", list_name="bad.example").line.startswith("dry-run verdict: would block: "))


# -- the wiring ------------------------------------------------------------------------------

FIXED = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
LAPTOP, CAM = "192.168.1.30", "192.168.1.40"
DEVICES = [{"name": "cam-1", "ip": CAM, "mac": "aa:bb:cc:dd:ee:40", "profile": "iot"},
           {"name": "laptop", "ip": LAPTOP, "mac": "aa:bb:cc:dd:ee:30"}]


def iso(days_ago):
    return (FIXED - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Scores:
    """Random-looking score for names that contain a made-up marker; ordinary otherwise."""
    TABLE = {"xkqzvwpt": 0.997}

    def score_one(self, domain):
        v = next((s for k, s in self.TABLE.items() if k in domain), 0.01)
        return {"dga": v, "dga_trm": v, "dga_lr": v}


class FakeNrd:
    """The newly registered list, with two made-up young domains."""
    YOUNG = {"young-site.example": 2, "other-site.example": 3}

    def match(self, host, now=0.0):
        for name, days in self.YOUNG.items():
            if host == name or host.endswith("." + name):
                return days, name
        return None


class Stack:
    """A whole ghost-dns decision path on its own state, with a fixed clock."""

    def __init__(self, verdict, d, **extra):
        feed = os.path.join(d, "threat_feed.txt")
        with open(feed, "w", encoding="utf-8") as f:
            f.write("bad-host.example\n")
        popular = os.path.join(d, "popular.txt")
        with open(popular, "w", encoding="utf-8") as f:
            f.write("popular-site.example\n")
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(d, "s.json"), "events_path": os.path.join(d, "e.jsonl"),
            "query_log": None, "resolved_ips_path": None, "threat_feed_path": feed,
            "popular_path": popular, "allowlist_path": os.path.join(HERE, "allowlist.txt"),
            "pi_ip": "192.168.1.2", "shadow": False, "learning": False, "nrd_mode": "alert",
            "verdict": verdict, **extra})
        self.state = GhostState(self.cfg["state_path"], learning_default=False)
        self.state.clock = lambda: FIXED
        self.r = Resolver(self.cfg, self.state, Scores(), Enforcer(NullBackend()),
                          DeviceMap.from_json(DEVICES), EventLog(self.cfg["events_path"]))
        self.r.clock = lambda: 1000.0
        self.r.det.wait_loaded(10)
        self.r.det.nrd = FakeNrd()
        # the IoT camera learned one cloud name a long time ago; the network has used it for a month
        self.state.iot_observe("cam-1", "api.cam-cloud.example", 7)
        self.state.iot["cam-1"]["since"] = iso(8)
        self.state.set_first_seen("api.cam-cloud.example", iso(30))

    def decide(self, host, ip=LAPTOP):
        return self.r.decide(ip, host, "A")

    def events(self):
        try:
            with open(self.cfg["events_path"], encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            return []


# One lookup sequence for every wiring test: laptop first, then the camera.
LAPTOP_SEQ = ["www.popular-site.example", "xkqzvwpt.example", "bad-host.example", "shop.young-site.example",
              "xkqzvwpt2.other-site.example", "news.quiet.example", "www.popular-site.example",
              "xkqzvwpt.example"]
CAM_SEQ = ["api.cam-cloud.example", "c2.cloud-x.example"]


def run_sequence(stack):
    out = []
    for h in LAPTOP_SEQ:
        d = stack.decide(h, LAPTOP)
        out.append((h, d.action, d.reason))
    for h in CAM_SEQ:
        d = stack.decide(h, CAM)
        out.append((h, d.action, d.reason))
    return out


class ConfigTests(unittest.TestCase):
    def test_default_is_off(self):
        self.assertEqual(config_mod.load_config(None, {})["verdict"], "off")

    def test_dry_run_and_off_are_accepted(self):
        for mode in ("off", "dry-run"):
            self.assertEqual(config_mod.load_config(None, {"verdict": mode})["verdict"], mode)

    def test_on_is_refused_as_not_built(self):
        with self.assertRaises(ValueError) as cm:
            config_mod.load_config(None, {"verdict": "on"})
        self.assertIn("not built yet", str(cm.exception))

    def test_other_values_are_refused(self):
        for bad in ("maybe", "Dry-Run", True, 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                config_mod.load_config(None, {"verdict": bad})


class OffTests(unittest.TestCase):
    def test_off_writes_no_device_memory_and_no_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            s = Stack("off", d)
            run_sequence(s)
            self.assertEqual(s.state.device_seen, {})
            self.assertEqual({k: s.r.stats[k] for k in ("verdict_allow", "verdict_hold", "verdict_block",
                                                       "verdict_errors")}, dict.fromkeys(
                ("verdict_allow", "verdict_hold", "verdict_block", "verdict_errors"), 0))
            for e in s.events():
                self.assertNotIn("would_hold", e)
                self.assertNotIn("would_block_verdict", e)


class DryRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = [tempfile.TemporaryDirectory(), tempfile.TemporaryDirectory()]
        self.off = Stack("off", self.tmp[0].name)
        self.dry = Stack("dry-run", self.tmp[1].name)
        self.off_out = run_sequence(self.off)
        self.dry_out = run_sequence(self.dry)

    def tearDown(self):
        for t in self.tmp:
            t.cleanup()

    def test_dry_run_never_changes_a_decision(self):
        self.assertEqual(self.dry_out, self.off_out)

    def test_dry_run_writes_the_same_events(self):
        def core(evts):
            return [(e["device"], e["domain"], e["rule"], e["action"]) for e in evts]
        self.assertEqual(core(self.dry.events()), core(self.off.events()))
        self.assertEqual(len(self.dry.events()), len(self.off.events()))

    def test_dry_run_marks_the_events_it_would_have_acted_on(self):
        marks = {(e["rule"], e["domain"]): ("hold" if e.get("would_hold") else
                                            "block" if e.get("would_block_verdict") else None)
                 for e in self.dry.events()}
        self.assertEqual(marks[("dga_high", "xkqzvwpt.example")], "hold")          # a block the verdict holds
        self.assertEqual(marks[("threat_feed", "bad-host.example")], "block")
        self.assertEqual(marks[("new_domain", "shop.young-site.example")], "hold")
        self.assertEqual(marks[("dga_high", "xkqzvwpt2.other-site.example")], "block")
        self.assertEqual(marks[("iot_new_domain", "c2.cloud-x.example")], "hold")

    def test_the_reason_line_is_on_the_marked_event(self):
        evt = next(e for e in self.dry.events() if e["domain"] == "bad-host.example")
        self.assertTrue(evt["would_block_verdict"] is True)
        self.assertTrue(any(r.startswith("dry-run verdict: would block: ") for r in evt["reasons"]))
        self.assertNotIn("would_hold", evt)

    def test_marked_events_pass_the_validator(self):
        for e in self.dry.events():
            self.assertEqual(validate_events.validate_event(e), [], e)

    def test_stats_count_the_judged_lookups(self):
        s = self.dry.r.stats
        # first sightings per device: 6 names for the laptop, 2 for the camera (its learned name included)
        self.assertEqual(s["verdict_allow"] + s["verdict_hold"] + s["verdict_block"], 8)
        self.assertEqual((s["verdict_allow"], s["verdict_hold"], s["verdict_block"]), (3, 3, 2))
        self.assertEqual(s["verdict_errors"], 0)
        self.assertEqual(self.off.r.stats["verdict_allow"], 0)

    def test_a_crash_inside_the_verdict_is_swallowed(self):
        with tempfile.TemporaryDirectory() as d:
            s = Stack("dry-run", d)
            with mock.patch.object(s.r, "_verdict_evidence", side_effect=RuntimeError("boom")):
                out = run_sequence(s)
            self.assertEqual(out, self.off_out)
            self.assertEqual(s.r.stats["verdict_errors"], 8)
            self.assertEqual(s.r.stats["verdict_hold"] + s.r.stats["verdict_block"] + s.r.stats["verdict_allow"], 0)

    def test_a_crash_in_the_hook_is_swallowed_too(self):
        with tempfile.TemporaryDirectory() as d:
            s = Stack("dry-run", d)
            s.r.on_verdict = mock.Mock(side_effect=RuntimeError("hook"))
            self.assertEqual(run_sequence(s), self.off_out)
            self.assertEqual(s.r.stats["verdict_errors"], 8)


class DeviceMemoryTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "s.json")
        self.state = GhostState(self.path, learning_default=False)
        self.state.clock = lambda: FIXED

    def test_a_domain_is_new_once_per_device(self):
        self.assertTrue(self.state.device_observe("laptop", "www.site.example"))
        self.assertFalse(self.state.device_observe("laptop", "cdn.site.example"))   # same registrable domain
        self.assertTrue(self.state.device_observe("tv", "www.site.example"))         # another device

    def test_memory_is_bounded_per_device(self):
        with mock.patch.object(state_mod, "_MAX_SEEN_PER_DEVICE", 3):
            for i in range(4):
                self.state.device_observe("laptop", f"n{i}.example")
            self.assertEqual(len(self.state.device_seen["laptop"]), 3)
            self.assertTrue(self.state.device_observe("laptop", "n0.example"))   # the oldest was forgotten

    def test_memory_is_bounded_in_devices(self):
        with mock.patch.object(state_mod, "_MAX_SEEN_DEVICES", 1):
            self.assertTrue(self.state.device_observe("laptop", "a.example"))
            self.assertFalse(self.state.device_observe("tv", "a.example"))

    def test_memory_is_persisted_and_hashed(self):
        self.state.device_observe("laptop", "www.site.example")
        self.state.save()
        with open(self.path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("site.example", raw)
        again = GhostState(self.path, learning_default=False)
        self.assertFalse(again.device_observe("laptop", "www.site.example"))

    def test_iot_status_reads_without_learning(self):
        self.assertEqual(self.state.iot_status("cam-1", "x.example", 7), "learning")
        self.assertEqual(self.state.iot, {})                # nothing was learned by the read
        self.state.iot_observe("cam-1", "api.cloud.example", 7)
        self.assertEqual(self.state.iot_status("cam-1", "api.cloud.example", 7), "learning")
        self.state.iot["cam-1"]["since"] = iso(8)
        self.assertEqual(self.state.iot_status("cam-1", "api.cloud.example", 7), "known")
        self.assertEqual(self.state.iot_status("cam-1", "other.example", 7), "new")
        self.assertEqual(self.state.iot_count("cam-1"), 1)  # the read added nothing


class ReplaySummaryTests(unittest.TestCase):
    def test_summary_gives_counts_and_holds_per_device_per_day(self):
        vcount = Counter({"allow": 5, "hold": 4, "block": 1})
        holds = Counter({("laptop", "2026-11-01"): 3, ("tv", "2026-11-02"): 1})
        buf = io.StringIO()
        with redirect_stdout(buf):
            replay_querylog.print_verdict_summary(vcount, holds, 2.0)
        text = buf.getvalue()
        self.assertIn("10 lookups judged", text)
        self.assertIn("allow 5, hold 4, block 1", text)
        self.assertIn("laptop", text)
        self.assertIn("2.00 per day", text)      # 4 holds over 2 days
        self.assertIn("all devices", text)

    def test_summary_without_holds(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            replay_querylog.print_verdict_summary(Counter(), Counter(), 0.0)
        self.assertIn("no holds", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
