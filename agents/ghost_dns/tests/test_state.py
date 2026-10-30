"""Tests for state.py"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from state import GhostState


class StateTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "state.json")

    def _fresh(self):
        return GhostState(self.path)

    def test_allow_block_roundtrip(self):
        s = self._fresh()
        s.add_block("bad.example")
        self.assertTrue(s.is_blocked("bad.example"))
        s.allow("bad.example")
        self.assertFalse(s.is_blocked("bad.example"))
        self.assertTrue(s.is_allowed("bad.example"))

    def test_allow_matches_registrable(self):
        s = self._fresh()
        s.allow("example.com")
        self.assertTrue(s.is_allowed("www.example.com"))

    def test_persistence(self):
        s = self._fresh()
        s.add_block("bad.example")
        s.isolate("dell")
        s.set_learning(False)
        s.set_lockdown(True)
        s2 = GhostState(self.path)
        self.assertTrue(s2.is_blocked("bad.example"))
        self.assertTrue(s2.is_isolated("dell"))
        self.assertFalse(s2.learning)
        self.assertTrue(s2.lockdown)

    def test_novelty(self):
        s = self._fresh()
        self.assertTrue(s.note_seen("new.example"))      # first time
        self.assertFalse(s.note_seen("new.example"))     # second time
        self.assertTrue(s.is_new("new.example", 7))

    def test_note_seen_persists_across_restart(self):
        # first_seen must survive a restart (e.g. the Day-7 enforcement flip),
        # else every domain looks new again and the learning window is lost.
        s = self._fresh()
        s.note_seen("fresh.example")
        s.flush()
        s2 = GhostState(self.path)
        self.assertIn("fresh.example", s2.first_seen)
        self.assertFalse(s2.note_seen("fresh.example"))  # already known on reload

    def test_confirm_block_promotion(self):
        s = self._fresh()
        self.assertFalse(s.confirm_block("c2.example", threshold=3))
        self.assertFalse(s.confirm_block("c2.example", threshold=3))
        self.assertTrue(s.confirm_block("c2.example", threshold=3))
        self.assertTrue(s.is_blocked("c2.example"))

    def test_isolate_release(self):
        s = self._fresh()
        s.isolate("dell")
        self.assertTrue(s.is_isolated("dell"))
        s.release("dell")
        self.assertFalse(s.is_isolated("dell"))

    def test_record_and_lookup_event(self):
        s = self._fresh()
        s.record_event({"event_id": "evt_1", "domain": "x.example",
                        "device": "dell", "ip": "192.168.1.30", "time": "t"})
        self.assertEqual(s.event("evt_1")["domain"], "x.example")
        self.assertIsNone(s.event("missing"))

    def test_load_allowlist_file(self):
        p = os.path.join(self.dir, "allow.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("# comment\nexample.com\n\nfoo.net\n")
        s = self._fresh()
        s.load_allowlist_file(p)
        self.assertTrue(s.is_allowed("example.com"))
        self.assertTrue(s.is_allowed("foo.net"))


if __name__ == "__main__":
    unittest.main()
