"""Tests for events.py -- validated against the fw_bot events validator."""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(os.path.dirname(HERE), "fw_bot"))  # validate_events only
import events as E
import validate_events as V


class EventsTests(unittest.TestCase):
    def test_make_event_is_schema_valid(self):
        evt = E.make_event(device="dell", ip="192.168.1.30",
                           mac="aa:bb:cc:dd:ee:01", domain="bad.example",
                           rule="dga_high", action="block", severity="high",
                           scores={"dga": 0.97}, reasons=["dga score 0.97"])
        self.assertEqual(V.validate_event(evt), [])

    def test_flow_pseudo_domain_valid(self):
        evt = E.make_event(device="dell", domain="raw-ip.flow.ghostwall",
                           dst_ip="185.199.108.153", rule="raw_ip",
                           action="recommend", severity="warn")
        self.assertEqual(V.validate_event(evt), [])

    def test_event_id_format(self):
        self.assertRegex(E.new_event_id(), E.EVENT_ID_RE)

    def test_bad_event_id_rejected(self):
        with self.assertRaises(ValueError):
            E.make_event(device="d", domain="a.example", rule="r",
                         action="allow", event_id="not a valid id!")

    def test_invalid_action(self):
        with self.assertRaises(ValueError):
            E.make_event(device="d", domain="a.example", rule="r", action="nuke")

    def test_invalid_severity(self):
        with self.assertRaises(ValueError):
            E.make_event(device="d", domain="a.example", rule="r",
                         action="allow", severity="meh")

    def test_scores_rounded_and_in_range(self):
        evt = E.make_event(device="d", domain="a.example", rule="r",
                           action="recommend", scores={"dga": 0.123456})
        self.assertEqual(evt["scores"]["dga"], 0.1235)

    def test_eventlog_appends(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "events.jsonl")
        log = E.EventLog(path)
        log.write(E.make_event(device="d", domain="a.example", rule="r",
                               action="allow"))
        log.write(E.make_event(device="d", domain="b.example", rule="r",
                               action="allow"))
        with open(path, encoding="utf-8") as f:
            self.assertEqual(len(f.read().strip().splitlines()), 2)
        # and every line validates
        self.assertEqual(V.main(["validate_events.py", path]), 0)


if __name__ == "__main__":
    unittest.main()
