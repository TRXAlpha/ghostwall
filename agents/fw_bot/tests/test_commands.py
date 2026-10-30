"""Tests for commands.py against a stubbed ControlClient."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import commands
from commands import handle_command, parse_command
from control_client import ControlClient, ControlError


class StubClient(ControlClient):
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def _record(self, name, *a):
        if self.fail:
            raise ControlError("boom", status=500)
        self.calls.append((name,) + a)
        return self._respond(name, *a)

    def _respond(self, name, *a):
        return {}

    def status(self):
        return self._record("status") or {
            "ok": True, "lockdown": False, "learning": True,
            "devices": [
                {"name": "laptop", "ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff",
                 "isolated": False, "blocked_domains": ["bad.example"]},
            ],
        }

    def device(self, name):
        self.calls.append(("device", name))
        if self.fail:
            raise ControlError("unknown device", status=404)
        return {"ok": True, "name": name, "ip": "192.168.1.10",
                "mac": "aa:bb:cc:dd:ee:ff", "isolated": False,
                "blocked_domains": ["bad.example"], "last_seen": "2026-10-20T21:00:00Z"}

    def isolate(self, name):
        self.calls.append(("isolate", name))
        return {"ok": True, "name": name, "isolated": True}

    def release(self, name):
        self.calls.append(("release", name))
        return {"ok": True, "name": name, "isolated": False}

    def allow(self, domain):
        self.calls.append(("allow", domain))
        return {"ok": True, "domain": domain, "allowed": True}

    def lockdown(self):
        self.calls.append(("lockdown",))
        return {"ok": True, "lockdown": True}

    def learning(self, enabled):
        self.calls.append(("learning", enabled))
        return {"ok": True, "learning": enabled}


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.c = StubClient()

    def test_parse(self):
        self.assertEqual(parse_command("/fw status"), ("status", []))
        self.assertEqual(parse_command("/fw device laptop"), ("device", ["laptop"]))
        self.assertEqual(parse_command("/fw@ghost learning off"), ("learning", ["off"]))
        self.assertEqual(parse_command("/fw"), ("status", []))
        self.assertEqual(parse_command("/start"), ("", []))
        self.assertEqual(parse_command("hello"), ("", []))

    def test_status(self):
        out = handle_command("/fw status", self.c)
        self.assertIn("lockdown: off", out)
        self.assertIn("learning: on", out)
        self.assertIn("- laptop (192.168.1.10)", out)
        self.assertIn("bad.example", out)

    def test_device(self):
        out = handle_command("/fw device laptop", self.c)
        self.assertIn("ip: 192.168.1.10", out)
        self.assertIn("isolated: no", out)
        self.assertEqual(handle_command("/fw device", self.c), "usage: /fw device <name>")

    def test_isolate_release_allow(self):
        self.assertEqual(handle_command("/fw isolate laptop", self.c), "laptop isolated.")
        self.assertEqual(handle_command("/fw release laptop", self.c), "laptop released.")
        self.assertEqual(handle_command("/fw allow example.com", self.c),
                         "example.com added to allowlist.")
        self.assertIn(("isolate", "laptop"), self.c.calls)

    def test_lockdown_learning(self):
        self.assertEqual(handle_command("/fw lockdown", self.c), "Lockdown ON.")
        self.assertEqual(handle_command("/fw learning on", self.c), "Learning mode on.")
        self.assertEqual(handle_command("/fw learning off", self.c), "Learning mode off.")
        self.assertIn("usage", handle_command("/fw learning", self.c))

    def test_unknown_and_error(self):
        self.assertIn("unknown subcommand", handle_command("/fw bogus", self.c))
        c = StubClient(fail=True)
        out = handle_command("/fw status", c)
        self.assertTrue(out.startswith("fw error:"))
        out = handle_command("/fw device nope", c)
        self.assertTrue(out.startswith("fw error:"))

    def test_non_fw_returns_empty(self):
        self.assertEqual(handle_command("/start", self.c), "")


if __name__ == "__main__":
    unittest.main()
