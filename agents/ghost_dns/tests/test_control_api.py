"""Tests for control_api.py against the control API contract (docs/REFERENCE.md).

Driven by a small inline urllib client rather than importing fw_bot's
control_client: both fw_bot and ghost-dns ship a module named `config`, and
pulling fw_bot's client into this process would shadow one with the other.
fw_bot's client is tested on its side in fw_bot/tests/test_control_client.py;
here we check the server honours the same wire contract."""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config as config_mod
from control_api import ControlServer
from devices import DeviceMap
from enforce import Enforcer, NullBackend
from state import GhostState


class ControlError(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


class ControlClient:
    """Minimal control API client (GET /status, POST the rest)."""

    def __init__(self, base):
        self.base = base.rstrip("/")

    def _call(self, path, body=None, get=False):
        data = None if get else json.dumps(body or {}).encode()
        req = urllib.request.Request(
            self.base + path, data=data, method="GET" if get else "POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error", e.reason)
            except Exception:
                msg = e.reason
            raise ControlError(msg, status=e.code)

    def status(self):
        return self._call("/status", get=True)

    def device(self, name):
        return self._call("/device", {"name": name})

    def isolate(self, name):
        return self._call("/isolate", {"name": name})

    def release(self, name):
        return self._call("/release", {"name": name})

    def allow(self, domain):
        return self._call("/allow", {"domain": domain})

    def lockdown(self):
        return self._call("/lockdown", {})

    def learning(self, enabled):
        return self._call("/learning", {"enabled": enabled})

    def unblock(self, event_id, domain):
        return self._call("/unblock", {"event_id": event_id, "domain": domain})


class ControlApiTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "state.json"),
            "control_port": 0,
        })
        self.state = GhostState(self.cfg["state_path"])
        self.enforcer = Enforcer(NullBackend())
        self.devices = DeviceMap.from_json(
            [{"name": "dell", "ip": "192.168.1.30", "mac": "aa:bb:cc:dd:ee:01"}])
        self.server = ControlServer(self.cfg, self.state, self.enforcer, self.devices)
        self.port = self.server.httpd.server_address[1]
        self.t = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.t.start()
        self.client = ControlClient(f"http://127.0.0.1:{self.port}")

    def tearDown(self):
        self.server.shutdown()

    def test_status(self):
        r = self.client.status()
        self.assertTrue(r["ok"])
        self.assertTrue(r["learning"])
        self.assertFalse(r["lockdown"])
        self.assertEqual(r["devices"][0]["name"], "dell")
        self.assertIsInstance(r["stats"], dict)

    def test_device(self):
        r = self.client.device("dell")
        self.assertEqual(r["ip"], "192.168.1.30")

    def test_unknown_device_404(self):
        with self.assertRaises(ControlError) as cm:
            self.client.device("nope")
        self.assertEqual(cm.exception.status, 404)

    def test_isolate_release(self):
        self.assertTrue(self.client.isolate("dell")["isolated"])
        self.assertTrue(self.state.is_isolated("dell"))
        self.assertFalse(self.client.release("dell")["isolated"])
        self.assertFalse(self.state.is_isolated("dell"))
        # enforcement went through the (null) backend
        self.assertTrue(any("isolated_dev" in c for c in self.enforcer.backend.calls))

    def test_allow(self):
        r = self.client.allow("example.com")
        self.assertTrue(r["allowed"])
        self.assertTrue(self.state.is_allowed("example.com"))

    def test_lockdown_toggles(self):
        self.assertTrue(self.client.lockdown()["lockdown"])
        self.assertTrue(self.state.lockdown)
        self.assertFalse(self.client.lockdown()["lockdown"])

    def test_learning(self):
        self.assertFalse(self.client.learning(False)["learning"])
        self.assertFalse(self.state.learning)

    def test_unblock_by_domain(self):
        self.state.add_block("bad.example")
        r = self.client.unblock("evt_x", "bad.example")
        self.assertTrue(r["unblocked"])
        self.assertFalse(self.state.is_blocked("bad.example"))

    def test_unblock_by_event_id(self):
        self.state.add_block("c2.example")
        self.state.record_event({"event_id": "evt_1", "domain": "c2.example",
                                 "device": "dell", "ip": "192.168.1.30", "time": "t"})
        # client requires a domain arg; API resolves it from the event when blank
        import urllib.request, json
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/unblock",
            data=json.dumps({"event_id": "evt_1"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req) as resp:
            out = json.loads(resp.read())
        self.assertEqual(out["domain"], "c2.example")
        self.assertFalse(self.state.is_blocked("c2.example"))


if __name__ == "__main__":
    unittest.main()
