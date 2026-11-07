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


class RecordingNft(NullBackend):
    """Records calls like NullBackend but reports itself as the nft backend."""

    @property
    def name(self):
        return "nft"


class ControlApiTests(unittest.TestCase):
    backend = NullBackend
    extra_cfg: dict = {}

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "state.json"),
            "control_port": 0, **self.extra_cfg,
        })
        self.state = GhostState(self.cfg["state_path"])
        self.enforcer = Enforcer(self.backend())
        self.devices = DeviceMap.from_json(
            [{"name": "workpc", "ip": "192.168.1.30", "mac": "aa:bb:cc:dd:ee:01"}])
        self.server = ControlServer(self.cfg, self.state, self.enforcer, self.devices)
        self.port = self.server.httpd.server_address[1]
        self.t = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.t.start()
        self.client = ControlClient(f"http://127.0.0.1:{self.port}")

    def tearDown(self):
        self.server.shutdown()

    def _raw(self, path, body=b"{}", headers=None, method="POST"):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method,
                                     data=None if method == "GET" else body, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_status(self):
        r = self.client.status()
        self.assertTrue(r["ok"])
        self.assertTrue(r["learning"])
        self.assertFalse(r["lockdown"])
        self.assertEqual(r["enforce"], "null")
        self.assertEqual(r["devices"][0]["name"], "workpc")
        self.assertIsNone(r["devices"][0]["last_seen"])
        self.assertIsInstance(r["stats"], dict)

    def test_device(self):
        r = self.client.device("workpc")
        self.assertEqual(r["ip"], "192.168.1.30")
        self.assertIn("last_seen", r)

    def test_unknown_device_404(self):
        with self.assertRaises(ControlError) as cm:
            self.client.device("nope")
        self.assertEqual(cm.exception.status, 404)

    def test_isolate_refused_without_enforcement(self):
        # Saying "isolated" while nothing changed would be worse than refusing.
        with self.assertRaises(ControlError) as cm:
            self.client.isolate("workpc")
        self.assertEqual(cm.exception.status, 409)
        self.assertIn("enforcement is off", str(cm.exception))
        self.assertFalse(self.state.is_isolated("workpc"))
        with self.assertRaises(ControlError) as cm:
            self.client.lockdown()
        self.assertEqual(cm.exception.status, 409)
        self.assertFalse(self.state.lockdown)

    def test_release_always_allowed(self):
        self.state.isolate("workpc")  # e.g. left by an older version
        self.assertFalse(self.client.release("workpc")["isolated"])
        self.assertFalse(self.state.is_isolated("workpc"))

    def test_allow(self):
        r = self.client.allow("example.com")
        self.assertTrue(r["allowed"])
        self.assertTrue(self.state.is_allowed("example.com"))

    def _with_iot_device(self):
        self.server.httpd.RequestHandlerClass.state["devices"] = DeviceMap.from_json(
            [{"name": "workpc", "ip": "192.168.1.30", "mac": "aa:bb:cc:dd:ee:01"},
             {"name": "cam-1", "ip": "192.168.1.40", "mac": "aa:bb:cc:dd:ee:40", "profile": "iot"}])

    def test_allow_for_one_iot_device(self):
        self._with_iot_device()
        r = self.client._call("/allow", {"domain": "api.partner.example", "device": "cam-1"})
        self.assertEqual((r["domain"], r["device"]), ("partner.example", "cam-1"))   # the family
        self.assertEqual(self.state.iot_count("cam-1"), 1)
        self.assertFalse(self.state.is_allowed("partner.example"))     # not the network-wide list
        for dev, code in (("workpc", 409), ("nobody", 404)):
            with self.assertRaises(ControlError) as cm:
                self.client._call("/allow", {"domain": "partner.example", "device": dev})
            self.assertEqual(cm.exception.status, code)

    def test_untrust_and_relearn_an_iot_device(self):
        self._with_iot_device()
        self.client._call("/allow", {"domain": "partner.example", "device": "cam-1"})
        r = self.client._call("/untrust", {"domain": "x.partner.example", "device": "cam-1"})
        self.assertEqual((r["domain"], r["device"], r["allowed"]), ("partner.example", "cam-1", False))
        with self.assertRaises(ControlError) as cm:
            self.client._call("/untrust", {"domain": "partner.example", "device": "cam-1"})
        self.assertEqual(cm.exception.status, 404)
        self.client._call("/allow", {"domain": "partner.example", "device": "cam-1"})
        self.assertTrue(self.client._call("/relearn", {"name": "cam-1"})["relearning"])
        self.assertEqual(self.state.iot_count("cam-1"), 0)
        with self.assertRaises(ControlError) as cm:
            self.client._call("/relearn", {"name": "workpc"})
        self.assertEqual(cm.exception.status, 409)

    def test_status_shows_iot_devices(self):
        self._with_iot_device()
        st = self.client.status()
        self.assertEqual(st["iot_enforce"], "off")
        by = {d["name"]: d for d in st["devices"]}
        self.assertNotIn("profile", by["workpc"])
        self.assertEqual((by["cam-1"]["profile"], by["cam-1"]["iot_domains"], by["cam-1"]["iot_learning_until"]),
                         ("iot", 0, None))
        self.state.iot_observe("cam-1", "api.cam-cloud.example", 7)
        self.state.iot["cam-1"]["since"] = "2026-11-01T10:00:00Z"
        cam = {d["name"]: d for d in self.client.status()["devices"]}["cam-1"]
        self.assertEqual((cam["iot_domains"], cam["iot_learning_until"]), (1, "2026-11-08T10:00:00Z"))

    def test_learning(self):
        self.assertFalse(self.client.learning(False)["learning"])
        self.assertFalse(self.state.learning)

    def test_learning_needs_a_boolean(self):
        # A missing or string flag must not silently turn blocking on.
        for body in ({}, {"enabled": "false"}, {"enabled": 0}):
            with self.assertRaises(ControlError) as cm:
                self.client._call("/learning", body)
            self.assertEqual(cm.exception.status, 400)
        self.assertTrue(self.state.learning)

    def test_post_must_be_json(self):
        # A cross-site form or no-cors fetch can only send text/plain or form types.
        self.assertEqual(self._raw("/allow", b'{"domain":"evil.example"}',
                                   {"Content-Type": "text/plain"}), 415)
        self.assertEqual(self._raw("/learning", b'{"enabled":false}'), 415)
        self.assertFalse(self.state.is_allowed("evil.example"))
        self.assertTrue(self.state.learning)

    def test_rebinding_host_refused(self):
        # A DNS-rebinding page reaches 127.0.0.1 but still sends its own Host.
        evil = {"Host": "rebind.evil.example:5380", "Content-Type": "application/json"}
        self.assertEqual(self._raw("/status", headers=evil, method="GET"), 403)
        self.assertEqual(self._raw("/allow", b'{"domain":"evil.example"}', evil), 403)
        self.assertFalse(self.state.is_allowed("evil.example"))
        for ok in ("127.0.0.1:5380", "localhost:5380", "[::1]:5380"):
            self.assertEqual(self._raw("/status", headers={"Host": ok}, method="GET"), 200)

    def test_unblock_by_domain(self):
        self.state.add_block("bad.example")
        r = self.client.unblock("evt_x", "bad.example")
        self.assertTrue(r["unblocked"])
        self.assertFalse(self.state.is_blocked("bad.example"))

    def test_unblock_by_event_id(self):
        self.state.add_block("c2.example")
        self.state.record_event({"event_id": "evt_1", "domain": "c2.example",
                                 "device": "workpc", "ip": "192.168.1.30", "time": "t"})
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


class EnforcingControlApiTests(ControlApiTests):
    """The same contract with enforcement on (enforce: nft)."""
    backend = RecordingNft
    extra_cfg = {"pi_ip": "192.168.1.20"}

    def test_status(self):
        self.assertEqual(self.client.status()["enforce"], "nft")

    def test_isolate_refused_without_enforcement(self):
        self.assertTrue(self.client.isolate("workpc")["isolated"])
        self.assertTrue(self.state.is_isolated("workpc"))
        self.assertTrue(any("isolated_dev" in c for c in self.enforcer.backend.calls))
        self.assertFalse(self.client.release("workpc")["isolated"])
        self.assertFalse(self.state.is_isolated("workpc"))

    def test_isolate_hits_where_the_device_is_now(self):
        # workpc's address in devices.json may belong to another device by now (DHCP); its
        # queries come from .31, so isolating "workpc" must cut off .31, not .30.
        res = type("R", (), {"current_ip": {"workpc": "192.168.1.31"}, "last_seen": {
            "192.168.1.31": "2026-11-03T10:00:00Z", "192.168.1.30": "2026-11-03T10:01:00Z"}})()
        self.server.httpd.RequestHandlerClass.state["resolver"] = res
        self.assertEqual(self.client.isolate("workpc")["ip"], "192.168.1.31")
        calls = " ".join(" ".join(c) for c in self.enforcer.backend.calls)
        self.assertIn("192.168.1.31", calls)
        self.assertNotIn("192.168.1.30", calls)
        st = self.client.status()
        self.assertEqual([(d["name"], d["ip"]) for d in st["devices"]], [("workpc", "192.168.1.31")])
        self.assertEqual([c["ip"] for c in st["clients"]], ["192.168.1.30"])   # the newcomer at .30
        self.assertFalse(self.client.release("workpc")["isolated"])

    def test_lockdown_toggles(self):
        self.assertTrue(self.client.lockdown()["lockdown"])
        self.assertTrue(self.state.lockdown)
        self.assertFalse(self.client.lockdown()["lockdown"])

    def test_lockdown_needs_pi_ip(self):
        self.cfg["pi_ip"] = None
        with self.assertRaises(ControlError) as cm:
            self.client.lockdown()
        self.assertEqual(cm.exception.status, 409)
        self.assertFalse(self.state.lockdown)




class ControlAuthTests(unittest.TestCase):
    """Actions need the token from control_token; /status does not."""

    def setUp(self):
        from control_api import ensure_token, token_path
        self.dir = tempfile.mkdtemp()
        self.cfg = config_mod.load_config(None, {
            "state_path": os.path.join(self.dir, "state.json"), "control_port": 0})
        self.tpath = token_path(self.cfg)
        self.token = ensure_token(self.tpath)
        self.server = ControlServer(self.cfg, GhostState(self.cfg["state_path"]),
                                    Enforcer(NullBackend()),
                                    DeviceMap.from_json([{"name": "workpc", "ip": "192.168.1.30"}]),
                                    token=self.token)
        self.port = self.server.httpd.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()

    def _post(self, path, body, auth=None, method="POST"):
        h = {"Content-Type": "application/json"}
        if auth:
            h["Authorization"] = auth
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method,
                                     data=None if method == "GET" else json.dumps(body).encode(),
                                     headers=h)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_token_file_is_private_and_stable(self):
        from control_api import ensure_token
        self.assertEqual(os.stat(self.tpath).st_mode & 0o777, 0o600)
        self.assertEqual(self.tpath, os.path.join(self.dir, "control_token"))
        self.assertEqual(ensure_token(self.tpath), self.token)  # restarts keep the token
        self.assertGreaterEqual(len(self.token), 40)

    def test_actions_need_the_token(self):
        for auth in (None, "Bearer wrong", "Basic " + self.token, self.token):
            self.assertEqual(self._post("/allow", {"domain": "example.com"}, auth), 401, auth)
        self.assertEqual(self._post("/allow", {"domain": "example.com"}, "Bearer " + self.token), 200)
        self.assertEqual(self._post("/learning", {"enabled": False}, None), 401)

    def test_status_stays_open(self):
        self.assertEqual(self._post("/status", {}, None, method="GET"), 200)
        self.assertEqual(self._post("/status", {}, None), 200)

    def _status_body(self, auth=None, method="GET"):
        h = {"Content-Type": "application/json"}
        if auth:
            h["Authorization"] = auth
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/status", method=method,
                                     data=None if method == "GET" else b"{}", headers=h)
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def test_status_without_the_token_names_no_device(self):
        # Any local user or process can reach this port: the household's device list
        # (names, IPs, MACs, who was online when) needs the token like any action.
        self.server.httpd.RequestHandlerClass.state["resolver"] = type("R", (), {"last_seen": {
            "192.168.1.30": "2026-11-03T10:00:00Z", "192.168.1.77": "2026-11-03T10:01:00Z"}})()
        for method in ("GET", "POST"):
            for auth in (None, "Bearer wrong"):
                st = self._status_body(auth, method)
                raw = json.dumps(st)
                self.assertTrue(st["devices_hidden"], (method, auth))
                self.assertNotIn("devices", st)
                self.assertNotIn("clients", st)
                for leak in ("workpc", "192.168.1.30", "192.168.1.77"):
                    self.assertNotIn(leak, raw, (method, auth))
                self.assertEqual((st["named_devices"], st["unnamed_clients"]), (1, 1))
                self.assertIn("stats", st)                     # health checks still work
            full = self._status_body("Bearer " + self.token, method)
            self.assertNotIn("devices_hidden", full)
            self.assertEqual([d["name"] for d in full["devices"]], ["workpc"])
            self.assertEqual([c["ip"] for c in full["clients"]], ["192.168.1.77"])

    def test_allow_rejects_non_domains(self):
        ok = "Bearer " + self.token
        for bad in ("<script>", "a b.com", "x" * 300, "..", "evil.com/path"):
            self.assertEqual(self._post("/allow", {"domain": bad}, ok), 400, bad)

    def test_token_off_with_empty_path(self):
        from control_api import token_path
        self.assertIsNone(token_path({"state_path": "/x/state.json", "control_token_path": ""}))

    def test_refuses_non_loopback_bind(self):
        cfg = dict(self.cfg, control_host="0.0.0.0")
        with self.assertRaises(ValueError):
            ControlServer(cfg, None, None, None)


class TrustListTests(ControlAuthTests):
    def test_trusted_list_and_undo(self):
        tok = "Bearer " + self.token
        g = self.server.httpd.RequestHandlerClass.state["gstate"]
        g.allowlist.add("starter.example"); g.static_allow.add("starter.example")
        self.assertEqual(self._post("/allow", {"domain": "mine.example"}, tok), 200)
        self.assertEqual(g.trusted(), ["mine.example"])                  # the starter entry isn't "yours"
        self.assertEqual(self._post("/trusted", {}, None), 401)
        self.assertEqual(self._post("/untrust", {"domain": "starter.example"}, tok), 409)
        self.assertEqual(self._post("/untrust", {"domain": "mine.example"}, tok), 200)
        self.assertFalse(g.is_allowed("mine.example"))
        self.assertEqual(self._post("/untrust", {"domain": "mine.example"}, tok), 404)


class ClientHangsUp(unittest.TestCase):
    """A client that gives up before the answer (a status poll with a short timeout)
    used to print a BrokenPipeError traceback into ghost-dns's journal."""

    def test_send_to_a_closed_client_is_quiet(self):
        import io
        from control_api import ControlHandler

        class Gone(io.RawIOBase):
            def write(self, b):
                raise BrokenPipeError(32, "Broken pipe")

        h = ControlHandler.__new__(ControlHandler)
        h.wfile, h.request_version, h.requestline, h.command = Gone(), "HTTP/1.1", "GET /status HTTP/1.1", "GET"
        h.close_connection = False
        h._send(200, {"ok": True})            # must not raise
        self.assertTrue(h.close_connection)


if __name__ == "__main__":
    unittest.main()
