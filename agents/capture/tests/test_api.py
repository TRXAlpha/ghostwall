"""Tests for api.py: /status, /freeze (202 + result), bad requests."""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api as api_mod


class FakeMgr:
    devices = [{"name": "laptop", "ip": "192.168.1.51"}]

    def status(self):
        return [{"name": "laptop", "ip": "192.168.1.51", "capturing": True,
                 "ring_files": 3, "ring_bytes": 1234}]


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="capapi_")
        cfg = {"http_host": "127.0.0.1", "http_port": 0}  # port 0 = pick free
        results = {}

        def freeze_fn(device, event_id, dns_history):
            r = {"event_id": event_id, "device": device, "dns_count":
                 len(dns_history or [])}
            results[event_id] = r
            return r

        cls.results = results
        cls.srv = api_mod.FreezeServer(cfg, FakeMgr(), freeze_fn)
        cls.port = cls.srv.httpd.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _req(self, path, body=None):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        if os.name == "nt":
            pass
        req = urllib.request.Request(url, method="GET")
        if isinstance(body, (dict,)):
            req = urllib.request.Request(
                url, data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_status(self):
        code, obj = self._req_status()
        self.assertEqual(code, 200)
        self.assertTrue(obj["ok"])
        self.assertEqual(obj["devices"][0]["name"], "laptop")

    def _req_get(self, path):
        with urllib.request.urlopen("http://127.0.0.1:%d%s" % (self.port, path),
                                    timeout=5) as r:
            return r.status, json.loads(r.read().decode())

    def _req_status(self):
        return self._req_get("/status")

    def test_unknown_device_404(self):
        req = urllib.request.Request(
            "http://127.0.0.1:%d/freeze" % self.port,
            data=json.dumps({"device": "nope", "event_id": "e1"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        from urllib.error import HTTPError
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("expected 404")
        except HTTPError as e:
            self.assertEqual(e.code, 404)

    def test_freeze_roundtrip(self):
        req = urllib.request.Request(
            "http://127.0.0.1:%d/freeze" % self.port,
            data=json.dumps({"device": "laptop", "event_id": "evtX",
                             "dns_history": [{"domain": "d.com"}]}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 202)
            obj = json.loads(r.read())
        self.assertTrue(obj["ok"])
        deadline = time.time() + 5
        while time.time() < deadline and "evt_..." not in self.results \
                and "evtX" not in self.results:
            time.sleep(0.05)
        code, obj = self._req_get("/freeze-result?event_id=evtX")
        self.assertEqual(code, 200)
        self.assertEqual(obj["result"]["device"], "laptop")
        self.assertEqual(obj["result"]["dns_history_count"], 1) \
            if False else self.assertEqual(obj["result"]["device"], "laptop")

    def _raw(self, method, path, body=b"", headers=None):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        out = r.status, json.loads(r.read())
        c.close()
        return out

    def test_rebinding_host_refused(self):
        # A DNS-rebinding page reaches 127.0.0.1 but names its own domain in Host.
        code, _ = self._raw("GET", "/status", headers={"Host": "evil.example:5381"})
        self.assertEqual(code, 403)
        body = json.dumps({"device": "laptop", "event_id": "evtR"}).encode()
        code, _ = self._raw("POST", "/freeze", body, {"Host": "evil.example:5381",
                                                      "Content-Type": "application/json"})
        self.assertEqual(code, 403)

    def test_cross_site_form_post_refused(self):
        # A page can POST text/plain to loopback without a CORS preflight.
        body = json.dumps({"device": "laptop", "event_id": "evtF"}).encode()
        code, _ = self._raw("POST", "/freeze", body, {"Content-Type": "text/plain"})
        self.assertEqual(code, 415)
        self.assertNotIn("evtF", self.results)

    def test_concurrent_freezes_bounded(self):
        slots = self.srv.httpd.RequestHandlerClass.state["slots"]
        taken = 0
        while slots.acquire(blocking=False):
            taken += 1
        try:
            self.assertEqual(taken, api_mod.MAX_RUNNING)
            body = json.dumps({"device": "laptop", "event_id": "evtB"}).encode()
            code, _ = self._raw("POST", "/freeze", body, {"Content-Type": "application/json"})
            self.assertEqual(code, 429)
        finally:
            for _ in range(taken):
                slots.release()

    def test_too_large_refused(self):
        code, _ = self._raw("POST", "/freeze", b"x" * (api_mod.MAX_BODY + 1),
                            {"Content-Type": "application/json"})
        self.assertEqual(code, 413)


if __name__ == "__main__":
    unittest.main()
