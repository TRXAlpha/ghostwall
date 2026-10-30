"""Control API contract smoke test: a fake /status on 127.0.0.1:5380.

Run with a stub control server on 5380 to prove ControlClient speaks the
control API contract end to end.
"""
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from control_client import ControlClient, ControlError


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        responses = {
            "/status": {"ok": True, "lockdown": False, "learning": True,
                        "devices": [{"name": "laptop", "ip": "192.168.1.10",
                                     "mac": "aa:bb:cc:dd:ee:ff", "isolated": False,
                                     "blocked_domains": ["bad.example"]}]},
            "/device": {"ok": True, "name": body.get("name"), "ip": "192.168.1.10",
                        "mac": "aa:bb:cc:dd:ee:ff", "isolated": False,
                        "blocked_domains": [], "last_seen": "2026-10-20T21:00:00Z"},
            "/isolate": {"ok": True, "name": body.get("name"), "isolated": True},
            "/release": {"ok": True, "name": body.get("name"), "isolated": False},
            "/allow": {"ok": True, "domain": body.get("domain"), "allowed": True},
            "/lockdown": {"ok": True, "lockdown": True},
            "/learning": {"ok": True, "learning": body.get("enabled")},
            "/unblock": {"ok": True, "event_id": body.get("event_id"),
                         "unblocked": True},
            "/nope": (None, None),
        }
        if self.path == "/nope":
            self.send_response(404)
            data = b'{"ok": false, "error": "unknown device"}'
        else:
            self.send_response(200)
            data = json.dumps(responses.get(self.path, {"ok": True})).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST


class ControlClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.httpd = httpd
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        cls.client = ControlClient(f"http://127.0.0.1:{httpd.server_address[1]}")

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_all_endpoints(self):
        import threading
        from http.server import ThreadingHTTPServer
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        c = ControlClient(f"http://127.0.0.1:{port}")
        try:
            s = c.status()
            self.assertTrue(s["ok"])
            self.assertEqual(s["devices"][0]["name"], "laptop")
            d = c.device("laptop")
            self.assertEqual(d["ip"], "192.168.1.10")
            self.assertTrue(c.isolate("laptop")["isolated"])
            self.assertFalse(c.release("laptop")["isolated"])
            self.assertTrue(c.allow("example.com")["allowed"])
            self.assertTrue(c.lockdown()["lockdown"])
            self.assertTrue(c.learning(True)["learning"])
            self.assertTrue(c.unblock("evt_1", "x.biz")["unblocked"])
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
