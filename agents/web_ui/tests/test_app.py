"""Tests for web_ui/app.py: action validation, password and same-origin checks (loopback only)."""
import base64, contextlib, http.client, io, os, sys, tempfile, threading, unittest
from http.server import ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app


class Server:
    """The dashboard on a free loopback port; the control API is deliberately unreachable."""

    def __init__(self, password=None):
        self.events = os.path.join(tempfile.mkdtemp(), "events.jsonl")
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.make_handler("http://127.0.0.1:9", self.events, password))
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def req(self, method, path, host=None, auth=None, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if auth is not None:
            h["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        r.read()
        c.close()
        return r

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class AccessTests(unittest.TestCase):
    def test_no_password_accepts_ip_hosts_only(self):
        s = Server()
        self.addCleanup(s.close)
        self.assertEqual(s.req("GET", "/").status, 200)
        self.assertEqual(s.req("GET", "/", host=f"localhost:{s.port}").status, 200)
        self.assertEqual(s.req("GET", "/api/events", host="rebind.example:8088").status, 403)

    def test_password_required_when_set(self):
        s = Server(password="hunter22")
        self.addCleanup(s.close)
        r = s.req("GET", "/")
        self.assertEqual(r.status, 401)
        self.assertIn("Basic", r.getheader("WWW-Authenticate"))
        self.assertEqual(s.req("GET", "/", auth="ghostwall:wrong").status, 401)
        self.assertEqual(s.req("GET", "/", auth="ghostwall:hunter22").status, 200)
        self.assertEqual(s.req("GET", "/", host="ghostpi.local:8088", auth="ghostwall:hunter22").status, 200)

    def test_actions_need_json_from_same_origin(self):
        s = Server()
        self.addCleanup(s.close)
        bad = b'{"action": "nope"}'
        cross = s.req("POST", "/api/action", body=bad,
                      headers={"Content-Type": "application/json", "Origin": "http://evil.example"})
        self.assertEqual(cross.status, 403)
        form = s.req("POST", "/api/action", body=bad, headers={"Content-Type": "text/plain"})
        self.assertEqual(form.status, 403)
        same = s.req("POST", "/api/action", body=bad,
                     headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{s.port}"})
        self.assertEqual(same.status, 400)  # reached validation: unknown action

    def test_refuses_lan_bind_without_password(self):
        os.environ.pop("GHOSTWALL_WEB_PASSWORD", None)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(app.main(["--bind", "0.0.0.0", "--port", "0"]), 2)
        self.assertIn("without a password", err.getvalue())

    def test_password_header_parsing(self):
        self.assertFalse(app.password_ok(None, "x"))
        self.assertFalse(app.password_ok("Basic !!!", "x"))
        self.assertTrue(app.password_ok("Basic " + base64.b64encode(b"any:x").decode(), "x"))
        self.assertEqual(app.host_name("[::1]:8088"), "::1")


class ValidateTests(unittest.TestCase):
    def test_allow_normalises_domain(self):
        path, body = app.validate_action({"action": "allow", "params": {"domain": " FBSBX.com. "}})
        self.assertEqual((path, body), ("/allow", {"domain": "fbsbx.com"}))

    def test_rejects_bad_domain(self):
        with self.assertRaises(ValueError):
            app.validate_action({"action": "allow", "params": {"domain": "a b;rm -rf"}})

    def test_rejects_unknown_action(self):
        with self.assertRaises(ValueError):
            app.validate_action({"action": "shutdown", "params": {}})

    def test_device_name_validated(self):
        path, body = app.validate_action({"action": "isolate", "params": {"name": "bambu-a1mini"}})
        self.assertEqual(path, "/isolate")
        with self.assertRaises(ValueError):
            app.validate_action({"action": "isolate", "params": {"name": "x; drop"}})

    def test_drops_unexpected_keys(self):
        _, body = app.validate_action({"action": "learning", "params": {"enabled": 1, "evil": "x"}})
        self.assertEqual(body, {"enabled": True})

if __name__ == "__main__":
    unittest.main()
