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
        _, body = app.validate_action({"action": "learning", "params": {"enabled": True, "evil": "x"}})
        self.assertEqual(body, {"enabled": True})

    def test_learning_needs_a_boolean(self):
        for params in ({}, {"enabled": 1}, {"enabled": "off"}):
            with self.assertRaises(ValueError):
                app.validate_action({"action": "learning", "params": params})

if __name__ == "__main__":
    unittest.main()


class HardeningTests(unittest.TestCase):
    def test_page_has_csp_matching_its_script(self):
        import hashlib, re
        page, csp = app.page_and_csp()
        script = re.search(rb"<script>(.*?)</script>", page, re.S).group(1)
        h = base64.b64encode(hashlib.sha256(script).digest()).decode()
        self.assertIn(f"'sha256-{h}'", csp)
        self.assertNotIn("unsafe-inline' ;", csp)
        self.assertIn("script-src 'sha256-", csp)
        s = Server()
        try:
            r = s.req("GET", "/")
            self.assertEqual(r.status, 200)
            self.assertEqual(r.getheader("Content-Security-Policy"), csp)
        finally:
            s.close()

    def test_password_guessing_is_limited_per_client(self):
        t = [0.0]
        lim = app.FailLimiter(limit=3, window=60, clock=lambda: t[0])
        for _ in range(3):
            self.assertFalse(lim.blocked("10.0.0.5"))
            lim.fail("10.0.0.5")
        self.assertTrue(lim.blocked("10.0.0.5"))
        self.assertFalse(lim.blocked("10.0.0.6"))
        t[0] = 61.0
        self.assertFalse(lim.blocked("10.0.0.5"))

    def test_wrong_passwords_get_429(self):
        s = Server(password="right")
        try:
            codes = [s.req("GET", "/api/status", auth="ghostwall:wrong").status for _ in range(11)]
            self.assertEqual(codes[:10], [401] * 10)
            self.assertEqual(codes[10], 429)
        finally:
            s.close()


class ControlTokenTests(unittest.TestCase):
    """The dashboard forwards actions with ghost-dns's control token."""

    def test_token_is_sent(self):
        import json
        from http.server import BaseHTTPRequestHandler
        seen = []

        class Ctl(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                seen.append(self.headers.get("Authorization"))
                ok = self.headers.get("Authorization") == "Bearer tok123"
                body = json.dumps({"ok": ok, "error": None if ok else "token"}).encode()
                self.send_response(200 if ok else 401)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        ctl = ThreadingHTTPServer(("127.0.0.1", 0), Ctl)
        threading.Thread(target=ctl.serve_forever, daemon=True).start()
        d = tempfile.mkdtemp()
        tok = os.path.join(d, "control_token")
        with open(tok, "w") as f:
            f.write("tok123\n")
        srv = ThreadingHTTPServer(("127.0.0.1", 0), app.make_handler(
            f"http://127.0.0.1:{ctl.server_address[1]}", os.path.join(d, "e.jsonl"), None, tok))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/api/action", body=json.dumps({"action": "learning", "params": {"enabled": True}}),
                      headers={"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"})
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 200)
            self.assertEqual(seen, ["Bearer tok123"])
        finally:
            srv.shutdown(); ctl.shutdown()


@unittest.skipUnless(__import__("shutil").which("openssl"), "needs the openssl command")
class TlsTests(unittest.TestCase):
    """HTTPS on the dashboard port, and plain HTTP there redirected to it."""

    @classmethod
    def setUpClass(cls):
        import subprocess
        d = tempfile.mkdtemp()
        cls.cert, cls.key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=localhost", "-keyout", cls.key, "-out", cls.cert],
                       check=True, capture_output=True)
        cls.srv = app.DashboardServer(("127.0.0.1", 0), app.make_handler(
            "http://127.0.0.1:9", os.path.join(d, "events.jsonl"), "pw"))
        cls.srv.tls = app.tls_context(cls.cert, cls.key)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_https_works_and_still_needs_the_password(self):
        import ssl
        ctx = ssl.create_default_context(cafile=self.cert)
        ctx.check_hostname = False
        c = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=5, context=ctx)
        c.request("GET", "/api/status")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 401)
        c.close()

    def test_plain_http_is_redirected(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/api/events?limit=5", headers={"Host": f"gw.example:{self.port}"})
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 301)
        self.assertEqual(r.getheader("Location"), f"https://gw.example:{self.port}/api/events?limit=5")
        c.close()

    def test_garbage_host_is_not_reflected(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.putrequest("GET", "/", skip_host=True)
        c.putheader("Host", "evil.example/\\r\\nX: y")
        c.endheaders()
        r = c.getresponse()
        r.read()
        self.assertEqual(r.getheader("Location"), "https://localhost/")
        c.close()
