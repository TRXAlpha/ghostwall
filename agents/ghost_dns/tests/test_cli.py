"""ghostwall CLI against a fake control API and a fake Telegram API."""
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import ghostwall_cli as cli  # noqa: E402

SEEN = []
UPDATES = []


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/status":
            self._reply({"ok": True, "shadow": True, "models": "trm+lr", "stats": {"queries": 1234},
                         "feed": {"domains": 150000, "updated": None},
                         "devices": [{"name": "laptop", "ip": "192.168.1.10", "last_seen": None}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        SEEN.append((self.path, self.headers.get("Authorization"), body))
        if self.path.startswith("/bot"):
            method = self.path.rsplit("/", 1)[1]
            if method == "getMe":
                return self._reply({"ok": True, "result": {"username": "example_gw_bot"}})
            if method == "getUpdates":
                res = [u for u in UPDATES if u["update_id"] >= body.get("offset", 0)]
                return self._reply({"ok": True, "result": res})
            return self._reply({"ok": True, "result": {}})
        if self.headers.get("Authorization") != "Bearer tok-example":
            return self._reply({"ok": False, "error": "need Authorization"}, 401)
        self._reply({"ok": True, "domain": body.get("domain"), "learning": body.get("enabled")})


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        cli.CONTROL, cli.TELEGRAM = base, base

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        SEEN.clear()
        UPDATES.clear()
        self.data, self.etc = tempfile.mkdtemp(), tempfile.mkdtemp()
        cli.DATA, cli.ETC = self.data, self.etc
        with open(os.path.join(self.data, "control_token"), "w") as f:
            f.write("tok-example\n")

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_status(self):
        code, out, _ = self.run_cli("status")
        self.assertEqual(code, 0)
        self.assertIn("1,234 queries", out)
        self.assertIn("laptop", out)

    def test_allow_sends_token_and_validates(self):
        code, out, _ = self.run_cli("allow", "Example.COM.")
        self.assertEqual(code, 0)
        self.assertEqual(SEEN[-1], ("/allow", "Bearer tok-example", {"domain": "example.com"}))
        code, _, err = self.run_cli("allow", "not a domain")
        self.assertEqual(code, 1)
        self.assertIn("not a domain", err)

    def test_learning(self):
        self.assertEqual(self.run_cli("learning", "off")[0], 0)
        self.assertEqual(SEEN[-1][2], {"enabled": False})

    def test_refused_action_is_explained(self):
        os.remove(os.path.join(self.data, "control_token"))
        code, _, err = self.run_cli("allow", "example.com")
        self.assertEqual(code, 1)
        self.assertIn("refused", err)

    def test_alerts_reads_across_rotation(self):
        with open(os.path.join(self.data, "events.jsonl.1"), "w") as f:
            f.write(json.dumps({"time": "t1", "device": "pc", "domain": "old.example", "rule": "dga_high"}) + "\n")
        with open(os.path.join(self.data, "events.jsonl"), "w") as f:
            f.write(json.dumps({"time": "t2", "device": "pc", "domain": "new.example", "rule": "doh_bypass",
                                "scores": {"dga": 0.5}, "reasons": ["why"]}) + "\n")
        code, out, _ = self.run_cli("alerts", "-n", "5")
        self.assertEqual(code, 0)
        self.assertLess(out.index("new.example"), out.index("old.example"))

    def test_telegram_setup_writes_private_files(self):
        UPDATES.extend([
            {"update_id": 5, "message": {"chat": {"id": -100, "type": "group"}, "from": {"id": 7}}},
            {"update_id": 6, "message": {"chat": {"id": 4242, "type": "private"},
                                         "from": {"id": 4242, "first_name": "Sam"}}},
        ])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.cmd_telegram(type("A", (), {"wait": 5})(), token="123456:" + "A" * 30,
                                    start_service=False, private=True)
        self.assertEqual(code, 0)
        with open(os.path.join(self.etc, "owner.json")) as f:
            self.assertEqual(json.load(f)["chat_id"], 4242)       # the private chat, not the group
        env = os.path.join(self.etc, "fw_bot.env")
        self.assertEqual(os.stat(env).st_mode & 0o777, 0o640)
        with open(env) as f:
            text = f.read()
        self.assertIn("FW_BOT_TELEGRAM_TOKEN=123456:", text)
        self.assertRegex(text, r"FW_BOT_CALLBACK_SECRET=[0-9a-f]{64}")
        self.assertIn("FW_BOT_PRIVACY=minimal", text)

    def test_bad_token_shape_refused(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(cli.CliError):
                cli.cmd_telegram(type("A", (), {"wait": 1})(), token="nope", start_service=False)


if __name__ == "__main__":
    unittest.main()


class CalibrateTests(unittest.TestCase):
    def test_calibrate_on_a_small_log(self):
        d = tempfile.mkdtemp()
        cli.ETC = d
        log = os.path.join(d, "querylog.json")
        normal = ["google.com", "netflix.com", "wikipedia.org", "github.com", "bbc.co.uk", "amazon.de",
                  "spotify.com", "reddit.com", "weather.example", "my-printer.local"]
        with open(log, "w") as f:
            for i in range(300):
                f.write(json.dumps({"QH": f"site{i}shop.example" if i % 3 else normal[i % len(normal)],
                                    "IP": "192.168.1.5", "QT": "A"}) + "\n")
            f.write(json.dumps({"QH": "xk2qv9zr7wpl3mfa.top", "IP": "192.168.1.5", "QT": "A"}) + "\n")
        r = cli.calibrate(log, None)
        self.assertGreater(r["names"], 100)
        self.assertNotIn("my-printer.local", [reg for _, reg in r["top"]])        # internal names skipped
        self.assertEqual(r["top"][0][1], "xk2qv9zr7wpl3mfa.top")                   # the odd one out first
        self.assertTrue(all(0 < t < 1 for t in r["suggest"].values()))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["calibrate", "--querylog", log, "--apply"]), 0)
        with open(os.path.join(d, "ghost_dns.json")) as f:
            self.assertIn("recommend_threshold", json.load(f))


class NameTests(unittest.TestCase):
    def setUp(self):
        self.etc = tempfile.mkdtemp()
        cli.ETC = self.etc

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_name_creates_renames_and_validates(self):
        self.assertEqual(self.run_cli("name", "192.168.1.20", "laptop")[0], 0)
        self.assertEqual(self.run_cli("name", "192.168.1.20", "work-laptop")[0], 0)   # rename
        self.assertEqual(self.run_cli("name", "192.168.1.21", "work-laptop")[0], 1)   # taken
        self.assertEqual(self.run_cli("name", "not-an-ip", "x")[0], 1)
        self.assertEqual(self.run_cli("name", "192.168.1.22", "bad name;")[0], 1)
        with open(os.path.join(self.etc, "devices.json")) as f:
            data = json.load(f)
        self.assertEqual(data["_pending"], [{"name": "work-laptop", "ip": "192.168.1.20", "mac": None,
                                             "profile": "normal"}])
        sys.path.insert(0, HERE)
        from devices import DeviceMap
        self.assertEqual(DeviceMap.from_json(data).device_for_ip("192.168.1.20").name, "work-laptop")
