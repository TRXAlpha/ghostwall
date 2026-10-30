"""End-to-end tests: FwBot against fake Telegram server + fake control API."""
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fake_telegram import FakeTelegram
from fw_bot import FwBot
from signing import make_callback

SECRET = "s3cret"
EVENT = {
    "time": "2026-10-20T21:04:05Z", "device": "laptop", "domain": "xkjqwehz.biz",
    "dst_ip": "203.0.113.7", "rule": "dga_high", "action": "block",
    "severity": "high", "event_id": "evt_01abc", "reasons": ["dga score 0.93"],
    "capture": "pcap", "ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff",
}


class FakeControlHandler(BaseHTTPRequestHandler):
    routes = {}  # class attr set per-test

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.requests.append((self.path, body))
        handler = self.server.routes.get(self.path)
        if handler:
            status, resp = handler(body)
        else:
            status, resp = 200, {"ok": True}
        data = json.dumps(resp).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST


class FakeControl:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []

        class H(FakeControlHandler):
            pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.routes = routes
        self.server.requests = self.requests
        FakeControlHandler.routes = routes
        self.port = self.server.server_address[1]

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"


def make_bot(tmp, tg):
    p = os.path.join(tmp, "owner.json")
    with open(p, "w") as f:
        f.write(json.dumps({"owner_chat_id": 4242}))
    from config import Config
    cfg = Config.load(
        p, env={"FW_BOT_CALLBACK_SECRET": SECRET},
        labels_path=os.path.join(tmp, "labels.jsonl"),
        digest_path=os.path.join(tmp, "digest.jsonl"),
        telegram_api=tg.base, telegram_token="TESTTOKEN",
    )
    cfg.control_base = os.environ.get("FW_TEST_CONTROL_BASE", cfg.control_base)
    return FwBot(cfg)


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fwbot_e2e_")
        self.tg = FakeTelegram()
        self.control = FakeControl({
            "/status": lambda b: (200, {"ok": True, "lockdown": False,
                                        "learning": True,
                                        "devices": [{"name": "laptop", "ip": "192.168.1.10",
                                                     "isolated": False}]}),
            "/unblock": lambda b: (200, {"ok": True, "event_id": b.get("event_id"),
                                         "unblocked": True}),
        })
        self.tg.start()
        self.control.start()
        self.bot = make_bot(self.tmp, self.tg)
        self.bot.cfg.control_base = self.control.base
        self.bot.client = type(self.bot.client)(self.control.base)
        self.bot.callbacks.client = self.bot.client

    def tearDown(self):
        self.tg.stop()
        self.control.server.server_close()

    def test_owner_only_and_command(self):
        # non-owner command ignored
        r = self.bot.process_update({"message": {"chat": {"id": 7},
                                                 "from": {"id": 7},
                                                 "text": "/fw status"}})
        self.assertTrue(r.startswith("ignored"))
        # owner command hits the fake control API
        r = self.bot.process_update({"message": {"chat": {"id": 4242},
                                                 "from": {"id": 4242},
                                                 "text": "/fw status"}})
        self.assertIn("laptop", r)
        self.assertEqual(self.control.requests[-1][0], "/status")

    def test_alert_send_and_callback_unblock(self):
        action = self.bot.feed_event(dict(EVENT), chat_id=4242)
        self.assertEqual(action, "sent")
        self.assertEqual(len(self.tg.sent), 1)
        payload = self.tg.sent[0]
        self.assertTrue(payload["text"].startswith("BLOCKED · laptop"))
        kb = payload["reply_markup"]["inline_keyboard"][0]
        self.assertEqual(len(kb), 4)
        # owner presses Unblock via a delivered update
        cb_data = kb[0]["callback_data"]
        upd = {"callback_query": {"message": {"chat": {"id": 4242},
                                              "message_id": self.bot.grouper.groups[
                                                  ("laptop", "dga_high", "high")].message_id},
                                  "from": {"id": 4242}, "data": cb_data}}
        r = self.bot.process_update(upd)
        self.assertIn("Unblocked", r)
        self.assertEqual(self.control.requests[-1], ("/unblock",
                        {"event_id": "evt_01abc", "domain": "xkjqwehz.biz"}))
        self.assertEqual(len(self.tg.edits), 1)
        with open(self.bot.cfg.labels_path, encoding="utf-8") as f:
            rec = json.loads(f.read().strip())
        self.assertEqual((rec["action"], rec["user"]), ("unblock", 4242))

    def test_tampered_callback_ignored(self):
        self.bot.feed_event(dict(EVENT), chat_id=4242)
        kb = self.tg.sent[0]["reply_markup"]["inline_keyboard"][0]
        bad = kb[0]["callback_data"][:-1] + ("9" if kb[0]["callback_data"][-1] != "9" else "8")
        upd = {"callback_query": {"message": {"chat": {"id": 4242},
                                              "message_id": self.bot.grouper.groups[
                                                  ("laptop", "dga_high", "high")].message_id},
                                  "from": {"id": 4242}, "data": bad}}
        r = self.bot.process_update(upd)
        self.assertIn("ignored", r)
        self.assertEqual(self.tg.edits, [])

    def test_grouping_and_rate_limit(self):
        self.bot.feed_event(dict(EVENT), chat_id=4242)
        self.bot.feed_event(dict(EVENT, event_id="evt_02"), chat_id=4242)
        self.assertEqual(len(self.tg.sent), 1)  # collapsed, not a second message
        # window expiry -> new message
        self.bot.grouper.window = 0.0
        self.bot.feed_event(dict(EVENT, event_id="evt_03"), chat_id=4242)
        self.assertEqual(len(self.tg.sent), 2)

    def test_info_digest(self):
        r = self.bot.feed_event(dict(EVENT, severity="info", event_id="evt_i"))
        self.assertEqual(r, "digest")
        self.assertEqual(len(self.tg.sent), 0)
        out = self.bot.write_digest()
        self.assertIn("digest", out)
        with open(self.bot.cfg.digest_path, encoding="utf-8") as f:
            self.assertTrue(f.read().strip())


if __name__ == "__main__":
    unittest.main()
