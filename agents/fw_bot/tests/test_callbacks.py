"""Tests for callbacks.py: owner-only, HMAC, control calls, labels.jsonl."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from callbacks import CallbackHandler, append_label
from config import Config
from control_client import ControlClient, ControlError
from signing import make_callback

SECRET = b"s3cret"
EVENT = {
    "time": "2026-10-20T21:04:05Z", "device": "laptop", "ip": "192.168.1.10",
    "mac": "aa:bb:cc:dd:ee:ff", "domain": "xkjqwehz.biz", "dst_ip": "203.0.113.7",
    "ja4": "t13d_abc", "scores": {"dga": 0.93}, "rule": "dga_high",
    "action": "block", "severity": "high", "event_id": "evt_01abc",
}


class StubAPI:
    def __init__(self):
        self.edits = []

    def edit_alert(self, chat_id, message_id, text, event=None, secret=None):
        self.edits.append((chat_id, message_id, text))


class StubClient(ControlClient):
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def unblock(self, event_id, domain):
        self.calls.append(("unblock", event_id, domain))
        if self.fail:
            raise ControlError("boom", status=500)
        return {"ok": True}

    def isolate(self, name):
        self.calls.append(("isolate", name))
        return {"ok": True, "name": name, "isolated": True}


def make_cfg(tmp):
    p = os.path.join(tmp, "owner.json")
    with open(p, "w") as f:
        f.write(json.dumps({"owner_chat_id": 4242}))
    return Config.load(p, env={"FW_BOT_CALLBACK_SECRET": "s3cret"},
                       labels_path=os.path.join(tmp, "labels.jsonl"))


class CallbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fwbot_cb_")
        self.cfg = make_cfg(self.tmp)
        self.api = StubAPI()
        self.client = StubClient()
        self.h = CallbackHandler(self.cfg, self.client, self.api,
                                 events_lookup={"evt_01abc": EVENT})

    def _q(self, action, user=4242, tamper=False, event_id="evt_01abc"):
        from signing import make_callback
        data = make_callback(action, event_id, SECRET)
        if tamper:
            data = data[:-1] + ("9" if data[-1] != "9" else "8")
        return {"message": {"chat": {"id": 4242}, "message_id": 10},
                "from": {"id": user}, "data": data}

    def test_owner_only(self):
        out = self.h.handle(self._q("unblock", user=999))
        self.assertTrue(out.startswith("ignored:"))
        self.assertEqual(self.client.calls, [])
        self.assertEqual(self.api.edits, [])
        self.assertFalse(os.path.exists(self.cfg.labels_path))

    def test_unblock_flow(self):
        out = self.h.handle(self._q("unblock"))
        self.assertIn("Unblocked", out)
        self.assertEqual(self.client.calls, [("unblock", "evt_01abc", "xkjqwehz.biz")])
        self.assertEqual(self.api.edits[0][0], 4242)
        self.assertEqual(self.api.edits[0][1], 10)
        self.assertIn("Unblocked xkjqwehz.biz", self.api.edits[0][2])
        # labels.jsonl
        with open(self.cfg.labels_path, encoding="utf-8") as f:
            rec = json.loads(f.read().strip())
        self.assertEqual(rec["event_id"], "evt_01abc")
        self.assertEqual(rec["action"], "unblock")
        self.assertEqual(rec["device"], "laptop")
        self.assertEqual(rec["domain"], "xkjqwehz.biz")
        self.assertEqual(rec["user"], 4242)
        self.assertIn("time", rec)

    def test_tampered_callback_rejected(self):
        out = self.h.handle(self._q("unblock", tamper=True))
        self.assertIn("ignored", out)
        self.assertEqual(self.client.calls, [])

    def test_isolate_and_keep_and_details(self):
        self.assertIn("isolated", self.h.handle(self._q("isolate")))
        self.assertIn("Kept blocked", self.h.handle(self._q("keep")))
        out = self.h.handle(self._q("details"))
        self.assertIn("dga=0.93", out)
        self.assertIn("ja4: t13d_abc", out)
        with open(self.cfg.labels_path, encoding="utf-8") as f:
            recs = [json.loads(l) for l in f if l.strip()]
        self.assertEqual([r["action"] for r in recs],
                         ["isolate", "keep", "details"])

    def test_control_error_shows_failure(self):
        self.client.fail = True
        out = self.h.handle(self._q("unblock"))
        self.assertIn("FAILED", out)
        with open(self.cfg.labels_path, encoding="utf-8") as f:
            recs = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["action"], "unblock")

    def test_multiple_presses_appended(self):
        self.h.handle(self._q("unblock"))
        self.h.handle(self._q("keep"))
        self.h.handle(self._q("unblock", user=4242))
        with open(self.cfg.labels_path, encoding="utf-8") as f:
            recs = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(recs), 3)
        self.assertEqual([r["action"] for r in recs], ["unblock", "keep", "unblock"])


if __name__ == "__main__":
    unittest.main()
