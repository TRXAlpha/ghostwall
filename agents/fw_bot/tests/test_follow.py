"""Tests for send-only follow mode (no Telegram polling)."""
import json, os, sys, tempfile, unittest
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import fw_bot


class FakeBot:
    def __init__(self):
        self.calls = []

    def feed_event(self, evt, chat_id=None):
        self.calls.append((evt["event_id"], chat_id))
        return "sent"


def evt(i):
    return {"time": "2026-10-26T10:00:00Z", "device": "dell", "domain": f"d{i}.example.com",
            "rule": "dga_high", "action": "recommend", "severity": "high", "event_id": f"evt_{i}"}


class FollowTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "events.jsonl")
        with open(self.path, "w"):
            pass
        self.bot = FakeBot()

    def _append(self, *objs, raw=""):
        with open(self.path, "a", encoding="utf-8") as f:
            for o in objs:
                f.write(json.dumps(o) + "\n")
            f.write(raw)

    def test_history_before_start_is_not_replayed(self):
        self._append(evt(1))
        fo = fw_bot.Follower(self.bot, self.path, 42)
        self.assertEqual(fo.poll(), 0)
        self.assertEqual(self.bot.calls, [])

    def test_new_lines_sent_once(self):
        fo = fw_bot.Follower(self.bot, self.path, 42)
        self._append(evt(2), evt(3))
        self.assertEqual(fo.poll(), 2)
        self.assertEqual(fo.poll(), 0)  # nothing new: not resent
        self.assertEqual(self.bot.calls, [("evt_2", 42), ("evt_3", 42)])

    def test_partial_line_waits_for_newline(self):
        fo = fw_bot.Follower(self.bot, self.path, 42)
        full = json.dumps(evt(9))
        self._append(raw=full[:20])
        self.assertEqual(fo.poll(), 0)
        self._append(raw=full[20:] + "\n")
        self.assertEqual(fo.poll(), 1)
        self.assertEqual(self.bot.calls, [("evt_9", 42)])

    def test_truncation_restarts_from_top(self):
        fo = fw_bot.Follower(self.bot, self.path, 42)
        self._append(evt(1), evt(2))
        fo.poll()
        with open(self.path, "w"):
            pass  # rotated
        self._append(evt(5))
        fo.poll()
        self.assertEqual(self.bot.calls[-1], ("evt_5", 42))

    def test_skips_garbage_lines(self):
        fo = fw_bot.Follower(self.bot, self.path, 42)
        self._append(raw="not json\n")
        self._append(evt(8))
        self.assertEqual(fo.poll(), 1)
        self.assertEqual(self.bot.calls, [("evt_8", 42)])


class FakeCfg:
    def is_owner(self, chat_id):
        return chat_id == 42


class FakeDispatcher:
    def text(self, text):
        return "reply:" + text

    def callback(self, query):
        return "cb:" + query["data"]


class CommandRouterTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.r = fw_bot.CommandRouter(FakeCfg(), FakeDispatcher(), lambda c, t: self.sent.append((c, t)))

    def msg(self, chat_id, text):
        return {"update_id": 1, "message": {"chat": {"id": chat_id}, "text": text}}

    def test_owner_command_gets_reply(self):
        self.assertEqual(self.r.handle(self.msg(42, "/fw log 5")), "replied")
        self.assertEqual(self.sent, [(42, "reply:/fw log 5")])

    def test_stranger_is_ignored(self):
        self.assertEqual(self.r.handle(self.msg(7, "/fw isolate dell")), "ignored: not owner")
        self.assertEqual(self.sent, [])

    def test_non_command_is_ignored(self):
        self.assertEqual(self.r.handle(self.msg(42, "hello")), "ignored: not a command")
        self.assertEqual(self.sent, [])

    def test_buttons_go_to_dispatcher(self):
        self.assertEqual(self.r.handle({"callback_query": {"data": "x"}}), "cb:x")


if __name__ == "__main__":
    unittest.main()
