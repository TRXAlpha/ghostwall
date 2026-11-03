"""Alerts must survive Telegram failing for a while (outages, a Pi losing Wi-Fi, the owner
not having pressed Start yet) and the bot restarting, and errors must be said (without
the bot token) instead of swallowed."""
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import alerts  # noqa: E402
import fw_bot  # noqa: E402
from fake_telegram import FakeTelegram  # noqa: E402
from test_e2e import make_bot  # noqa: E402


def evt(i, device="laptop", when="2026-11-03T10:00:00Z"):
    return {"time": when, "device": device, "domain": f"d{i}.example.com",
            "rule": "dga_high", "action": "recommend", "severity": "high", "event_id": f"evt_{i}"}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.tg = FakeTelegram()
        self.tg.start()
        self.bot = make_bot(self.tmp, self.tg)
        self.events = os.path.join(self.tmp, "events.jsonl")
        self.state = os.path.join(self.tmp, "fw_bot_follow.json")
        open(self.events, "w").close()
        self.err = io.StringIO()
        self.quiet = contextlib.ExitStack()
        self.quiet.enter_context(contextlib.redirect_stderr(self.err))
        self.quiet.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def tearDown(self):
        self.quiet.close()
        self.tg.stop()

    def append(self, *evts):
        with open(self.events, "a") as f:
            for e in evts:
                f.write(json.dumps(e) + "\n")

    def sent_domains(self):
        return [m["text"].split("\n")[1] for m in self.tg.sent]

    def follower(self, **kw):
        kw.setdefault("max_backoff", 0)
        return fw_bot.Follower(self.bot, self.events, 4242, **kw)

    def test_alert_survives_a_failed_send(self):
        fo = self.follower()
        self.tg.fail_sends = 2                       # Telegram down for a moment
        self.append(evt(1, "laptop"), evt(2, "phone"))
        for _ in range(4):
            fo.poll()
        self.assertEqual(self.sent_domains(), ["d1.example.com", "d2.example.com"])  # in order
        self.assertNotIn("TESTTOKEN", self.err.getvalue())
        self.assertIn("Telegram unreachable", self.err.getvalue())
        self.assertIn("answers again", self.err.getvalue())

    def test_retry_waits_and_backs_off(self):
        clock = Clock()
        fo = self.follower(clock=clock, max_backoff=60)
        self.tg.fail_sends = 3
        self.append(evt(1))
        fo.poll()                                    # fails: wait 1 s
        tries = lambda: sum(1 for m, _ in self.tg.requests if m == "sendMessage")  # noqa: E731
        self.assertEqual(tries(), 1)
        fo.poll()
        self.assertEqual(tries(), 1)                 # still waiting: Telegram is not hammered
        clock.t += 1.1
        fo.poll()                                    # fails again: wait 2 s
        clock.t += 1.1
        fo.poll()
        self.assertEqual(tries(), 2)
        clock.t += 1.0
        fo.poll()                                    # fails a third time
        clock.t += 4.1
        fo.poll()
        self.assertEqual(self.sent_domains(), ["d1.example.com"])
        self.assertEqual(self.err.getvalue().count("Telegram unreachable"), 1)   # said once

    def test_owner_who_never_pressed_start_is_told_how_to_fix_it(self):
        self.tg.fail_status, self.tg.fail_sends = 403, 1
        fo = self.follower()
        self.append(evt(1))
        fo.poll()
        self.assertIn("press Start", self.err.getvalue())
        fo.poll()                                    # after Start: the kept alert goes out
        self.assertEqual(self.sent_domains(), ["d1.example.com"])

    def test_a_message_telegram_refuses_is_skipped_not_blocking(self):
        self.tg.fail_status, self.tg.fail_sends = 400, 1
        fo = self.follower()
        self.append(evt(1), evt(2, "phone"))
        fo.poll()
        self.assertEqual(self.sent_domains(), ["d2.example.com"])

    def test_restart_sends_what_was_written_while_stopped(self):
        fo = self.follower(state_path=self.state)
        self.append(evt(1))
        fo.poll()
        self.tg.fail_sends = 1
        self.append(evt(2, "tv"))
        fo.poll()                                    # Telegram fails, then the bot stops
        self.append(evt(3, "phone"))                 # written while the bot is down
        self.bot.grouper.groups.clear()              # (a new process remembers no groups)
        fo2 = self.follower(state_path=self.state)
        fo2.poll()
        self.assertEqual(self.sent_domains(), ["d1.example.com", "d2.example.com", "d3.example.com"])

    def test_restart_across_a_rotation(self):
        fo = self.follower(state_path=self.state)
        self.append(evt(1))
        fo.poll()
        self.append(evt(2, "tv"))                    # unsent when the bot stops...
        os.replace(self.events, self.events + ".1")  # ...ghost-dns rotates...
        self.append(evt(3, "phone"))                 # ...and keeps writing
        fo2 = self.follower(state_path=self.state)
        fo2.poll()
        self.assertEqual(self.sent_domains(), ["d1.example.com", "d2.example.com", "d3.example.com"])

    def test_rotation_waits_for_the_old_file_while_telegram_is_down(self):
        fo = self.follower()
        self.append(evt(1))
        self.tg.fail_sends = 1
        os.replace(self.events, self.events + ".1")
        self.append(evt(2, "phone"))
        fo.poll()                                    # evt 1 (old file) fails
        fo.poll()
        self.assertEqual(self.sent_domains(), ["d1.example.com", "d2.example.com"])

    def test_first_start_does_not_replay_history(self):
        self.append(evt(1))
        self.follower(state_path=self.state).poll()
        self.assertEqual(self.tg.sent, [])
        self.follower(state_path=self.state).poll()   # nor does the second
        self.assertEqual(self.tg.sent, [])

    def test_late_alert_says_when_it_happened(self):
        fo = self.follower()
        old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.append(evt(1, when=old), evt(2, "phone", when=now))
        fo.poll()
        self.assertIn("(sent late)", self.tg.sent[0]["text"])
        self.assertNotIn("sent late", self.tg.sent[1]["text"])

    def test_follow_never_dies(self):
        self.tg.fail_sends = 10 ** 6                 # Telegram unreachable for good
        self.append(evt(3))
        with mock.patch.object(fw_bot.Follower, "poll", side_effect=[OSError("disk"), 0, 0]):
            fw_bot.follow(self.bot, self.events, 4242, poll_seconds=0.01, max_loops=3)  # must not raise
        self.assertIn("can't read", self.err.getvalue())
        self.assertIn("again", self.err.getvalue())
        fw_bot.follow(self.bot, self.events, 4242, poll_seconds=0.01, max_loops=3)
        self.assertEqual(self.tg.sent, [])

    def test_bad_token_is_said_out_loud(self):
        self.tg.fail_status, self.tg.fail_updates = 401, 3
        fw_bot.poll_updates(self.bot.cfg, lambda u: None, max_polls=3, max_backoff=0.01)
        out = self.err.getvalue()
        self.assertIn("rejected the bot token", out)
        self.assertNotIn("TESTTOKEN", out)
        self.assertEqual(out.count("401"), 1)        # said once, not once per retry

    def test_errors_never_carry_the_token(self):
        api = alerts.TelegramAPI("htps://bad-scheme.invalid", "123:SECRETTOKEN")
        with self.assertRaises(alerts.TelegramError) as cm:
            api._call("sendMessage", {})
        self.assertNotIn("SECRETTOKEN", str(cm.exception))
        self.assertIsNone(cm.exception.__cause__)
        self.assertTrue(cm.exception.__suppress_context__)


class KindTests(unittest.TestCase):
    def test_kinds(self):
        k = lambda s, d="": alerts.TelegramError("sendMessage", s, d).kind  # noqa: E731
        self.assertEqual(k(None), "network")
        self.assertEqual(k(502), "network")
        self.assertEqual(k(429), "rate")
        self.assertEqual(k(401), "token")
        self.assertEqual(k(403, "Forbidden: bot can't initiate conversation with a user"), "chat")
        self.assertEqual(k(400, "Bad Request: chat not found"), "chat")
        self.assertEqual(k(409), "conflict")
        self.assertEqual(k(400, "Bad Request: message is too long"), "message")


if __name__ == "__main__":
    unittest.main()
