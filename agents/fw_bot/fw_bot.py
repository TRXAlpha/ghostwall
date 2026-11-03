"""fw_bot.py: wires config, control client, alerts, grouping, commands,
callbacks into a Telegram update loop. Stdlib only.

Usage (ghostwall-fw-bot.service runs it this way; docs/OPERATIONS.md#telegram):
    FW_BOT_TELEGRAM_TOKEN=... FW_BOT_CALLBACK_SECRET=... python fw_bot.py \
        --owner-file /etc/ghostwall/owner.json --follow /var/lib/ghostwall/events.jsonl [--commands]
"""
from __future__ import annotations

import json
import os
import sys
import time

import alerts
import commands
import config as cfgmod
from callbacks import CallbackHandler
from config import Config, ConfigError
from control_client import ControlClient
from grouping import AlertGrouper


class FwBot:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.client = ControlClient(cfg.control_base)
        self.api = alerts.TelegramAPI(cfg.telegram_api, cfg.telegram_token)
        self.grouper = AlertGrouper(cfg.group_window_minutes)
        self.callbacks = CallbackHandler(cfg, self.client, self.api)
        self.events_by_id: dict[str, dict] = {}
        self._digest_lines: list[str] = []

    # ---- incoming Telegram updates ------------------------------------
    def process_update(self, update: dict) -> str:
        """Handle one Telegram update. Returns a short action marker."""
        if "callback_query" in update:
            return self.callbacks.handle(update["callback_query"])
        msg = update.get("message") or {}
        text = msg.get("text", "")
        if not self.cfg.is_owner_message(msg):
            return "ignored: not owner"
        if not text.startswith("/fw"):
            return "ignored: not a command"
        return commands.handle_command(text, self.client)

    # ---- alert ingestion (events.jsonl feed) ---------------------------
    def feed_event(self, event: dict, chat_id: int | None = None) -> str:
        """Route one event: group / rate-limit / digest. Returns action taken."""
        kind, payload = self.grouper.feed(event)
        if kind == "digest":
            self._digest_buffer(
                f"{payload.get('time')} {payload.get('device')} "
                f"{payload.get('domain')} {payload.get('rule')}")
            return "digest"
        grp = payload
        self.events_by_id[grp.event["event_id"]] = grp.event
        self.callbacks.events = self.events_by_id
        if kind == "new":
            if chat_id is None:
                return "new (no chat_id; not sent)"
            try:
                grp.message_id = self.api.send_alert(chat_id, grp.event, self.cfg.secret, now=time.time())
            except Exception:
                # Not delivered: forget the group, so the retry is a new alert again and
                # not a counter update on a message that was never sent.
                if self.grouper.groups.get(grp.key) is grp:
                    del self.grouper.groups[grp.key]
                raise
            return "sent"
        # update: refresh counter on the existing message (best effort: the alert itself
        # went out, so a failed edit must not hold up the alerts behind it)
        if grp.message_id is not None and chat_id is not None:
            try:
                self.api.edit_alert(
                    chat_id, grp.message_id,
                    alerts.group_text(alerts.format_alert(grp.event), grp.count),
                    event=grp.event, secret=self.cfg.secret,
                )
            except alerts.TelegramError as exc:
                return f"updated (x{grp.count}; counter not refreshed: {exc})"
        return "updated"

    def _digest(self, event: dict) -> None:
        line = f"{event.get('time')} {event.get('device')} {event.get('domain')} {event.get('rule')}"
        self._digest_buffer(line)

    # -- daily digest buffer (info severity only) ------------------------
    _DIGEST_HEADER = "daily digest\n===========\n"

    def _digest_buffer(self, line: str) -> list[str]:
        """Append an info-severity line to the in-memory digest buffer."""
        self._digest_lines.append(line)
        return self._digest_lines

    def write_digest(self) -> str:
        """Flush digest buffer to a JSONL file; returns the path written."""
        import json
        with open(self.cfg.digest_path, "a", encoding="utf-8") as f:
            for line in self._digest_lines:
                f.write(json.dumps({"line": line}) + "\n")
        n = len(self._digest_lines)
        self._digest_lines.clear()
        return f"{n} digest entries written to {self.cfg.digest_path}"

    # ---- polling loop (long polling) -----------------------------------
    def run(self, max_polls: int | None = None) -> None:
        poll_updates(self.cfg, lambda upd: self.process_update(update=upd), max_polls=max_polls)


class Problems:
    """Says each distinct problem once instead of once per retry, and says when it
    clears. Never prints the bot token."""

    def __init__(self, token: str = ""):
        self.token = token
        self.current: str | None = None   # the key of the problem last said

    def redact(self, msg: str) -> str:
        return msg.replace(self.token, "<token>") if self.token else msg

    def say(self, msg: str) -> None:
        print(self.redact(msg), file=sys.stderr, flush=True)

    def report(self, msg: str, key: str | None = None) -> None:
        """key: what counts as "the same problem" (default: the message itself), so an
        outage whose error text keeps changing is still said once."""
        if (key or msg) != self.current:
            self.say(msg)
            self.current = key or msg

    def clear(self, msg: str) -> None:
        if self.current is not None:
            self.say(msg)
            self.current = None


def explain(err: "alerts.TelegramError", chat_id: int | None = None) -> str:
    """What a TelegramError means for the owner, and what fixes it."""
    kind = err.kind
    if kind == "token":
        return (f"[fw_bot] Telegram rejected the bot token (HTTP {err.status}). Check "
                "FW_BOT_TELEGRAM_TOKEN in /etc/ghostwall/fw_bot.env (or run: sudo ghostwall "
                "telegram), then: sudo systemctl restart ghostwall-fw-bot")
    if kind == "chat":
        return (f"[fw_bot] Telegram won't let the bot write to chat {chat_id} (HTTP {err.status}: "
                f"{err.description}). Open your bot in Telegram and press Start (a bot can't write "
                "first), and check chat_id in /etc/ghostwall/owner.json. Alerts are kept until then.")
    if kind == "conflict":
        return ("[fw_bot] Telegram says another process polls this bot token (HTTP 409), so /fw "
                "commands and buttons may go there. Stop the other bot, or remove --commands from "
                "ghostwall-fw-bot (docs/OPERATIONS.md, 'Already running a bot').")
    if kind == "rate":
        return f"[fw_bot] Telegram asks to slow down (HTTP 429); waiting {err.retry_after or '?'}s"
    return f"[fw_bot] Telegram unreachable ({err}); retrying, alerts are kept until it answers"


def _backoff(prev: float, err: "alerts.TelegramError | None", cap: float) -> float:
    """Seconds to wait before the next try: doubling from 1 up to cap, or what a 429 asks."""
    if err is not None and err.kind == "rate" and err.retry_after:
        return min(float(err.retry_after), 3600.0)
    return min(max(prev * 2, 1.0), cap)


def _inode(path: str) -> int:
    try:
        return os.stat(path).st_ino
    except FileNotFoundError:
        return -1


class Follower:
    """Send-only tail of events.jsonl. Each alert is sent once, in order, and the position
    moves past a line only once Telegram took it: while Telegram is down (or refuses the
    token or the chat) the alert waits and is retried with a growing pause, so nothing is
    lost. Telegram refusing one particular message skips just that one.

    With state_path, the position survives restarts (also across a rotation while the
    bot was down), so alerts written while the bot was stopped are sent when it starts.
    Without a saved position it starts at the current end: history is never replayed."""

    def __init__(self, bot: "FwBot", events_path: str, chat_id: int, state_path: str | None = None,
                 clock=time.monotonic, max_backoff: float = 60.0):
        self.bot = bot
        self.path = events_path
        self.chat_id = chat_id
        self.state_path = state_path
        self.clock = clock
        self.max_backoff = max_backoff
        self.backoff = 0.0
        self.retry_at = 0.0
        self.held: dict | None = None   # the alert waiting for Telegram
        self.problems = Problems(getattr(getattr(bot, "cfg", None), "telegram_token", "") or "")
        self.offset = os.path.getsize(events_path) if os.path.exists(events_path) else 0
        self.inode = _inode(events_path)
        self._resume()

    # -- position across restarts ------------------------------------------
    def _resume(self) -> None:
        if not self.state_path:
            return
        try:
            with open(self.state_path, encoding="utf-8") as f:
                saved = json.load(f)
            ino, off = int(saved["inode"]), max(0, int(saved["offset"]))
        except FileNotFoundError:
            self._save()   # first start: remember "from here on"
            return
        except (OSError, ValueError, KeyError, TypeError):
            return
        end = self.offset
        if ino == -1:
            self.offset = 0                    # the file appeared while the bot was stopped
        elif ino == self.inode:
            self.offset = off if off <= end else 0   # (smaller now: it was emptied and refilled)
        elif _inode(self.path + ".1") == ino:
            self.inode, self.offset = ino, off       # rotated while stopped: poll() drains .1 first
        else:
            print("[fw_bot] events.jsonl was replaced more than once while the bot was stopped; "
                  "alerts from that time are on the dashboard, not sent", file=sys.stderr, flush=True)
            return
        if self.inode != _inode(self.path) or self.offset < end:
            print("[fw_bot] sending the alerts written while the bot was stopped", flush=True)

    def _save(self) -> None:
        if not self.state_path:
            return
        tmp = self.state_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"inode": self.inode, "offset": self.offset}, f)
            os.replace(tmp, self.state_path)
        except OSError as exc:
            print(f"[fw_bot] can't save the alert position to {self.state_path} ({exc}); "
                  "alerts written while the bot is stopped will not be sent",
                  file=sys.stderr, flush=True)
            self.state_path = None

    # -- tail ----------------------------------------------------------------
    def poll(self) -> int:
        """Send what is new. Returns how many alerts went out (or were handled)."""
        if self.clock() < self.retry_at:
            return 0   # Telegram failed a moment ago: wait out the pause
        start = (self.inode, self.offset)
        sent = 0
        try:
            if not os.path.exists(self.path):
                return sent
            ino = _inode(self.path)
            if ino != self.inode:
                # ghost-dns rotated the log: finish what was added to the old file first
                if self.inode != -1 and _inode(self.path + ".1") == self.inode:
                    n, done = self._read(self.path + ".1")
                    sent += n
                    if not done:
                        return sent   # Telegram failed half-way: the old file stays first
                self.inode, self.offset = ino, 0
            elif os.path.getsize(self.path) < self.offset:
                self.offset = 0  # file was truncated
            sent += self._read(self.path)[0]
            return sent
        finally:
            if (self.inode, self.offset) != start:
                self._save()

    def _read(self, path: str) -> tuple[int, bool]:
        """Send the complete lines after self.offset. Returns (handled, reached_end); stops
        early, without moving past the line, when Telegram can't take it right now."""
        sent = 0
        with open(path, "rb") as f:
            f.seek(self.offset)
            for raw in f:
                if not raw.endswith(b"\n"):
                    break  # partial line: retry on the next pass
                line = raw.decode("utf-8", "replace").strip()
                try:
                    evt = json.loads(line) if line else None
                except ValueError:
                    evt = None
                if not isinstance(evt, dict):
                    self.offset += len(raw)   # blank or garbage: nothing to send
                    continue
                try:
                    result = self.bot.feed_event(evt, chat_id=self.chat_id)
                except alerts.TelegramError as exc:
                    if exc.kind != "message":
                        self._hold(evt, exc)
                        return sent, False
                    result = f"refused by Telegram, skipped ({exc})"
                except Exception as exc:  # noqa: BLE001 (a bad event or a bug: skip that one line)
                    result = f"skipped, could not be sent ({type(exc).__name__}: {exc})"
                self.offset += len(raw)
                if self.held is not None:
                    self.problems.clear("[fw_bot] Telegram answers again; sending the alerts that waited")
                    self.held, self.backoff, self.retry_at = None, 0.0, 0.0
                print(self.problems.redact(
                    f"[fw_bot] {result}: {evt.get('event_id')} {evt.get('domain')} "
                    f"{evt.get('rule')}/{evt.get('action')}"), flush=True)
                sent += 1
        return sent, True

    def _hold(self, evt: dict, exc: "alerts.TelegramError") -> None:
        self.held = evt
        self.backoff = _backoff(self.backoff, exc, self.max_backoff)
        self.retry_at = self.clock() + self.backoff
        self.problems.report(explain(exc, self.chat_id), key=exc.kind)


def follow(bot: "FwBot", events_path: str, chat_id: int, poll_seconds: float = 1.0,
           max_loops: int | None = None, state_path: str | None = None) -> None:
    """Run a Follower forever (or max_loops passes). Never calls getUpdates, so it
    can share a bot token with another process that polls it, without a 409. Never
    raises: in --commands mode it is a background thread, and a dead one would leave the
    bot answering commands while sending no alerts."""
    f = Follower(bot, events_path, chat_id, state_path=state_path)
    reading = Problems(f.problems.token)
    loops = 0
    while max_loops is None or loops < max_loops:
        loops += 1
        try:
            f.poll()
            reading.clear(f"[fw_bot] reading {events_path} again")
        except Exception as exc:  # noqa: BLE001 (e.g. events.jsonl unreadable for a moment)
            reading.report(f"[fw_bot] can't read {events_path}: {type(exc).__name__}: {exc}; retrying")
        time.sleep(poll_seconds)


class CommandRouter:
    """Standalone command handling (--follow --commands): owner /fw messages and
    alert buttons go through the dispatcher, and text replies are sent back.
    Use it only when no other process polls the same bot token."""

    def __init__(self, cfg: Config, dispatcher, send):
        self.cfg, self.dispatcher, self.send = cfg, dispatcher, send

    def handle(self, update: dict) -> str:
        if "callback_query" in update:
            return self.dispatcher.callback(update["callback_query"])
        msg = update.get("message") or {}
        chat_id = (msg.get("chat") or {}).get("id")
        text = msg.get("text", "")
        if not self.cfg.is_owner_message(msg):
            return "ignored: not owner"
        if not text.startswith("/fw"):
            return "ignored: not a command"
        self.send(chat_id, self.dispatcher.text(text))
        return "replied"


def poll_updates(cfg: Config, handle, max_polls: int | None = None, max_backoff: float = 60.0) -> None:
    """Long-poll getUpdates forever (or max_polls times) and pass each update to handle().
    A failure is said once (what it means and what fixes it), then retried with a
    growing pause."""
    api = alerts.TelegramAPI(cfg.telegram_api, cfg.telegram_token)
    problems = Problems(cfg.telegram_token)
    offset, polls, pause = 0, 0, 0.0
    while max_polls is None or polls < max_polls:
        polls += 1
        try:
            batch = api.get_updates(offset + 1)
        except alerts.TelegramError as exc:
            problems.report(explain(exc), key=exc.kind)
            pause = _backoff(pause, exc, max_backoff)
            time.sleep(pause)
            continue
        problems.clear("[fw_bot] Telegram answers again; commands and buttons work")
        pause = 0.0
        for upd in batch:
            if not isinstance(upd, dict):
                continue
            offset = max(offset, upd.get("update_id", 0))
            try:
                handle(upd)
            except Exception as exc:  # keep the loop alive
                problems.say(f"update error: {exc}")


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="fw_bot", description="ghostwall firewall-control Telegram bot")
    ap.add_argument("--owner-file", required=True, help="path to owner.json")
    ap.add_argument("--labels", default="labels.jsonl")
    ap.add_argument("--digest", default="digest.jsonl")
    ap.add_argument("--control-base", default=cfgmod.CONTROL_BASE)
    ap.add_argument("--events", help="replay an events.jsonl file once, then exit")
    ap.add_argument("--follow", help="send-only: tail this events.jsonl and alert the owner (no polling)")
    ap.add_argument("--follow-state", metavar="PATH",
                    help="with --follow: where the alert position is kept across restarts "
                         "(default: fw_bot_follow.json next to the events file)")
    ap.add_argument("--commands", action="store_true",
                    help="with --follow: also poll Telegram for /fw commands and alert buttons "
                         "(only if no other bot process uses this token)")
    args = ap.parse_args(argv)
    try:
        cfg = Config.load(
            args.owner_file,
            labels_path=args.labels,
            digest_path=args.digest,
            control_base=args.control_base,
        )
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    bot = FwBot(cfg)
    if args.events:
        with open(args.events, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    bot.feed_event(json.loads(line))
        print(bot.write_digest())
        return 0
    if not cfg.telegram_token:
        print("FW_BOT_TELEGRAM_TOKEN not set; cannot send or poll", file=sys.stderr)
        return 2
    state = None
    if args.follow:
        state = args.follow_state or os.path.join(
            os.path.dirname(os.path.abspath(args.follow)), "fw_bot_follow.json")
    if args.follow and args.commands:
        import threading
        import dispatch
        print(f"fw_bot follow+commands: {args.follow} -> owner {cfg.owner_chat_id}", flush=True)
        threading.Thread(target=follow, args=(bot, args.follow, cfg.owner_chat_id),
                         kwargs={"state_path": state}, daemon=True).start()
        router = CommandRouter(cfg, dispatch.Dispatcher(cfg, args.follow, args.control_base, bot.api),
                               lambda chat_id, text: bot.api._call("sendMessage", {"chat_id": chat_id, "text": text}))
        poll_updates(cfg, router.handle)
        return 0
    if args.follow:
        print(f"fw_bot follow mode: {args.follow} -> owner {cfg.owner_chat_id} (send-only)", flush=True)
        follow(bot, args.follow, cfg.owner_chat_id, state_path=state)
        return 0
    bot.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
