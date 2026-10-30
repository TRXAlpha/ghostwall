"""fw_bot.py: wires config, control client, alerts, grouping, commands,
callbacks into a Telegram update loop. Stdlib only, Python 3.13.

Usage:
    FW_BOT_CALLBACK_SECRET=... .venv/Scripts/python.exe fw_bot.py \
        --owner-file state/owner.json [--labels labels.jsonl] [--once]
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

import alerts
import commands
import config as cfgmod
from callbacks import CallbackHandler, append_label
from config import Config
from control_client import ControlClient
from grouping import AlertGrouper, severity_of


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
        chat_id = (msg.get("chat") or {}).get("id")
        from_user = (msg.get("from") or {}).get("id")
        text = msg.get("text", "")
        if not self.cfg.is_owner(chat_id):
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
            msg_id = self.api.send_alert(chat_id, grp.event, self.cfg.secret)
            grp.message_id = msg_id
            return "sent"
        # update: refresh counter on the existing message
        if grp.message_id is not None and chat_id is not None:
            self.api.edit_alert(
                chat_id, grp.message_id,
                alerts.group_text(alerts.format_alert(grp.event), grp.count),
                event=grp.event, secret=self.cfg.secret,
            )
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
    def run(self, poll_seconds: float = 2.0, max_updates: int | None = None) -> None:
        import time as _time
        offset = 0
        seen = 0
        while max_updates is None or offset < max_updates:
            url = f"{self.cfg.telegram_api}/bot{self.cfg.telegram_token}/getUpdates"
            req = urllib.request.Request(
                f"{url}?timeout=25&offset={offset + 1}", method="GET")
            try:
                with urllib.request.urlopen(req, timeout=self.cfg.group_window_minutes * 0 + 30) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
            except Exception:
                time.sleep(poll_seconds)
                continue
            for upd in body.get("result", []):
                offset = max(offset, upd.get("update_id", 0))
                try:
                    self.process_update(update=upd)
                except Exception as exc:  # keep the loop alive
                    print(f"update error: {exc}", file=sys.stderr)


class Follower:
    """Send-only tail of events.jsonl. Records the current end of the file at
    creation, so history is never replayed. Each poll() sends new alerts once."""

    def __init__(self, bot: "FwBot", events_path: str, chat_id: int):
        self.bot = bot
        self.path = events_path
        self.chat_id = chat_id
        self.offset = os.path.getsize(events_path) if os.path.exists(events_path) else 0

    def poll(self) -> int:
        sent = 0
        if not os.path.exists(self.path):
            return sent
        if os.path.getsize(self.path) < self.offset:
            self.offset = 0  # file was truncated or rotated
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            for raw in f:
                if not raw.endswith(b"\n"):
                    break  # partial line: retry on the next pass
                self.offset += len(raw)
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except ValueError:
                    continue
                result = self.bot.feed_event(evt, chat_id=self.chat_id)
                print(f"[fw_bot] {result}: {evt.get('event_id')} {evt.get('domain')} "
                      f"{evt.get('rule')}/{evt.get('action')}", flush=True)
                sent += 1
        return sent


def follow(bot: "FwBot", events_path: str, chat_id: int, poll_seconds: float = 1.0,
           max_loops: int | None = None) -> None:
    """Run a Follower forever (or max_loops passes). Never calls getUpdates, so it
    can share a bot token with another poller such as ghost-bot without a 409."""
    f = Follower(bot, events_path, chat_id)
    loops = 0
    while max_loops is None or loops < max_loops:
        loops += 1
        f.poll()
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
        if not self.cfg.is_owner(chat_id):
            return "ignored: not owner"
        if not text.startswith("/fw"):
            return "ignored: not a command"
        self.send(chat_id, self.dispatcher.text(text))
        return "replied"


def poll_updates(cfg: Config, handle, poll_seconds: float = 2.0) -> None:
    """Long-poll getUpdates forever and pass each update to handle()."""
    offset = 0
    url = f"{cfg.telegram_api}/bot{cfg.telegram_token}/getUpdates"
    while True:
        try:
            with urllib.request.urlopen(f"{url}?timeout=25&offset={offset + 1}", timeout=30) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except Exception:
            time.sleep(poll_seconds)
            continue
        for upd in body.get("result", []):
            offset = max(offset, upd.get("update_id", 0))
            try:
                handle(upd)
            except Exception as exc:  # keep the loop alive
                print(f"update error: {exc}", file=sys.stderr)


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
    if args.follow and args.commands:
        import threading
        import dispatch
        print(f"fw_bot follow+commands: {args.follow} -> owner {cfg.owner_chat_id}", flush=True)
        threading.Thread(target=follow, args=(bot, args.follow, cfg.owner_chat_id), daemon=True).start()
        router = CommandRouter(cfg, dispatch.Dispatcher(cfg, args.follow, args.control_base, bot.api),
                               lambda chat_id, text: bot.api._call("sendMessage", {"chat_id": chat_id, "text": text}))
        poll_updates(cfg, router.handle)
        return 0
    if args.follow:
        print(f"fw_bot follow mode: {args.follow} -> owner {cfg.owner_chat_id} (send-only)", flush=True)
        follow(bot, args.follow, cfg.owner_chat_id)
        return 0
    bot.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
