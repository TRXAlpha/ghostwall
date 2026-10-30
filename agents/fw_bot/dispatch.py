"""Telegram dispatcher for Ghostwall.

Used by `fw_bot.py --follow --commands`, or imported by another bot that already
owns the token's getUpdates loop (only one process may poll a token). Handles:
  - text commands:  /fw help | log [n] | summary | status | device | isolate |
                    release | allow | lockdown | learning on|off
  - alert buttons:  Unblock / Keep / Isolate / Details (signed callback_data)

Stdlib only. Nothing here polls Telegram; the caller passes updates in.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

import alerts
import commands
from callbacks import CallbackHandler
from config import Config
from control_client import ControlClient

DEFAULT_EVENTS = "/opt/ghostwall/agents/ghost_dns/events.jsonl"
DEFAULT_CONTROL = "http://127.0.0.1:5380"
MAX_LOG = 30
TAIL_BYTES = 512 * 1024

HELP = (
    "ghostwall commands:\n"
    "/fw status              resolver, devices, modes\n"
    "/fw log [n]             last n decisions (default 10, max 30)\n"
    "/fw summary             last 24h counts\n"
    "/fw device <name>       one device\n"
    "/fw isolate <name>      cut a device off\n"
    "/fw release <name>      restore a device\n"
    "/fw allow <domain>      trust a domain\n"
    "/fw lockdown            toggle LAN lockdown\n"
    "/fw learning on|off     learning (alert only) vs enforce"
)


def read_events(path: str, limit: int | None = None) -> list[dict]:
    """Newest-first list of parsed events from the tail of the log."""
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - TAIL_BYTES))
        lines = f.read().decode("utf-8", "replace").splitlines()
    out: list[dict] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
        if limit is not None and len(out) >= limit:
            break
    return out


class EventIndex:
    """dict-like lookup used by CallbackHandler (event_id -> event)."""

    def __init__(self, path: str):
        self.path = path

    def get(self, event_id: str, default=None):
        for e in read_events(self.path):
            if e.get("event_id") == event_id:
                return e
        return default


def _ts(e: dict) -> str:
    return (e.get("time") or "").replace("T", " ").replace("Z", "")


def format_log(events: list[dict]) -> str:
    if not events:
        return "No decisions logged yet."
    lines = []
    for e in events:
        score = (e.get("scores") or {}).get("dga")
        s = f" {score:.2f}" if isinstance(score, (int, float)) else ""
        lines.append(f"{_ts(e)}  {e.get('device', '?')}  {e.get('domain', '?')}\n"
                     f"    {e.get('action', '?')} · {e.get('rule', '?')}{s} · {e.get('severity', '?')}")
    return "\n".join(lines)


def format_summary(events: list[dict], now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    recent = []
    for e in events:
        try:
            t = datetime.strptime(e["time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if t >= cutoff:
            recent.append(e)
    if not recent:
        return "No decisions in the last 24h."
    actions = Counter(e.get("action", "?") for e in recent)
    rules = Counter(e.get("rule", "?") for e in recent)
    devices = Counter(e.get("device", "?") for e in recent)
    domains = Counter(e.get("domain", "?") for e in recent)
    top = lambda c: ", ".join(f"{k} ({v})" for k, v in c.most_common(5))  # noqa: E731
    return (
        f"last 24h: {len(recent)} decisions\n"
        f"actions: {', '.join(f'{k} {v}' for k, v in actions.items())}\n"
        f"rules: {top(rules)}\n"
        f"devices: {top(devices)}\n"
        f"domains: {top(domains)}"
    )


class Dispatcher:
    def __init__(self, cfg: Config, events_path: str, control_base: str, api):
        self.cfg = cfg
        self.events_path = events_path
        self.client = ControlClient(control_base)
        self.callbacks = CallbackHandler(cfg, self.client, api, EventIndex(events_path))

    # ---- text commands --------------------------------------------------
    def text(self, text: str) -> str:
        parts = text.strip().split()
        sub = parts[1].lower() if len(parts) > 1 else "help"
        args = parts[2:]
        if sub in ("help", "?"):
            return HELP
        if sub == "log":
            try:
                n = int(args[0]) if args else 10
            except ValueError:
                return "usage: /fw log [n]"
            n = max(1, min(n, MAX_LOG))
            return format_log(read_events(self.events_path, n))
        if sub == "summary":
            return format_summary(read_events(self.events_path, 5000))
        return commands.handle_command(text, self.client)

    # ---- alert buttons --------------------------------------------------
    def callback(self, query: dict) -> str:
        return self.callbacks.handle(query)


def from_env(env: dict, api_base: str = "https://api.telegram.org") -> Dispatcher:
    """Build a dispatcher using ghost-bot's already-loaded environment.

    env needs TELEGRAM_BOT_TOKEN and FW_BOT_CALLBACK_SECRET; owner comes from
    owner.json, passed in via `owner_chat_id` in env as FW_OWNER_CHAT_ID."""
    token = env.get("TELEGRAM_BOT_TOKEN", "")
    secret = env.get("FW_BOT_CALLBACK_SECRET", "")
    owner = int(env["FW_OWNER_CHAT_ID"])
    cfg = Config(owner_chat_id=owner, telegram_token=token, secret=secret.encode(),
                 telegram_api=api_base, labels_path=env.get("FW_LABELS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "labels.jsonl")))
    api = alerts.TelegramAPI(api_base, token)
    return Dispatcher(cfg, env.get("FW_EVENTS", DEFAULT_EVENTS),
                      env.get("FW_CONTROL", DEFAULT_CONTROL), api)
