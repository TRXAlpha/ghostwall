"""Alert formatting, inline keyboard, Telegram send/edit via HTTP. Stdlib only."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from signing import make_callback

ALERT_HEADER = "BLOCKED"


def format_alert(event: dict, count: int = 1) -> str:
    """`BLOCKED · <device>` / `<domain> -> <dst ip>` / `Why:` / `Capture:`."""
    device = event.get("device", "unknown")
    domain = event.get("domain", "?")
    dst = event.get("dst_ip") or "?"
    reasons = event.get("reasons") or [event.get("rule", "rule fired")]
    why = "; ".join(str(r) for r in reasons)
    capture = event.get("capture") or "none"
    lines = [
        f"{ALERT_HEADER} · {device}" + (f" (x{count})" if count > 1 else ""),
        f"{domain} \u2192 {dst}",
        f"Why: {why}",
        f"Capture: {capture}",
    ]
    return "\n".join(lines)


def inline_keyboard(event: dict, secret: bytes) -> list[list[dict]]:
    """One row: [Unblock] [Keep blocked] [Isolate device] [Details]."""
    def btn(text, action):
        return {
            "text": text,
            "callback_data": make_callback(action, event["event_id"], secret),
        }

    return [[
        btn("Unblock", "unblock"),
        btn("Keep blocked", "keep"),
        btn("Isolate device", "isolate"),
        btn("Details", "details"),
    ]]


class TelegramAPI:
    """Minimal Bot API client (sendMessage / editMessageText / answerCallbackQuery)."""

    def __init__(self, base: str, token: str, timeout: float = 5.0):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _call(self, method: str, payload: dict) -> dict:
        url = f"{self.base}/bot{self.token}/{method}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            out = json.loads(resp.read().decode("utf-8"))
        if not out.get("ok"):
            raise RuntimeError(f"telegram {method} failed: {out}")
        return out.get("result", {})

    def send_alert(self, chat_id: int, event: dict, secret: bytes) -> int:
        result = self._call("sendMessage", {
            "chat_id": chat_id,
            "text": format_alert(event),
            "reply_markup": {"inline_keyboard": inline_keyboard(event, secret)},
        })
        return result["message_id"]

    def edit_alert(self, chat_id: int, message_id: int, text: str,
                   event: dict | None = None, secret: bytes | None = None) -> None:
        payload = {"chat_id": chat_id, "message_id": message_id, "text": text}
        if event is not None and secret:
            payload["reply_markup"] = {"inline_keyboard": inline_keyboard(event, secret)}
        self._call("editMessageText", payload)


def group_text(base_text: str, count: int) -> str:
    """Append/refresh the collapsed counter line for grouped alerts."""
    marker = f"(x{count})"
    lines = base_text.split("\n")
    if lines and lines[0].rstrip().endswith(")") and "(x" in lines[0]:
        lines[0] = lines[0].rsplit("(x", 1)[0].rstrip() + " " + marker
    else:
        lines[0] = lines[0].rstrip() + " " + marker
    return "\n".join(lines)
