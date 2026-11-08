"""Alert formatting, inline keyboard, Telegram send/edit via HTTP. Stdlib only."""
from __future__ import annotations

import datetime
import http.client
import json
import os
import urllib.error
import urllib.request

from signing import make_callback


RULE_WORDS = {
    "threat_feed": "known malware or phishing domain", "dga_burst": "burst of random-looking domains",
    "nx_burst": "burst of lookups of unregistered domains",
    "dga_high": "very random-looking new domain", "dga_suspect": "random-looking new domain",
    "dga_corroborated": "random name on a risky TLD", "doh_bypass": "may be bypassing your DNS filter",
    "abused_service": "started using a service malware favours", "dns_tunnel": "possible data over DNS",
    "dns_beacon": "looked up on a fixed timer", "blocklist": "on your blocklist",
    "upstream_block": "blocked by your upstream DNS filter",
    "raw_ip": "connected to a raw IP", "doh_ip": "uses its own DNS-over-HTTPS", "beacon": "connects on a fixed timer",
    "iot_new_domain": "IoT device looked up a domain it never used",
    "new_domain": "newly registered domain, new to your network",
}


def minimal() -> bool:
    """FW_BOT_PRIVACY=minimal: messages name the device and the kind of alert, never a
    domain, IP or MAC, so Telegram learns that something happened, not what. The
    details are on the dashboard."""
    return os.environ.get("FW_BOT_PRIVACY", "").strip().lower() == "minimal"


def is_block(event: dict) -> bool:
    return event.get("action") == "block"


def head(event: dict) -> str:
    """ISOLATED when auto-isolate cut the device off, else BLOCKED or ALERT."""
    return "ISOLATED" if event.get("auto_isolated") else "BLOCKED" if is_block(event) else "ALERT"


LATE_AFTER = 300   # seconds: an alert sent later than this says when it happened


def late_note(event: dict, now: float | None) -> str | None:
    """`Happened 09:12 (sent late)` for an alert queued while Telegram or the bot was
    down; None for one sent as it happened (or without a usable time)."""
    if now is None:
        return None
    try:
        t = datetime.datetime.fromisoformat(str(event.get("time", "")).replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=datetime.timezone.utc)
    if now - t.timestamp() <= LATE_AFTER:
        return None
    local = t.astimezone()
    same_day = local.date() == datetime.datetime.fromtimestamp(now).astimezone().date()
    return f"Happened {local.strftime('%H:%M' if same_day else '%a %d %b %H:%M')} (sent late)"


def format_alert(event: dict, count: int = 1, now: float | None = None) -> str:
    """`BLOCKED · <device>` for a block, `ALERT · <device>` for anything Ghostwall only
    flagged (shadow and learning mode), then the domain, `Why:` and the capture if any.
    With `now`, an alert older than LATE_AFTER also says when it happened."""
    device = event.get("device", "unknown")
    late = late_note(event, now)
    if minimal():
        what = RULE_WORDS.get(event.get("rule"), "alert")
        return "\n".join([
            f"{head(event)} · {device}" + (f" (x{count})" if count > 1 else ""),
            f"{what} ({event.get('severity', 'warn')})",
            *([f"Isolated automatically. Undo: Release device below, or sudo ghostwall release {device}"]
              if event.get("auto_isolated") else []),
            *(["Automatic isolation failed: see the dashboard."] if event.get("auto_isolate_failed") else []),
            *([late] if late else []),
            "Details on the dashboard (privacy mode: no domains are sent to Telegram).",
        ])
    domain = event.get("domain", "?")
    reasons = event.get("reasons") or [event.get("rule", "rule fired")]
    lines = [
        f"{head(event)} · {device}" + (f" (x{count})" if count > 1 else ""),
        domain + (f" → {event['dst_ip']}" if event.get("dst_ip") else ""),
        "Why: " + "; ".join(str(r) for r in reasons),
    ]
    if event.get("capture"):
        lines.append(f"Capture: {event['capture']}")
    if late:
        lines.append(late)
    return "\n".join(lines)


def inline_keyboard(event: dict, secret: bytes) -> list[list[dict]]:
    """A block: [Unblock] [Keep blocked] [Isolate device] [Details].
    An alert (nothing was blocked): [Trust domain] [Details]."""
    def btn(text, action):
        return {
            "text": text,
            "callback_data": make_callback(action, event["event_id"], secret),
        }

    if event.get("auto_isolated"):
        return [[btn("Release device", "release"), btn("Details", "details")]]
    if event.get("rule") == "iot_new_domain":   # refused or not, the way out is allowing it for the device
        return [[btn("Allow for this device", "trust"), btn("Isolate device", "isolate"), btn("Details", "details")]]
    if not is_block(event):
        # On the threat feed: trusting one takes a typed `ghostwall allow` (the alert
        # says so), not one tap on a phone. A burst is many different
        # names: trusting the one in the alert would change nothing.
        if event.get("rule") in ("threat_feed", "dga_burst", "nx_burst"):
            return [[btn("Details", "details")]]
        return [[btn("Trust domain", "trust"), btn("Details", "details")]]
    return [[
        btn("Unblock", "unblock"),
        btn("Keep blocked", "keep"),
        btn("Isolate device", "isolate"),
        btn("Details", "details"),
    ]]


class TelegramError(Exception):
    """A Bot API call failed. Its text never contains the bot token (the token is part of
    every request URL, so urllib's own errors can carry it).

    kind says what to do about it:
      network   no answer, or Telegram's side failed (5xx): wait and retry
      rate      HTTP 429: wait retry_after seconds, then retry
      token     HTTP 401/404: the bot token is wrong
      chat      HTTP 403, or 400 "chat not found": the bot may not write to that chat
                (usually: the owner never pressed Start in the bot's chat)
      conflict  HTTP 409: another process polls this token
      message   any other 4xx: Telegram refuses this one message; others can still go
    """

    def __init__(self, method: str, status: int | None, description: str,
                 retry_after: float | None = None):
        self.method, self.status, self.description = method, status, description
        self.retry_after = retry_after
        super().__init__(f"telegram {method}: "
                         + (f"HTTP {status}: {description}" if status else description))

    @property
    def kind(self) -> str:
        s = self.status
        if s is None or s >= 500:
            return "network"
        if s == 429:
            return "rate"
        if s in (401, 404):
            return "token"
        if s == 403 or (s == 400 and "chat not found" in self.description.lower()):
            return "chat"
        if s == 409:
            return "conflict"
        return "message"


class TelegramAPI:
    """Minimal Bot API client (sendMessage / editMessageText / getUpdates). Every failure
    is a TelegramError."""

    def __init__(self, base: str, token: str, timeout: float = 5.0):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout

    def redact(self, text: str) -> str:
        return text.replace(self.token, "<token>") if self.token else text

    def _request(self, method: str, req, timeout: float):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                out = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001 (a proxy's HTML page, an empty body, ...)
                body = {}
            retry = (body.get("parameters") or {}).get("retry_after")
            desc = self.redact(str(body.get("description") or exc.reason))
            raise TelegramError(method, exc.code, desc,
                                float(retry) if isinstance(retry, (int, float)) else None) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as exc:
            # no answer, a cut-off answer, or not JSON
            raise TelegramError(method, None, self.redact(str(getattr(exc, "reason", exc)))) from None
        if not isinstance(out, dict) or not out.get("ok"):
            out = out if isinstance(out, dict) else {}
            raise TelegramError(method, out.get("error_code") or 400,
                                self.redact(str(out.get("description") or "not ok")))
        return out.get("result", {})

    def _call(self, method: str, payload: dict) -> dict:
        req = urllib.request.Request(
            f"{self.base}/bot{self.token}/{method}", data=json.dumps(payload).encode("utf-8"),
            method="POST", headers={"Content-Type": "application/json"})
        return self._request(method, req, self.timeout)

    def get_updates(self, offset: int, wait: int = 25) -> list:
        """Long poll: Telegram holds the request up to `wait` seconds."""
        req = urllib.request.Request(
            f"{self.base}/bot{self.token}/getUpdates?timeout={wait}&offset={offset}", method="GET")
        result = self._request("getUpdates", req, wait + 10)
        return result if isinstance(result, list) else []

    def send_alert(self, chat_id: int, event: dict, secret: bytes, now: float | None = None) -> int:
        result = self._call("sendMessage", {
            "chat_id": chat_id,
            "text": format_alert(event, now=now),
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
