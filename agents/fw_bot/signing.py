"""HMAC-signed callback data for inline keyboards. Short, tamper-proof."""
from __future__ import annotations

import base64
import hmac
import hashlib

# actions are single letters to keep callback data under Telegram's 64-byte limit
ACTIONS = {"u": "unblock", "k": "keep", "i": "isolate", "d": "details"}
ACTION_CODES = {v: k for k, v in ACTIONS.items()}

MAX_LEN = 64


class CallbackError(ValueError):
    """Malformed or forged callback data."""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def make_callback(action: str, event_id: str, secret: bytes) -> str:
    """Return `<code>.<event_id>.<hmac-prefix>` signed over (action, event_id)."""
    if action not in ACTION_CODES:
        raise ValueError(f"unknown action: {action}")
    if not event_id or len(event_id) > 64 or not all(
        c.isalnum() or c in "_-" for c in event_id
    ):
        raise ValueError(f"bad event_id: {event_id!r}")
    code = ACTION_CODES[action]
    mac = hmac.new(secret, f"{code}:{event_id}".encode(), hashlib.sha256).digest()
    data = f"{code}.{event_id}.{_b64url(mac)[:16]}"
    if len(data) > MAX_LEN:
        raise ValueError("callback data too long")
    return data


def parse_callback(data: str, secret: bytes) -> tuple[str, str]:
    """Verify signature; return (action, event_id) or raise CallbackError."""
    parts = data.split(".")
    if len(parts) != 3:
        raise CallbackError("malformed callback data")
    code, event_id, sig = parts
    if code not in ACTIONS:
        raise CallbackError("unknown action code")
    expected = _b64url(
        hmac.new(secret, f"{code}:{event_id}".encode(), hashlib.sha256).digest()
    )[:16]
    if not hmac.compare_digest(sig, expected):
        raise CallbackError("bad signature")
    return ACTIONS[code], event_id
