"""events.jsonl writer. Produces lines valid against the schema in docs/REFERENCE.md.

The contract lives in docs/REFERENCE.md and is enforced by agents/fw_bot/validate_events.py;
the resolver test suite runs real events through that validator so this writer
and the consumer can never silently drift.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone

EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
VALID_ACTIONS = {"block", "recommend", "allow"}
VALID_SEVERITIES = {"info", "warn", "high", "critical"}


def now_iso() -> str:
    """ISO 8601 UTC with a trailing Z, e.g. 2026-10-22T21:04:05Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_event_id() -> str:
    return "evt_" + secrets.token_hex(8)


def make_event(
    *,
    device: str,
    domain: str,
    rule: str,
    action: str,
    ip: str | None = None,
    mac: str | None = None,
    dst_ip: str | None = None,
    ja4: str | None = None,
    scores: dict | None = None,
    severity: str = "warn",
    reasons: list[str] | None = None,
    capture: str | None = None,
    event_id: str | None = None,
    time: str | None = None,
) -> dict:
    if action not in VALID_ACTIONS:
        raise ValueError(f"invalid action {action!r}")
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"invalid severity {severity!r}")
    evt: dict = {
        "time": time or now_iso(),
        "device": device,
        "domain": domain.rstrip(".").lower(),
        "rule": rule,
        "action": action,
        "severity": severity,
        "event_id": event_id or new_event_id(),
    }
    if mac is not None:
        evt["mac"] = mac
    if ip is not None:
        evt["ip"] = ip
    if dst_ip is not None:
        evt["dst_ip"] = dst_ip
    if ja4 is not None:
        evt["ja4"] = ja4
    if scores:
        evt["scores"] = {k: round(float(v), 4) for k, v in scores.items()}
    if reasons:
        evt["reasons"] = list(reasons)
    if capture is not None:
        evt["capture"] = capture
    if not EVENT_ID_RE.match(evt["event_id"]):
        raise ValueError(f"event_id does not match schema: {evt['event_id']!r}")
    return evt


class EventLog:
    """Append-only JSONL writer, line-atomic and thread-safe."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    def write(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)
