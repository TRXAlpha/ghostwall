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
    trust: str | None = None,
    would_block: bool = False,
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
        # a model that isn't loaded scores None (no onnxruntime: no "dga_trm"); leave it out
        evt["scores"] = {k: round(float(v), 4) for k, v in scores.items() if v is not None}
    if reasons:
        evt["reasons"] = list(reasons)
    if capture is not None:
        evt["capture"] = capture
    if trust and trust.rstrip(".").lower() != evt["domain"]:
        # what the Trust button should allowlist when it isn't the name itself
        evt["trust"] = trust.rstrip(".").lower()
    if would_block:
        evt["would_block"] = True   # iot_enforce is not "on" (or cannot block here): it would be refused
    if not EVENT_ID_RE.match(evt["event_id"]):
        raise ValueError(f"event_id does not match schema: {evt['event_id']!r}")
    return evt


try:
    import fcntl  # serialises rotation between ghost-dns and ghost-flow (Linux, macOS)
except ImportError:  # pragma: no cover - Windows dev box: one writer, no lock needed
    fcntl = None

MAX_BYTES = 32 * 2**20  # events.jsonl starts over past this; one events.jsonl.1 is kept


class EventLog:
    """Append-only JSONL writer, line-atomic and thread-safe, with size rotation.

    Past max_bytes the file becomes <path>.1 (replacing an older .1) and a new one
    starts. ghost-dns and ghost-flow append to the same file from two processes, so
    rotation happens under an flock and only if the file we hold is still the one at
    `path` (else the other process rotated first and we just reopen)."""

    def __init__(self, path: str, max_bytes: int = MAX_BYTES):
        self.path = path
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    def write(self, event: dict) -> None:
        line = (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            for _ in range(3):
                with open(self.path, "ab") as f:
                    if fcntl:
                        fcntl.flock(f, fcntl.LOCK_EX)
                    try:
                        if os.fstat(f.fileno()).st_ino != _inode(self.path):
                            continue  # rotated under us: write to the new file
                        if self.max_bytes and f.tell() + len(line) > self.max_bytes and f.tell() > 0:
                            os.replace(self.path, self.path + ".1")
                            continue
                        f.write(line)
                        return
                    finally:
                        if fcntl:
                            fcntl.flock(f, fcntl.LOCK_UN)
            with open(self.path, "ab") as f:  # never drop an alert over a rotation race
                f.write(line)


def _inode(path: str) -> int:
    try:
        return os.stat(path).st_ino
    except FileNotFoundError:
        return -1


def read_tail(path: str, limit: int | None, tail_bytes: int) -> list[dict]:
    """Newest-first events from the end of the log, continuing into <path>.1 after a
    rotation so a fresh file doesn't make recent history look empty."""
    out: list[dict] = []
    for p in (path, path + ".1"):
        if not os.path.exists(p):
            continue
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - tail_bytes))
            lines = f.read().decode("utf-8", "replace").splitlines()
        if size > tail_bytes and lines:
            lines = lines[1:]  # the first line is probably cut off
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
            if limit is not None and len(out) >= limit:
                return out
        if size > tail_bytes:
            break  # this file alone was longer than the tail: don't reach further back
    return out
