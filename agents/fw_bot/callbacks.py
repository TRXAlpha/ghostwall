"""Callback query handling: HMAC verify, control API call, edit message,
append labels.jsonl. Owner-only. Stdlib only."""
from __future__ import annotations

import json
import time

from config import Config
from control_client import ControlClient, ControlError
from signing import CallbackError, parse_callback


def append_label(path: str, *, event_id: str, action: str, device: str,
                 domain: str, user: int, ts: float | None = None) -> dict:
    rec = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time())),
        "event_id": event_id,
        "action": action,
        "device": device,
        "domain": domain,
        "user": user,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    return rec


class CallbackHandler:
    def __init__(self, cfg, client: ControlClient, api, events_lookup=None):
        """events_lookup: event_id -> event dict (for Details / re-formatting)."""
        self.cfg = cfg
        self.client = client
        self.api = api
        self.events = events_lookup or {}

    def _err_text(self, action: str, exc: Exception) -> str:
        return f"FAILED ({action}): {exc}"

    def handle(self, query: dict) -> str:
        """Process one Telegram callback_query dict. Returns reply text.

        Non-owner queries and forgeries are ignored (no edit), logged via
        return of a short marker string beginning with 'ignored:'.
        """
        chat_id = (query.get("message") or {}).get("chat", {}).get("id")
        message_id = (query.get("message") or {}).get("message_id")
        from_user = (query.get("from") or {}).get("id")
        data = query.get("data", "")

        if not self.cfg.is_owner(from_user):
            return "ignored: not owner"
        try:
            action, event_id = parse_callback(data, self.cfg.secret)
        except CallbackError as exc:
            return f"ignored: {exc}"
        try:
            event = self.events.get(event_id, {})
            device = str(event.get("device", "?"))
            domain = str(event.get("domain", "?"))
            if action == "unblock":
                self.client.unblock(event_id, domain)
                text = f"Unblocked {domain} (event {event_id})."
            elif action == "keep":
                text = f"Kept blocked: {domain}."
            elif action == "isolate":
                self.client.isolate(device)
                text = f"{device} isolated."
            elif action == "details":
                text = self._details(event_id, event)
            else:
                return "ignored: unknown action"
        except ControlError as exc:
            text = self._err_text(action, exc)
        if isinstance(chat_id, int) and isinstance(message_id, int):
            self.api.edit_alert(chat_id, message_id, text)
        append_label(
            self.cfg.labels_path, event_id=event_id, action=action,
            device=device, domain=domain, user=from_user,
        )
        return text

    def _details(self, event_id: str, event: dict) -> str:
        if not event:
            return f"event {event_id}: no details available"
        scores = event.get("scores") or {}
        score_s = ", ".join(f"{k}={v}" for k, v in scores.items())
        lines = [
            f"event {event_id}",
            f"device: {event.get('device', '?')} ({event.get('ip', '?')})",
            f"mac: {event.get('mac', '?')}",
            f"domain: {event.get('domain', '?')} \u2192 {event.get('dst_ip', '?')}",
            f"ja4: {event.get('ja4', '?')}",
            f"scores: {score_s or 'none'}",
            f"rule: {event.get('rule', '?')} action: {event.get('action', '?')}",
            f"time: {event.get('time', '?')}",
        ]
        return "\n".join(lines)
