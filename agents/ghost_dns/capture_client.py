"""Fire-and-forget client for the capture freeze API (agents/capture/api.py).

On a high-severity alert the resolver POSTs /freeze so the packet-capture
agent snapshots the pcap ring around the event. Failures are swallowed and
logged -- a missing or down capture agent must never block DNS resolution.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request


class CaptureClient:
    def __init__(self, base_url: str, enabled: bool = True, timeout: float = 3.0):
        self.base = base_url.rstrip("/")
        self.enabled = enabled
        self.timeout = timeout
        self.last_error: str | None = None

    def freeze(self, device: str, event_id: str, dns_history=None) -> None:
        """Trigger a freeze in a background thread (never blocks the caller)."""
        if not self.enabled:
            return
        body = {"device": device, "event_id": event_id}
        if dns_history is not None:
            body["dns_history"] = dns_history
        threading.Thread(target=self._post, args=(body,), daemon=True).start()

    def _post(self, body: dict) -> None:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.base + "/freeze", data=data, method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.last_error = str(exc)
