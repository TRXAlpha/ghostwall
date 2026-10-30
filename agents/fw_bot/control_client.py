"""HTTP client for the local control API (docs/REFERENCE.md). Stdlib only."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from config import HTTP_TIMEOUT


class ControlError(Exception):
    """The control API returned an error or was unreachable."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _request(base: str, path: str, body: dict | None, timeout: float = HTTP_TIMEOUT) -> dict:
    url = base.rstrip("/") + path
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST" if data is not None else "GET",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
            msg = str(payload.get("error", exc.reason))
        except Exception:
            msg = str(exc.reason)
        raise ControlError(msg, status=exc.code) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ControlError(f"control API unreachable: {exc}") from exc
    if not isinstance(payload, dict):
        raise ControlError("control API returned non-object JSON")
    if not payload.get("ok", False):
        raise ControlError(str(payload.get("error", "unknown error")))
    return payload


class ControlClient:
    def __init__(self, base: str, timeout: float = HTTP_TIMEOUT):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def _call(self, path: str, body: dict | None = None, get: bool = False) -> dict:
        if get:
            body = None
        return _request(self.base, path, body, self.timeout)

    # -- control API endpoints (docs/REFERENCE.md) ------------------------------------------------
    def status(self) -> dict:
        try:
            return self._call("/status", get=True)
        except ControlError as exc:
            if exc.status is None:  # server may only accept POST
                return self._call("/status", {})
            raise

    def device(self, name: str) -> dict:
        return self._call("/device", {"name": name})

    def isolate(self, name: str) -> dict:
        return self._call("/isolate", {"name": name})

    def release(self, name: str) -> dict:
        return self._call("/release", {"name": name})

    def allow(self, domain: str) -> dict:
        return self._call("/allow", {"domain": domain})

    def lockdown(self) -> dict:
        return self._call("/lockdown", {})

    def learning(self, enabled: bool) -> dict:
        return self._call("/learning", {"enabled": bool(enabled)})

    def unblock(self, event_id: str, domain: str) -> dict:
        return self._call("/unblock", {"event_id": event_id, "domain": domain})
