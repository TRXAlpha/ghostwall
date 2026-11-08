"""HTTP client for the local control API (docs/REFERENCE.md). Stdlib only."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from config import HTTP_TIMEOUT

# ghost-dns writes its control-API token next to state.json on first start; actions
# (everything but /status) need it. Read lazily: ghost-dns may create it after we start.
INSTALLED_TOKEN = "/var/lib/ghostwall/control_token"
DEV_TOKEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "ghost_dns", "control_token")


def default_token_file() -> str:
    env = os.environ.get("FW_BOT_CONTROL_TOKEN_FILE")
    if env:
        return env
    return INSTALLED_TOKEN if os.path.exists(INSTALLED_TOKEN) else DEV_TOKEN


class ControlError(Exception):
    """The control API returned an error or was unreachable."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _request(base: str, path: str, body: dict | None, timeout: float = HTTP_TIMEOUT,
             token: str | None = None) -> dict:
    url = base.rstrip("/") + path
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        url,
        data=data,
        method="POST" if data is not None else "GET",
        headers=headers,
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
    def __init__(self, base: str, timeout: float = HTTP_TIMEOUT, token_file: str | None = None):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.token_file = token_file if token_file is not None else default_token_file()
        self._token: str | None = None

    def _get_token(self) -> str | None:
        if self._token is None and self.token_file:
            try:
                with open(self.token_file, encoding="utf-8") as f:
                    self._token = f.read().strip() or None
            except OSError:
                return None
        return self._token

    def _call(self, path: str, body: dict | None = None, get: bool = False) -> dict:
        if get:
            body = None
        try:
            return _request(self.base, path, body, self.timeout, self._get_token())
        except ControlError as exc:
            if exc.status != 401:
                raise
            self._token = None  # ghost-dns made a new token: read it again, once
            return _request(self.base, path, body, self.timeout, self._get_token())

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

    def allow(self, domain: str, device: str | None = None) -> dict:
        body = {"domain": domain}
        if device:
            body["device"] = device   # an IoT device's own set, not the allowlist
        return self._call("/allow", body)

    def lockdown(self) -> dict:
        return self._call("/lockdown", {})

    def learning(self, enabled: bool) -> dict:
        return self._call("/learning", {"enabled": bool(enabled)})

    def unblock(self, event_id: str, domain: str) -> dict:
        return self._call("/unblock", {"event_id": event_id, "domain": domain})
