"""Ghostwall web UI: a small dashboard for the ghost-dns resolver.

Stdlib only. Serves one HTML page and a JSON API that reads the resolver's
events log and forwards actions to the local control API (127.0.0.1:5380).

    GHOSTWALL_WEB_PASSWORD=... python app.py --bind 0.0.0.0 --port 8088

Any address other than loopback needs a password (HTTP Basic auth, user
`ghostwall`); install.sh generates one. Read-only views: /api/status,
/api/events. Actions (POST /api/action) must come from the dashboard's own
origin as JSON, are limited to the control API's own endpoints and are
validated before forwarding.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EVENTS = os.path.join(os.path.dirname(HERE), "ghost_dns", "events.jsonl")
DEFAULT_CONTROL = "http://127.0.0.1:5380"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# Action name -> (control endpoint, allowed body keys)
ACTIONS = {
    "isolate": ("/isolate", {"name"}),
    "release": ("/release", {"name"}),
    "allow": ("/allow", {"domain"}),
    "lockdown": ("/lockdown", set()),
    "learning": ("/learning", {"enabled"}),
}

PAGE = os.path.join(HERE, "index.html")


def control_call(base: str, path: str, body: dict | None = None, timeout: float = 5.0) -> dict:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base.rstrip("/") + path, data=data,
                                 method="POST" if data is not None else "GET",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def read_events(path: str, limit: int) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - 256 * 1024))  # tail only; the log can grow large
        lines = f.read().decode("utf-8", "replace").splitlines()
    out = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
        if len(out) >= limit:
            break
    return out


def validate_action(payload: dict) -> tuple[str, dict]:
    """Return (control path, body) or raise ValueError."""
    name = payload.get("action")
    if name not in ACTIONS:
        raise ValueError(f"unknown action {name!r}")
    path, allowed = ACTIONS[name]
    body = {k: v for k, v in (payload.get("params") or {}).items() if k in allowed}
    if name in ("isolate", "release") and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(body.get("name", ""))):
        raise ValueError("device name required")
    if name == "allow":
        domain = str(body.get("domain", "")).strip().rstrip(".").lower()
        if not DOMAIN_RE.match(domain):
            raise ValueError("valid domain required")
        body["domain"] = domain
    if name == "learning":
        body["enabled"] = bool(body.get("enabled"))
    return path, body


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def password_ok(header: str | None, password: str) -> bool:
    """Check an `Authorization: Basic ...` header. Any user name; the password is the secret."""
    if not header or not header.startswith("Basic "):
        return False
    try:
        _, _, given = base64.b64decode(header[6:], validate=True).decode("utf-8").partition(":")
    except (binascii.Error, UnicodeDecodeError):
        return False
    return hmac.compare_digest(given.encode("utf-8"), password.encode("utf-8"))


def host_name(host_header: str | None) -> str:
    """'192.168.1.5:8088' -> '192.168.1.5', '[::1]:8088' -> '::1'."""
    return urllib.parse.urlsplit("//" + (host_header or "")).hostname or ""


def make_handler(control_base: str, events_path: str, password: str | None = None):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: dict, extra: dict | None = None) -> None:
            self._send(code, json.dumps(obj).encode("utf-8"), "application/json", extra)

        def log_message(self, fmt, *args):  # quiet
            pass

        def _allowed(self) -> bool:
            """Password if one is set. Without one (loopback only), accept only IP or
            localhost Host headers, so a DNS-rebinding page can't drive the dashboard."""
            if password:
                if password_ok(self.headers.get("Authorization"), password):
                    return True
                time.sleep(0.5)  # slow down guessing
                self._json(401, {"ok": False, "error": "password required"},
                           {"WWW-Authenticate": 'Basic realm="Ghostwall", charset="UTF-8"'})
                return False
            host = host_name(self.headers.get("Host"))
            if host == "localhost":
                return True
            try:
                ipaddress.ip_address(host)
                return True
            except ValueError:
                self._json(403, {"ok": False, "error": "use the IP address, or set a password"})
                return False

        def _same_origin(self) -> bool:
            """Actions only from the dashboard itself: JSON body, and an Origin (when the
            browser sends one) that matches the Host. Blocks cross-site form posts."""
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                return False
            origin = self.headers.get("Origin")
            return origin is None or urllib.parse.urlsplit(origin).netloc == self.headers.get("Host")

        def do_GET(self):
            if not self._allowed():
                return
            if self.path in ("/", "/index.html"):
                with open(PAGE, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif self.path == "/api/status":
                try:
                    st = control_call(control_base, "/status", timeout=3)
                    self._json(200, {"ok": True, "resolver": st})
                except (urllib.error.URLError, OSError, ValueError) as e:
                    self._json(503, {"ok": False, "error": f"resolver unreachable: {e}"})
            elif self.path.startswith("/api/events"):
                m = re.search(r"[?&]limit=(\d+)", self.path)
                limit = min(int(m.group(1)) if m else 50, 500)
                self._json(200, {"ok": True, "events": read_events(events_path, limit)})
            else:
                self._json(404, {"ok": False, "error": "not found"})

        def do_POST(self):
            if not self._allowed():
                return
            if self.path != "/api/action":
                self._json(404, {"ok": False, "error": "not found"})
                return
            if not self._same_origin():
                self._json(403, {"ok": False, "error": "cross-origin request refused"})
                return
            try:
                n = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(n) or b"{}")
                path, body = validate_action(payload)
            except (ValueError, TypeError) as e:
                self._json(400, {"ok": False, "error": str(e)})
                return
            try:
                res = control_call(control_base, path, body, timeout=5)
                self._json(200, res)
            except urllib.error.HTTPError as e:
                self._json(e.code, {"ok": False, "error": e.reason})
            except (urllib.error.URLError, OSError) as e:
                self._json(503, {"ok": False, "error": f"resolver unreachable: {e}"})

    return Handler


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ghostwall web UI (password: GHOSTWALL_WEB_PASSWORD env var)")
    ap.add_argument("--bind", default="127.0.0.1", help="bind address; anything but loopback needs a password")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--control", default=DEFAULT_CONTROL)
    ap.add_argument("--events", default=DEFAULT_EVENTS)
    args = ap.parse_args(argv)
    # From the environment, not argv, so it never shows up in `ps`.
    password = os.environ.get("GHOSTWALL_WEB_PASSWORD") or None
    if not password and not is_loopback(args.bind):
        print(f"[web-ui] refusing to listen on {args.bind} without a password: set GHOSTWALL_WEB_PASSWORD "
              "(install.sh puts one in /etc/ghostwall/ghostwall.env), or bind 127.0.0.1", file=sys.stderr, flush=True)
        return 2
    srv = ThreadingHTTPServer((args.bind, args.port), make_handler(args.control, args.events, password))
    srv.daemon_threads = True
    print(f"[web-ui] http://{args.bind}:{args.port}  password={'on' if password else 'off'}  "
          f"control={args.control}  events={args.events}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
