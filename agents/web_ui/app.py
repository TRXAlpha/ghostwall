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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EVENTS = os.path.join(os.path.dirname(HERE), "ghost_dns", "events.jsonl")
DEFAULT_CONTROL = "http://127.0.0.1:5380"
# ghost-dns writes its control-API token next to state.json on first start.
INSTALLED_TOKEN = "/var/lib/ghostwall/control_token"
DEV_TOKEN = os.path.join(os.path.dirname(HERE), "ghost_dns", "control_token")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# Action name -> (control endpoint, allowed body keys)
ACTIONS = {
    "isolate": ("/isolate", {"name"}),
    "release": ("/release", {"name"}),
    "allow": ("/allow", {"domain", "device"}),   # device: an IoT device's own set
    "untrust": ("/untrust", {"domain"}),
    "trusted": ("/trusted", set()),
    "lockdown": ("/lockdown", set()),
    "learning": ("/learning", {"enabled"}),
}

PAGE = os.path.join(HERE, "index.html")


def page_and_csp(path: str = PAGE) -> tuple[bytes, str]:
    """The page and a Content-Security-Policy that allows only its own inline script
    (by hash). Domain names in alerts come from whatever devices look up, so even
    though the page escapes them, a script that slipped through could not run."""
    import hashlib
    with open(path, "rb") as f:
        page = f.read()
    hashes = []
    for m in re.finditer(rb"<script>(.*?)</script>", page, re.S):
        hashes.append("'sha256-" + base64.b64encode(hashlib.sha256(m.group(1)).digest()).decode() + "'")
    csp = ("default-src 'none'; script-src " + (" ".join(hashes) or "'none'") +
           "; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; "
           "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    return page, csp


class TokenFile:
    """The control-API token, read lazily (ghost-dns may create it after we start)."""

    def __init__(self, path: str | None):
        self.path, self._tok = path, None

    def get(self) -> str | None:
        if self._tok is None and self.path:
            try:
                with open(self.path, encoding="utf-8") as f:
                    self._tok = f.read().strip() or None
            except OSError:
                return None
        return self._tok

    def reset(self) -> None:
        self._tok = None  # re-read after a 401 (the token file was replaced)


def default_token_path() -> str:
    env = os.environ.get("GHOSTWALL_CONTROL_TOKEN_FILE")
    if env:
        return env
    return INSTALLED_TOKEN if os.path.exists(INSTALLED_TOKEN) else DEV_TOKEN


def control_call(base: str, path: str, body: dict | None = None, timeout: float = 5.0,
                 token: str | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base.rstrip("/") + path, data=data,
                                 method="POST" if data is not None else "GET",
                                 headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def read_events(path: str, limit: int) -> list[dict]:
    """Newest-first events from the end of the log, continuing into <path>.1 after
    ghost-dns rotated it, so a fresh file doesn't make recent history look empty."""
    out: list[dict] = []
    for p in (path, path + ".1"):
        if not os.path.exists(p):
            continue
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 256 * 1024))
            lines = f.read().decode("utf-8", "replace").splitlines()
        if size > 256 * 1024 and lines:
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
        if size > 256 * 1024:
            break  # the tail of this file alone was enough history
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
    if name in ("allow", "untrust"):
        domain = str(body.get("domain", "")).strip().rstrip(".").lower()
        if not DOMAIN_RE.match(domain):
            raise ValueError("valid domain required")
        body["domain"] = domain
        if "device" in body and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(body["device"])):
            raise ValueError("device must be a device name")
    if name == "learning" and not isinstance(body.get("enabled"), bool):
        raise ValueError("enabled must be true or false")
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


class FailLimiter:
    """At most `limit` wrong passwords per client address per `window` seconds.
    Sleeping on a failure alone doesn't stop guessing: requests run in parallel."""

    def __init__(self, limit: int = 10, window: float = 60.0, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, client: str, now: float) -> list[float]:
        recent = [t for t in self._fails.get(client, []) if now - t < self.window]
        if recent:
            self._fails[client] = recent
        else:
            self._fails.pop(client, None)
        return recent

    def blocked(self, client: str) -> bool:
        with self._lock:
            return len(self._recent(client, self.clock())) >= self.limit

    def fail(self, client: str) -> None:
        with self._lock:
            now = self.clock()
            if len(self._fails) > 10000:  # bound memory under a spray of addresses
                self._fails = {c: v for c, v in self._fails.items() if now - v[-1] < self.window}
            self._recent(client, now)
            self._fails.setdefault(client, []).append(now)


def make_handler(control_base: str, events_path: str, password: str | None = None,
                 token_file: str | None = None):
    tokens = TokenFile(token_file)
    limiter = FailLimiter()
    page, csp = page_and_csp()

    class Handler(BaseHTTPRequestHandler):
        timeout = 30   # seconds a connection may sit idle; it holds one of the server's slots

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
                client = self.client_address[0]
                if limiter.blocked(client):
                    self._json(429, {"ok": False, "error": "too many wrong passwords; wait a minute"},
                               {"Retry-After": "60"})
                    return False
                if password_ok(self.headers.get("Authorization"), password):
                    return True
                if self.headers.get("Authorization"):
                    limiter.fail(client)  # a browser's first, credential-less request is no guess
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
                self._send(200, page, "text/html; charset=utf-8",
                           {"Content-Security-Policy": csp, "Referrer-Policy": "no-referrer"})
            elif self.path == "/api/status":
                try:
                    st = control_call(control_base, "/status", timeout=3, token=tokens.get())
                    if st.get("devices_hidden"):   # the token file was replaced: read it again once
                        tokens.reset()
                        st = control_call(control_base, "/status", timeout=3, token=tokens.get())
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
            # Read the body first: replying over unread bytes can reset the connection.
            try:
                n = int(self.headers.get("Content-Length", 0))
            except ValueError:
                n = 0
            if n > 65536:
                self.close_connection = True
                self._json(413, {"ok": False, "error": "request too large"})
                return
            raw = self.rfile.read(n) if n > 0 else b""
            if not self._allowed():
                return
            if self.path != "/api/action":
                self._json(404, {"ok": False, "error": "not found"})
                return
            if not self._same_origin():
                self._json(403, {"ok": False, "error": "cross-origin request refused"})
                return
            try:
                payload = json.loads(raw or b"{}")
                if not isinstance(payload, dict):
                    raise ValueError("expected a JSON object")
                path, body = validate_action(payload)
            except (ValueError, TypeError) as e:
                self._json(400, {"ok": False, "error": str(e)})
                return
            try:
                try:
                    res = control_call(control_base, path, body, timeout=5, token=tokens.get())
                except urllib.error.HTTPError as e:
                    if e.code != 401:
                        raise
                    tokens.reset()  # ghost-dns made a new token; read it again once
                    res = control_call(control_base, path, body, timeout=5, token=tokens.get())
                self._json(200, res)
            except urllib.error.HTTPError as e:
                try:  # pass on the control API's own explanation, e.g. why isolation is refused
                    msg = json.loads(e.read()).get("error") or e.reason
                except (ValueError, OSError, AttributeError):
                    msg = e.reason
                self._json(e.code, {"ok": False, "error": msg})
            except (urllib.error.URLError, OSError) as e:
                self._json(503, {"ok": False, "error": f"resolver unreachable: {e}"})

    return Handler


class RedirectToHttps(BaseHTTPRequestHandler):
    """Plain HTTP on the HTTPS port: send the browser to https:// (old bookmarks)."""

    def _go(self):
        host = self.headers.get("Host") or ""
        if not re.fullmatch(r"[A-Za-z0-9.\-\[\]:]{1,300}", host):
            host = "localhost"
        self.send_response(301)
        self.send_header("Location", f"https://{host}{self.path if self.path.startswith('/') else '/'}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = do_HEAD = _go

    def log_message(self, fmt, *args):
        pass


class DashboardServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that speaks HTTPS when given a TLS context, and answers plain
    HTTP on the same port with a redirect. The TLS handshake happens in the request's
    own thread, so a slow client can't stall the others."""

    daemon_threads = True
    tls: ssl.SSLContext | None = None
    max_connections = 64   # one thread each: idle connections from the LAN must not exhaust a Pi

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)   # too many at once: drop this one
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def finish_request(self, request, client_address):
        if self.tls is None:
            return super().finish_request(request, client_address)
        request.settimeout(10)
        try:
            first = request.recv(1, socket.MSG_PEEK)
        except OSError:
            return
        if first != b"\x16":   # not a TLS handshake: plain HTTP
            RedirectToHttps(request, client_address, self)
            return
        try:
            conn = self.tls.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            self.RequestHandlerClass(conn, client_address, self)
        finally:
            try:
                conn.close()
            except OSError:
                pass


def tls_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ghostwall web UI (password: GHOSTWALL_WEB_PASSWORD env var)")
    ap.add_argument("--bind", default="127.0.0.1", help="bind address; anything but loopback needs a password")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--control", default=DEFAULT_CONTROL)
    ap.add_argument("--events", default=DEFAULT_EVENTS)
    ap.add_argument("--tls-cert", default=os.environ.get("GHOSTWALL_WEB_TLS_CERT") or None,
                    help="serve HTTPS with this certificate (env GHOSTWALL_WEB_TLS_CERT)")
    ap.add_argument("--tls-key", default=os.environ.get("GHOSTWALL_WEB_TLS_KEY") or None,
                    help="its private key (env GHOSTWALL_WEB_TLS_KEY)")
    ap.add_argument("--control-token-file", default=None,
                    help="ghost-dns control-API token (default: /var/lib/ghostwall/control_token if present, "
                         "else next to ghost_dns/state.json; env GHOSTWALL_CONTROL_TOKEN_FILE)")
    args = ap.parse_args(argv)
    # From the environment, not argv, so it never shows up in `ps`.
    password = os.environ.get("GHOSTWALL_WEB_PASSWORD") or None
    if not password and not is_loopback(args.bind):
        print(f"[web-ui] refusing to listen on {args.bind} without a password: set GHOSTWALL_WEB_PASSWORD "
              "(install.sh puts one in /etc/ghostwall/ghostwall.env), or bind 127.0.0.1", file=sys.stderr, flush=True)
        return 2
    srv = DashboardServer((args.bind, args.port), make_handler(args.control, args.events, password,
                                                               args.control_token_file or default_token_path()))
    scheme = "http"
    if args.tls_cert and args.tls_key:
        srv.tls = tls_context(args.tls_cert, args.tls_key)
        scheme = "https"
    elif not is_loopback(args.bind):
        print("[web-ui] note: plain HTTP; the password crosses your network readable "
              "(GHOSTWALL_WEB_TLS_CERT/KEY turn on HTTPS)", file=sys.stderr, flush=True)
    print(f"[web-ui] {scheme}://{args.bind}:{args.port}  password={'on' if password else 'off'}  "
          f"control={args.control}  events={args.events}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
