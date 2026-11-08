"""Local control API on 127.0.0.1:5380 -- the server side of docs/REFERENCE.md.

Loopback only, no auth (same trust model as the capture freeze API). Shares the
one GhostState / Enforcer / DeviceMap with the resolver, so a change here takes
effect on the resolver's next query. Every handler returns {"ok": true, ...} or
a non-2xx {"ok": false, "error": ...}.

Loopback is not one caller, though: every local user and process on the box can
reach it, and so can a web page in a browser there. So:
  * a request must name a loopback Host (a DNS-rebinding page names its own domain);
  * a POST must be JSON (a cross-site form or a no-cors fetch cannot send that
    content type without a CORS preflight, which is never answered here);
  * every action (anything but /status) needs `Authorization: Bearer <token>`. The
    token is generated on first start into a file only the ghostwall user can read
    (control_token_path, /var/lib/ghostwall/control_token when installed), so the
    dashboard and the Telegram bot can act and other local users cannot;
  * /status without the token is a summary (mode, counters, how many devices): the
    device list (names, IPs, MACs, when each was last online) needs the token too.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tokenizer import registrable_part

# A hostname: dot-separated labels of letters, digits, '-' and '_' (some real names
# have it), 253 characters at most. Anything else can't be a name worth trusting.
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")

ENFORCEMENT_OFF = ('enforcement is off: isolation and lockdown need "enforce": "nft" and '
                   'gateway mode (docs/OPERATIONS.md)')


def loopback_host(host_header: str | None) -> bool:
    """True for a missing Host or one naming loopback: 127.0.0.1:5380, [::1], localhost."""
    if not host_header:
        return True
    host = urllib.parse.urlsplit("//" + host_header).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def ensure_token(path: str) -> str:
    """Read the control token from path, creating it (mode 0600) on first use."""
    try:
        with open(path, encoding="utf-8") as f:
            tok = f.read().strip()
        if tok:
            return tok
    except FileNotFoundError:
        pass
    tok = secrets.token_urlsafe(32)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(tok + "\n")
    os.replace(tmp, path)
    return tok


def token_path(cfg: dict) -> str | None:
    """The configured token file; by default next to state.json. "" or false disables auth."""
    p = cfg.get("control_token_path", None)
    if p is None:
        return os.path.join(os.path.dirname(os.path.abspath(cfg["state_path"])), "control_token")
    return p or None


class ControlHandler(BaseHTTPRequestHandler):
    timeout = 10  # an idle local connection must not hold a thread forever
    state = {}  # injected: {"gstate":.., "enforcer":.., "devices":.., "cfg":.., "resolver":.., "token":..}

    # -- helpers ----------------------------------------------------------
    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        try:
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # The client gave up first (a status poll with a short timeout, a restart):
            # nothing to answer, and not worth a traceback in the journal.
            self.close_connection = True

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        if n > 65536:  # every real request is a few bytes
            self.close_connection = True
            return {"__too_big__": True}
        raw = self.rfile.read(n)
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            return {"__bad_json__": True}
        return data if isinstance(data, dict) else {}

    def log_message(self, fmt, *args):  # quiet
        pass

    # -- dispatch ---------------------------------------------------------
    def do_GET(self):
        if not loopback_host(self.headers.get("Host")):
            self._send(403, {"ok": False, "error": "use 127.0.0.1"})
        elif self.path == "/status":
            self._send(200, self._status(full=self._authorized()))
        else:
            self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        body = self._body()  # read first: replying over unread bytes can reset the connection
        if body.get("__too_big__"):
            self._send(413, {"ok": False, "error": "request too large"})
            return
        if not loopback_host(self.headers.get("Host")):
            self._send(403, {"ok": False, "error": "use 127.0.0.1"})
            return
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            self._send(415, {"ok": False, "error": "send JSON (Content-Type: application/json)"})
            return
        if body.get("__bad_json__"):
            self._send(400, {"ok": False, "error": "bad JSON"})
            return
        if self.path == "/status" and not self._authorized():
            self._send(200, self._status(full=False))
            return
        if not self._authorized():
            self._send(401, {"ok": False, "error": "need Authorization: Bearer <token> "
                             "(the token is in control_token next to state.json)"})
            return
        routes = {
            "/status": lambda: self._status(full=True),   # (unauthorized: answered below)
            "/device": lambda: self._device(body),
            "/isolate": lambda: self._isolate(body),
            "/release": lambda: self._release(body),
            "/allow": lambda: self._allow(body),
            "/trusted": self._trusted,
            "/untrust": lambda: self._untrust(body),
            "/lockdown": self._lockdown,
            "/learning": lambda: self._learning(body),
            "/unblock": lambda: self._unblock(body),
            "/relearn": lambda: self._relearn(body),
        }
        fn = routes.get(self.path)
        if fn is None:
            self._send(404, {"ok": False, "error": "not found"})
            return
        try:
            code, obj = fn() if self.path != "/status" else (200, fn())
        except _ApiError as e:
            self._send(e.code, {"ok": False, "error": e.message})
            return
        except Exception as e:  # noqa: BLE001
            self._send(500, {"ok": False, "error": str(e)})
            return
        self._send(code, obj)

    def _authorized(self) -> bool:
        token = self.state.get("token")
        if not token:
            return True  # auth switched off (control_token_path: "")
        given = self.headers.get("Authorization") or ""
        if not given.startswith("Bearer "):
            return False
        return hmac.compare_digest(given[7:].strip().encode("utf-8"), token.encode("utf-8"))

    # -- endpoint implementations ----------------------------------------
    def _status(self, full: bool = True) -> dict:
        """full: with the device list (needs the token). Without it, anyone on the box
        could learn every device's name, IP and MAC and when each was last online."""
        g = self.state["gstate"]
        dmap = self.state["devices"]
        res = self.state.get("resolver")
        seen = getattr(res, "last_seen", {})
        blocked = sorted(g.blocklist)
        devices = []
        for d in dmap.all():
            ip = self._current_ip(d)
            devices.append({
                "name": d.name, "ip": ip, "mac": d.mac,
                "isolated": g.is_isolated(d.name),
                "last_seen": seen.get(ip),
                "blocked_domains": blocked,
                **self._iot_status(d),
            })
        named = {self._current_ip(d) for d in dmap.all()}
        # clients seen but not named yet (for `ghostwall devices` / `ghostwall name`)
        clients = sorted(((t, ip) for ip, t in seen.items() if ip not in named), reverse=True)[:50]
        out = {"ok": True, "named_devices": len(devices), "unnamed_clients": len(clients),
               "lockdown": g.lockdown, "learning": g.learning,
               "shadow": bool(getattr(res, "shadow", False)),
               "source": getattr(res, "source", None),
               "enforce": self.state["enforcer"].backend.name,
               # counters since start; "queries" rising proves queries are being scored
               "stats": dict(getattr(res, "stats", None) or {})}
        out["iot_enforce"] = self.state["cfg"].get("iot_enforce", "off")
        scorer = getattr(res, "scorer", None)
        if scorer is not None:
            out["models"] = getattr(scorer, "backend", None)
        feed = getattr(getattr(res, "det", None), "threat_feed", None)
        if feed is not None:
            n, mtime = feed.info()
            out["feed"] = {"domains": n, "updated": datetime.fromtimestamp(mtime, timezone.utc)
                           .strftime("%Y-%m-%dT%H:%M:%SZ") if mtime else None}
        popular = getattr(getattr(res, "det", None), "popular", None)
        if popular is not None:
            n, mtime = popular.info()
            out["popular"] = {"domains": n, "updated": datetime.fromtimestamp(mtime, timezone.utc)
                              .strftime("%Y-%m-%dT%H:%M:%SZ") if mtime else None}
        if full:
            out["devices"] = devices
            out["clients"] = [{"ip": ip, "last_seen": t} for t, ip in clients]
        else:
            out["devices_hidden"] = True   # "send the token to see them", not "no devices"
        return out

    def _iot_status(self, d) -> dict:
        """An IoT device's profile, how many domain families it has, and until when it learns."""
        if str(d.profile).lower() != "iot":
            return {}
        g = self.state["gstate"]
        out = {"profile": "iot", "iot_domains": g.iot_count(d.name), "iot_learning_until": None}
        since = g.iot_since(d.name)
        if since:
            try:
                start = datetime.strptime(since, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                days = float(self.state["cfg"].get("iot_learn_days", 7))
                out["iot_learning_until"] = (start + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                pass
        return out

    def _device(self, body):
        name = str(body.get("name", "")).strip()
        d = self.state["devices"].device_for_name(name)
        if d is None:
            raise _ApiError(404, "unknown device")
        g = self.state["gstate"]
        seen = getattr(self.state.get("resolver"), "last_seen", {})
        ip = self._current_ip(d)
        return 200, {"ok": True, "name": d.name, "ip": ip, "mac": d.mac,
                     "isolated": g.is_isolated(d.name),
                     "last_seen": seen.get(ip),
                     "blocked_domains": sorted(g.blocklist)}

    def _require_enforcement(self) -> None:
        # The null backend would only record the wish; saying "isolated" for that is
        # worse than refusing, because it looks like the device was cut off.
        if self.state["enforcer"].backend.name == "null":
            raise _ApiError(409, ENFORCEMENT_OFF)

    def _isolate(self, body):
        d = self._require_device(body)
        self._require_enforcement()
        ip = self._current_ip(d)   # where it is now: its old address may be another device's
        if not _ipv4(ip) and _ipv4(d.ip):
            ip = d.ip              # it queried over IPv6; the isolated_dev set holds IPv4 only
        self.state["enforcer"].isolate(ip)
        self.state["gstate"].isolate(d.name, ip)
        return 200, {"ok": True, "name": d.name, "ip": ip, "isolated": True}

    def _release(self, body):
        # Allowed without enforcement too, so state left by an older version can be cleared.
        # Idempotent: an address that is not in the set any more (a second press, a reboot
        # emptied it) counts as released. Every address it may have been isolated at is
        # tried: the ones recorded when it was isolated, where it is now, devices.json.
        d = self._require_device(body)
        g = self.state["gstate"]
        ips = []
        for ip in g.isolated_addresses(d.name) + [self._current_ip(d), d.ip]:
            if ip and ip not in ips and _ipv4(ip):
                ips.append(ip)
        failed = None
        for ip in ips:
            try:
                self.state["enforcer"].release(ip)
            except Exception as exc:  # noqa: BLE001 (nft missing, no permission...)
                failed = failed or exc
        if failed is not None:
            # Still in the set somewhere: saying "released" would be a lie. State stays
            # isolated, so the dashboard keeps offering Release.
            raise _ApiError(500, f"could not release {d.name}: {failed}")
        g.release(d.name)
        return 200, {"ok": True, "name": d.name, "isolated": False}

    def _allow(self, body):
        domain = str(body.get("domain", "")).strip().rstrip(".").lower()
        if not domain:
            raise _ApiError(400, "need domain")
        if not DOMAIN_RE.match(domain):
            raise _ApiError(400, "not a domain name")
        if str(body.get("device", "")).strip():
            # Trust on an iot_new_domain alert: that device's set only, not the allowlist
            d = self._iot_device(body)
            reg = registrable_part(domain)
            self.state["gstate"].iot_allow(d.name, reg)
            return 200, {"ok": True, "domain": reg, "device": d.name, "allowed": True}
        self.state["gstate"].allow(domain)
        return 200, {"ok": True, "domain": domain, "allowed": True}

    def _iot_device(self, body):
        name = str(body.get("device", "")).strip()
        d = self.state["devices"].device_for_name(name)
        if d is None:
            raise _ApiError(404, "unknown device")
        if str(d.profile).lower() != "iot":
            raise _ApiError(409, f'{d.name} is not marked "profile": "iot" in devices.json')
        return d

    def _relearn(self, body):
        """Forget what an IoT device normally talks to: it learns again from its next lookup."""
        d = self._iot_device({"device": body.get("name", "")})
        self.state["gstate"].iot_relearn(d.name)
        return 200, {"ok": True, "name": d.name, "relearning": True}

    def _trusted(self):
        return 200, {"ok": True, "domains": self.state["gstate"].trusted()}

    def _untrust(self, body):
        domain = str(body.get("domain", "")).strip().rstrip(".").lower()
        if not DOMAIN_RE.match(domain):
            raise _ApiError(400, "not a domain name")
        g = self.state["gstate"]
        if str(body.get("device", "")).strip():   # undo an "allow for this device"
            d = self._iot_device(body)
            if not g.iot_forget(d.name, domain):
                raise _ApiError(404, f"{registrable_part(domain)} is not in what {d.name} normally talks to")
            return 200, {"ok": True, "domain": registrable_part(domain), "device": d.name, "allowed": False}
        if domain in g.static_allow:
            raise _ApiError(409, f"{domain} is in the starter allowlist file (allowlist_path); remove it there")
        if not g.untrust(domain):
            raise _ApiError(404, f"{domain} is not trusted")
        return 200, {"ok": True, "domain": domain, "allowed": False}

    def _lockdown(self):
        self._require_enforcement()
        pi_ip = self.state["cfg"].get("pi_ip")
        if not pi_ip:
            raise _ApiError(409, 'set "pi_ip" (this box\'s LAN address) in ghost_dns.json first')
        g = self.state["gstate"]
        new = not g.lockdown
        self.state["enforcer"].set_lockdown(new, pi_ip)
        g.set_lockdown(new)
        return 200, {"ok": True, "lockdown": new}

    def _learning(self, body):
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            raise _ApiError(400, 'need {"enabled": true} or {"enabled": false}')
        self.state["gstate"].set_learning(enabled)
        return 200, {"ok": True, "learning": enabled}

    def _unblock(self, body):
        event_id = str(body.get("event_id", "")).strip()
        domain = str(body.get("domain", "")).strip().rstrip(".").lower()
        if not domain and event_id:
            evt = self.state["gstate"].event(event_id)
            if evt and evt.get("domain"):
                domain = evt["domain"]
        if not domain:
            raise _ApiError(400, "need domain or a known event_id")
        if not DOMAIN_RE.match(domain):
            raise _ApiError(400, "not a domain name")
        g = self.state["gstate"]
        undo = body.get("undo") is True
        if undo:    # `ghostwall unblock --undo`: let the DNS server block it again
            g.set_dns_exception(domain, False)
            return 200, {"ok": True, "domain": domain, "unblocked": False}
        g.unblock(domain)
        g.set_dns_exception(domain)    # also an exception in the DNS server's blocklists (dns_block.py)
        return 200, {"ok": True, "event_id": event_id, "domain": domain,
                     "unblocked": True}

    def _current_ip(self, d) -> str:
        """The address a named device last queried from (its name follows its MAC,
        devices.py), else the one in devices.json."""
        cur = getattr(self.state.get("resolver"), "current_ip", None) or {}
        return cur.get(d.name, d.ip)

    def _require_device(self, body):
        name = str(body.get("name", "")).strip()
        d = self.state["devices"].device_for_name(name)
        if d is None:
            raise _ApiError(404, "unknown device")
        return d


def _ipv4(ip) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).version == 4
    except ValueError:
        return False


class _ApiError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ControlServer:
    def __init__(self, cfg, gstate, enforcer, devices, resolver=None, token: str | None = None):
        host = cfg["control_host"]
        if not loopback_host(host if ":" not in host else f"[{host}]"):
            # No TLS and one shared token: this API must never be reachable from the LAN.
            raise ValueError(f"control_host must be a loopback address, not {host!r}")
        inject = {"cfg": cfg, "gstate": gstate, "enforcer": enforcer,
                  "devices": devices, "resolver": resolver, "token": token}
        handler = type("H", (ControlHandler,), {"state": inject})
        self.httpd = ThreadingHTTPServer((cfg["control_host"], int(cfg["control_port"])),
                                         handler)
        self.httpd.daemon_threads = True

    def serve_forever(self):
        self.httpd.serve_forever()

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
