"""Local control API on 127.0.0.1:5380 -- the server side of docs/REFERENCE.md.

Loopback only, no auth (same trust model as the capture freeze API). Shares the
one GhostState / Enforcer / DeviceMap with the resolver, so a change here takes
effect on the resolver's next query. Every handler returns {"ok": true, ...} or
a non-2xx {"ok": false, "error": ...}.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ControlHandler(BaseHTTPRequestHandler):
    state = {}  # injected: {"gstate":.., "enforcer":.., "devices":.., "cfg":.., "resolver":..}

    # -- helpers ----------------------------------------------------------
    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        if n <= 0:
            return {}
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
        if self.path == "/status":
            self._send(200, self._status())
        else:
            self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        body = self._body()
        if body.get("__bad_json__"):
            self._send(400, {"ok": False, "error": "bad JSON"})
            return
        routes = {
            "/status": self._status,
            "/device": lambda: self._device(body),
            "/isolate": lambda: self._isolate(body),
            "/release": lambda: self._release(body),
            "/allow": lambda: self._allow(body),
            "/lockdown": self._lockdown,
            "/learning": lambda: self._learning(body),
            "/unblock": lambda: self._unblock(body),
        }
        fn = routes.get(self.path)
        if fn is None:
            self._send(404, {"ok": False, "error": "not found"})
            return
        try:
            code, obj = fn() if self.path not in ("/status", "/lockdown") else (200, fn())
        except _ApiError as e:
            self._send(e.code, {"ok": False, "error": e.message})
            return
        except Exception as e:  # noqa: BLE001
            self._send(500, {"ok": False, "error": str(e)})
            return
        self._send(code, obj)

    # -- endpoint implementations ----------------------------------------
    def _status(self) -> dict:
        g = self.state["gstate"]
        dmap = self.state["devices"]
        blocked = sorted(g.blocklist)
        devices = []
        for d in dmap.all():
            devices.append({
                "name": d.name, "ip": d.ip, "mac": d.mac,
                "isolated": g.is_isolated(d.name),
                "blocked_domains": blocked,
            })
        res = self.state.get("resolver")
        return {"ok": True, "devices": devices,
                "lockdown": g.lockdown, "learning": g.learning,
                "shadow": bool(getattr(res, "shadow", False)),
                # counters since start; "queries" rising proves queries are being scored
                "stats": dict(getattr(res, "stats", None) or {})}

    def _device(self, body):
        name = str(body.get("name", "")).strip()
        d = self.state["devices"].device_for_name(name)
        if d is None:
            raise _ApiError(404, "unknown device")
        g = self.state["gstate"]
        return 200, {"ok": True, "name": d.name, "ip": d.ip, "mac": d.mac,
                     "isolated": g.is_isolated(d.name),
                     "blocked_domains": sorted(g.blocklist)}

    def _isolate(self, body):
        d = self._require_device(body)
        self.state["enforcer"].isolate(d.ip)
        self.state["gstate"].isolate(d.name)
        return 200, {"ok": True, "name": d.name, "isolated": True}

    def _release(self, body):
        d = self._require_device(body)
        self.state["enforcer"].release(d.ip)
        self.state["gstate"].release(d.name)
        return 200, {"ok": True, "name": d.name, "isolated": False}

    def _allow(self, body):
        domain = str(body.get("domain", "")).strip().rstrip(".").lower()
        if not domain:
            raise _ApiError(400, "need domain")
        self.state["gstate"].allow(domain)
        return 200, {"ok": True, "domain": domain, "allowed": True}

    def _lockdown(self) -> dict:
        g = self.state["gstate"]
        new = not g.lockdown
        self.state["enforcer"].set_lockdown(new, self.state["cfg"].get("pi_ip", "192.168.1.20"))
        g.set_lockdown(new)
        return {"ok": True, "lockdown": new}

    def _learning(self, body):
        enabled = bool(body.get("enabled", False))
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
        self.state["gstate"].unblock(domain)
        return 200, {"ok": True, "event_id": event_id, "domain": domain,
                     "unblocked": True}

    def _require_device(self, body):
        name = str(body.get("name", "")).strip()
        d = self.state["devices"].device_for_name(name)
        if d is None:
            raise _ApiError(404, "unknown device")
        return d


class _ApiError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ControlServer:
    def __init__(self, cfg, gstate, enforcer, devices, resolver=None):
        inject = {"cfg": cfg, "gstate": gstate, "enforcer": enforcer,
                  "devices": devices, "resolver": resolver}
        handler = type("H", (ControlHandler,), {"state": inject})
        self.httpd = ThreadingHTTPServer((cfg["control_host"], int(cfg["control_port"])),
                                         handler)
        self.httpd.daemon_threads = True

    def serve_forever(self):
        self.httpd.serve_forever()

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
