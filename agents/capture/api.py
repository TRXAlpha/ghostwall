"""Local HTTP freeze API on 127.0.0.1:5381 (stdlib http.server).

Loopback only, no auth, so it applies the same browser defences as the control
API: a request must name a loopback Host (a DNS-rebinding page names its own
domain) and a POST must be JSON (a cross-site form or no-cors fetch cannot send
that without a CORS preflight, which is never answered). Freezes run in worker
threads, so their number and the results kept are bounded too.
"""
import ipaddress
import json
import threading
import urllib.parse
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 65536
MAX_RUNNING = 4       # concurrent freezes; each one copies ring files for minutes
MAX_RESULTS = 200     # finished freeze results kept for /freeze-result


def loopback_host(host_header):
    """True for a missing Host or one naming loopback (127.0.0.1:5381, [::1], localhost)."""
    if not host_header:
        return True
    host = urllib.parse.urlsplit("//" + host_header).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class FreezeHandler(BaseHTTPRequestHandler):
    timeout = 10  # an idle local connection must not hold a thread forever
    # injected by the server factory: {"ring_manager": ..., "cfg": ...}
    state = {}

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not loopback_host(self.headers.get("Host")):
            self._send(403, {"ok": False, "error": "use 127.0.0.1"})
            return
        if self.path.startswith("/freeze-result"):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("event_id", [""])[0]
            res = self.state.get("results", {}).get(q)
            if res is None:
                self._send(404, {"ok": False, "error": "unknown or pending event"})
            else:
                self._send(200, {"ok": True, "result": res})
            return
        if self.path == "/status":
            mgr = self.state.get("ring_manager")
            rows = mgr.status() if mgr else []
            self._send(200, {"ok": True, "devices": rows})
        else:
            self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        if n > MAX_BODY:
            self.close_connection = True
            self._send(413, {"ok": False, "error": "request too large"})
            return
        raw = self.rfile.read(n) if n > 0 else b""  # read first: replying over unread bytes can reset
        if not loopback_host(self.headers.get("Host")):
            self._send(403, {"ok": False, "error": "use 127.0.0.1"})
            return
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            self._send(415, {"ok": False, "error": "send JSON (Content-Type: application/json)"})
            return
        if self.path != "/freeze":
            self._send(404, {"ok": False, "error": "not found"})
            return
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            self._send(400, {"ok": False, "error": "bad JSON"})
            return
        if not isinstance(body, dict):
            self._send(400, {"ok": False, "error": "expected a JSON object"})
            return
        device = str(body.get("device", "")).strip()
        event_id = str(body.get("event_id", "")).strip()
        if not device or not event_id:
            self._send(400, {"ok": False, "error": "need device and event_id"})
            return
        mgr = self.state.get("ring_manager")
        known = {d["name"] for d in mgr.devices} if mgr else set()
        if device not in known:
            self._send(404, {"ok": False, "error": "unknown device"})
            return
        fn = self.state.get("freeze_fn")
        if fn is None:
            self._send(503, {"ok": False, "error": "freeze not wired"})
            return
        slots = self.state["slots"]
        if not slots.acquire(blocking=False):
            self._send(429, {"ok": False, "error": "too many freezes running; try again later"})
            return

        # run the freeze in a worker thread so the HTTP reply is immediate
        def worker():
            try:
                res = fn(device, event_id, body.get("dns_history"))
            except Exception as e:  # noqa: BLE001
                res = {"error": str(e)}
            finally:
                slots.release()
            results = self.state["results"]
            with self.state["lock"]:
                results[event_id] = res
                results.move_to_end(event_id)
                while len(results) > MAX_RESULTS:
                    results.popitem(last=False)

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        self._send(202, {"ok": True, "event_id": event_id,
                         "status": "freeze started; poll /freeze-result?event_id=..."})

    def log_message(self, fmt, *args):  # quiet
        pass


class FreezeServer:
    def __init__(self, cfg: dict, ring_manager, freeze_fn):
        handler = type("H", (FreezeHandler,), {"state": {
            "cfg": cfg, "ring_manager": ring_manager, "freeze_fn": freeze_fn,
            "results": OrderedDict(), "lock": threading.Lock(),
            "slots": threading.BoundedSemaphore(MAX_RUNNING)}})
        self.httpd = ThreadingHTTPServerWithResults((cfg["http_host"],
                                                      cfg["http_port"]), handler)

    def serve_forever(self):
        self.httpd.serve_forever()

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ThreadingHTTPServerWithResults(ThreadingHTTPServer):
    daemon_threads = True
