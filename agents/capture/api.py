"""Local HTTP freeze API on 127.0.0.1:5381 (stdlib http.server)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FreezeHandler(BaseHTTPRequestHandler):
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
        if self.path.startswith("/freeze-result"):
            q = self.path.split("=", 1)[-1]
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
        if self.path != "/freeze":
            self._send(404, {"ok": False, "error": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            self._send(400, {"ok": False, "error": "bad JSON"})
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
        # run the freeze in a worker thread so the HTTP reply is immediate
        def worker():
            try:
                meta = fn(device, event_id, body.get("dns_history"))
                self.state.setdefault("results", {})[event_id] = meta
            except Exception as e:  # noqa: BLE001
                self.state.setdefault("results", {})[event_id] = {
                    "error": str(e)}

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
            "results": {}}})
        self.httpd = ThreadingHTTPServerWithResults((cfg["http_host"],
                                                      cfg["http_port"]), handler)

    def serve_forever(self):
        self.httpd.serve_forever()

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ThreadingHTTPServerWithResults(ThreadingHTTPServer):
    daemon_threads = True
