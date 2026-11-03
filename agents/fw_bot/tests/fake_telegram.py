"""Fake Telegram Bot API server for tests. Local http.server, stdlib only.

Records sendMessage / editMessageText / getUpdates calls; delivers scripted
updates from getUpdates. Run in-thread: FakeTelegram(("127.0.0.1", port)).
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeTelegram:
    def __init__(self, addr=("127.0.0.1", 0)):
        self.updates: list[dict] = []       # pending updates to serve
        self.sent: list[dict] = []          # sendMessage results
        self.edits: list[dict] = []         # editMessageText calls
        self.requests: list[tuple[str, dict]] = []  # (method, payload)
        self._offset = 0
        self.fail_sends = 0                 # answer this many sendMessage calls with fail_status
        self.fail_status = 502
        self.fail_updates = 0               # likewise for getUpdates
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, result):
                body = json.dumps({"ok": True, "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
                parts = self.path.split("/")
                method = parts[-1]
                outer.requests.append((method, payload))
                if method == "sendMessage" and outer.fail_sends > 0:
                    outer.fail_sends -= 1
                    self._fail()
                    return
                if method == "sendMessage":
                    outer.sent.append(payload)
                    outer._offset += 1
                    self._reply({"message_id": 100 + outer._offset,
                                 "chat": payload.get("chat")})
                elif method == "editMessageText":
                    outer.edits.append(payload)
                    self._reply(True)
                else:
                    self._reply({})

            def _fail(self):
                body = json.dumps({"ok": False, "error_code": outer.fail_status,
                                   "description": "scripted failure"}).encode()
                self.send_response(outer.fail_status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if "getUpdates" in self.path and outer.fail_updates > 0:
                    outer.fail_updates -= 1
                    self._fail()
                elif "getUpdates" in self.path:
                    batch, outer.updates = outer.updates, []
                    self._reply(batch)
                else:
                    self._reply({})

        self.server = ThreadingHTTPServer(("", 0), Handler)
        self.port = self.server.server_address[1]
        self._thread = None

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *a):
        self.stop()
