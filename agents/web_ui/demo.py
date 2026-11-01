#!/usr/bin/env python3
"""Run the dashboard against a made-up day, no resolver needed.

    python demo.py [--port 8088]

Starts a fake control API on 127.0.0.1:5381 and the dashboard on --port, with the
alerts from demo_events.json in a temp dir. Those alerts are not hand-written:
make_demo.py produced them by running the real detector (models, allowlist,
thresholds) over a scripted day on five invented devices. The fake control API
answers like a fresh install in shadow mode; "Trust" works against fake state.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import app

HERE = os.path.dirname(os.path.abspath(__file__))
DEVICES = [
    {"name": "laptop", "ip": "192.168.1.10", "mac": "02:00:00:00:00:10"},
    {"name": "phone", "ip": "192.168.1.11", "mac": "02:00:00:00:00:11"},
    {"name": "tv", "ip": "192.168.1.12", "mac": "02:00:00:00:00:12"},
    {"name": "printer", "ip": "192.168.1.13", "mac": "02:00:00:00:00:13"},
    {"name": "console", "ip": "192.168.1.14", "mac": "02:00:00:00:00:14"},
]


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_demo() -> dict:
    with open(os.path.join(HERE, "demo_events.json"), encoding="utf-8") as f:
        return json.load(f)


def sample_events(now: datetime, demo: dict | None = None) -> list[dict]:
    """demo_events.json with real timestamps, oldest first (as events.jsonl is)."""
    out = []
    for i, e in enumerate(sorted((demo or load_demo())["events"], key=lambda e: -e["minutes_ago"])):
        e = dict(e)
        mins = e.pop("minutes_ago")
        out.append({"time": iso(now - timedelta(minutes=mins)), **e, "event_id": f"evt_demo{i:02d}"})
    return out


def fake_control(port: int, demo: dict) -> ThreadingHTTPServer:
    st = {"learning": True, "lockdown": False}
    now = datetime.now(timezone.utc)
    seen = {d["ip"]: iso(now - timedelta(seconds=20 + 40 * i)) for i, d in enumerate(DEVICES)}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _status(self):
            return {"ok": True, "shadow": True, "source": "adguard", "enforce": "null",
                    "learning": st["learning"], "lockdown": st["lockdown"], "models": demo["models"],
                    "feed": {"domains": 152845, "updated": iso(now - timedelta(hours=7, minutes=12))},
                    "stats": {"queries": demo["queries"], "recommended": len(demo["events"]), "blocked": 0},
                    "devices": [dict(d, isolated=False, last_seen=seen[d["ip"]], blocked_domains=[])
                                for d in DEVICES]}

        def do_GET(self):
            self._json(self._status())

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if self.path == "/allow":
                self._json({"ok": True, **body, "allowed": True})
            else:  # as on a real shadow-mode install: nothing to isolate or lock down
                self._json({"ok": False, "error": "enforcement is off (demo)"}, 409)

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Ghostwall dashboard demo")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--control-port", type=int, default=5381)
    args = ap.parse_args(argv)
    demo = load_demo()
    events = os.path.join(tempfile.mkdtemp(prefix="ghostwall-demo-"), "events.jsonl")
    with open(events, "w", encoding="utf-8") as f:
        for e in sample_events(datetime.now(timezone.utc), demo):
            f.write(json.dumps(e) + "\n")
    fake_control(args.control_port, demo)
    return app.main(["--port", str(args.port), "--control", f"http://127.0.0.1:{args.control_port}",
                     "--events", events])


if __name__ == "__main__":
    raise SystemExit(main())
