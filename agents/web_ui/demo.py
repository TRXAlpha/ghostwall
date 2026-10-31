#!/usr/bin/env python3
"""Run the dashboard against made-up data, no resolver needed.

    python demo.py [--port 8088]

Starts a fake control API on 127.0.0.1:5381 and the dashboard on --port, with a
sample events file in a temp dir. The domains are ones the detectors really
flagged on a home network; device names, IPs and times are invented. Actions
(trust, isolate, lockdown) work against the fake state.
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

DEVICES = [
    {"name": "laptop", "ip": "192.168.1.10", "mac": "02:00:00:00:00:10"},
    {"name": "phone", "ip": "192.168.1.11", "mac": "02:00:00:00:00:11"},
    {"name": "tv", "ip": "192.168.1.12", "mac": "02:00:00:00:00:12"},
    {"name": "printer", "ip": "192.168.1.13", "mac": "02:00:00:00:00:13"},
    {"name": "console", "ip": "192.168.1.14", "mac": "02:00:00:00:00:14"},
]

# (minutes ago, device, domain, rule, severity, dga score or None, reasons)
SAMPLE = [
    (6, "tv", "xjw4kqpz7rmd.top", "dga_burst", "high", 0.99,
     ["6 random-looking new domains in 10 min", "dga score 0.99", "first seen"]),
    (6, "tv", "pzq8vnhy2kxc.top", "dga_burst", "high", 0.98,
     ["6 random-looking new domains in 10 min", "first seen"]),
    (41, "phone", "cloudflare-dns.com", "doh_bypass", "warn", None,
     ["resolved DoH/DoT provider cloudflare-dns.com", "this device may be bypassing your DNS filter"]),
    (95, "laptop", "qzxkvwjhplrtm5746.top", "dga_high", "high", 1.00,
     ["dga score 1.00", "first seen", "not blocked (shadow mode)"]),
    (180, "printer", "t1.a7f3e9c2.dyndns-ip.net", "dns_beacon", "warn", 0.71,
     ["queried every 300 s (12 samples)", "dga score 0.71"]),
    (300, "phone", "sz-special-overseas.ovgtm.com", "dga_suspect", "warn", 0.70,
     ["dga score 0.70", "first seen"]),
    (410, "laptop", "cdn.fwupd.org", "dga_suspect", "warn", 0.69, ["dga score 0.69", "first seen"]),
    (720, "console", "update-7c1e.duckdns.org", "dga_corroborated", "warn", 0.83,
     ["dga score 0.83", "rarely legitimate TLD", "first seen"]),
    (1100, "laptop", "cloudflare-dns.com", "doh_bypass", "warn", None,
     ["resolved DoH/DoT provider cloudflare-dns.com", "this device may be bypassing your DNS filter"]),
]


def sample_events(now: datetime) -> list[dict]:
    out = []
    for i, (mins, dev, dom, rule, sev, score, reasons) in enumerate(reversed(SAMPLE)):
        ip = next(d["ip"] for d in DEVICES if d["name"] == dev)
        e = {"time": (now - timedelta(minutes=mins)).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "device": dev, "ip": ip, "domain": dom, "rule": rule, "action": "recommend",
             "severity": sev, "event_id": f"evt_demo{i:02d}", "reasons": reasons}
        if score is not None:
            e["scores"] = {"dga": score}
        out.append(e)
    return out


def fake_control(port: int) -> ThreadingHTTPServer:
    st = {"learning": True, "lockdown": False, "isolated": set()}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj):
            b = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _status(self):
            return {"ok": True, "shadow": True, "learning": st["learning"], "lockdown": st["lockdown"],
                    "stats": {"queries": 41873, "recommended": len(SAMPLE), "blocked": 0},
                    "devices": [dict(d, isolated=d["name"] in st["isolated"], blocked_domains=[])
                                for d in DEVICES]}

        def do_GET(self):
            self._json(self._status())

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            p = self.path
            if p == "/learning":
                st["learning"] = bool(body.get("enabled"))
            elif p == "/lockdown":
                st["lockdown"] = not st["lockdown"]
            elif p == "/isolate":
                st["isolated"].add(body.get("name"))
            elif p == "/release":
                st["isolated"].discard(body.get("name"))
            self._json({"ok": True, **body})

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Ghostwall dashboard demo")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--control-port", type=int, default=5381)
    args = ap.parse_args(argv)
    events = os.path.join(tempfile.mkdtemp(prefix="ghostwall-demo-"), "events.jsonl")
    with open(events, "w", encoding="utf-8") as f:
        for e in sample_events(datetime.now(timezone.utc)):
            f.write(json.dumps(e) + "\n")
    fake_control(args.control_port)
    return app.main(["--port", str(args.port), "--control", f"http://127.0.0.1:{args.control_port}",
                     "--events", events])


if __name__ == "__main__":
    raise SystemExit(main())
