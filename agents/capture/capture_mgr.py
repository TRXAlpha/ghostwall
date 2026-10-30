#!/usr/bin/env python3
"""capture_mgr: per-device rolling packet capture + freeze API for the Pi.

Commands:
  start   [--allow-nontmpfs]        start tcpdump rings (foreground, Ctrl-C clean)
  status                            per-device ring usage
  freeze <device> --event-id X [--dns-history FILE | --dns-json JSON]
  serve                             HTTP API on 127.0.0.1:5381 (+ /status)
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (check_ring_dir, load_config, load_devices, ring_usage)
from ring import RingManager, safe_name
from incidents import freeze_incident


def cmd_status(cfg, devices, mgr=None):
    if mgr is None:
        from ring import RingManager
        mgr = RingManager(cfg, devices)
    rows = mgr.status()
    for r in rows:
        print("%-20s %-15s capturing=%-5s files=%-3d %.1f KB" % (
            r["name"], r["ip"], str(r["capturing"]).lower(),
            r["ring_files"], r["ring_bytes"] / 1024))
    return rows


def _load_dns_history(args):
    if args.dns_history:
        with open(args.dns_history, "r", encoding="utf-8") as f:
            return json.load(f)
    if args.dns_json:
        return json.loads(args.dns_json)
    return []


def cmd_freeze(cfg, args):
    devices = load_devices(cfg["devices_json"], cfg["max_devices"])
    if args.device not in {d["name"] for d in devices}:
        raise SystemExit("unknown device: %s" % args.device)
    mgr = _MaybeRingManager(cfg, devices)
    dns = _load_dns_history(args)
    meta = freeze_incident(cfg, args.device, args.event_id, dns, mgr)
    print("incident written: %s (merge=%s)" % (meta["pcap"], meta["merge_method"]))


def cmd_serve(cfg):
    devices = load_devices(cfg["devices_json"], cfg["max_devices"])
    check_ring_dir(cfg, allow_nontmpfs=False)
    from ring import RingManager as RM
    mgr = RM(cfg, devices)
    mgr.start_all()

    def freeze_fn(device, event_id, dns_history):
        return freeze_incident(cfg, device, event_id, dns_history, mgr)

    import api as api_mod
    srv = api_mod.FreezeServer(cfg, mgr, freeze_fn)
    print("capture server on %s:%d, %d device rings; Ctrl-C to stop"
          % (cfg["http_host"], cfg["http_port"], len(devices)))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        mgr.stop_all()
        print("clean shutdown")


def cmd_start(cfg, allow_nontmpfs):
    devices = load_devices(cfg["devices_json"], cfg["max_devices"])
    check_ring_dir(cfg, allow_nontmpfs)
    mgr = RingManager(cfg, devices)
    n = mgr.start_all()
    print("started %d tcpdump rings in %s (Ctrl-C to stop)" % (n, cfg["ring_dir"]))
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        mgr.stop_all()
        print("clean shutdown")


class _MaybeRingManager:
    """Device lookup shim for CLI freeze (no live rings assumed)."""

    def __init__(self, cfg, devices):
        self.cfg = cfg
        self.devices = devices
        self.ring_dir = cfg["ring_dir"]

    def device_ip(self, name):
        for d in self.devices:
            if d["name"] == name:
                return d["ip"]
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("start")
    p.add_argument("--allow-nontmpfs", action="store_true")
    p.add_argument("--devices")
    p.add_argument("--ring-dir")
    p.add_argument("--ring-seconds", type=int)
    p.add_argument("--keep-minutes", type=int)
    p.add_argument("--total-ring-mb", type=float)
    p.add_argument("--interface")
    p.add_argument("--tcpdump", dest="tcpdump")
    p.add_argument("--max-devices", type=int)
    sub.add_parser("status").add_argument("--devices")
    p = sub.add_parser("freeze")
    p.add_argument("device")
    p.add_argument("--event-id", required=True)
    p.add_argument("--dns-history", default=None)
    p.add_argument("--dns-json", default=None)
    p.add_argument("--devices")
    p.add_argument("--ring-dir")
    p.add_argument("--ring-seconds", type=int)
    p.add_argument("--freeze-extra-minutes", type=float)
    p.add_argument("--incidents-dir")
    p.add_argument("--retention-mb", type=float)
    p.add_argument("--allow-nontmpfs", action="store_true")
    sub.add_parser("serve").add_argument("--devices")
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return
    ov = {"devices_json": getattr(args, "devices", None),
          "ring_dir": getattr(args, "ring_dir", None),
          "ring_seconds": getattr(args, "ring_seconds", None),
          "ring_keep_minutes": getattr(args, "keep_minutes", None),
          "total_ring_mb": getattr(args, "total_ring_mb", None),
          "interface": getattr(args, "interface", None),
          "tcpdump": getattr(args, "tcpdump", None),
          "max_devices": getattr(args, "max_devices", None),
          "incidents_dir": getattr(args, "incidents_dir", None),
          "freeze_extra_minutes": getattr(args, "freeze_extra_minutes", None),
          "retention_mb": getattr(args, "retention_mb", None)}
    cfg = load_config(ov)
    if args.cmd == "start":
        cmd_start(cfg, args.allow_nontmpfs)
    elif args.cmd == "status":
        cmd_status(cfg, load_devices(cfg["devices_json"], cfg["max_devices"]))
    elif args.cmd == "freeze":
        cmd_freeze(cfg, args)
    elif args.cmd == "serve":
        cmd_serve(cfg)


if __name__ == "__main__":
    main()
