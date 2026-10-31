"""ghost-dns entrypoint: build the one shared state, start the control API
thread, and run the DNS resolver loop.

    python app.py [--config ghost_dns.json] [--dns-port 53] [--control-port 5380]
                  [--enforce null|nft] [--learning/--no-learning]
                  [--upstream 127.0.0.1] [--upstream-port 5300] [--once]

`--once` builds everything, prints a readiness line and exits (used by smoke
tests and to validate a config without opening sockets). Defaults are safe:
loopback, learning on, null enforcement (see config.py).
"""
from __future__ import annotations

import argparse
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import config as config_mod          # noqa: E402
from capture_client import CaptureClient  # noqa: E402
from control_api import ControlServer     # noqa: E402
from devices import DeviceMap             # noqa: E402
from enforce import Enforcer, NftBackend, NullBackend  # noqa: E402
from events import EventLog               # noqa: E402
from resolver import Resolver             # noqa: E402
from scoring import Scorer                # noqa: E402
from state import GhostState              # noqa: E402


def build(cfg: dict):
    """Construct all components from a config dict. Returns the pieces so tests
    can drive them without opening any socket."""
    devices = (DeviceMap.load(cfg["devices_json"])
               if os.path.exists(cfg["devices_json"]) else DeviceMap([]))
    gstate = GhostState(cfg["state_path"], learning_default=bool(cfg["learning"]))
    gstate.load_allowlist_file(cfg.get("allowlist_path"))
    scorer = Scorer(cfg.get("onnx_model"), cfg.get("lr_coef"), cfg.get("lr_meta"))
    backend = NftBackend() if cfg.get("enforce") == "nft" else NullBackend()
    enforcer = Enforcer(backend)
    enforcer.lockdown = gstate.lockdown
    event_log = EventLog(cfg["events_path"])
    capture = CaptureClient(cfg["capture_url"], enabled=bool(cfg.get("capture_enabled")))
    resolver = Resolver(cfg, gstate, scorer, enforcer, devices, event_log, capture)
    return devices, gstate, scorer, enforcer, event_log, capture, resolver


def main(argv=None):
    ap = argparse.ArgumentParser(description="ghost-dns resolver + control API")
    ap.add_argument("--config")
    ap.add_argument("--dns-host")
    ap.add_argument("--dns-port", type=int)
    ap.add_argument("--control-host")
    ap.add_argument("--control-port", type=int)
    ap.add_argument("--upstream")
    ap.add_argument("--upstream-port", type=int)
    ap.add_argument("--enforce", choices=["null", "nft"])
    ap.add_argument("--learning", dest="learning", action="store_true", default=None)
    ap.add_argument("--no-learning", dest="learning", action="store_false")
    ap.add_argument("--once", action="store_true", help="build and exit (no sockets)")
    ap.add_argument("--shadow", action="store_true", default=None,
                    help="do NOT serve DNS; score the DNS server's query log instead (safe: stays out of the DNS path)")
    ap.add_argument("--querylog", help="AdGuard querylog.json or Pi-hole pihole.log to follow in shadow mode")
    ap.add_argument("--querylog-format", choices=["auto", "adguard", "pihole"])
    args = ap.parse_args(argv)

    overrides = {
        "dns_host": args.dns_host, "dns_port": args.dns_port,
        "control_host": args.control_host, "control_port": args.control_port,
        "upstream": args.upstream, "upstream_port": args.upstream_port,
        "enforce": args.enforce, "learning": args.learning,
        "shadow": args.shadow, "querylog": args.querylog,
        "querylog_format": args.querylog_format,
    }
    cfg = config_mod.load_config(args.config, overrides)

    devices, gstate, scorer, enforcer, event_log, capture, resolver = build(cfg)

    print(f"[ghost-dns] models={scorer.backend} enforce={enforcer.backend.name} "
          f"learning={gstate.learning} devices={len(devices.all())} "
          f"upstream={cfg['upstream']}:{cfg['upstream_port']}", flush=True)
    if resolver.shadow:
        print(f"[ghost-dns] SHADOW mode: not serving DNS; following {cfg['querylog']}  "
              f"control http://{cfg['control_host']}:{cfg['control_port']}", flush=True)
    else:
        print(f"[ghost-dns] DNS {cfg['dns_host']}:{cfg['dns_port']} (udp+tcp, v6={cfg.get('dns_host6')})  "
              f"control http://{cfg['control_host']}:{cfg['control_port']}", flush=True)

    if args.once:
        print("[ghost-dns] --once: built OK, exiting", flush=True)
        return 0

    control = ControlServer(cfg, gstate, enforcer, devices, resolver)
    t = threading.Thread(target=control.serve_forever, daemon=True)
    t.start()
    follower = None
    try:
        if resolver.shadow:
            from shadow import QueryLogFollower
            follower = QueryLogFollower(resolver, cfg["querylog"], fmt=cfg.get("querylog_format", "auto"))
            print(f"[ghost-dns] query log format: {follower.fmt}", flush=True)
            follower.run()
        else:
            resolver.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if follower:
            follower.stop()
        gstate.flush()
        control.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
