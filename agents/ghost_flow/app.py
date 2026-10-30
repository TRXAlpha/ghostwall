"""ghost-flow entrypoint: build the inspector and bind the NFQUEUE source.

    python app.py [--config ghost_flow.json] [--queue 100]
                  [--enforce null|nft] [--learning/--no-learning]
                  [--autoblock] [--once]

`--once` builds and prints a readiness line without binding NFQUEUE (smoke test
/ config check). On non-Linux hosts (the dev box) NFQUEUE is unavailable, so
run with --once here and drive the inspector from tests or source.replay.
"""
from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GHOST_DNS = os.path.join(os.path.dirname(HERE), "ghost_dns")
# Insert GHOST_DNS first, then HERE, so HERE wins for shared basenames (config).
sys.path.insert(0, GHOST_DNS)
sys.path.insert(0, HERE)

import config as config_mod           # noqa: E402
from beacon import BeaconDetector     # noqa: E402
from inspector import Inspector       # noqa: E402
from rawip import RawIPDetector       # noqa: E402
from resolved import ResolvedIPs      # noqa: E402
from source import NfqueueSource      # noqa: E402

# from the ghost-dns core:
from capture_client import CaptureClient  # noqa: E402
from devices import DeviceMap             # noqa: E402
from enforce import Enforcer, NftBackend, NullBackend  # noqa: E402
from events import EventLog               # noqa: E402


def build(cfg: dict, autoblock: bool = False):
    resolved = ResolvedIPs(cfg["resolved_ips_path"], int(cfg["resolved_ttl_seconds"]))
    rawip = RawIPDetector(resolved, set(cfg.get("rawip_exceptions", [])))
    beacon = BeaconDetector(
        min_samples=int(cfg["beacon_min_samples"]),
        window_seconds=int(cfg["beacon_window_seconds"]),
        max_cv=float(cfg["beacon_max_cv"]),
        min_interval=float(cfg["beacon_min_interval"]),
    )
    devices = (DeviceMap.load(cfg["devices_json"])
               if os.path.exists(cfg["devices_json"]) else DeviceMap([]))
    event_log = EventLog(cfg["events_path"])
    backend = NftBackend() if cfg.get("enforce") == "nft" else NullBackend()
    enforcer = Enforcer(backend)
    capture = CaptureClient(cfg["capture_url"], enabled=bool(cfg.get("capture_enabled")))
    insp = Inspector(cfg, resolved, rawip, beacon, devices, event_log,
                     enforcer=enforcer, capture=capture, autoblock=autoblock)
    return resolved, rawip, beacon, devices, event_log, enforcer, insp


def main(argv=None):
    ap = argparse.ArgumentParser(description="ghost-flow connection inspector")
    ap.add_argument("--config")
    ap.add_argument("--queue", type=int)
    ap.add_argument("--enforce", choices=["null", "nft"])
    ap.add_argument("--learning", dest="learning", action="store_true", default=None)
    ap.add_argument("--no-learning", dest="learning", action="store_false")
    ap.add_argument("--autoblock", action="store_true",
                    help="allow auto-blocking confirmed beacons (needs --enforce nft and --no-learning)")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)

    cfg = config_mod.load_config(args.config, {
        "enforce": args.enforce, "learning": args.learning,
        "nfqueue_num": args.queue,
    })
    resolved, rawip, beacon, devices, event_log, enforcer, insp = build(cfg, args.autoblock)

    print(f"[ghost-flow] enforce={enforcer.backend.name} learning={insp.learning} "
          f"autoblock={args.autoblock} devices={len(devices.all())} "
          f"queue={cfg['nfqueue_num']}", flush=True)
    print(f"[ghost-flow] resolved<-{cfg['resolved_ips_path']}  events->{cfg['events_path']}",
          flush=True)

    if args.once:
        print("[ghost-flow] --once: built OK, exiting", flush=True)
        return 0

    try:
        NfqueueSource(int(cfg["nfqueue_num"])).run(insp.inspect)
    except ImportError:
        print("[ghost-flow] netfilterqueue not available (need Linux + root). "
              "Use --once here; the Pi service binds the queue.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
