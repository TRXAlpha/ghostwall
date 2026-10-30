"""ghost-flow configuration: safe defaults + optional JSON overrides.

Like ghost-dns, defaults are safe: learning mode on (flow findings are
recommendations, the NFQUEUE verdict is always ACCEPT), null enforcement.
ghost-flow and ghost-dns append to the SAME events.jsonl so fw_bot shows DNS
and connection alerts in one stream, and ghost-flow reads ghost-dns's
resolved_ips.jsonl to know which destinations had a DNS lookup.
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
GHOST_DNS = os.path.join(os.path.dirname(HERE), "ghost_dns")
NETCONF = os.path.join(os.path.dirname(HERE), "netconf")

DEFAULTS = {
    # shared with ghost-dns
    "resolved_ips_path": os.path.join(GHOST_DNS, "resolved_ips.jsonl"),
    "events_path": os.path.join(GHOST_DNS, "events.jsonl"),
    "devices_json": os.path.join(NETCONF, "devices.json"),

    # safety
    "learning": True,
    "enforce": "null",          # "null" or "nft"
    "block_on_rawip": False,    # raw-IP alone never auto-blocks, even off learning

    # NFQUEUE (Linux). On the Pi the nft rule is `queue num 100 bypass`.
    "nfqueue_num": 100,

    # raw-IP
    "resolved_ttl_seconds": 3600,
    "rawip_exceptions": [],     # IPs clients legitimately reach without DNS (NTP, etc.)

    # beacon
    "beacon_min_samples": 5,
    "beacon_window_seconds": 3600,
    "beacon_max_cv": 0.15,
    "beacon_min_interval": 5.0,

    # capture freeze on high-severity flow alerts
    "capture_url": "http://127.0.0.1:5381",
    "capture_enabled": False,
    "freeze_severity": "high",
}


def load_config(path: str | None = None, overrides: dict | None = None) -> dict:
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    if overrides:
        cfg.update({k: v for k, v in overrides.items() if v is not None})
    return cfg
