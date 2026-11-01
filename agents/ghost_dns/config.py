"""ghost-dns configuration: safe defaults + optional JSON overrides.

Defaults are chosen so a fresh start is SAFE: learning mode on (score-based
blocks become recommendations only), enforcement backend null (no kernel
changes), and the resolver binds to loopback. Going live on the Pi means
pointing --config at a file that flips `learning` off, sets the nft backend,
and binds eth0 -- a deliberate, reviewed step.
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

DEFAULTS = {
    # --- DNS listener ---
    "dns_host": "127.0.0.1",
    "dns_port": 53,
    "upstream": "127.0.0.1",   # on the Pi this is AdGuard Home (e.g. 127.0.0.1:5300)
    "upstream_port": 53,
    "dns_timeout": 2.0,
    # Shadow mode: don't serve DNS at all; score AdGuard's or Pi-hole's query log
    # instead. The DNS server keeps port 53, so Ghostwall can never break your DNS.
    "shadow": False,
    "querylog": "/opt/AdGuardHome/data/querylog.json",
    "querylog_format": "auto",      # "adguard" (querylog.json), "pihole" (pihole.log) or "auto"
    "dns_host6": "::",              # IPv6 listener (UDP+TCP); set null to disable
    "tcp_timeout": 5,
    # If the primary upstream (AdGuard) is down, answer from these instead of
    # failing: one dead upstream must never mean "no internet". Set [] to disable.
    "upstream_fallbacks": ["9.9.9.9"],
    "primary_retry_seconds": 10,    # skip a failed primary this long before retrying
    "event_dedupe_seconds": 86400,  # one alert per device per domain family per day
    "workers": 16,                  # concurrent in-flight queries
    "resolved_dedupe_seconds": 300,  # min gap before re-logging a resolved IP
    "block_response": "sinkhole",   # "sinkhole" or "nxdomain"
    "sinkhole_ip4": "0.0.0.0",
    "sinkhole_ip6": "::",

    # --- control API (docs/REFERENCE.md) ---
    "control_host": "127.0.0.1",
    "control_port": 5380,

    # --- models / scoring ---
    "onnx_model": os.path.join(ROOT, "ghostwall", "models", "trm_dga_v2.onnx"),
    "lr_coef": os.path.join(ROOT, "ghostwall", "models", "lr_coef.npy"),
    "lr_meta": os.path.join(ROOT, "ghostwall", "models", "lr_meta.json"),
    # Thresholds are set from measurement, not guesswork. On 50k benign + 50k DGA
    # domains from each of the frozen 2024 and 2025 test years, the shipped mean scores:
    #   >=0.60 -> flags ~6.5% of NORMAL domains (what made the first deploy so noisy)
    #   >=0.90 -> flags ~2.0% of normal domains (would block 1 in 50 normal domains)
    #   >=0.96 -> ~1% false positives, ~61% of DGA caught
    #   >=0.995-> ~0.2% false positives, ~47% of DGA caught
    # On normal names never seen in training the false positives about double (~2%,
    # ~0.4%). agents/dga_eval/eval_shipped.py reproduces all of these.
    # A single score cannot do better, so the rest of the detection comes from the
    # behavioural/evidence detectors in detectors.py.
    "recommend_threshold": 0.96,
    "block_threshold": 0.995,
    "corroborated_threshold": 0.80,   # alert at this score only with a rare TLD
    "suspect_only_new": True,         # plain suspect alerts only for names new to this network
    "burst_min_score": 0.80,          # DGA burst: score a domain must reach to count...
    "burst_min_distinct": 5,          # ...and how many different ones from one device
    "tunnel_min_distinct": 30,        # distinct subdomains of one apex per 10 min
    "beacon_min_samples": 8,          # regular repeats of one name before alerting
    "beacon_min_dga": 0.5,            # ...and only if the name itself looks odd (apps poll on timers)
    "tunnel_min_long": 12,            # distinct 40+ char random subdomains of one apex per 10 min
    "threat_feed_path": os.path.join(HERE, "threat_feed.txt"),  # built by update_feed.py

    # --- safety / policy ---
    "learning": True,          # True => score-blocks are recommendations only
    "enforce": "null",         # "null" or "nft"
    "pi_ip": None,             # this box's LAN address; lockdown keeps it reachable
    "novelty_days": 7,         # a domain is "new" until seen for this long
    "auto_promote_after": 3,   # confirmations before a recommend becomes a block

    # --- paths ---
    # Development defaults (next to the code). An installed system keeps state and
    # events in /var/lib/ghostwall and config in /etc/ghostwall; go_shadow.sh writes
    # those paths into /etc/ghostwall/ghost_dns.json.
    "state_path": os.path.join(HERE, "state.json"),
    "events_path": os.path.join(HERE, "events.jsonl"),
    "query_log": None,         # inline mode: a text log of every query (your DNS server keeps one already)
    "devices_json": os.path.join(os.path.dirname(HERE), "netconf", "devices.json"),
    "allowlist_path": os.path.join(HERE, "allowlist.txt"),
    "resolved_ips_path": os.path.join(HERE, "resolved_ips.jsonl"),  # inline mode, read by ghost-flow
    "log_max_bytes": 16 * 2**20,  # query_log / resolved_ips_path start over (one .1 kept) past this

    # --- capture freeze trigger (agents/capture/api.py) ---
    "capture_url": "http://127.0.0.1:5381",
    "capture_enabled": False,  # only fire freezes once capture is actually running
    "freeze_severity": "high",  # minimum severity that triggers a pcap freeze
}


def load_config(path: str | None = None, overrides: dict | None = None) -> dict:
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    if overrides:
        cfg.update({k: v for k, v in overrides.items() if v is not None})
    return cfg
