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
    # ...except where a daily repeat is only noise: a phone with "Private DNS" or a browser
    # with "secure DNS" on keeps using its DoH provider; say so once a month, not daily.
    "rule_dedupe_seconds": {"doh_bypass": 30 * 86400, "iot_new_domain": 30 * 86400,
                            "new_domain": 7 * 86400},
    "alert_rate_per_device": 30,    # alerts per device per minute at most (0 = no cap)
    "workers": 16,                  # concurrent in-flight queries
    "resolved_dedupe_seconds": 300,  # min gap before re-logging a resolved IP
    "block_response": "sinkhole",   # "sinkhole" or "nxdomain"
    "sinkhole_ip4": "0.0.0.0",
    "sinkhole_ip6": "::",

    # --- control API (docs/REFERENCE.md) ---
    "control_host": "127.0.0.1",    # loopback only; anything else is refused
    "control_port": 5380,
    "control_token_path": None,     # None: control_token next to state.json; "" turns auth off

    # --- models / scoring ---
    # "default": the shipped TRM + n-gram ensemble (measured on DRIFT).
    # "v3-public": the 1-5-gram model trained on public data, alone (no onnxruntime, about
    # 100 MB less RAM), with thresholds calibrated to the same false-positive rates;
    # see agents/dga_eval/results_v3_public.md. Opt-in: never measured on DRIFT.
    "models": "default",
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
    # nx_burst: one device failing to resolve (NXDOMAIN) this many different unregistered
    # domains within nx_burst_window seconds. Catches DGAs by their failed lookups, also the
    # dictionary-word ones the models miss; agents/dga_eval/nx_sim.py measures it.
    "nx_burst_enabled": True,
    "nx_burst_min_distinct": 10,
    "nx_burst_window": 600,
    "nx_burst_ignore_devices": [],    # names or IPs of boxes that fail lookups on purpose (link checkers)
    "tunnel_min_distinct": 30,        # distinct subdomains of one apex per 10 min
    "beacon_min_samples": 8,          # regular repeats of one name before alerting
    "service_baseline_days": 3,       # abused_service: learn each device's normal services this long
    "beacon_min_dga": 0.5,            # ...and only if the name itself looks odd (apps poll on timers)
    # IoT default-deny (devices marked "profile": "iot" in devices.json; docs/OPERATIONS.md):
    # learn the registrable domains each one looks up for iot_learn_days, then alert on any
    # other. iot_enforce: "off" (alert only), "dry-run" (alert says would_block) or "on"
    # (inline mode with learning off refuses names outside the set; shadow mode never blocks).
    "iot_learn_days": 7,
    "iot_enforce": "off",
    # Newly registered domains (rule new_domain; docs/OPERATIONS.md): a name whose registrable
    # domain is on the NRD list (registered in the last nrd_days days), first seen on this network
    # within novelty_days, not a popular site, not allowlisted. "off" (the list is not even
    # downloaded), "alert" or "block" (inline mode with learning off refuses it; an IoT device's
    # lookup follows iot_enforce; shadow mode never blocks). update_nrd.py (the daily feed
    # service) downloads the list into nrd_path (None = nrd_domains.bin next to the threat feed)
    # only while nrd_mode is not "off". nrd_days: 7 to 35, rounded up to whole weeks.
    "nrd_mode": "off",
    "nrd_days": 14,
    "nrd_path": None,
    "tunnel_min_long": 12,            # distinct 40+ char random subdomains of one apex per 10 min
    "threat_feed_path": os.path.join(HERE, "threat_feed.txt"),  # built by update_feed.py
    # Popular-domain guard: a name whose registrable domain is on this list never raises
    # dga_high/dga_suspect/dga_corroborated on its score alone. It is the Tranco top
    # list update_feed.py caches in rank order (--cache-top or GHOSTWALL_POPULAR_TOP,
    # 1M); popular_top_n takes its first N. None = popular_domains.txt next to
    # threat_feed_path; "" or no file = no guard. On public lists the top 1M cut DGA
    # false positives the most and hid no DGA name: agents/dga_eval/fp_independent.py.
    "popular_path": None,
    # Gateway mode: IP reputation networks (update_ipfeed.py: Spamhaus DROP, abuse.ch C2)
    # that LAN devices may not reach. None = ip_blocklist.txt next to threat_feed_path.
    "ip_blocklist_path": None,
    "popular_top_n": 1000000,

    # --- DNS-server blocking (dns_block.py; docs/OPERATIONS.md "Block with your DNS server") ---
    # The feed becomes a blocklist inside AdGuard Home or Pi-hole, which then refuses the
    # names for every device. Ghostwall stays out of the DNS path: it only generates the
    # list, serves it on dns_block_bind:dns_block_port and tells the DNS server's API.
    # "off" (default: an upgrade never starts blocking by itself), "dry-run" (builds the
    # list and reports what it would block; registers nothing) or "on". Env: DNS_BLOCK_FEED.
    "dns_block_feed": "off",
    "dns_block_ads": "off",             # "off", "pro" or "ultimate": HaGeZi Multi lists. Env: DNS_BLOCK_ADS
    # "on": HaGeZi's DoH/VPN/Tor/Proxy bypass list too (breaks VPN apps and encrypted-DNS apps on
    # purpose). Env: DNS_BLOCK_BYPASS.
    "dns_block_bypass": "off",
    # With dns_block_feed "on": use-application-dns.net (Firefox then turns its own DoH off) and
    # iCloud Private Relay's mask.icloud.com / mask-h2.icloud.com answer NXDOMAIN, so those devices
    # use your DNS. "no-relay" keeps Private Relay working; "off" skips both. Env: DNS_BLOCK_CANARIES.
    "dns_block_canaries": "on",
    "dns_block_bind": "127.0.0.1",     # where the list is served (Docker: 0.0.0.0, reachable on the compose network only)
    "dns_block_port": 5382,
    "dns_block_url": None,              # the URL the DNS server fetches it from (default http://127.0.0.1:<port>/ghostwall-blocklist.txt)
    # Protective upstream: "off", "quad9" or "cloudflare" (set by go_shadow.sh from
    # DNS_PROTECTIVE_UPSTREAM). Names the upstream refuses are recorded as upstream_block
    # and never count for nx_burst. "quad9" also reads an NXDOMAIN without SOA as its block.
    "protective_upstream": "off",

    # --- safety / policy ---
    "learning": True,          # True => score-blocks are recommendations only
    "enforce": "null",         # "null" or "nft"
    "pi_ip": None,             # this box's LAN address; lockdown keeps it reachable
    "novelty_days": 7,         # a domain is "new" until seen for this long
    "auto_promote_after": 3,   # confirmations before a recommend becomes a block

    # --- auto-isolate (opt-in; docs/OPERATIONS.md) ---
    # "off", "dry-run" (events say "would_isolate", nothing changes) or "on". "on" needs
    # gateway mode ("enforce": "nft") and pi_ip; without them it behaves as dry-run, and
    # so it does while `learning` is on (learning means "alerts only") and in shadow mode.
    "auto_isolate": "off",
    # Only rules whose false positives are rare AND whose finding is about the device itself:
    #   threat_feed  exact matches only: never a parent-domain match, a name under a popular
    #                site (Tranco top N: a shared platform or CDN), a service malware abuses
    #                (abused_service) or a name only phishing lists carry (a phishing page
    #                is a person clicking a link, not an infected device). One unclear case
    #                in 19.5 days of field data, a CDN host (docs/FIELD_RESULTS.md).
    #   dns_tunnel   dozens of distinct random subdomains of one apex; the one field false
    #                positive (a game launcher) is fixed and tested.
    # Left out on purpose: nx_burst (no field false positive, but link checkers and mail
    # filters fail lookups legitimately; add it once nx_burst_ignore_devices fits your
    # network) and every score-only rule (dga_*), blocklist, doh_bypass, abused_service and
    # dns_beacon, which fire on normal software. raw_ip, beacon and doh_ip are ghost-flow's
    # and cannot be listed: ghost-flow does not isolate.
    "auto_isolate_rules": ["threat_feed", "dns_tunnel"],
    # Device names (or addresses) never isolated: your own computers, the router. The Pi
    # (pi_ip), loopback, unnamed clients and anything not an IPv4 LAN address never are.
    "auto_isolate_exempt": [],
    "auto_isolate_max_per_hour": 2,  # past this it only alerts and says why (0 = never isolate)

    # --- contain (opt-in; docs/OPERATIONS.md "Contain what was detected") ---
    # What one device was caught reaching is refused for EVERY device for contain_days:
    # Ghostwall refuses the name itself in inline mode; ghostwall-dnsblock pushes it to
    # AdGuard Home / Pi-hole (needs DNS_BLOCK_FEED=on); in gateway mode ("enforce": "nft")
    # the public IPv4 addresses it answered with are dropped to and from, unless another
    # domain answered with the same address (contain_ips false turns the address part off).
    # "off", "dry-run" (events say "would_contain") or "on" ("on" while `learning` is on
    # behaves as dry-run). Never a name you trust, a popular site (Tranco top N), a shared
    # platform (abused_service, dynamic DNS) or an internal name. Undo: ghostwall uncontain.
    "contain": "off",
    # Rules whose finding names one destination with high confidence:
    #   threat_feed  the listed name itself (also blocks it at the gateway by address)
    #   dns_tunnel   the zone the tunnel goes to
    #   dga_high     a name new to this network scoring over block_threshold
    # Also allowed: dns_beacon, dga_corroborated, new_domain (more false positives: your
    # call). Refused: rules that are about a device or a crowd of names, not one destination.
    "contain_rules": ["threat_feed", "dns_tunnel", "dga_high"],
    "contain_days": 7,
    "contain_max_per_day": 20,       # past this it only alerts and says why (0 = never contain)
    "contain_ips": True,

    # --- paths ---
    # Development defaults (next to the code). An installed system keeps state and
    # events in /var/lib/ghostwall and config in /etc/ghostwall; go_shadow.sh writes
    # those paths into /etc/ghostwall/ghost_dns.json.
    "state_path": os.path.join(HERE, "state.json"),
    "events_path": os.path.join(HERE, "events.jsonl"),
    "query_log": None,         # inline mode: a text log of every query (your DNS server keeps one already)
    "devices_json": os.path.join(os.path.dirname(HERE), "netconf", "devices.json"),
    # The kernel's neighbour table (netlink; IPv4 and IPv6): lets a device's name follow
    # its MAC to a new address (devices.py). "" turns that off: names stay with addresses.
    "neighbours_path": "/proc/net/arp",
    "allowlist_path": os.path.join(HERE, "allowlist.txt"),
    "resolved_ips_path": os.path.join(HERE, "resolved_ips.jsonl"),  # inline mode, read by ghost-flow
    "log_max_bytes": 16 * 2**20,  # query_log / resolved_ips_path start over (one .1 kept) past this

    # --- capture freeze trigger (agents/capture/api.py) ---
    "capture_url": "http://127.0.0.1:5381",
    "capture_enabled": False,  # only fire freezes once capture is actually running
    "freeze_severity": "high",  # minimum severity that triggers a pcap freeze
}


IOT_ENFORCE = ("off", "dry-run", "on")
NRD_MODES = ("off", "alert", "block")
AUTO_ISOLATE_MODES = ("off", "dry-run", "on")
# The rules ghost-dns raises (and so can act on). ghost-flow's are named apart: listing one
# would silently do nothing.
DNS_RULES = ("threat_feed", "dns_tunnel", "nx_burst", "dga_burst", "dga_high", "dga_suspect",
             "dga_corroborated", "blocklist", "doh_bypass", "abused_service", "dns_beacon",
             "iot_new_domain", "new_domain")
FLOW_RULES = ("raw_ip", "beacon", "doh_ip")


def _check_auto_isolate(cfg: dict) -> None:
    if cfg.get("auto_isolate") not in AUTO_ISOLATE_MODES:
        raise ValueError(f'auto_isolate must be "off", "dry-run" or "on", not {cfg.get("auto_isolate")!r}')
    rules = cfg.get("auto_isolate_rules")
    if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
        raise ValueError('auto_isolate_rules must be a list of rule names, e.g. ["threat_feed", "dns_tunnel"]')
    for r in rules:
        if r in FLOW_RULES:
            raise ValueError(f"auto_isolate_rules: {r} is a ghost-flow rule, and ghost-flow does not "
                             "isolate; remove it")
        if r not in DNS_RULES:
            raise ValueError(f"auto_isolate_rules: unknown rule {r!r} (one of: {', '.join(DNS_RULES)})")
    exempt = cfg.get("auto_isolate_exempt")
    if not isinstance(exempt, list) or not all(isinstance(x, str) for x in exempt):
        raise ValueError('auto_isolate_exempt must be a list of device names, e.g. ["workpc"]')
    cap = cfg.get("auto_isolate_max_per_hour")
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 0:
        raise ValueError(f"auto_isolate_max_per_hour must be a whole number, 0 or more, not {cap!r}")

CONTAIN_RULES = ("threat_feed", "dns_tunnel", "dga_high", "dns_beacon", "dga_corroborated", "new_domain")


def _check_contain(cfg: dict) -> None:
    if cfg.get("contain") not in AUTO_ISOLATE_MODES:
        raise ValueError(f'contain must be "off", "dry-run" or "on", not {cfg.get("contain")!r}')
    rules = cfg.get("contain_rules")
    if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
        raise ValueError('contain_rules must be a list of rule names, e.g. ["threat_feed", "dns_tunnel"]')
    for r in rules:
        if r not in CONTAIN_RULES:
            raise ValueError(f"contain_rules: {r!r} does not name one destination with confidence "
                             f"(one of: {', '.join(CONTAIN_RULES)})")
    days = cfg.get("contain_days")
    if isinstance(days, bool) or not isinstance(days, (int, float)) or not 0 < days <= 365:
        raise ValueError(f"contain_days must be a number of days from above 0 to 365, not {days!r}")
    cap = cfg.get("contain_max_per_day")
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 0:
        raise ValueError(f"contain_max_per_day must be a whole number, 0 or more, not {cap!r}")


V3_PUBLIC = {
    "onnx_model": None,
    "lr_coef": os.path.join(ROOT, "ghostwall", "models", "lr_v3_public.npy"),
    "lr_meta": os.path.join(ROOT, "ghostwall", "models", "lr_v3_public.json"),
}


def load_config(path: str | None = None, overrides: dict | None = None) -> dict:
    cfg = dict(DEFAULTS)
    mine: set = set()   # keys the user set; a model preset never overrides those
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            user = json.load(f)
        cfg.update(user)
        mine |= set(user)
    if overrides:
        given = {k: v for k, v in overrides.items() if v is not None}
        cfg.update(given)
        mine |= set(given)
    if cfg.get("ip_blocklist_path") is None and cfg.get("threat_feed_path"):
        cfg["ip_blocklist_path"] = os.path.join(os.path.dirname(cfg["threat_feed_path"]), "ip_blocklist.txt")
    if cfg.get("nrd_path") is None and cfg.get("threat_feed_path"):
        cfg["nrd_path"] = os.path.join(os.path.dirname(cfg["threat_feed_path"]), "nrd_domains.bin")
    if cfg.get("popular_path") is None and cfg.get("threat_feed_path"):
        cfg["popular_path"] = os.path.join(os.path.dirname(cfg["threat_feed_path"]), "popular_domains.txt")
    if cfg.get("models") == "v3-public":
        for k, v in V3_PUBLIC.items():
            if k not in mine:
                cfg[k] = v
        try:
            with open(cfg["lr_meta"], encoding="utf-8") as f:
                calibrated = json.load(f).get("thresholds", {})
        except (OSError, ValueError):
            calibrated = {}
        for k, v in calibrated.items():
            if k in DEFAULTS and k not in mine:
                cfg[k] = float(v)
    elif cfg.get("models") not in (None, "default"):
        raise ValueError(f'models must be "default" or "v3-public", not {cfg.get("models")!r}')
    if cfg.get("iot_enforce") not in IOT_ENFORCE:   # a typo must not quietly mean "off"
        raise ValueError(f'iot_enforce must be "off", "dry-run" or "on", not {cfg.get("iot_enforce")!r}')
    if cfg.get("nrd_mode") not in NRD_MODES:
        raise ValueError(f'nrd_mode must be "off", "alert" or "block", not {cfg.get("nrd_mode")!r}')
    days = cfg.get("nrd_days")
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 35:
        raise ValueError(f"nrd_days must be a whole number from 1 to 35 (rounded up to whole weeks), not {days!r}")
    _check_auto_isolate(cfg)
    _check_contain(cfg)
    return cfg
