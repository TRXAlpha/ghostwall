# Reference

The control API, the event format, ghost-dns configuration keys and command-line
flags.

## Control API

HTTP/JSON on `127.0.0.1:5380`, served by `ghost-dns` (`control_api.py`), used by the
dashboard and Telegram bot. It refuses to start on anything but a loopback address.
Loopback is still shared by every local user and by web pages in a browser on the
same machine, so:

- every request must name a loopback `Host` such as `127.0.0.1:5380` (else 403, which
  stops DNS rebinding);
- POSTs must send `Content-Type: application/json` (else 415);
- every endpoint except `/status` needs `Authorization: Bearer <token>` (else 401). `/status`
  answers without it too, but then as a summary: no `devices` or `clients`, `"devices_hidden": true`
  instead (any local user or process can reach the port, and the list names every device,
  its IP and MAC and when it was last online).
  `ghost-dns` creates the token on first start in `control_token` next to `state.json`
  (`/var/lib/ghostwall/control_token` when installed, `/data/control_token` in Docker),
  readable only by the `ghostwall` user. The dashboard and the bot read it from there.

```bash
curl -X POST http://127.0.0.1:5380/allow -H 'Content-Type: application/json' \
     -H "Authorization: Bearer $(sudo cat /var/lib/ghostwall/control_token)" -d '{"domain":"example.com"}'
```

Every response is a JSON object: `{"ok": true, ...}` on success, or a non-2xx status
with `{"ok": false, "error": "..."}`. All endpoints take POST with a JSON body;
`/status` also accepts GET.

| Endpoint | Body | Returns |
|---|---|---|
| `/status` | — | `devices` (name, ip, mac, isolated, last_seen, blocked_domains) and `clients` (unnamed addresses seen, newest first, up to 50): with the token only; `named_devices`, `unnamed_clients` (counts), `lockdown`, `learning`, `shadow`, `source` (`adguard` or `pihole` in shadow mode), `enforce` (`null` or `nft`), `models`, `feed` (`domains`, `updated`), `stats` (counters since start; `queries` rising means it is scoring; `suppressed` counts repeat alerts, `rate_limited` alerts dropped by `alert_rate_per_device`, `blocked_upstream` random-looking names AdGuard had already blocked) |
| `/device` | `{"name": "laptop"}` | that device plus `last_seen` (its latest query since ghost-dns started, or null); 404 if unknown |
| `/isolate` | `{"name": "laptop"}` | `{"name", "ip", "isolated": true}`: the device may only reach the Pi's DNS. `ip` is where it queried from last (its name follows its MAC), not necessarily the address in `devices.json`. 409 unless `enforce` is `nft` |
| `/release` | `{"name": "laptop"}` | `{"name", "isolated": false}`. Idempotent: tries the address recorded at isolation, the current one and the devices.json one. 500 if nft refuses (the device stays isolated). CLI: `sudo ghostwall release NAME` (alias `unisolate`); Telegram: the Release device button on an isolated alert |
| `/allow` | `{"domain": "example.com"}` | `{"domain", "allowed": true}`: allowlisted network-wide. 400 unless it is a hostname. With `"device": "cam-1"`: adds the domain family to that IoT device's own set only (404 for an unknown device, 409 if it is not IoT) |
| `/trusted` | `{}` | `{"domains": [...]}`: what was trusted with `/allow` (the starter `allowlist.txt` aside) |
| `/relearn` | `{"name": "cam-1"}` | forgets an IoT device's learned set; learning starts again with its next lookup. 409 if it is not IoT |
| `/untrust` | `{"domain": "example.com"}` | `{"domain", "allowed": false}`: undoes `/allow`; 409 for a starter-file entry, 404 if not trusted |
| `/lockdown` | `{}` | `{"lockdown": bool}`: toggles; drops forwarded traffic except to the Pi and tailnet. 409 unless `enforce` is `nft` and `pi_ip` is set |
| `/learning` | `{"enabled": true\|false}` | `{"learning": bool}`: learning on means alerts only. Anything but a boolean is a 400 |
| `/unblock` | `{"event_id": "...", "domain": "..."}` | `{"event_id", "unblocked": true}` (alert buttons) |

Isolation and lockdown change the kernel's nftables, so they exist only with
`"enforce": "nft"`; with the default null backend they are refused rather than
pretended.

## events.jsonl

One JSON object per line, written by `ghost-dns` and `ghost-flow`, read by the
dashboard and `fw_bot`. `agents/fw_bot/validate_events.py <file>` checks a file
against this schema (exit 1 on any invalid line).

| Field | Required | Notes |
|---|---|---|
| `time` | yes | ISO 8601 UTC, e.g. `2026-10-20T21:04:05Z` |
| `device` | yes | device name from `devices.json`, or the client IP |
| `domain` | yes | lowercase, no trailing dot |
| `rule` | yes | `threat_feed`, `dga_burst`, `nx_burst`, `dga_high`, `dga_suspect`, `dga_corroborated`, `doh_bypass`, `abused_service`, `dns_tunnel`, `dns_beacon`, `iot_new_domain`, `upstream_block` (info, action allow: the upstream resolver refused it), `blocklist`, `raw_ip`, `doh_ip`, `beacon` |
| `action` | yes | `block`, `recommend` or `allow` |
| `event_id` | yes | `^[A-Za-z0-9_-]{1,64}$` |
| `severity` | no | `info`, `warn` (default), `high`, `critical` |
| `ip`, `mac` | no | the client |
| `dst_ip`, `ja4` | no | connection events |
| `scores` | no | numbers in 0..1, e.g. `{"dga": 0.97}` |
| `reasons` | no | short human strings |
| `capture` | no | pcap note |
| `auto_isolated` | no | `true`: the device was isolated; the last reason says how to undo it |
| `would_isolate` | no | `true`: it would have been (dry-run, learning or shadow mode, the hourly cap, or a failure) |
| `auto_isolate_failed` | no | `true`: nft or state.json refused; isolate by hand |
| `would_block` | no | `true` on an `iot_new_domain` alert that `iot_enforce` would have refused but did not (dry-run, shadow mode or learning mode) |
| `trust` | no | what Trust allowlists when it isn't `domain`: a `dns_tunnel` alert names one of many throw-away subdomains, so Trust takes the zone (`trust: "example.com"`). `threat_feed`, `dga_burst` and `nx_burst` alerts offer no Trust (the feed wins anyway; a burst is many different names). A `threat_feed` alert's first reason names the list: `evil.example is on URLhaus (malware)`, or for a parent match `x.evil.example is under evil.example, which is on Phishing Army (phishing)` |

```json
{"time":"2026-10-20T21:04:05Z","device":"laptop","ip":"192.168.1.10",
 "domain":"xkjqwehz.biz","rule":"dga_high","action":"recommend","severity":"high",
 "scores":{"dga":0.998},"reasons":["dga score 1.00","new to this network"],
 "event_id":"evt_01abc"}
```

## ghost-dns configuration

Defaults live in `agents/ghost_dns/config.py`; `/etc/ghostwall/ghost_dns.json`
overrides any of them. The most useful keys:

| Key | Default | Meaning |
|---|---|---|
| `shadow` | `false` (installer: `true`) | score the DNS server's query log instead of serving DNS |
| `querylog` | `/opt/AdGuardHome/data/querylog.json` | the log followed in shadow mode: AdGuard's `querylog.json` or Pi-hole's `pihole.log` |
| `querylog_format` | `"auto"` | `"adguard"`, `"pihole"`, or `"auto"` (from the file's first line, else its name) |
| `learning` | `true` | alerts only; nothing is blocked |
| `score_after_answer` | `true` | inline mode with `learning` on: answer a query first and score it right after, so a new name doesn't wait for the models (they can't change the answer then; the confirmed blocklist is still checked first). With `learning` off the score decides the answer, so it always comes first |
| `models` | `"default"` | `"v3-public"`: the opt-in 1-5-gram model alone (no onnxruntime), with the calibrated thresholds from `lr_v3_public.json` for any threshold you haven't set yourself |
| `enforce` | `"null"` | `"nft"` lets isolate and lockdown change nftables |
| `dns_host`, `dns_port` | `127.0.0.1`, `53` | inline listener (IPv4); `dns_host6` `"::"` for IPv6, `null` to disable |
| `upstream`, `upstream_port` | `127.0.0.1`, `53` | inline upstream (AdGuard on `5300`) |
| `upstream_fallbacks` | `["9.9.9.9"]` | used when the upstream is down; `[]` to disable |
| `block_response` | `"sinkhole"` | or `"nxdomain"`; sinkhole answers `sinkhole_ip4` / `sinkhole_ip6` |
| `recommend_threshold` | `0.96` | single-name alert score (~1% false positives) |
| `block_threshold` | `0.995` | single-name block score (~0.2% false positives; ~0.4% on names never seen in training) |
| `corroborated_threshold` | `0.80` | alert score when the TLD is rarely legitimate |
| `suspect_only_new` | `true` | plain score alerts only for names new to this network |
| `novelty_days` | `7` | how long a name counts as new |
| `burst_min_score`, `burst_min_distinct` | `0.80`, `5` | DGA burst: score and count per device in 10 min |
| `nx_burst_enabled` | `true` | `nx_burst`: alert when one device fails to resolve (NXDOMAIN) many different unregistered domains, the way a DGA implant searches for its server. Needs the answer's response code: AdGuard's query log (`Answer`), Pi-hole's log (`reply ... is NXDOMAIN` lines) or inline mode |
| `dns_block_feed` | `"off"` | `"off"`, `"dry-run"` or `"on"`: hand the threat feed to AdGuard Home / Pi-hole as a blocklist (dns_block.py). Env `DNS_BLOCK_FEED` wins |
| `dns_block_ads` | `"off"` | `"off"`, `"pro"` or `"ultimate"` (HaGeZi Multi). Env `DNS_BLOCK_ADS` |
| `dns_block_bypass` | `"off"` | `"on"` adds HaGeZi's DoH/VPN/Tor/Proxy bypass list (breaks VPN apps on purpose). Env `DNS_BLOCK_BYPASS` |
| `dns_block_canaries` | `"on"` | with the feed on: `"on"`, `"no-relay"` (keep iCloud Private Relay) or `"off"`. Env `DNS_BLOCK_CANARIES` |
| `dns_block_bind`, `dns_block_port`, `dns_block_url` | `127.0.0.1`, `5382`, `http://127.0.0.1:5382/ghostwall-blocklist.txt` | where the list is served and the URL the DNS server fetches. Env `DNS_BLOCK_BIND`, `DNS_BLOCK_PORT`, `DNS_BLOCK_URL` |
| `protective_upstream` | `"off"` | `"off"`, `"quad9"` or `"cloudflare"` (set by go_shadow.sh from `DNS_PROTECTIVE_UPSTREAM`). `quad9` also reads an NXDOMAIN without SOA as the upstream's block |
| `auto_isolate` | `"off"` | `"dry-run"`: alerts say `would_isolate`, nothing changes. `"on"`: cut off the device behind a high-confidence finding, like `/isolate`. Behaves as dry-run in learning or shadow mode, without `"enforce": "nft"` (gateway mode) or without `pi_ip` |
| `auto_isolate_rules` | `["threat_feed", "dns_tunnel"]` | rules that may isolate. `threat_feed` only on an exact match that is not under a popular site, not on an abused shared service and not on phishing lists only (a click on a link doesn't make a device infected). ghost-flow rules (`raw_ip`, `beacon`, `doh_ip`) are refused |
| `auto_isolate_exempt` | `[]` | device names or addresses never isolated. The Pi, loopback, unnamed clients and non-IPv4 addresses never are |
| `auto_isolate_max_per_hour` | `2` | past this it only alerts and says why. Kept in state.json across restarts. `0` = never |
| `iot_learn_days` | `7` | devices marked `"profile": "iot"` in devices.json: days, from the device's first lookup, during which the registrable domains it looks up are learned (hashed in state.json, at most 512 per device) |
| `iot_enforce` | `"off"` | `"off"`: `iot_new_domain` only alerts. `"dry-run"`: alerts carry `"would_block": true`. `"on"`: inline mode with learning off refuses (as `block_response`) names outside the device's set; shadow and learning mode never refuse. Any other value stops ghost-dns at start. DNS level only: a hard-coded IP or the device's own DoH is not refused (gateway mode still alerts: `raw_ip`, `doh_ip`) |
| `nx_burst_ignore_devices` | `[]` | device names (or IPs) whose failed lookups never count: a box that checks many domains on purpose (link checker, mail filter, dnstwist) |
| `nx_burst_min_distinct`, `nx_burst_window` | `10`, `600` | how many different domains in how many seconds. Only a registrable domain itself (or its `www.`) under a TLD of the root zone (IANA's list, `ghost_dns/tlds.txt`) counts, and only on an empty NXDOMAIN (one that carries a CNAME means the name exists; an empty NOERROR proves nothing either way); never one that has resolved on this network before (kept hashed in `state.json`), one whose NXDOMAIN names a zone inside it, a local or search-domain name, a reverse lookup, a `_service` record, WPAD, a trusted name, or anything AdGuard or Pi-hole blocked or answered itself. A name is counted once per device, so a device stuck on the same dead domains alerts at most once. Simulation: [results_nx_sim.md](../agents/dga_eval/results_nx_sim.md) |
| `tunnel_min_distinct`, `tunnel_min_long` | `30`, `12` | DNS tunnel thresholds per apex in 10 min: that many distinct subdomains (averaging 14+ characters), or that many distinct 40+ character high-entropy ones. Under a domain on the popular list only the second counts |
| `beacon_min_samples`, `beacon_min_dga` | `8`, `0.5` | DNS beacon thresholds. A name under a domain on the popular list (`popular_path`) never raises `dns_beacon`: a script or page polling a big site on a timer is not a call-home, and a C2 needs a domain its operator controls. The list is only consulted when the timing test would fire |
| `service_baseline_days` | `3` | `abused_service`: how long each device learns which of those services it normally uses |
| `event_dedupe_seconds` | `86400` | one alert per device, domain and rule per day |
| `alert_rate_per_device` | `30` | at most this many alerts per device per minute (`0`: no cap). Any web page can make a browser look up thousands of made-up names; blocks still happen, only their alerts are dropped |
| `control_host`, `control_port` | `127.0.0.1`, `5380` | control API; must be loopback |
| `control_token_path` | `null` | `null`: `control_token` next to `state_path`; `""` turns the token off (not recommended) |
| `threat_feed_path` | installer: `/var/lib/ghostwall/threat_feed.txt` | written by `update_feed.py` |
| `popular_path` | `popular_domains.txt` next to `threat_feed_path`; `""` turns it off | popular-domain guard for the DGA rules. A name whose registrable domain is on this list (the Tranco top list `update_feed.py` caches in rank order, `GHOSTWALL_POPULAR_TOP`, 1M by default) never raises `dga_high`, `dga_suspect` or `dga_corroborated` on its score alone and is never blocked on score. It still counts for `threat_feed` and `nx_burst`, and for `dns_tunnel` by its long random labels only (a big site's many service names are not a tunnel); it never raises `dns_beacon`. Reloaded when the file changes; with no file the rules behave as before. `ghostwall status` shows its size; `/status` returns `"popular": {"domains", "updated"}`. Held as sorted 64-bit hashes: 8 MiB for the top 1M (`ghost_dns/bench_lists.py`); in inline mode it loads in the background |
| `popular_top_n` | `1000000` | how many of the list's entries (in rank order) the guard uses. On public lists the top 1M cut DGA false positives the most and hid no DGA name ([results_fp_independent.md](../agents/dga_eval/results_fp_independent.md)) |
| `allowlist_path` | `agents/ghost_dns/allowlist.txt` | starter allowlist |
| `devices_json` | installer: `/etc/ghostwall/devices.json` | device names; unknown clients are named by IP. An entry's `"profile"` is `"normal"` (default), `"strict"` or `"iot"` (default-deny: `iot_learn_days`, `iot_enforce`, rule `iot_new_domain`; set with `sudo ghostwall profile NAME iot`). An entry with a `mac` is known by it: its name follows it to a new IPv4 address, and its old address loses the name once another device has it |
| `neighbours_path` | `/proc/net/arp` | which MAC is at an address: this default means the kernel's neighbour table (IPv4 and IPv6, read over netlink like `ip neigh`; `/proc/net/arp`, IPv4 only, if netlink isn't available); another path is read as a file in `/proc/net/arp`'s format. Only devices on this box's own network are in it (Docker's bridge network: none, so names stay on addresses). `""` turns it off |
| `state_path`, `events_path` | installer: `/var/lib/ghostwall/state.json`, `.../events.jsonl` | persistent state and the alert log. The log starts a new file past 32 MiB and keeps one `events.jsonl.1`; the dashboard and bot read across both |
| `query_log` | `null` (off) | inline mode: a text log of every query |
| `resolved_ips_path` | installer: `/var/lib/ghostwall/resolved_ips.jsonl` | inline mode: answered IPs, read by ghost-flow |
| `log_max_bytes` | 16 MiB | `query_log` and `resolved_ips_path` start a new file past this (one `.1` kept) |
| `capture_enabled` | `false` | POST `/freeze` to the capture agent on high alerts |
| `pi_ip` | unset | this box's LAN address; lockdown needs it and keeps it reachable, and its own lookups never raise `doh_bypass` |

## Command-line tools

| Command | Purpose |
|---|---|
| `ghostwall status \| version \| devices \| name IP NAME \| alerts \| allow D \| trusted \| untrust D \| unblock D \| learning on\|off \| password \| telegram \| calibrate [--target P] [--apply]` | everyday commands (`ghost_dns/ghostwall_cli.py`, on the PATH after install; actions need sudo) |
| `ghost_dns/app.py --config FILE` | run ghost-dns; `--shadow --querylog FILE`, `--once` (build and exit), `--dns-port`, `--upstream`, `--enforce`, `--learning/--no-learning` |
| `ghost_dns/go_shadow.sh` | switch to shadow mode safely (root) |
| `ghost_dns/update_feed.py --out FILE [--feed URL ...] [--min N] [--popular-top N] [--cache-top N] [--tranco-id ID]` | download the threat feeds (https only). Defaults: URLhaus (malware), Phishing Army (phishing), HaGeZi TIF mini (malware, C2, phishing). In `ghostwall.env`: `GHOSTWALL_FEEDS` (space-separated URLs) replaces the default list; `GHOSTWALL_FEED_POPULAR_TOP` (default `100000`, `0` = only the built-in exclusions) and `GHOSTWALL_TRANCO_ID` (pin a list) set the popularity guard; `GHOSTWALL_POPULAR_TOP` (`--cache-top`, default `1000000`) is how many popular domains are cached, in rank order, for ghost-dns's DGA guard (the feed guard uses the first N of them). An entry whose exact name (or name without `www.`) is in the Tranco top N, or is a shared platform or service host (`github.io`, `drive.google.com`, ...), is dropped; hosts under them, like `evil.github.io`, stay. The Tranco list is cached as `popular_domains.txt` next to the feed. A source that fails or shrinks below half keeps its previous contents for up to 14 days while the others update (a warning, exit 0). Exit 1 means the file was not written: no source downloaded, fewer than `--min` names, or no popularity list (no download and no cache) |
| `ghost_dns/replay_querylog.py --querylog FILE [--set KEY=VALUE ...] [--config FILE \| --no-config] [--events-out FILE] [--devices FILE] [--feed FILE] [--popular FILE]` | dry-run detection over real history with throw-away state; changes and sends nothing. Uses your `/etc/ghostwall/ghost_dns.json` (thresholds, ignored devices; never its state or events files), the feed it names or else the installed `/var/lib/ghostwall/threat_feed.txt` with `popular_domains.txt` next to it, and `/etc/ghostwall/devices.json`. `--set` tries another value without editing your config (`--set nx_burst_min_distinct=15 --set popular_top_n=100000`; the value is JSON when it parses). Each alert carries the time of the query that raised it; the summary counts alerts per rule, device and day, and `--events-out` keeps them all. Passes the answer code, so `nx_burst` replays too |
| `web_ui/demo.py` | the dashboard on demo data, no install needed |
| `web_ui/make_demo.py` | regenerate the demo data by running the real detector over a scripted day |
| `ghost_dns/eval_detection.py` | before/after simulation on labelled data |
| `ghost_dns/bench_latency.py [-n 200]` | inline-mode answer time for never-seen names, scoring before vs after the answer |
| `dga_eval/fp_independent.py --data DIR [--download] [--jobs N]` | DGA false positives on Cisco Umbrella and Majestic (lists the thresholds were not set on), scored as the resolver does, with and without the popular-domain guard → `results_fp_independent.md` |
| `ghost_dns/dns_block.py run\|once\|unregister\|upstream [--config F]` | the DNS-server blocking service: builds and serves the list, registers it with AdGuard (`/control/filtering`) or Pi-hole v6 (`/api/lists`), exceptions from Trust and `ghostwall unblock`. Logins from `ADGUARD_URL` / `ADGUARD_USER` / `ADGUARD_PASSWORD` or `PIHOLE_URL` / `PIHOLE_PASSWORD` in ghostwall.env, never logged |
| `ghost_dns/measure_blocklists.py --querylog FILE [--feed F] [--tranco F] [--download DIR]` | how many names and queries of your log each list would block, and each list's Tranco top 10k / 100k overlap |
| `ghostwall unblock DOMAIN [--undo]`, `ghostwall blocking` | an exception in the DNS server's blocklists (and off Ghostwall's own blocklist); what the blocklists hold and whether they are registered |
| `netconf/gen.py [--devices FILE] [--config FILE]` | renders the gateway configs into `agents/netconf/out/`. `config.json` keys besides the network ones: `egress_block` (default true), `egress_block_tcp` (`[23, 25, 135, 139, 445, 2323]`), `egress_block_udp` (`[137, 138, 1900]`), `iot_egress_lock` (`"off"` / `"log"` / `"on"`, for devices with `"profile": "iot"`), `iot_allowed_tcp` (`[80, 443, 8883]`), `iot_allowed_udp` (`[123, 443]`); a bad value stops it; the `doh_ip4` / `doh_ip6` sets come from `agents/netconf/doh_ips.txt` (also ghost-flow's `doh_ip` list; public addresses only, anything else stops it) |
| `ghost_dns/bench_lists.py [--dir /var/lib/ghostwall] [--top N]` | memory, load time and lookup time of the threat feed and the popular-domain list as ghost-dns holds them |
| `dga_eval/feed_overlap.py [--tranco FILE] [--date D]` | each threat feed's overlap with the Tranco top 1k/10k/100k/1M and what the guard drops → `results_feeds.md` |
| `dga_eval/nx_sim.py --data DIR` | simulated time to an `nx_burst` alert per public DGA family → `results_nx_sim.md` |
| `dga_eval/baselines.py --data DIR` | the shipped models against simple "looks random" rules (entropy, ...) on the same public names → `results_baselines.md` |
| `dga_eval/fair_lstm.py --data DIR` | 1-5-gram model vs an early-stopped LSTM, 3 seeds × 5 unseen-family folds → `results_lstm_fair.md` |
| `dga_eval/train_public.py --data DIR` | retrain the opt-in `v3-public` model and its thresholds → `results_v3_public.md` |
| `dga_eval/public_bench.py --data DIR --download` | public DGA benchmark (pinned data, ~2 h on 4 cores; needs scikit-learn, torch, onnx) → `results_public.md` |
| `fw_bot/fw_bot.py --owner-file FILE --follow EVENTS [--commands] [--follow-state FILE] [--env-file FILE]` | Telegram alerts, optionally commands. Alerts are sent in order and kept while Telegram fails; the position survives restarts in `--follow-state` (default `fw_bot_follow.json` next to EVENTS). `--env-file` reads the `FW_BOT_*` settings from a `KEY=VALUE` file where systemd's `EnvironmentFile` isn't there (the Docker image) |
| `fw_bot/validate_events.py FILE` | validate an events file |
| `web_ui/app.py --bind ADDR --port 8088 [--tls-cert F --tls-key F] [--control-token-file FILE]` | dashboard (the token file defaults to `/var/lib/ghostwall/control_token`) |
| `netconf/gen.py [--devices F] [--config F] [--out DIR]` | render gateway-mode configs into `netconf/out/` (settings from `netconf/config.json` unless `--config`) |
