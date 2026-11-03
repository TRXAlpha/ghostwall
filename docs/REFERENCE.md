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
- every endpoint except `/status` needs `Authorization: Bearer <token>` (else 401).
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
| `/status` | — | `devices` (name, ip, mac, isolated, last_seen, blocked_domains), `clients` (unnamed addresses seen, newest first, up to 50), `lockdown`, `learning`, `shadow`, `source` (`adguard` or `pihole` in shadow mode), `enforce` (`null` or `nft`), `models`, `feed` (`domains`, `updated`), `stats` (counters since start; `queries` rising means it is scoring; `suppressed` counts repeat alerts, `rate_limited` alerts dropped by `alert_rate_per_device`, `blocked_upstream` random-looking names AdGuard had already blocked) |
| `/device` | `{"name": "laptop"}` | that device plus `last_seen` (its latest query since ghost-dns started, or null); 404 if unknown |
| `/isolate` | `{"name": "laptop"}` | `{"name", "isolated": true}`: the device may only reach the Pi's DNS. 409 unless `enforce` is `nft` |
| `/release` | `{"name": "laptop"}` | `{"name", "isolated": false}` |
| `/allow` | `{"domain": "example.com"}` | `{"domain", "allowed": true}`: allowlisted network-wide. 400 unless it is a hostname |
| `/trusted` | `{}` | `{"domains": [...]}`: what was trusted with `/allow` (the starter `allowlist.txt` aside) |
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
| `rule` | yes | `threat_feed`, `dga_burst`, `dga_high`, `dga_suspect`, `dga_corroborated`, `doh_bypass`, `abused_service`, `dns_tunnel`, `dns_beacon`, `blocklist`, `raw_ip`, `doh_ip`, `beacon` |
| `action` | yes | `block`, `recommend` or `allow` |
| `event_id` | yes | `^[A-Za-z0-9_-]{1,64}$` |
| `severity` | no | `info`, `warn` (default), `high`, `critical` |
| `ip`, `mac` | no | the client |
| `dst_ip`, `ja4` | no | connection events |
| `scores` | no | numbers in 0..1, e.g. `{"dga": 0.97}` |
| `reasons` | no | short human strings |
| `capture` | no | pcap note |

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
| `tunnel_min_distinct`, `tunnel_min_long` | `30`, `12` | DNS tunnel thresholds per apex in 10 min |
| `beacon_min_samples`, `beacon_min_dga` | `8`, `0.5` | DNS beacon thresholds |
| `service_baseline_days` | `3` | `abused_service`: how long each device learns which of those services it normally uses |
| `event_dedupe_seconds` | `86400` | one alert per device, domain and rule per day |
| `alert_rate_per_device` | `30` | at most this many alerts per device per minute (`0`: no cap). Any web page can make a browser look up thousands of made-up names; blocks still happen, only their alerts are dropped |
| `control_host`, `control_port` | `127.0.0.1`, `5380` | control API; must be loopback |
| `control_token_path` | `null` | `null`: `control_token` next to `state_path`; `""` turns the token off (not recommended) |
| `threat_feed_path` | installer: `/var/lib/ghostwall/threat_feed.txt` | written by `update_feed.py` |
| `allowlist_path` | `agents/ghost_dns/allowlist.txt` | starter allowlist |
| `devices_json` | installer: `/etc/ghostwall/devices.json` | device names; unknown clients are named by IP |
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
| `ghost_dns/update_feed.py --out FILE [--feed URL ...]` | download threat feeds (https only; `GHOSTWALL_FEEDS` in `ghostwall.env`, space-separated, replaces the default list); keeps the old file if any feed fails |
| `ghost_dns/replay_querylog.py --querylog FILE [--devices FILE]` | dry-run detection over real history (uses the installed phishing list and devices by default) |
| `web_ui/demo.py` | the dashboard on demo data, no install needed |
| `web_ui/make_demo.py` | regenerate the demo data by running the real detector over a scripted day |
| `ghost_dns/eval_detection.py` | before/after simulation on labelled data |
| `dga_eval/fair_lstm.py --data DIR` | 1-5-gram model vs an early-stopped LSTM, 3 seeds × 5 unseen-family folds → `results_lstm_fair.md` |
| `dga_eval/train_public.py --data DIR` | retrain the opt-in `v3-public` model and its thresholds → `results_v3_public.md` |
| `dga_eval/public_bench.py --data DIR --download` | public DGA benchmark (pinned data, ~2 h on 4 cores; needs scikit-learn, torch, onnx) → `results_public.md` |
| `fw_bot/fw_bot.py --owner-file FILE --follow EVENTS [--commands] [--follow-state FILE]` | Telegram alerts, optionally commands. Alerts are sent in order and kept while Telegram fails; the position survives restarts in `--follow-state` (default `fw_bot_follow.json` next to EVENTS) |
| `fw_bot/validate_events.py FILE` | validate an events file |
| `web_ui/app.py --bind ADDR --port 8088 [--tls-cert F --tls-key F] [--control-token-file FILE]` | dashboard (the token file defaults to `/var/lib/ghostwall/control_token`) |
| `netconf/gen.py` | render gateway-mode configs into `netconf/out/` |
