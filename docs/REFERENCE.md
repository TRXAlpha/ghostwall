# Reference

The control API, the event format, ghost-dns configuration keys and command-line
flags.

## Control API

HTTP/JSON on `127.0.0.1:5380`, served by `ghost-dns` (`control_api.py`), used by the
dashboard and Telegram bot. No authentication: it must never listen beyond loopback.

Every response is a JSON object: `{"ok": true, ...}` on success, or a non-2xx status
with `{"ok": false, "error": "..."}`. All endpoints take POST with a JSON body;
`/status` also accepts GET.

| Endpoint | Body | Returns |
|---|---|---|
| `/status` | — | `devices` (name, ip, mac, isolated, blocked_domains), `lockdown`, `learning`, `shadow`, `stats` (counters since start; `queries` rising means it is scoring) |
| `/device` | `{"name": "laptop"}` | that device plus `last_seen`; 404 if unknown |
| `/isolate` | `{"name": "laptop"}` | `{"name", "isolated": true}`: the device may only reach the Pi's DNS |
| `/release` | `{"name": "laptop"}` | `{"name", "isolated": false}` |
| `/allow` | `{"domain": "example.com"}` | `{"domain", "allowed": true}`: allowlisted network-wide |
| `/lockdown` | `{}` | `{"lockdown": bool}`: toggles; drops forwarded traffic except to the Pi and tailnet |
| `/learning` | `{"enabled": bool}` | `{"learning": bool}`: learning on means alerts only |
| `/unblock` | `{"event_id": "...", "domain": "..."}` | `{"event_id", "unblocked": true}` (alert buttons) |

Isolation and lockdown only change the kernel with `"enforce": "nft"`; otherwise they
are recorded in state only.

## events.jsonl

One JSON object per line, written by `ghost-dns` and `ghost-flow`, read by the
dashboard and `fw_bot`. `agents/fw_bot/validate_events.py <file>` checks a file
against this schema (exit 1 on any invalid line).

| Field | Required | Notes |
|---|---|---|
| `time` | yes | ISO 8601 UTC, e.g. `2026-10-20T21:04:05Z` |
| `device` | yes | device name from `devices.json`, or the client IP |
| `domain` | yes | lowercase, no trailing dot |
| `rule` | yes | `threat_feed`, `dga_burst`, `dga_high`, `dga_suspect`, `dga_corroborated`, `doh_bypass`, `dns_tunnel`, `dns_beacon`, `blocklist`, `raw_ip`, `beacon` |
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

Defaults live in `agents/ghost_dns/config.py`; `ghost_dns.json` overrides any of them.
The most useful keys:

| Key | Default | Meaning |
|---|---|---|
| `shadow` | `false` (installer: `true`) | score AdGuard's query log instead of serving DNS |
| `querylog` | `/opt/AdGuardHome/data/querylog.json` | the log followed in shadow mode |
| `learning` | `true` | alerts only; nothing is blocked |
| `enforce` | `"null"` | `"nft"` lets isolate and lockdown change nftables |
| `dns_host`, `dns_port` | `127.0.0.1`, `53` | inline listener (IPv4); `dns_host6` `"::"` for IPv6, `null` to disable |
| `upstream`, `upstream_port` | `127.0.0.1`, `53` | inline upstream (AdGuard on `5300`) |
| `upstream_fallbacks` | `["9.9.9.9"]` | used when the upstream is down; `[]` to disable |
| `block_response` | `"sinkhole"` | or `"nxdomain"`; sinkhole answers `sinkhole_ip4` / `sinkhole_ip6` |
| `recommend_threshold` | `0.96` | single-name alert score (~1% false positives) |
| `block_threshold` | `0.995` | single-name block score (~0.1% false positives) |
| `corroborated_threshold` | `0.80` | alert score when the TLD is rarely legitimate |
| `suspect_only_new` | `true` | plain score alerts only for names new to this network |
| `novelty_days` | `7` | how long a name counts as new |
| `burst_min_score`, `burst_min_distinct` | `0.80`, `5` | DGA burst: score and count per device in 10 min |
| `tunnel_min_distinct`, `tunnel_min_long` | `30`, `12` | DNS tunnel thresholds per apex in 10 min |
| `beacon_min_samples`, `beacon_min_dga` | `8`, `0.5` | DNS beacon thresholds |
| `event_dedupe_seconds` | `86400` | one alert per device, domain and rule per day |
| `threat_feed_path` | installer: `/var/lib/ghostwall/threat_feed.txt` | written by `update_feed.py` |
| `allowlist_path` | `agents/ghost_dns/allowlist.txt` | starter allowlist |
| `devices_json` | `agents/netconf/devices.json` | device names; unknown clients are named by IP |
| `capture_enabled` | `false` | POST `/freeze` to the capture agent on high alerts |
| `pi_ip` | `192.168.1.20` | the Pi's LAN address, used by the lockdown rule; set yours before enforcing |

## Command-line tools

| Command | Purpose |
|---|---|
| `ghost_dns/app.py --config FILE` | run ghost-dns; `--shadow --querylog FILE`, `--once` (build and exit), `--dns-port`, `--upstream`, `--enforce`, `--learning/--no-learning` |
| `ghost_dns/go_shadow.sh` | switch to shadow mode safely (root) |
| `ghost_dns/update_feed.py --out FILE [--feed URL ...]` | download threat feeds; keeps the old file on failure |
| `ghost_dns/replay_querylog.py --querylog FILE [--devices FILE]` | dry-run detection over real history |
| `ghost_dns/eval_detection.py` | before/after simulation on labelled data |
| `fw_bot/fw_bot.py --owner-file FILE --follow EVENTS [--commands]` | Telegram alerts, optionally commands |
| `fw_bot/validate_events.py FILE` | validate an events file |
| `web_ui/app.py --bind ADDR --port 8088` | dashboard |
| `netconf/gen.py` | render gateway-mode configs into `netconf/out/` |
