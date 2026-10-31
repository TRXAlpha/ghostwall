# Ghostwall

**A local-first AI DNS firewall for a home network.** Ghostwall runs on a Raspberry Pi
next to [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome), scores every DNS
lookup on your network with tiny CPU models and behavioural detectors, and tells you
(dashboard and Telegram) when a device starts acting like it is infected. Nothing
leaves your network.

> **Status: a working detector, an experimental blocker.** The recommended *shadow
> mode* has run on the author's home network since October 2026: it reads AdGuard's
> query log and alerts, and cannot break DNS. *Inline mode* (Ghostwall answers DNS
> and blocks) and kernel enforcement (device isolation, lockdown) are implemented
> and unit-tested, but have **not** been proven on a real network yet. See
> [Limits](#limits).

![Ghostwall dashboard](docs/img/dashboard.png)

<sub>Dashboard with demo data (`python agents/web_ui/demo.py`). Light theme follows your OS:
[screenshot](docs/img/dashboard-light.png).</sub>

## Why not just AdGuard Home or Pi-hole?

Keep them. Ghostwall runs on top and covers what a blocklist can't:

| | AdGuard Home / Pi-hole | + Ghostwall |
|---|---|---|
| Known-bad domains (lists) | yes | yes (threat feed) |
| Random-looking domains nobody has listed yet (DGA) | no | yes |
| DNS tunnelling, timer-like beacons | no | yes |
| A device skipping your filter via DNS-over-HTTPS | no | flagged |
| Per-device "this looks infected" alerts | no | dashboard + Telegram |
| Can break your DNS | it is your DNS | no (shadow mode only reads the log) |

## What it catches

| Rule | Meaning | Severity |
|---|---|---|
| `threat_feed` | the name is on a phishing/malware list (~150k domains, refreshed daily) | high |
| `dga_burst` | one device looked up 5+ different random-looking domains within 10 minutes | high |
| `dga_high` / `dga_suspect` | a single very random-looking name that is new to your network | high / warn |
| `dga_corroborated` | a fairly random name on a rarely-legitimate TLD (`.top`, `.xyz`, ...) | warn |
| `doh_bypass` | a device looked up a DNS-over-HTTPS provider, so it may be skipping your filter | warn |
| `dns_tunnel` | many long random subdomains of one domain (data smuggled over DNS) | high |
| `dns_beacon` | a random-looking name queried on a fixed timer | warn |

An alert, as written to `events.jsonl` and sent to Telegram:

```json
{"time":"2026-10-30T15:11:26Z","device":"phone","domain":"cloudflare-dns.com","rule":"doh_bypass",
 "action":"recommend","severity":"warn",
 "reasons":["resolved DoH/DoT provider cloudflare-dns.com","this device may be bypassing your DNS filter"]}
```

Internal names (`*.local`, `*.ts.net`, single labels, `_service` records) are never
scored, and repeat alerts for the same device and domain are collapsed to one per day.

How well: the domain model alone catches about 60% of algorithmically generated (DGA)
domains at a 1% false-positive rate, so Ghostwall leans on the other detectors and on
novelty (only names new to your network alert). Replaying 8.7 days of one real home
network (70,615 queries, 7 devices) produced 13 alerts. Details:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#detection).

## Install (shadow mode)

Requirements: a Linux box (Raspberry Pi 4 or better, Debian 12+ / Raspberry Pi OS),
Python 3.11+, and AdGuard Home already serving your network's DNS with its query log
on.

```bash
git clone https://github.com/TRXAlpha/ghostwall.git
cd ghostwall
sudo nano agents/ghost_dns/ghostwall.env.example   # only if AdGuard is not in /opt/AdGuardHome
sudo ./install.sh
```

`install.sh` copies the project to `/opt/ghostwall`, creates a Python venv and a
`ghostwall` system user, installs the systemd units, downloads the threat feed and
starts `ghost-dns` in shadow mode. Your DNS keeps working exactly as before. Config
lives in `/etc/ghostwall/ghostwall.env`; re-running the installer keeps it.

Then:

```bash
tail -f /opt/ghostwall/agents/ghost_dns/events.jsonl   # decisions as they happen
curl -s http://127.0.0.1:5380/status                    # devices, learning, lockdown
```

- **Dashboard:** `http://127.0.0.1:8088` (set `GHOSTWALL_WEB_BIND` to your Tailscale IP
  to reach it from your tailnet; it has no login, so never bind it to the LAN).
- **Telegram alerts and `/fw` commands:** the installer prints the four commands.
- **Name your devices:** copy `agents/netconf/devices.example.json` to
  `/opt/ghostwall/agents/netconf/devices.json` and fill in your devices so alerts say
  `laptop` instead of an IP.
- **Check it against your own history** (changes nothing):
  `sudo /opt/ghostwall/.venv/bin/python /opt/ghostwall/agents/ghost_dns/replay_querylog.py --querylog <your querylog.json>`

Everything else (going inline, enforcement, the Pi-as-gateway setup, troubleshooting,
rollback): [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Try it without a Pi

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
python agents/ghost_dns/app.py --dns-port 5553 --control-port 5380 --upstream 1.1.1.1
dig @127.0.0.1 -p 5553 google.com          # forwarded
dig @127.0.0.1 -p 5553 kjqwehdzxklqw.biz   # flagged (recommend, learning mode)
```

Just the dashboard, with sample data (stdlib only): `python agents/web_ui/demo.py`, then
open http://127.0.0.1:8088.

## How it works

```
devices ──DNS──▶ AdGuard Home ──▶ internet
                     │ querylog.json
                     ▼
               ghost-dns (shadow) ── scores + detectors ──▶ events.jsonl ──▶ dashboard, Telegram
                     │
               control API 127.0.0.1:5380  (status, allow, isolate, lockdown, learning)
```

`ghost-dns` is the decision core. It scores the registrable part of each name with an
ensemble of a ~108k-parameter recursive model (ONNX) and a hashed character n-gram
logistic regression (pure numpy), then runs the behavioural detectors. In inline mode
the same core answers DNS itself, with AdGuard as its upstream, and can sinkhole.
Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). API, event format and
config keys: [docs/REFERENCE.md](docs/REFERENCE.md).

## Limits

- **Detection is name-based.** It sees what a device looks up, not what it does
  afterwards. The domain model still misses about 4 in 10 DGA domains.
- **Inline mode and enforcement are unproven on a real network.** The first inline
  deployment broke a workstation's DNS; the resolver was hardened afterwards (TCP,
  IPv6, upstream fallback, fail-open), but run shadow mode for at least a week first.
- **`ghost-flow`** (raw-IP, beacon and JA4 connection checks) and **`capture`**
  (pcap freeze on alert) need the Pi to be the network's gateway. They are tested on
  recorded traffic only.
- **No authentication** on the control API (loopback) or the dashboard. Keep both off
  the LAN.
- Tested on one home network. Expect to allowlist a few domains in the first week.

## Tests

Stdlib `unittest`, no network needed (`numpy` and `onnxruntime` for the scoring tests):

```bash
for d in agents/ghost_dns/tests agents/ghost_flow/tests agents/fw_bot/tests agents/capture/tests agents/web_ui/tests; do
  python -m unittest discover -s "$d" || break
done
python agents/netconf/test_gen.py
```

## Repository layout

```
install.sh          shadow-mode installer
agents/ghost_dns/   the decision core: resolver, scoring, detectors, shadow follower, control API
agents/web_ui/      dashboard
agents/fw_bot/      Telegram alerts and /fw commands
agents/ghost_flow/  connection inspector (gateway mode)
agents/capture/     per-device pcap ring + freeze on alert (gateway mode)
agents/netconf/     generator for the Pi-as-gateway configs (dnsmasq, nftables, sysctl)
agents/dga_eval/    model evaluation scripts and results
ghostwall/          shipped models + the numpy LR trainer
trm/                model training code
src/ai_firewall/    earlier offline log-analysis CLI + Windows endpoint heuristics (scripts/)
scanner/, third_party/  PE-file malware scanner research (not used by the firewall)
```

## License

[MIT](LICENSE) © Morogan Christian. `third_party/thrember` is Apache 2.0 (see its own license).
