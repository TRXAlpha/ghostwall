# Changelog

## Unreleased (after v0.2.0-beta.2)

Update as usual: `git pull && sudo ./install.sh` (Docker: `git pull && docker compose up -d --build`).
Your settings, alerts, allowlist and thresholds are kept.

### Things that change for you

- **The dashboard is HTTPS** (`https://<box>:8088`; plain `http://` redirects). The certificate
  is self-signed: the browser warns once; the installer prints its fingerprint.
  `GHOSTWALL_WEB_TLS=off` in `ghostwall.env` keeps HTTP.
- **Control API actions need a token** (`Authorization: Bearer $(sudo cat /var/lib/ghostwall/control_token)`).
  The dashboard, the bot and the new `ghostwall` command use it by themselves; only your own
  `curl` calls need the header. `/status` stays open.
- **Telegram commands count only from you, in your private chat with the bot** (not from
  other members of a group).
- **Docker:** AdGuard's config is now mounted only into a small `adguard-tune` service; use the
  new `compose.yaml` if you copied the old one. Images are pinned.

### Fixed

- `install.sh` stopped at step 1 on Python 3.10 and 3.11 (Debian 12, Raspberry Pi OS, Ubuntu
  22.04): fresh installs never got past "find your DNS server".
- Without onnxruntime (e.g. 32-bit ARM) no score-based alert was ever written.
- Names under dynamic-DNS providers (`<random>.ddns.net`, duckdns, no-ip, ...) were scored as
  the provider's name, which hid whole malware families.
- Updates deleted thresholds you had set; Trust on a DoH alert did nothing; the history replay
  ignored the log's time (novelty, de-duplication); every restart re-sent the day's alerts.
- `/opt/ghostwall` kept the cloning user's ownership, so that user could change code that runs
  with more rights.

- Gateway mode: the queue rule in OPERATIONS.md was invalid nftables syntax (`ct original
  proto-dst != 53`), so ghost-flow never saw a packet; `ghost-capture.service` couldn't start
  (`serve` rejected `--ring-dir`, and its tmpfs mount ran without the right to mount); and
  tcpdump's `-W` with `-G` made the capture ring exit after one round (about 5 minutes), so
  later freezes were empty. A freeze also skipped the last seconds before the alert. All
  fixed and now tested on a real kernel queue with real tcpdump.

### Security

Control API token; capture API browser checks and limits; owner-only Telegram commands;
per-device alert rate cap and throttled state writes (a web page can make a browser look up
thousands of names); fsync'd state; anchored Pi-hole parser; dashboard CSP and a limit on wrong
passwords; `state.json` keeps "first seen" domains as keyed hashes instead of a readable list of
every site your household visits (converted on the first start); tighter systemd sandboxes; hash-locked Python dependencies; `events.jsonl` rotates.

### New

- `abused_service`: a device starts using a service malware favours (Telegram bot API, Discord
  CDN, paste sites, tunnels, file drops, ...) after learning its normal ones for 3 days.
- `doh_ip` (gateway mode): DNS-over-HTTPS straight to a resolver's IP.
- Names AdGuard or Pi-hole already blocked raise no single-score alert (they still count
  toward bursts).
- `ghostwall` command: `status`, `version`, `devices`, `name`, `alerts`, `allow`, `trusted`,
  `untrust`, `learning`, `password`, `telegram` (guided setup), `calibrate` (thresholds from
  your own query log). The dashboard lists what you trusted, with an undo.
- `FW_BOT_PRIVACY=minimal`: no domains, IPs or MACs in Telegram messages.
- Opt-in `"models": "v3-public"` (no onnxruntime), and a public, reproducible benchmark:
  `agents/dga_eval/results_public.md`, with a fairer LSTM rematch in `results_lstm_fair.md`.
- CI installs Ghostwall for real under systemd (Debian 12, Ubuntu 22.04 and 24.04), inline
  mode included.
