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
  `curl` calls need the header. `/status` stays open as a summary; its device list (names, IPs,
  MACs, last seen) needs the token too, so `ghostwall devices` needs sudo and plain
  `ghostwall status` shows only counts.
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
- Telegram dropped alerts: one failed send (Telegram down, the Pi offline, the owner not
  having pressed Start) skipped that alert for good and, with `--commands` (the shipped
  setting), silently stopped all later alerts while commands kept working. A restart
  skipped everything written while the bot was down, and a wrong token only showed as
  silence. Alerts now wait and retry in order, survive restarts and say "sent late";
  the journal says once what is wrong and how to fix it, without the token.
- Trust on a `dns_tunnel` alert trusted the one throw-away subdomain in it, so the next
  query alerted again; it now trusts the zone (the event's new `trust` field). A
  `dga_burst` alert no longer offers Trust at all: it is many different names, and
  trusting the one shown changed nothing. `ghostwall alerts` prints local time, not UTC.
- Inline mode made every never-seen name wait for the models before answering, even with
  learning on, where the score can't change the answer. It now answers first and scores
  right after: about 6 ms → 0.1 ms median per new name on an x86 VM (more saved on a Pi;
  `agents/ghost_dns/bench_latency.py` measures it).
  With learning off the score still comes first, as it decides the block.
- A name on the phishing list could not be trusted: `ghostwall allow` said "no more alerts"
  and the next lookup alerted again (in inline mode: stayed blocked). The list names some
  link shorteners and apps as a whole (on 2026-11-03: `hubs.ly`, `dub.sh`, `sider.ai`, ...), so that
  meant permanent false alarms. Trusting the listed name now works; a listed subdomain of a
  trusted name still alerts, and every feed alert says how to trust it.
- Shadow mode skipped the queries written in the last moments before AdGuard rotated its
  query log (or Pi-hole's logrotate truncated `pihole.log`); it reads them from the `.1`
  file first now.
- Docker: `ghostwall telegram` set everything up and sent nothing, ever: the image had no
  Telegram bot and nothing said so. The image now ships it and starts it once the setup
  has written its files (restart the container, as the setup says); CI checks an alert
  reaches a stand-in Telegram from the locked-down container.
- Device names stuck to addresses: once DHCP gave the laptop's old address to the TV,
  the TV's alerts said `laptop` and "isolate laptop" cut off the TV. `ghostwall name` now
  records the MAC, ghost-dns reads the kernel's neighbour table, and a name follows its MAC,
  IPv6 privacy addresses included (a phone used to show up as a new unnamed client every
  day): alerts, the device list and isolation use where the device is now, and an old address
  shows as an address. Names given before this, without a MAC, work as before; name them
  again while the device is online to pin them.
- `/opt/ghostwall` kept the cloning user's ownership, so that user could change code that runs
  with more rights.

- Gateway mode: the queue rule in OPERATIONS.md was invalid nftables syntax (`ct original
  proto-dst != 53`), so ghost-flow never saw a packet; `ghost-capture.service` couldn't start
  (`serve` rejected `--ring-dir`, and its tmpfs mount ran without the right to mount); and
  tcpdump's `-W` with `-G` made the capture ring exit after one round (about 5 minutes), so
  later freezes were empty. A freeze also skipped the last seconds before the alert. All
  fixed and now tested on a real kernel queue with real tcpdump.
- The generated gateway firewall (`netconf/gen.py` → `ghostwall.nft`) never loaded: it began
  with `destroy table` (nftables 1.0.8+, while Debian 12 / Raspberry Pi OS ship 1.0.6) and put
  the DNS redirect in a filter chain, which the kernel refuses (`nft -c` didn't notice). The
  redirect now has its own nat chain, the reload works on 1.0.6, and the LAN interface is
  `lan_iface` in `netconf/config.json` instead of `eth0` written into every file.

### Security

Control API token; capture API browser checks and limits; owner-only Telegram commands;
per-device alert rate cap and throttled state writes (a web page can make a browser look up
thousands of names); fsync'd state; anchored Pi-hole parser; dashboard CSP and a limit on wrong
passwords; `state.json` keeps "first seen" domains as keyed hashes instead of a readable list of
every site your household visits (converted on the first start); tighter systemd sandboxes; hash-locked Python dependencies; `events.jsonl` rotates.
Pins no longer rot silently: Dependabot proposes action and image bumps weekly, and a weekly
CI job looks up every locked Python version in the OSV vulnerability database.

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
- CI installs Ghostwall for real under systemd (Debian 12 and 13, Ubuntu 22.04, 24.04 and
  26.04), inline mode included.
- CI lints the code (pyflakes, pinned). Its first run found a gateway test (the LAN
  interface setting) that had never run, and two tests that checked nothing; all fixed.
