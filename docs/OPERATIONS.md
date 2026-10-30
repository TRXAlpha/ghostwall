# Operations

Installing, running, tuning and undoing Ghostwall. The design is in
[ARCHITECTURE.md](ARCHITECTURE.md); API and config keys are in
[REFERENCE.md](REFERENCE.md).

All paths assume the installer's layout (`/opt/ghostwall`).

## Files and services

| Path | What |
|---|---|
| `/etc/ghostwall/ghostwall.env` | AdGuard paths and restart command, dashboard bind address |
| `/etc/ghostwall/fw_bot.env`, `/etc/ghostwall/owner.json` | Telegram token, button-signing secret, your chat id |
| `/opt/ghostwall/agents/ghost_dns/ghost_dns.json` | ghost-dns config (written by `go_shadow.sh`) |
| `/opt/ghostwall/agents/ghost_dns/events.jsonl` | every alert, one JSON object per line |
| `/opt/ghostwall/agents/ghost_dns/state.json` | allowlist, blocklist, novelty, learning and lockdown |
| `/opt/ghostwall/agents/netconf/devices.json` | your device names, MACs and IPs (optional) |
| `/var/lib/ghostwall/threat_feed.txt` | threat feed, refreshed daily |

| Service | Role |
|---|---|
| `ghostwall-dns` | the decision core (root; shadow or inline) |
| `ghostwall-web` | dashboard on port 8088 |
| `ghostwall-fw-bot` | Telegram alerts and `/fw` commands (optional) |
| `ghostwall-feed.timer` | daily threat-feed refresh |

## Install

See the [README](../README.md#install-shadow-mode). If AdGuard Home is not a standard
install in `/opt/AdGuardHome`, set `ADGUARD_YAML`, `ADGUARD_QUERYLOG` and
`ADGUARD_RESTART` in `ghostwall.env` first (Docker example inside the file). AdGuard's
query log must be enabled (Settings → General settings → Query logs). AdGuard writes
the log in batches (every 1,000 queries by default, `querylog.size_memory`), so
alerts can lag on a quiet network.

To update later: `git pull && sudo ./install.sh`.

## Daily use

- **Watch:** the dashboard, Telegram, or `tail -f .../events.jsonl`.
- **Trust a domain** that keeps getting flagged: `/fw allow <domain>`, the dashboard
  box, or
  `curl -X POST http://127.0.0.1:5380/allow -H 'Content-Type: application/json' -d '{"domain":"example.com"}'`.
  Domains that should be trusted everywhere can go in `agents/ghost_dns/allowlist.txt`.
- **Too noisy?** Raise `recommend_threshold` in `ghost_dns.json` (default 0.96) and
  restart `ghostwall-dns`. Replay your own history first to see the effect:

  ```bash
  sudo /opt/ghostwall/.venv/bin/python /opt/ghostwall/agents/ghost_dns/replay_querylog.py \
      --querylog /opt/AdGuardHome/data/querylog.json --devices /opt/ghostwall/agents/netconf/devices.json
  ```

  The replay uses a throw-away state and events file; it changes and sends nothing.

## Telegram

1. Create a bot with [@BotFather](https://t.me/BotFather) and note the token.
2. Send your bot any message, then read your chat id from
   `https://api.telegram.org/bot<TOKEN>/getUpdates` (`message.chat.id`).
3. Configure and start:

   ```bash
   sudo cp /opt/ghostwall/agents/fw_bot/fw_bot.env.example /etc/ghostwall/fw_bot.env
   sudo nano /etc/ghostwall/fw_bot.env          # token + `openssl rand -hex 32` secret
   echo '{"chat_id": 123456789}' | sudo tee /etc/ghostwall/owner.json
   sudo chown root:ghostwall /etc/ghostwall/fw_bot.env /etc/ghostwall/owner.json
   sudo chmod 640 /etc/ghostwall/fw_bot.env /etc/ghostwall/owner.json
   sudo systemctl enable --now ghostwall-fw-bot
   ```

Only your chat id can run commands or press alert buttons, and buttons are
HMAC-signed.

| Command | What it does |
|---|---|
| `/fw help` | list commands |
| `/fw status` | learning, lockdown and devices |
| `/fw log [n]` | last n decisions (default 10, max 30) |
| `/fw summary` | last 24 h by action, rule, device and domain |
| `/fw device <name>` | one device |
| `/fw isolate <name>` / `/fw release <name>` | cut a device off / restore it (needs `enforce: "nft"`) |
| `/fw allow <domain>` | trust a domain |
| `/fw lockdown` | toggle LAN lockdown (needs `enforce: "nft"`) |
| `/fw learning on\|off` | alert-only vs blocking (inline mode) |

**Already running a bot on the same token?** Only one process may poll a token. Remove
`--commands` from the `ghostwall-fw-bot` unit (it then only sends alerts) and route
`/fw` messages from your bot to `dispatch.Dispatcher`: `Dispatcher.text(text)` returns
the reply and `Dispatcher.callback(query)` handles alert buttons.

## Reaching the dashboard over Tailscale

Set `GHOSTWALL_WEB_BIND` in `ghostwall.env` to the Pi's Tailscale IP
(`tailscale ip -4`) and `sudo systemctl restart ghostwall-web`. The dashboard has no
login, so never bind it to a LAN or public address.

## Going inline (Ghostwall answers DNS)

Only after a week or more of clean shadow results. Inline mode lets Ghostwall block, and
also means DNS depends on it.

1. Move AdGuard to `127.0.0.1:5300`: in `AdGuardHome.yaml` set the DNS `port: 5300`
   (and bind it to `127.0.0.1`), then restart AdGuard and check
   `dig @127.0.0.1 -p 5300 example.com` works and `sudo ss -ulpn 'sport = :53'` shows
   nothing.
2. In `ghost_dns.json` set `"shadow": false`, `"dns_host": "0.0.0.0"`,
   `"dns_port": 53`, `"upstream": "127.0.0.1"`, `"upstream_port": 5300`. Keep
   `"learning": true`.
3. `sudo systemctl restart ghostwall-dns`, then from a client:
   `dig @<pi-ip> google.com` (answers) and `dig @<pi-ip> kjqwehdzxklqw.biz`
   (answers, plus a `recommend` event).
4. After another clean week, turn blocking on: `/fw learning off` or
   `"learning": false`. A new domain scoring ≥ 0.995, a threat-feed hit or a confirmed
   blocklist entry is then sinkholed. Established and allowlisted domains are never
   auto-blocked.
5. Optional: `"enforce": "nft"` lets `/fw isolate` and `/fw lockdown` change the
   kernel's `ghostwall` nftables table. This needs the gateway setup below, because
   isolation only affects traffic that passes through the Pi.

Back to shadow at any time: `sudo bash /opt/ghostwall/agents/ghost_dns/go_shadow.sh`
(moves AdGuard back to :53 and aborts if it does not answer).

## Gateway mode (ghost-flow and capture)

Connection-level checks need the Pi to be the LAN's default gateway. This changes the
whole network; read it fully first, and keep the router's admin page open.

1. Edit `agents/netconf/config.json` (`pi_ip`, `lan_cidr`, DHCP range) and
   `agents/netconf/devices.json`, then `python agents/netconf/gen.py`. Output goes to
   `agents/netconf/out/`.
2. Save current sysctl values for rollback:

   ```bash
   sudo mkdir -p /var/lib/ghostwall
   for k in net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.eth0.rp_filter \
            net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.conf.eth0.send_redirects; do
     echo "$k = $(sysctl -n $k)" | sudo tee -a /var/lib/ghostwall/sysctl-before.conf
   done
   ```

3. Apply, validating each step:

   ```bash
   cd /opt/ghostwall/agents/netconf/out
   sudo cp 99-ghostwall.conf /etc/sysctl.d/ && sudo sysctl --system
   sudo nft -c -f ghostwall.nft && sudo nft -f ghostwall.nft   # adds table ghostwall only
   dnsmasq --test -C dnsmasq.conf && sudo cp dnsmasq.conf /etc/dnsmasq.d/ghostwall.conf
   sudo systemctl enable --now dnsmasq
   sudo install -m 755 breakglass.sh /usr/local/bin/ghostwall-breakglass
   sudo install -m 755 health.sh /usr/local/bin/ghostwall-health
   sudo ghostwall-health
   ```

4. On the router: disable its DHCP server and IPv6 router advertisements. Renew a
   client's lease and check it gets an address in your DHCP range with the Pi as
   gateway and DNS.
5. **ghost-flow:** `sudo apt install libnetfilter-queue-dev`,
   `sudo /opt/ghostwall/.venv/bin/pip install NetfilterQueue`, copy
   `agents/ghost_flow/ghost_flow.example.json` to `ghost_flow.json`, install and start
   `ghostwall-flow.service`, then add the queue rule:
   `sudo nft add rule inet ghostwall forward iifname "eth0" ct state new ct original proto-dst != 53 queue num 100 bypass`.
   Leave it recommend-only (no `--autoblock`).
6. **capture:** install `tcpdump`, copy `agents/capture/` to `/opt/ghostwall/capture`
   with a `devices.json` using the same names, install `ghost-capture.service`, and set
   `"capture_enabled": true` in `ghost_dns.json`.

## Troubleshooting

| Symptom | Check |
|---|---|
| No events at all | `curl -s 127.0.0.1:5380/status`: `stats.queries` should rise over time. If not, `journalctl -u ghostwall-dns -n 30`; a `querylog not found` warning means `ADGUARD_QUERYLOG` is wrong or the query log is off. On a quiet network, wait for AdGuard's next batch write. No events with rising `queries` just means nothing suspicious. |
| Too many alerts | allowlist, raise `recommend_threshold`, replay to compare |
| Dashboard won't load | `systemctl status ghostwall-web`; check `GHOSTWALL_WEB_BIND` |
| Telegram silent | `journalctl -u ghostwall-fw-bot -n 50`; token, chat id, file permissions |
| Telegram `409 Conflict` | another process polls the same token; see "Already running a bot" |
| No DNS (inline) | `sudo bash .../go_shadow.sh` puts AdGuard back on :53 |

## Rollback and uninstall

- **Back to shadow:** `sudo bash /opt/ghostwall/agents/ghost_dns/go_shadow.sh`.
- **Clear enforcement:** `sudo nft flush set inet ghostwall blocked_ip` and
  `sudo nft flush set inet ghostwall isolated_dev`.
- **Undo gateway mode:** `sudo ghostwall-breakglass` (removes the `ghostwall` table,
  restores sysctl, prints the router steps), then
  `sudo systemctl disable --now dnsmasq` and re-enable DHCP and IPv6 RA on the router.
- **Uninstall:**

  ```bash
  sudo systemctl disable --now ghostwall-dns ghostwall-web ghostwall-fw-bot ghostwall-feed.timer
  sudo rm /etc/systemd/system/ghostwall-*.service /etc/systemd/system/ghostwall-feed.timer
  sudo systemctl daemon-reload
  sudo rm -rf /opt/ghostwall /etc/ghostwall /var/lib/ghostwall && sudo userdel ghostwall
  ```

  In shadow mode nothing else was changed; AdGuard is untouched.
