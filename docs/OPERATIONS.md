# Operations

Installing, running, tuning and undoing Ghostwall. The design is in
[ARCHITECTURE.md](ARCHITECTURE.md); API and config keys are in
[REFERENCE.md](REFERENCE.md).

All paths assume the installer's layout (`/opt/ghostwall`).

## Files and services

| Path | What |
|---|---|
| `/etc/ghostwall/ghostwall.env` | which DNS server and where its log is, dashboard address and password |
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

See the [README](../README.md#install). The installer finds AdGuard Home (native,
snap or Docker) or Pi-hole (native, or Docker with `/var/log/pihole` mounted) and writes
what it found to `/etc/ghostwall/ghostwall.env`. If it guesses wrong, edit that file
and re-run, or choose up front:

```bash
sudo DNS_SOURCE=adguard ADGUARD_YAML=/srv/adguard/conf/AdGuardHome.yaml \
     ADGUARD_QUERYLOG=/srv/adguard/work/data/querylog.json \
     ADGUARD_RESTART="docker restart adguard" ./install.sh
sudo DNS_SOURCE=pihole PIHOLE_LOG=/srv/pihole/log/pihole.log ./install.sh
```

**AdGuard Home:** the query log must be on (Settings → General settings → Query logs).
AdGuard keeps `querylog.size_memory` queries in memory before writing them (1,000 by
default), which delayed alerts by hours on a home network. The installer lowers it to
10 (`ADGUARD_FLUSH_EVERY` in `ghostwall.env`; `0` leaves it alone), keeps a backup of
`AdGuardHome.yaml` next to it, and restarts AdGuard once (a few seconds without DNS).

**Pi-hole:** Ghostwall reads `/var/log/pihole/pihole.log`, which Pi-hole writes as
queries happen, so there is no delay and nothing in Pi-hole is changed.

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

## Dashboard access

The installer binds the dashboard to all addresses (`GHOSTWALL_WEB_BIND=0.0.0.0`) with
a generated password (`GHOSTWALL_WEB_PASSWORD`, user `ghostwall`); both are in
`/etc/ghostwall/ghostwall.env`. Change either, then `sudo systemctl restart ghostwall-web`.

- **Only from your tailnet:** set `GHOSTWALL_WEB_BIND` to the box's Tailscale IP
  (`tailscale ip -4`).
- **Only from the box itself:** `127.0.0.1`, then `ssh -L 8088:127.0.0.1:8088 <box>`.
  Loopback is the only bind that may run without a password.
- It is plain HTTP: fine on a home LAN or tailnet, never expose it to the internet.
  Actions are accepted only as JSON from the dashboard's own origin.

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
| No events at all | `curl -s 127.0.0.1:5380/status`: `stats.queries` should rise over time. If not, `journalctl -u ghostwall-dns -n 30`; a `querylog not found` warning means the log path in `ghostwall.env` is wrong or the query log is off. AdGuard: `size_memory` under `querylog:` in `AdGuardHome.yaml` should be small (re-run the installer). No events with rising `queries` just means nothing suspicious. |
| Too many alerts | allowlist, raise `recommend_threshold`, replay to compare |
| Dashboard won't load | `systemctl status ghostwall-web`; check `GHOSTWALL_WEB_BIND`; any bind but loopback needs `GHOSTWALL_WEB_PASSWORD`. Ubuntu with ufw: `sudo ufw allow 8088/tcp` |
| Forgot the dashboard password | `sudo grep PASSWORD /etc/ghostwall/ghostwall.env` |
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
- **Uninstall:** `sudo /opt/ghostwall/uninstall.sh` (keeps `/etc/ghostwall`), or add
  `--purge` to remove settings, the threat feed and the `ghostwall` user too. If inline
  mode was on, it hands port 53 back to AdGuard first. The only change to your DNS
  server is AdGuard's smaller query-log buffer, which is harmless to keep; the original
  `AdGuardHome.yaml` is saved next to it as `AdGuardHome.yaml.bak-ghostwall-*`.
