# Operations

Installing, running, tuning and undoing Ghostwall. The design is in
[ARCHITECTURE.md](ARCHITECTURE.md); API and config keys are in
[REFERENCE.md](REFERENCE.md).

All paths assume the installer's layout (`/opt/ghostwall`).

## Files and services

| Path | What |
|---|---|
| `/etc/ghostwall/ghostwall.env` | which DNS server and where its log is, dashboard address and password |
| `/etc/ghostwall/ghost_dns.json` | ghost-dns config (written by `go_shadow.sh`) |
| `/etc/ghostwall/devices.json` | your device names, MACs and IPs (optional) |
| `/etc/ghostwall/fw_bot.env`, `/etc/ghostwall/owner.json` | Telegram token, button-signing secret, your chat id |
| `/var/lib/ghostwall/events.jsonl` | every alert, one JSON object per line |
| `/var/lib/ghostwall/state.json` | allowlist, blocklist, novelty, learning and lockdown |
| `/var/lib/ghostwall/control_token` | the control API token (created by ghost-dns; the dashboard and bot read it) |
| `/var/lib/ghostwall/novelty_key` | the key that turns "first seen" domains into hashes, so `state.json` holds no list of the sites your household visits |
| `/var/lib/ghostwall/threat_feed.txt` | malware and phishing lists, refreshed daily |
| `/var/lib/ghostwall/popular_domains.txt` | Tranco top 1M in rank order: the feed drops entries in its top 100k, the DGA rules skip names in all of it |
| `/opt/ghostwall` | the code and its Python venv; nothing you need to keep |

Versions before 0.2.0b2 kept config and data in `/opt/ghostwall/agents/`; the installer
moves them on upgrade. `/var/lib/ghostwall` is readable only by root and the `ghostwall`
group: `sudo tail ...`, or add yourself with `sudo usermod -aG ghostwall $USER`.

| Service | Role |
|---|---|
| `ghostwall-dns` | the decision core (user `ghostwall`; shadow or inline) |
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

**AdGuard Home:** the query log must be on and written to a file, and *Anonymize client IP*
off (otherwise every device looks like the same one): Settings → General settings → Logs
configuration. The installer and ghost-dns both warn about each of these.
AdGuard keeps `querylog.size_memory` queries in memory before writing them (1,000 by
default), which delayed alerts by hours on a home network. The installer lowers it to
10 (`ADGUARD_FLUSH_EVERY` in `ghostwall.env`; `0` leaves it alone), keeps a backup of
`AdGuardHome.yaml` next to it, and restarts AdGuard once (a few seconds without DNS).
The batching delays alerts but does not blur them: the timing rules (beacon, tunnel,
bursts) use each query's own time from the log, not the time Ghostwall read it.

**Pi-hole:** Ghostwall reads `/var/log/pihole/pihole.log`, which Pi-hole writes as
queries happen, so there is no delay and nothing in Pi-hole is changed.

To update later: `git pull && sudo ./install.sh`.

## Daily use

- **Watch:** the dashboard, Telegram, or `sudo tail -f /var/lib/ghostwall/events.jsonl`.
- **Trust a domain** that keeps getting flagged: `sudo ghostwall allow <domain>`,
  `/fw allow <domain>`, the dashboard box, or
  `curl -X POST http://127.0.0.1:5380/allow -H 'Content-Type: application/json' -H "Authorization: Bearer $(sudo cat /var/lib/ghostwall/control_token)" -d '{"domain":"example.com"}'`.
  Domains that should be trusted everywhere can go in `agents/ghost_dns/allowlist.txt`.
- **Too noisy?** `sudo ghostwall calibrate` scores your own query log and shows what share
  of your names each threshold flags, with your highest-scoring names;
  `--target 0.2 --apply` sets the alert threshold for about 0.2% of them. Or raise `recommend_threshold` in `/etc/ghostwall/ghost_dns.json`
  (default 0.96) and restart `ghostwall-dns`. Replay your own history first to see the effect:

  ```bash
  sudo /opt/ghostwall/.venv/bin/python /opt/ghostwall/agents/ghost_dns/replay_querylog.py \
      --querylog /opt/AdGuardHome/data/querylog.json --set recommend_threshold=0.98
  ```

  The replay uses a throw-away state and events file; it changes and sends nothing. It
  uses your settings in `/etc/ghostwall/ghost_dns.json`, the installed threat list and
  popular list and `/etc/ghostwall/devices.json`; each `--set KEY=VALUE` tries one other
  value (run it once without to compare). Up to 0.3.0b2 the replay ignored
  `ghost_dns.json`, and on installs upgraded from before 0.2.0b2 it replayed with an old
  copy of the feed and without the popular-domain guard.

## Telegram

The quick way: `sudo ghostwall telegram`. It asks for the token from
[@BotFather](https://t.me/BotFather), waits for you to message the bot, writes both
files below with the right permissions and starts the bot. By hand:

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

Only you can run commands or press alert buttons, and buttons are HMAC-signed. Add
`FW_BOT_PRIVACY=minimal` to `fw_bot.env` (and restart `ghostwall-fw-bot`) to keep
domains, IPs and MACs out of every message: Telegram's servers see them all.
Commands count only in your private chat with the bot: a message must come from your
id and be sent in that chat, so other members of a group the bot is in can't use it. An alert starts with `ALERT · <device>` and offers **Trust domain** and
**Details**; only a real block (inline mode, learning off) says `BLOCKED` and offers
Unblock, Keep blocked and Isolate.

| Command | What it does |
|---|---|
| `/fw help` | list commands |
| `/fw status` | learning, lockdown and devices |
| `/fw log [n]` | last n decisions (default 10, max 30) |
| `/fw summary` | last 24 h by action, rule, device and domain |
| `/fw device <name>` | one device |
| `/fw isolate <name>` / `/fw release <name>` | cut a device off / restore it (needs `enforce: "nft"`; refused otherwise) |
| `/fw allow <domain>` | trust a domain |
| `/fw lockdown` | toggle LAN lockdown (needs `enforce: "nft"`) |
| `/fw learning on\|off` | alert-only vs blocking (inline mode) |

**In Docker:** `docker compose exec ghostwall ghostwall telegram` writes the same two files
into `/data` (`ghostwall-data/` on the host); after `docker compose restart ghostwall` the
container runs the bot with `--commands`, as the systemd unit does.

**When Telegram is down** (or the Pi is offline, or you haven't pressed Start yet) alerts
wait in order and are retried with a growing pause (up to a minute); an alert that
arrives more than 5 minutes late says when it happened. The bot keeps its place in
`/var/lib/ghostwall/fw_bot_follow.json`, so alerts written while it was stopped are
sent when it starts (the very first start sends only new ones). A message Telegram
refuses outright is logged and skipped, so it can't hold up the rest.

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
- It is HTTPS with a self-signed certificate in `/etc/ghostwall/tls/` (made by the
  installer; plain `http://` on the same port redirects). The installer prints the
  certificate's SHA-256 fingerprint; compare it with what the browser shows the first
  time. Your own certificate: point `GHOSTWALL_WEB_TLS_CERT` and `GHOSTWALL_WEB_TLS_KEY`
  at it. `GHOSTWALL_WEB_TLS=off` (then re-run the installer, or remove those two lines)
  goes back to plain HTTP.
- Fine on a home LAN or tailnet; never expose it to the internet. Actions are accepted
  only as JSON from the dashboard's own origin.

## Block with your DNS server (opt-in)

Ghostwall can hand its threat feed to AdGuard Home or Pi-hole as a blocklist, so known
malware and phishing domains are refused for every device. Ghostwall still never sits in
the DNS path: it builds the list, serves it on 127.0.0.1:5382, and registers it through the
DNS server's own API (a small separate service, `ghostwall-dnsblock`, holds the login).

1. In `/etc/ghostwall/ghostwall.env` set the DNS server's login: `ADGUARD_URL`,
   `ADGUARD_USER`, `ADGUARD_PASSWORD`, or `PIHOLE_URL` and `PIHOLE_PASSWORD` (an app
   password if two-factor login is on). They are used for the API only and never logged.
2. Dry-run first: `DNS_BLOCK_FEED=dry-run`, then `sudo bash /opt/ghostwall/agents/ghost_dns/go_shadow.sh`.
   Nothing is registered. `sudo ghostwall blocking` shows the list, its sources, and how
   many names your devices asked for in the last 7 days are on it.
3. Measure what each list would block on your own network:
   `sudo -u ghostwall /opt/ghostwall/.venv/bin/python /opt/ghostwall/agents/ghost_dns/measure_blocklists.py --querylog <your query log> --feed /var/lib/ghostwall/threat_feed.txt --tranco /var/lib/ghostwall/popular_domains.txt --download /tmp/lists`.
4. On: `DNS_BLOCK_FEED=on`, re-run `go_shadow.sh`, check `sudo ghostwall blocking`. Docker: set
   `DNS_BLOCK_FEED` and the AdGuard login in `compose.yaml` and recreate the container.
5. Something broke? `sudo ghostwall allow example.com` (trust it) or
   `sudo ghostwall unblock example.com`: both become an exception in the DNS server within a
   minute or two. `sudo ghostwall unblock --undo example.com` blocks it again.
6. Undo everything: `DNS_BLOCK_FEED=off`, `DNS_BLOCK_ADS=off`, `DNS_BLOCK_BYPASS=off`, re-run
   `go_shadow.sh`. Ghostwall removes only its own lists and exception block; `uninstall.sh`
   does the same.

With blocking on or in dry-run the feed also grows: HaGeZi TIF medium instead of mini on
machines with about 2 GB of RAM or more, CERT Polska and OpenPhish (ThreatFox too if you set
`THREATFOX_URL`, which needs an abuse.ch key), all behind the popular-site guard. On
2026-11-07 that was 443,645 names, 0 of them in the Tranco top 100k.

- **Ads:** `DNS_BLOCK_ADS=pro` (HaGeZi Multi Pro) is the low-breakage choice; `ultimate`
  blocks more and breaks more (Meta and Microsoft features: it hit 593 of the Tranco top 10k
  on 2026-11-07, Pro 362). No DNS blocker can stop ads served from the same domain as the
  content (YouTube, Twitch, most in-app ads): use uBlock Origin in the browser for those.
- **Bypass and canaries:** with the feed on, `use-application-dns.net` (Firefox then turns its
  own DoH off) and iCloud Private Relay's names answer NXDOMAIN, so those devices use your
  DNS server; Private Relay stops working on this network, which is the point
  (`DNS_BLOCK_CANARIES=no-relay` keeps it). `DNS_BLOCK_BYPASS=on` adds HaGeZi's
  DoH/VPN/Tor/Proxy bypass list: it breaks VPN apps on purpose.
- **Protective upstream:** `DNS_PROTECTIVE_UPSTREAM=quad9` or `cloudflare` sets the DNS server's
  upstream to a resolver that blocks malware itself (once, reversible: `off` restores the
  previous one). Ghostwall reads its refusals as `upstream_block` (info) and doesn't count them
  for `nx_burst`. Trade-off: every uncached query goes to that provider. Quad9 is weaker on
  phishing; with Pi-hole prefer Cloudflare (Quad9's refusal can't be told apart there).
- **AdGuard or Pi-hole in Docker:** the DNS server fetches the list over HTTP and resolves
  the URL with its own DNS, so the URL must hold an address it can reach. `go_shadow.sh`
  finds the container's gateway (often 172.17.0.1), serves the list there and registers
  that URL; with host networking it stays on 127.0.0.1. The bundled `compose.yaml` gives
  Ghostwall a fixed address (172.30.53.3) for the same reason. Your own setup: set
  `DNS_BLOCK_BIND` and `DNS_BLOCK_URL` in ghostwall.env.
- **Limits:** Pi-hole blocks exact names only (no subdomains). A failing DNS-server API never
  stops Ghostwall: it logs once, retries, and the lists already registered stay in force.

## Newly registered domains (opt-in)

Most phishing sites and fresh malware servers run on domains registered days before they are
used, before any threat list has them. `new_domain` flags a lookup of a domain registered in the
last 14 days that your network has never used and that isn't a popular site.

1. Set `"nrd_mode": "alert"` in `/etc/ghostwall/ghost_dns.json`, then
   `sudo systemctl start ghostwall-feed` (it downloads the list: about 25 MB, 42 MiB in memory)
   and `sudo systemctl restart ghostwall-dns`.
2. See how often it would have fired on your own history first:
   `sudo -u ghostwall /opt/ghostwall/.venv/bin/python /opt/ghostwall/agents/ghost_dns/replay_querylog.py --querylog <your query log> --set nrd_mode=alert`.
3. Watch a week. A site you use? Trust it. `update_nrd.py --check NAME` says whether a name
   is on the list and how young it is.
4. `"nrd_mode": "block"` refuses those names in inline mode with learning off (IoT devices
   follow `iot_enforce`). Shadow mode can only alert.

Measured on 2026-11-08 ([results_nrd.md](../agents/dga_eval/results_nrd.md)): 0.02% of the
Tranco top 100k are on the list (and the rule skips popular sites anyway); 3.2% of the
non-popular names in Cisco Umbrella's top 1M are, an upper bound on how much ordinary
traffic could raise it, since Umbrella includes trackers and malware too; 4.1% of today's
threat-list entries were registered in the last 14 days. On a small board, `"nrd_days": 7`
about halves the memory (the first week alone was 2.7 million names).

## Contain what was detected (opt-in)

A blocklist only knows what somebody else reported. `contain` turns Ghostwall's own
high-confidence findings into a block for the whole network: what one device was caught
reaching is refused for every device for a week.

1. Set `"contain": "dry-run"` in `/etc/ghostwall/ghost_dns.json` and
   `sudo systemctl restart ghostwall-dns`. Alerts that would have contained something say
   "would block NAME for every device" and carry `would_contain`. Leave it a week.
2. Make sure something can enforce it: `DNS_BLOCK_FEED=on` (shadow mode: your DNS server
   does the refusing, [above](#block-with-your-dns-server-opt-in)) or inline mode
   (Ghostwall refuses it itself).
3. Set `"contain": "on"` and turn learning off (`sudo ghostwall learning off`).

What happens on a finding (`contain_rules`: an exact or parent hit on the threat lists, a
DNS tunnel, a very random name new to your network):

- the name and everything under it is refused for every device for `contain_days` (7).
  AdGuard Home gets a custom rule, Pi-hole a deny rule, at `ghostwall-dnsblock`'s next
  check (every 15 seconds); neither waits for a list download;
- in gateway mode the public IPv4 addresses the name answered with go into the firewall's
  `blocked_ip` set: dropped to them and from them, for forwarded traffic and for the Pi
  itself, for as long as the containment lasts. An address another domain also answered
  with is left alone, and one that another domain answers with later is let through again
  at once (the journal says so);
- the alert says what was blocked and how to undo it; other devices that try the name
  raise a `blocklist` alert naming the finding.

Check and undo:

```bash
sudo ghostwall contained            # what is blocked, by which rule, on which device, until when
sudo ghostwall uncontain NAME       # let it through again (also takes its addresses out)
sudo ghostwall allow NAME           # a false alarm: trust it (ends the containment too)
sudo nft list set inet ghostwall blocked_ip      # gateway mode: the addresses
```

It cannot be used to take a site away from you: a behaviour finding (`dns_tunnel`,
`dga_high`, ...) never contains a domain your network has already used for `novelty_days`
(7), and a tunnel-like burst of plain address lookups, which any web page can make a
browser send, contains its zone only if it continues past `confirm_seconds` (300).

It never contains a name you trust, a popular site (Tranco top 1M), a shared platform
(ngrok, dynamic DNS, paste sites) or an internal name, and at most `contain_max_per_day`
(20) new ones a day. Containments and their addresses survive a restart and a reboot.
Limits: the address block needs inline mode or AdGuard's log (Pi-hole's log has no full
answers) and holds IPv4 only; `"contain_ips": false` turns it off.

## Automatic isolation (opt-in)

Cuts a device off the moment it does something only infected devices do: an exact hit on a
malware list, or a DNS tunnel. Needs gateway mode (`"enforce": "nft"`) and `pi_ip` in
`/etc/ghostwall/ghost_dns.json`.

1. Start with `"auto_isolate": "dry-run"` for at least a week. Alerts that would have isolated
   are tagged "would isolate" on the dashboard.
2. Add your own computers and the router to `"auto_isolate_exempt"`.
3. Set `"auto_isolate": "on"` and turn learning off (`sudo ghostwall learning off`).

**One lookup is not proof.** A web page or an email can make any device look up a listed
name (a hidden image is enough), so a single `threat_feed` hit only alerts and says "not
isolated yet". The device is isolated when it reaches for the same thing again at least
`confirm_seconds` (300) later, which malware does and a closed page does not. The same goes
for a `dns_tunnel` made only of address lookups, the one kind a browser can be made to send;
a tunnel using TXT, NULL, CNAME or MX queries isolates at once. `"confirm_seconds": 0`
restores acting on the first sighting.

An isolated device can still reach the Pi's DNS and the tailnet, nothing else. Undo with the
Release device button in Telegram, the dashboard, or `sudo ghostwall release NAME`. The same
finding doesn't isolate it again for a day; a new one does. At most
`auto_isolate_max_per_hour` (2) isolations an hour, so a bad list can't take the house offline.
Isolations survive a reboot: release a device rather than flushing the nft set.

## Default-deny for IoT devices

Cameras, TVs and plugs talk to a small, stable set of services, and they can't run antivirus.
After a learning week, anything new is worth a look, and it can be refused.

1. Name the device and mark it: `sudo ghostwall name 192.168.1.40 cam-1`, then
   `sudo ghostwall profile cam-1 iot` (this restarts ghost-dns). Mark devices while you believe
   they are clean: what they do during the learning week becomes normal.
2. Let it learn for a week (`iot_learn_days`, default 7). `sudo ghostwall status` shows
   `IoT: learning until ...`, then `IoT: N domains`. Nothing alerts while it learns.
3. Afterwards each new domain family raises one `iot_new_domain` alert. If you know why (a
   firmware update, a new feature), tap Allow for this device, or run
   `sudo ghostwall allow api.vendor.example --device cam-1`: that allows it for cam-1 only.
   `sudo ghostwall untrust vendor.example --device cam-1` undoes it, `sudo ghostwall relearn cam-1`
   starts learning again.
4. Dry-run: set `"iot_enforce": "dry-run"` in `/etc/ghostwall/ghost_dns.json` and restart.
   Alerts say "would block". Watch a few days and allow what is legitimate.
5. On: `"iot_enforce": "on"`. In inline mode with learning off (`sudo ghostwall learning off`)
   names outside the set are refused like any block. Shadow mode can only alert. This is
   DNS-level only: a device that connects to a hard-coded IP or uses its own DoH is not refused
   (gateway mode alerts on those as `raw_ip` / `doh_ip`).

The network-wide allowlist does not exempt IoT devices (it trusts whole clouds, which would
make default-deny meaningless). The threat feed still wins over a learned name.

## Going inline (Ghostwall answers DNS)

Only after a week or more of clean shadow results. Inline mode lets Ghostwall block, and
also means DNS depends on it.

1. Move AdGuard to `127.0.0.1:5300`: in `AdGuardHome.yaml` set the DNS `port: 5300`
   (and bind it to `127.0.0.1`), then restart AdGuard and check
   `dig @127.0.0.1 -p 5300 example.com` works and `sudo ss -ulpn 'sport = :53'` shows
   nothing.
2. In `/etc/ghostwall/ghost_dns.json` set `"shadow": false`, `"dns_host": "0.0.0.0"`,
   `"dns_port": 53`, `"upstream": "127.0.0.1"`, `"upstream_port": 5300`. Keep
   `"learning": true`: then answers never wait for the models (a new name is scored right
   after it is answered). With learning off, every name not seen before waits for its score
   (about 6 ms each on an x86 VM, several times that on a Pi; `agents/ghost_dns/bench_latency.py`
   measures your box) because the score decides
   whether it is blocked.
3. `sudo systemctl restart ghostwall-dns`, then from a client:
   `dig @<pi-ip> google.com` (answers) and `dig @<pi-ip> kjqwehdzxklqw.biz`
   (answers, plus a `recommend` event).
4. After another clean week, turn blocking on: `/fw learning off` or
   `"learning": false`. A new domain scoring ≥ 0.995, a threat-feed hit or a confirmed
   blocklist entry is then sinkholed. Established and allowlisted domains are never
   auto-blocked.
5. Optional: `"enforce": "nft"` and `"pi_ip": "<this box's LAN address>"` let
   `/fw isolate` and `/fw lockdown` change the kernel's `ghostwall` nftables table. This
   needs the gateway setup below, because isolation only affects traffic that passes
   through the Pi, and ghost-dns needs `CAP_NET_ADMIN`, which it doesn't get by default:

   ```bash
   sudo systemctl edit ghostwall-dns     # add these three lines, save
   [Service]
   AmbientCapabilities=CAP_NET_ADMIN
   CapabilityBoundingSet=CAP_NET_ADMIN
   ```

Back to shadow at any time: `sudo bash /opt/ghostwall/agents/ghost_dns/go_shadow.sh`
(moves AdGuard back to :53 and aborts if it does not answer).

## Gateway mode (ghost-flow and capture)

Connection-level checks need the Pi to be the LAN's default gateway. This changes the
whole network; read it fully first, and keep the router's admin page open.

1. Edit `agents/netconf/config.json` (`lan_iface`, e.g. `eth0` on a Pi, `pi_ip`, `lan_cidr`, DHCP range) and
   `/etc/ghostwall/devices.json` (every device needs a MAC here), then
   `sudo python agents/netconf/gen.py --devices /etc/ghostwall/devices.json`. Output goes
   to `agents/netconf/out/`.
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

   From then on every device's DNS goes through your filter: plain DNS (port 53) to any
   server is answered by the Pi, DNS-over-TLS and DNS-over-QUIC (853) are dropped, and
   DNS-over-HTTPS to the public resolvers in `agents/netconf/doh_ips.txt` (Cloudflare,
   Google, Quad9, NextDNS, Mullvad, Control D, AdGuard and about a dozen more) is dropped,
   so browsers and apps with DoH built in fall back to it. The list holds only addresses
   dedicated to DNS: a resolver on a shared CDN address isn't in it, because blocking that
   would break websites; DoH by name is stopped at DNS instead (the bypass list). The Pi
   doesn't forward IPv6, so IPv6 can't get around it while the router's advertisements are
   off. Re-run `gen.py` after updating the code to pick up a longer list.

   It also drops ports no home device needs toward the internet: Telnet (23, 2323: how
   Mirai-style botnets spread), SMTP (25: spam bots; mail apps use 587/465), Windows RPC,
   NetBIOS and SMB (135, 137-139, 445), UPnP (1900). Only traffic leaving the LAN; devices
   still reach each other. Running a mail server at home? Set `"egress_block_tcp"` in
   `agents/netconf/config.json` to the list you want (or `"egress_block": false`).

   **Harden the Pi itself (recommended once gateway mode works):** in
   `agents/netconf/config.json` set `"input_policy": "drop"`: only SSH (LAN and tailnet), DNS,
   DHCP, ping, replies and the ports in `"lan_services_tcp"` (default `[3000, 8088]`: AdGuard's
   UI and the dashboard) reach the Pi; anything else you run on it needs its port listed.
   The default stays `"accept"` so an upgrade cannot lock you out. `"antispoof": "log"`, then
   `"on"`, drops LAN packets that carry a named device's address from a different MAC, so a
   device cannot borrow another's identity by taking its address (a cloned MAC is not
   caught). And in `/etc/ghostwall/fw_bot.env`, `FW_BOT_ACTIONS=tighten` lets Telegram
   alert, isolate and lock down but not release, trust or unblock: a stolen Telegram
   session then cannot open the firewall. Re-run `gen.py` and reload after a change.

   **Both directions:** the `blocked_ip`, `drop_net4` and `drop_net6` sets are matched as
   destination and as source, in the forward chain (your devices), the input chain (the Pi
   itself, before anything is accepted) and the output chain (the Pi's own traffic). Replies
   to your devices normally come back through the router, not the Pi: dropping the
   outbound packet is what ends a connection, and the router's NAT refuses what nobody
   asked for. Re-run `gen.py` and reload the firewall to get these rules on an existing
   gateway. Counters: `sudo nft list chain inet ghostwall input | grep counter`.

   **IP reputation:** LAN devices can't reach networks on Spamhaus DROP / DROPv6 (run by
   criminals, hijacked, or leased to botnet operators) or abuse.ch's botnet C2 lists (SSLBL,
   Feodo Tracker). `update_ipfeed.py` refreshes `/var/lib/ghostwall/ip_blocklist.txt` with
   the daily feed update (1,858 networks on 2026-11-07), and ghost-dns loads it into the
   firewall's `drop_net4` / `drop_net6` sets within a minute, in one transaction. Nothing
   private and nothing wider than a /8 (IPv6: /19) is ever loaded. Check with
   `sudo nft list set inet ghostwall drop_net4 | head`.

   **IoT egress lock (opt-in):** with `"iot_egress_lock": "log"` in `config.json`, devices
   marked `"profile": "iot"` in devices.json are logged (`journalctl -k | grep iot-egress`)
   whenever they reach the internet on anything but web (80, 443), MQTT over TLS (8883) and
   time (123); `"on"` drops it. Run `"log"` for a week first: some cameras stream to their
   cloud on other ports. `"iot_allowed_tcp"` / `"iot_allowed_udp"` widen it. Re-run `gen.py`
   and reload the firewall after a change.
5. **ghost-flow:** `sudo apt install libnetfilter-queue-dev build-essential python3-dev`,
   `sudo /opt/ghostwall/.venv/bin/pip install --require-hashes -r /opt/ghostwall/requirements-gateway.lock`,
   `sudo install -m 640 -g ghostwall /opt/ghostwall/agents/ghost_flow/ghost_flow.example.json /etc/ghostwall/ghost_flow.json`,
   `sudo install -m 644 /opt/ghostwall/agents/ghost_flow/ghostwall-flow.service /etc/systemd/system/`,
   `sudo systemctl enable --now ghostwall-flow` (it runs as `ghostwall` with `CAP_NET_ADMIN` only),
   then add the queue rule:
   `sudo nft add rule inet ghostwall forward iifname "eth0" ct state new meta l4proto '{ tcp, udp }' th dport != 53 queue num 100 bypass`.
   (Versions before this one documented `ct original proto-dst != 53`, which nft rejects.)
   `bypass` means traffic keeps flowing whenever ghost-flow isn't running.
   Leave it recommend-only (no `--autoblock`).
6. **capture:** `sudo apt install tcpdump`; if your LAN interface isn't `eth0`, write
   `{"interface": "eth1"}` to `/etc/ghostwall/capture.json`; then
   `sudo install -m 644 /opt/ghostwall/agents/capture/ghost-capture.service /etc/systemd/system/`,
   `sudo systemctl enable --now ghost-capture`, and set `"capture_enabled": true` in
   `ghost_dns.json`. It captures the devices in `/etc/ghostwall/devices.json`
   (`ghostwall name` adds them). Each keeps the last 5 minutes (`ring_keep_minutes`) in
   RAM; a high-severity alert freezes them plus 5 more minutes into
   `/var/lib/ghostwall/incidents/<event_id>/`.

## Troubleshooting

| Symptom | Check |
|---|---|
| No events at all | `ghostwall status`: "scored" should rise over time. If not, `journalctl -u ghostwall-dns -n 30`; a `querylog not found` warning means the log path in `ghostwall.env` is wrong or the query log is off. AdGuard: `size_memory` under `querylog:` in `AdGuardHome.yaml` should be small (re-run the installer). Rising numbers and no alerts just means nothing suspicious. |
| Too many alerts | `sudo ghostwall alerts` to see which rule; `sudo ghostwall allow <domain>` for names you trust (`ghostwall untrust` undoes it); `sudo ghostwall calibrate` to see what the thresholds flag on your network and `--target 0.2 --apply` to quieten them |
| Dashboard won't load | `systemctl status ghostwall-web`; it is `https://` now (plain `http://` redirects); check `GHOSTWALL_WEB_BIND`; any bind but loopback needs `GHOSTWALL_WEB_PASSWORD`. Ubuntu with ufw: `sudo ufw allow 8088/tcp` |
| Browser warns about the certificate | expected once: it is the box's own self-signed one. Compare the SHA-256 fingerprint the installer printed (`openssl x509 -noout -fingerprint -sha256 -in /etc/ghostwall/tls/cert.pem`) |
| Forgot the dashboard password | `sudo ghostwall password` |
| Alerts show IP addresses | `sudo ghostwall devices`, then `sudo ghostwall name <ip> <name>` |
| Telegram silent | `journalctl -u ghostwall-fw-bot -n 50` says why, once: a rejected token (fix `fw_bot.env`, restart), "press Start" (open the bot in Telegram and press Start: a bot can't write first) or Telegram unreachable. Alerts wait meanwhile and go out, marked "sent late", when Telegram answers; a restart resumes where the bot stopped |
| Telegram `409 Conflict` | another process polls the same token; see "Already running a bot" |
| No DNS (inline) | `sudo bash .../go_shadow.sh` puts AdGuard back on :53 |

## Rollback and uninstall

- **Back to shadow:** `sudo bash /opt/ghostwall/agents/ghost_dns/go_shadow.sh`.
- **Clear enforcement:** `sudo nft flush set inet ghostwall blocked_ip` and
  `sudo nft flush set inet ghostwall isolated_dev`.
- **Undo gateway mode:** `sudo ghostwall-breakglass` (removes the `ghostwall` table,
  restores sysctl, prints the router steps), then
  `sudo systemctl disable --now dnsmasq` and re-enable DHCP and IPv6 RA on the router.
- **Uninstall:** `sudo /opt/ghostwall/uninstall.sh` (keeps `/etc/ghostwall` and
  `/var/lib/ghostwall`, so a reinstall carries on), or add `--purge` to remove settings,
  alerts, state, the threat lists and the `ghostwall` user too. If inline
  mode was on, it hands port 53 back to AdGuard first. The only change to your DNS
  server is AdGuard's smaller query-log buffer, which is harmless to keep; the original
  `AdGuardHome.yaml` is saved next to it as `AdGuardHome.yaml.bak-ghostwall-*`.
