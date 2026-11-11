# Ghostwall

[![tests](https://github.com/TRXAlpha/ghostwall/actions/workflows/tests.yml/badge.svg)](https://github.com/TRXAlpha/ghostwall/actions/workflows/tests.yml)
[![release](https://img.shields.io/github/v/release/TRXAlpha/ghostwall?include_prereleases&sort=semver)](https://github.com/TRXAlpha/ghostwall/releases)
[![license](https://img.shields.io/github/license/TRXAlpha/ghostwall)](LICENSE)

**Watches each device on your home network for the DNS habits of malware.** Ghostwall runs
next to [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) or
[Pi-hole](https://pi-hole.net) on a Raspberry Pi, a VM or any small Linux box. It reads
your DNS server's query log and flags a device that suddenly starts using a bot API, a
paste site or a tunnel service, smuggles data through DNS, calls home on a timer, looks up
known malware or phishing domains, bursts through random-looking names, or fails to
resolve one made-up domain after another (malware hunting for its server). It also tells you when a
device skips your DNS filter (DNS-over-HTTPS): not a sign of infection by itself (phones
and browsers do it when "Private DNS" or "secure DNS" is on), but your filter no longer
sees that device. Two small on-device models score how random a name looks; the behaviour
rules do most of the work. Alerts go to a dashboard or Telegram.

**It can also block, if you choose.** Opt-in, each with a dry-run first:
- **Caught once, blocked for everyone:** a destination one device was caught on is refused
  for every device for a week, and in gateway mode its addresses are dropped in both
  directions (`contain`, new in v0.3.0-beta.4).
- **Known-bad domains for every device:** Ghostwall hands its threat lists (about 440k
  malware, C2 and phishing domains) to AdGuard Home or Pi-hole as a blocklist, with
  optional ad lists. It still never sits in the DNS path.
- **IoT default-deny:** cameras, TVs and plugs learn their usual domains for a week, and
  anything new is flagged or refused.
- **Gateway mode** (the Pi routes your LAN):
  - an infected device is cut off automatically;
  - every device's DNS is forced through your filter;
  - botnet and criminal networks (Spamhaus DROP, abuse.ch) are dropped, to and from;
  - ports malware spreads on (Telnet, SMB, SMTP) are closed toward the internet.

Ghostwall never sends
your DNS traffic anywhere (one exception: in inline mode, while your DNS server is down,
it answers through a fallback resolver, Quad9 by default; `"upstream_fallbacks": []` turns
that off). The only things it downloads are the daily threat lists (domains and, for gateway mode,
botnet IP ranges) and a list of popular sites (Tranco, so popular sites are never flagged
as a whole), and the only thing it
sends out is the alerts themselves, if you turn on Telegram (domain names can be left out
of those too).

> **Status: a detector first; every kind of blocking is opt-in and starts as a dry-run.** The recommended *shadow mode*
> only reads the query log and alerts, so it is never in the path of your DNS (installing
> restarts AdGuard once, a few seconds, to make it write its log promptly). It has run on
> the author's home network (Raspberry Pi 4 + AdGuard Home) since late October 2026, which
> is not long, and **it has not caught a real infection yet**: there was none to catch, so
> the numbers from the field are false-alarm counts. Detection rates come from public data,
> including the DNS of 83 real infections replayed through it: behaviour rules alone flagged
> 53% of them, 75% of the last year's ([How well it works](#how-well-it-works)). *Inline mode* (Ghostwall answers DNS and
> blocks) passes an end-to-end test in CI (a systemd container with a stand-in AdGuard:
> forwarding, sinkholing, SERVFAIL when the upstream dies, and the way back to shadow
> mode), but is not proven on a real network. Blocking through AdGuard or Pi-hole is proven
> against the real servers in CI (a listed name is refused, a trusted one isn't), not yet on
> a real network. See [Limits](#limits).
>
> **It does not block every virus, and nothing on a network can.** It stacks layers so the
> damage stops early: [What happens when a device gets infected](#what-happens-when-a-device-gets-infected)
> says which layer stops what, and what still gets through.
>
> **Current release: v0.3.0-beta.6** (a second review: whoever runs a bad domain can no
> longer aim the firewall at your DNS resolver, a device can no longer get another one
> isolated by forging its address, an isolated device gets no DNS answers, a flood can no
> longer hide the alert that matters; on top of beta.5's fixes and beta.4's
> containment: a detected destination is blocked for every
> device, by name and, in gateway mode, by address in both directions; and beta.3's
> opt-in blocking through AdGuard or Pi-hole, IoT default-deny, newly registered domains,
> automatic isolation and gateway egress rules): [CHANGELOG](CHANGELOG.md). Already installed? `git pull && sudo
> ./install.sh` upgrades and keeps your settings, alerts, trusted domains and names.

**Try it** on the box that runs AdGuard Home or Pi-hole:

```bash
git clone https://github.com/TRXAlpha/ghostwall.git && cd ghostwall && sudo ./install.sh
```

It starts in shadow mode (it only reads the query log, so it can't break DNS);
`sudo /opt/ghostwall/uninstall.sh` removes it. Docker and other ways: [Install](#install).

![Ghostwall dashboard](docs/img/dashboard.png)

<sub>Demo mode (`python agents/web_ui/demo.py`). Every alert in it came out of the real
detector, run over a scripted day on five made-up devices
([make_demo.py](agents/web_ui/make_demo.py)); a test fails if the two ever disagree.
Light theme follows your OS: [screenshot](docs/img/dashboard-light.png).</sub>

## What happens when a device gets infected

Nothing on a network can promise to stop every piece of malware, and Ghostwall does not
claim to. What it does is stack layers, so that malware which gets past one meets the next,
and so that **what one device was caught doing is shut for every device** within seconds.
The aim: the damage stops at whatever happened in the first moments after the malware ran.

Read the table top to bottom as the life of an infection. "Mode" says where the layer works:
**S** shadow (the default), **D** with DNS-server blocking on (`DNS_BLOCK_FEED=on`),
**I** inline, **G** gateway. Everything that blocks is opt-in and has a dry-run.

| Stage | What the malware does | What stops or flags it | Mode |
|---|---|---|---|
| 1. Delivery | a person opens a phishing link or a malware download | the name is on the threat lists (about 440k names): refused for every device; `threat_feed` says which device tried | D, I |
| | the link is a domain registered days ago, on no list yet | `new_domain` (`nrd_mode`): alert, or refused in inline mode | S (alert), I (block) |
| 2. First call home | looks up a listed C2 or malware domain | refused; `threat_feed` alert; the device is cut off (`auto_isolate`) | D, I; G to cut off |
| | cycles through generated names (DGA) hunting for its server | `nx_burst` (failed lookups, word-based DGAs too), `dga_burst`, `dga_high` | S |
| | uses a bot API, a paste site, a tunnel or a file drop | `abused_service`, once the device has a 3-day baseline | S |
| | smuggles data through DNS itself | `dns_tunnel`; the tunnel's zone is contained; the device is cut off | S (alert), D/I/G to stop |
| | calls a hardcoded IP address, no DNS at all | `raw_ip`; the address is in a criminal network or a botnet C2 list: dropped | G |
| | hides its DNS in DNS-over-HTTPS | `doh_bypass` by name; 91 resolver addresses dropped, DoT (853) dropped, plain DNS forced to your filter | S (alert), G (block) |
| 3. The same malware, the next device | another device looks up the domain the first one was caught on | **contained**: refused for every device for 7 days (`contain`) | D, I |
| | another device connects to the address it resolved to | the address is dropped at the gateway, to and from | G |
| 4. Spreading | scans the internet on Telnet, SMB, RPC; sends spam on port 25 | those ports are closed toward the internet | G |
| | an IoT device (camera, TV, plug) is taken over | `iot_new_domain`: any domain outside what it learned is flagged or refused; `iot_egress_lock` limits it to web, MQTT-TLS and time | S (alert), I/G (block) |
| 5. Staying | keeps beaconing on a timer | `dns_beacon`, `beacon` | S, G |
| | the device is isolated | only DNS to the Pi and the tailnet still work; one tap releases it | G |

**What still gets through**, so you know what you are buying:

- Malware that only talks to big shared services (a cloud drive, a chat app, a CDN) on a
  device that already used them looks like everyone else. Nothing name-based can tell.
- Whatever the malware does **on the device itself** (encrypting files, stealing saved
  passwords and sending them through a service the device already uses). Ghostwall is on
  the network, not on the device: keep an antivirus and backups.
- The first connection to a destination nobody has listed and no rule has seen yet. The
  layers above shorten that window; they cannot make it zero.
- Spreading **inside** your LAN (device to device on the same switch or Wi-Fi) never
  passes the Pi, so no gateway rule sees it. Isolation stops an isolated device's traffic
  that the Pi routes, not its traffic to the device next to it.
- In shadow mode without DNS-server blocking, Ghostwall only alerts: it stops nothing.

Measured, not promised: with every default and **no threat list at all**, the behaviour
rules flagged the infected machine in 44 of 83 replayed real infections (53%), 38 of the
51 from the last year (75%), usually within 1 to 2 minutes
([How well it works](#how-well-it-works)). That also means 1 in 4 recent infections raised
nothing from behaviour alone. The lists and the firewall layers are there for those.

## Why not just AdGuard Home or Pi-hole?

Keep them. Ghostwall runs on top and covers what a blocklist can't:

| | AdGuard Home / Pi-hole | + Ghostwall |
|---|---|---|
| Known phishing, malware and C2 domains | blocks them (with those lists) | keeps the lists filled for you (about 440k domains, popular sites never listed as a whole), tells you which device tried, and which list named it |
| A camera or TV that starts using Telegram's bot API, a paste site, ngrok, a file drop | no | flagged the first time (each device learns its normal services first) |
| DNS tunnelling, timer-like beacons | no | yes |
| A device using its own DNS-over-HTTPS | no | flagged if it looks the server up by name; in gateway mode blocked by IP too (91 resolver addresses), and Firefox / Private Relay sent back to your filter |
| A camera that suddenly talks to somewhere new | no | flagged, or refused (opt-in IoT default-deny) |
| An infected device | no | cut off automatically on a sure finding (opt-in, gateway mode), one-tap Release |
| A domain nobody has listed, caught by behaviour on one device | no (not on any list) | refused for every device for a week (opt-in `contain`), its addresses dropped at the gateway |
| Botnet and criminal IP ranges, Telnet/SMB/SMTP toward the internet | no | dropped in gateway mode |
| Random-looking domains nobody has listed yet (DGA) | no | about 6 in 10 on [public data](agents/dga_eval/results_public.md), plus bursts of them |
| Malware cycling through generated domains, even word-like ones | no | a burst of failed (NXDOMAIN) lookups: all 25 public DGA families within 10 lookups [in a simulation](agents/dga_eval/results_nx_sim.md) |
| Per-device "this looks infected" alerts | no | dashboard + Telegram |
| Can break your DNS | it is your DNS | no (shadow mode only reads the log; blocking happens in your DNS server, through its own API) |

## What it catches

| Rule | Meaning | Severity |
|---|---|---|
| `threat_feed` | the name is on a known-bad list: [URLhaus](https://urlhaus.abuse.ch) (malware), [Phishing Army](https://phishing.army) (phishing) and [HaGeZi TIF mini](https://github.com/hagezi/dns-blocklists) (malware, C2, phishing), about 270k domains (3.3 MiB in memory), refreshed daily; the alert says which list. A popular site is never listed as a whole: an entry that is a Tranco top-100k domain or a shared platform (`github.io`, `drive.google.com`) is dropped at download time, while hosts under them (`evil.github.io`) stay ([results_feeds.md](agents/dga_eval/results_feeds.md)). Phishing Army lists some link shorteners and apps as a whole, because phishing runs through them: if one you use alerts, `sudo ghostwall allow <name>` (deliberately no one-tap Trust for these) | high |
| `dga_burst` | one device looked up 5+ different random-looking domains within 10 minutes | high |
| `nx_burst` | one device failed to resolve (NXDOMAIN) 10+ different unregistered domains within 10 minutes: malware searching for its server among generated names, even word-like ones the models miss. Typos, probes under real domains, local and search-domain names, Chrome's random probes and anything your DNS server blocked never count. Needs the answer code: AdGuard's or Pi-hole's log, or inline mode | high |
| `dga_high` / `dga_suspect` | a single very random-looking name that is new to your network (never a popular site's: Tranco top 1M) | high / warn |
| `dga_corroborated` | a fairly random name on a rarely-legitimate TLD (`.top`, `.xyz`, ...) | warn |
| `doh_bypass` | a device looked up a known DNS-over-HTTPS server, so it may be skipping your filter | warn |
| `abused_service` | a device that has been on your network for 3+ days starts using a service malware likes for commands, payloads or stolen data: Telegram's bot API, Discord's CDN, paste sites, ngrok and other tunnels, anonymous file drops, raw GitHub downloads, "what is my IP" lookups | warn |
| `dns_tunnel` | many long random subdomains of one domain (data smuggled over DNS) | high |
| `dns_beacon` | an odd-looking name queried on a fixed timer (never under a popular site: a polled weather or course page is not a call-home) | warn |
| `new_domain` | (opt-in, `nrd_mode`) a domain registered in the last 14 days, new to your network and not a popular site: where most phishing and fresh C2 lives before any list catches up. High when the name also looks random or sits on a risky TLD ([results_nrd.md](agents/dga_eval/results_nrd.md)) | warn / high |
| `iot_new_domain` | a device you marked IoT (camera, TV, plug) looked up a domain it never used in its learning week. Optional default-deny: alert, dry-run or refuse (`iot_enforce`) | warn |
| `lookalike` | an internationalised domain written with Cyrillic or Greek letters that look like a popular site's name (`pаypal` with a Cyrillic `а`): the classic phishing-link trick. Names with ordinary accents are left alone | high |
| `blocklist` | a device looked up a destination Ghostwall is blocking by itself: one that is contained (`contain`), or a `dga_high` name blocked in inline mode. The alert names the finding behind it and how to undo it | high |
| `doh_ip`, `raw_ip`, `beacon` | gateway mode only (`ghost-flow`): a connection straight to a DNS-over-HTTPS server's IP, to an IP nobody looked up, or on a fixed timer | warn / high |

What each rule can lead to when you turn blocking on: [What it blocks](#what-it-blocks-all-opt-in-each-with-a-dry-run).

An alert, as written to `events.jsonl` and sent to Telegram:

```json
{"time":"2026-10-30T15:11:26Z","device":"phone","domain":"cloudflare-dns.com","rule":"doh_bypass",
 "action":"recommend","severity":"warn",
 "reasons":["resolved DoH/DoT provider cloudflare-dns.com","this device may be bypassing your DNS filter"]}
```

Internal names (`*.local`, `*.ts.net`, single labels, `_service` records) are never
scored, and repeat alerts for the same device and domain are collapsed to one per day.
A random-looking name that AdGuard Home already blocked raises no alert of its own (no
connection happened, and most of those are ad and tracker junk); it still counts toward a
burst, and the other rules see it as usual.

**How well:** about 6 in 10 random-looking (DGA) names nobody has listed yet are caught
when 1% of normal names are flagged, on public data anyone can check; dictionary-word
DGAs mostly get through, so the behaviour rules above carry most of the weight. The
numbers, how to reproduce them and the LSTM comparison: [How well it works](#how-well-it-works).

## What it blocks (all opt-in, each with a dry-run)

Seven switches. Each is **off** after an install or an upgrade. Turn them on in this
order, one at a time, a few days apart; every one of them has a dry-run that only says what
it would have done. Details, checks and rollback for each: [docs/OPERATIONS.md](docs/OPERATIONS.md).

| # | Switch | What it does | Needs | Undo |
|---|---|---|---|---|
| 1 | `DNS_BLOCK_FEED=on` | the threat lists (443k names on 2026-11-07, none of them a top-100k site) become a blocklist in AdGuard Home or Pi-hole: refused for every device | AdGuard Home or Pi-hole v6 | `ghostwall unblock DOMAIN`, or `off` |
| 2 | `DNS_PROTECTIVE_UPSTREAM=quad9` | your DNS server asks a resolver that refuses known malware itself (a second, independent list) | step 1's service | `off` puts the old upstream back |
| 3 | `"contain": "on"` | a destination one device was caught on (`threat_feed`, `dns_tunnel`, a new `dga_high` name) is refused for **every** device for 7 days; in gateway mode its addresses are dropped to and from | step 1, or inline mode | `ghostwall uncontain DOMAIN`, Trust |
| 4 | `"profile": "iot"` + `"iot_enforce": "on"` | cameras, TVs and plugs may only look up what they learned in a week | inline mode to refuse; alerts in any mode | Trust for that device, `ghostwall relearn` |
| 5 | `"nrd_mode": "block"` | domains registered in the last 14 days, new to your network, are refused | inline mode to refuse; `"alert"` in any mode | `ghostwall allow DOMAIN` |
| 6 | gateway mode | botnet and criminal networks dropped **in both directions** (Spamhaus DROP, abuse.ch); Telnet, SMB, RPC, SMTP, UPnP closed toward the internet; all DNS forced through your filter; 91 DoH resolver addresses and DoT dropped | the Pi routes your LAN | `breakglass.sh`, re-enable DHCP on the router |
| 7 | `"auto_isolate": "on"` | a device behind an exact malware-list hit or a DNS tunnel is cut off at once (at most 2 an hour) | gateway mode | the Release button, `ghostwall release NAME` |

Optional extras with step 1: ad and tracker lists (`DNS_BLOCK_ADS=pro` or `ultimate`,
HaGeZi), and the DoH/VPN/Tor/proxy bypass list (`DNS_BLOCK_BYPASS=on`). DNS blocking can't
stop ads served from the same domain as the content (YouTube, in-app ads): a browser
extension is still needed for those.

### Contain: caught once, blocked for everyone

The gap this closes: a blocklist only knows what somebody else already reported. When
Ghostwall's own rules catch a device on something no list has, that used to be an alert and
nothing else, and the next device could walk into the same thing.

With `"contain": "on"` in `/etc/ghostwall/ghost_dns.json`, a high-confidence finding
becomes a block for the whole network:

1. **The name** (and everything under it) is refused for every device for `contain_days`
   (7). In inline mode Ghostwall refuses it itself. In shadow mode `ghostwall-dnsblock`
   hands it to AdGuard Home (a custom rule) or Pi-hole (a deny rule): in force at its next
   check (every 15 seconds), with no list download.
2. **Its addresses** (gateway mode): the public IPv4 addresses the name answered with are
   put in the firewall's `blocked_ip` set, which drops packets **to them and from them**,
   for forwarded traffic and for the Pi itself. That stops malware that already holds the
   address and never asks DNS again.
3. **The alert says so**, and how to undo it: `sudo ghostwall uncontain DOMAIN`.
   `sudo ghostwall contained` lists what is in force.

What keeps it from blocking the wrong thing:

- only rules that name **one destination** with confidence: `threat_feed` (the listed
  name), `dns_tunnel` (the tunnel's zone) and `dga_high` for a name new to your network.
  `dns_beacon`, `dga_corroborated` and `new_domain` can be added; rules about a device or a
  crowd of names (`nx_burst`, `dga_burst`, `abused_service`, `doh_bypass`) are refused;
- never a name you trust, a popular site (Tranco top 1M), a shared platform (ngrok,
  dynamic DNS, paste sites: other people's pages live there too) or an internal name;
- an address another domain also answered with is never dropped (shared hosting, a CDN);
  if another domain answers with a dropped address later, it is let through again at once;
- at most `contain_max_per_day` (20) new ones a day; while `learning` is on it only says
  what it would do; it ends by itself after 7 days unless the finding repeats;
- `"contain": "dry-run"` first: alerts then carry `would_contain` and change nothing.

"Both directions", honestly: in gateway mode the Pi routes what your devices **send**; the
replies usually come back through your router, not through the Pi. Dropping the outbound
packets is what kills a connection (no reply ever comes to a packet that never left), and
your router's NAT already refuses connections nobody inside asked for. The inbound rules
cover the Pi itself and any setup where the Pi is also on the return path.

## Install

Pick one. All of them start in shadow mode: your DNS keeps working exactly as before.

### 1. On the box that runs your DNS server (Pi, VM, mini PC)

Needs 64-bit Linux with systemd (Raspberry Pi OS, Debian 12 or 13, Ubuntu 22.04 to 26.04;
arm64 or x86_64), Python 3.10+, and AdGuard Home or Pi-hole on the same machine.

```bash
git clone https://github.com/TRXAlpha/ghostwall.git
cd ghostwall
sudo ./install.sh
```

The installer finds your DNS server by itself (AdGuard native, snap or Docker; Pi-hole
native or Docker), puts the code in `/opt/ghostwall` with its own Python venv, starts
the systemd services as an unprivileged `ghostwall` user, downloads the threat lists,
and prints the dashboard address and its password. Settings live in `/etc/ghostwall`,
alerts and state in `/var/lib/ghostwall`; updating and uninstalling both keep them.

With AdGuard Home it also lowers AdGuard's query-log buffer from 1,000 queries to 10 and
restarts AdGuard once (a few seconds without DNS). Otherwise AdGuard can hold queries
for hours before Ghostwall sees them. Pi-hole needs no change.

### 2. Docker: Ghostwall and AdGuard Home together

Any Docker host: a VM, a NAS, a mini PC or a Pi.

```bash
git clone https://github.com/TRXAlpha/ghostwall.git
cd ghostwall
docker compose up -d --build
```

1. Finish AdGuard's setup at `http://<host>:3000` (keep the query log on).
2. Wait for `docker compose logs adguard-tune` to say it set the buffer (about 10 s),
   then `docker compose restart adguardhome` once, so alerts arrive in seconds.
3. Point your router's DNS (or one test device) at the host.
4. Dashboard: `https://<host>:8088` (self-signed: the browser warns once), user `ghostwall`, password from
   `docker compose exec ghostwall ghostwall password`. The same `ghostwall` commands work
   there (`docker compose exec ghostwall ghostwall status`, `... alerts`, `... name`).
5. Telegram (optional): `docker compose exec ghostwall ghostwall telegram`, then
   `docker compose restart ghostwall`; the container runs the bot from then on.

The Ghostwall container runs with no capabilities (if you run AdGuard as a non-root user, it
needs `DAC_OVERRIDE` to read the log, and says so), a
read-only filesystem and `no-new-privileges`, and sees AdGuard's files read-only. Only the
small `adguard-tune` service, which has no network and sees nothing but that folder, can
write AdGuard's config (to lower its log buffer, keeping the file's owner). Images are pinned by digest (Dependabot proposes
bumps weekly). Copy those lines from `compose.yaml` if you write your own service. Docker Hub
rate-limiting your builds? `"registry-mirrors": ["https://mirror.gcr.io"]` in
`/etc/docker/daemon.json` (then restart Docker) pulls the same images from Google's mirror.

Port 53 already taken on Ubuntu? That is `systemd-resolved`; the "resolved" section of
AdGuard's [Docker docs](https://github.com/AdguardTeam/AdGuardHome/wiki/Docker) shows
how to free it. If every alert names the same `172.x.x.x` device, AdGuard isn't seeing
your clients' real addresses (lookups from the Docker host itself always look like
that); give the `adguardhome` service `network_mode: host` and remove its `ports:`.

Already running AdGuard Home or Pi-hole in Docker? Use only the `ghostwall` service and
mount your folders instead (Pi-hole: its container must mount `/var/log/pihole` from the
host too, e.g. `./pihole/log:/var/log/pihole`):

```yaml
  ghostwall:
    build: .
    restart: unless-stopped
    ports: ["8088:8088"]
    environment:
      GHOSTWALL_QUERYLOG: /pihole/log/pihole.log     # AdGuard: /adguard/work/data/querylog.json
    volumes:
      - ./pihole/log:/pihole/log:ro                  # your Pi-hole's /var/log/pihole folder
      - ./ghostwall-data:/data
```

### 3. Just look at it

The dashboard with the demo day (stdlib Python only, nothing installed):

```bash
python agents/web_ui/demo.py      # then open http://127.0.0.1:8088
```

### No DNS server yet?

Install [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome#getting-started) or
[Pi-hole](https://docs.pi-hole.net/main/basic-install/) first, or use the Docker option,
which includes AdGuard. A Raspberry Pi 4 or a VM with 1 CPU and 1 GB of RAM is plenty:
Ghostwall uses about 150 MB (100 MB for the detector, most of it the ONNX runtime, and
about 25 MB each for the dashboard and the Telegram bot).

## After installing

```bash
ghostwall status                  # is it scoring? ("queries" should keep rising)
sudo ghostwall alerts             # what it found, newest first
sudo ghostwall telegram           # alerts on your phone: paste a bot token, message the bot, done
sudo ghostwall allow example.com  # stop alerts for a domain you trust (ghostwall untrust undoes it)
sudo ghostwall calibrate          # after a few days: what each threshold would flag on YOUR network
ghostwall blocking                # DNS-server blocklists: sizes, and whether they are in use
sudo ghostwall contained          # destinations blocked for every device after an alert
sudo ghostwall uncontain DOMAIN   # let one through again
sudo ghostwall release NAME       # let an isolated device back on the network
```

- **Dashboard:** `https://<box>:8088` (plain `http://` redirects there), user `ghostwall`, password from
  `sudo ghostwall password`. To keep it to your tailnet or to the box itself, see
  [Dashboard access](docs/OPERATIONS.md#dashboard-access).
- **Name your devices:** `sudo ghostwall devices` lists the addresses it has seen;
  `sudo ghostwall name 192.168.1.20 laptop` names one, so alerts say `laptop` instead of
  an IP. It records the device's MAC, so the name follows it when DHCP hands out a new
  address, IPv6 privacy addresses included. (Or edit `/etc/ghostwall/devices.json`, as in `agents/netconf/devices.example.json`.)
- **Telegram alerts and `/fw` commands:** `sudo ghostwall telegram`, or by hand:
  [docs/OPERATIONS.md](docs/OPERATIONS.md#telegram).
- **Check it against your own history** (changes nothing):
  `sudo /opt/ghostwall/.venv/bin/python /opt/ghostwall/agents/ghost_dns/replay_querylog.py --querylog <querylog.json or pihole.log>`
  (with your settings; add `--set nx_burst_min_distinct=15`, or any other key, to try a value first)
- **Update:** `git pull && sudo ./install.sh`. **Remove:** `sudo /opt/ghostwall/uninstall.sh`
  (keeps your settings and alerts; `--purge` removes them too).

Everything else (going inline, enforcement, the Pi-as-gateway setup, troubleshooting,
rollback): [docs/OPERATIONS.md](docs/OPERATIONS.md).

## How well it works

**On real infections.** [results_real_malware.md](agents/dga_eval/results_real_malware.md)
(`agents/dga_eval/real_malware.py`) replays the DNS of 83 public packet captures of real
malware infections (Stratosphere Lab 2010-2018, malware-traffic-analysis.net November 2025 to
November 2026, pinned by sha256) through the real pipeline with every default. Behaviour
rules alone, with no threat list at all, flagged the infected machine in **44 of 83 (53%)**,
and in **38 of the 51 (75%)** recent ones, usually within 1 to 2 minutes; mostly a device
suddenly using a service malware favours, random-looking names, or its own DoH. Adding
today's lists raises that to 58% and 80%, an optimistic number: those lists were written
after these infections were analysed. 17 captures of normal traffic gave 5 false alarms in
3.5 device-days. Lab machines, not homes: it says what the rules see in real malware
DNS, not how quiet they are on your network.

**How well, on data anyone can check.** [results_public.md](agents/dga_eval/results_public.md)
uses only public data (25 DGA families from Netlab 360, the Tranco top 1M) and reproduces
with `agents/dga_eval/public_bench.py`. There the shipped models catch 60.3% of DGA
names when 1% of normal names are flagged (53.4% up to v0.2.0-beta.2, which did not
look inside dynamic-DNS names such as `x7kq2v9w.ddns.net`). Dictionary-word DGAs
(`brothernerveplace.com`) get through almost always: they look like normal names. A
plain score therefore only alerts for names new to your network, and the behaviour
rules above do the rest. Is that better than "this name looks random"? On the same names,
character entropy catches 11.6% and the best simple rule tried 16.2% at the same 1% of
normal names flagged
([results_baselines.md](agents/dga_eval/results_baselines.md), `agents/dga_eval/baselines.py`).

A 1-5-gram model retrained on the public data catches 80.5% of names from known families
and 64.8% from families it never saw, against 81.4% and 60.8% for an Endgame-style LSTM.
In a [fairer rematch](agents/dga_eval/results_lstm_fair.md) (the LSTM early-stopped on
held-out names, three seeds each, the same five unseen-family folds) it is 64.6% against
60.9% at 1% false positives and about even at 0.1% (38.0% against 37.2%): the LSTM wins
two folds, the n-gram model wins clearly on folds with dictionary-word families. One
dataset still. The n-gram model scores a name in about 40 µs in plain numpy (x86, one thread). A version trained on all of that data
ships as an opt-in: `"models": "v3-public"` in `/etc/ghostwall/ghost_dns.json`, then
`sudo systemctl restart ghostwall-dns`. It runs without onnxruntime (ghost-dns used 44 MB
instead of 71 MB on the x86 test machine) and its thresholds flag the same share of
normal names as the defaults ([results_v3_public.md](agents/dga_eval/results_v3_public.md)).
It is not the default because it has not been measured on a real network yet. Either way,
`sudo ghostwall calibrate` shows what the thresholds would flag on your own network.

**On private data.** On DRIFT (a 2017-2025 dataset that is not in this repo), trained
on 2017-2019 and tested on 2024-2025, the shipped models catch about 61% of DGA names
at 1% false positives and 47% at 0.2%
([results_shipped.md](agents/dga_eval/results_shipped.md); reproducing it needs the
dataset).

**False positives on lists the thresholds were not set on.**
[results_fp_independent.md](agents/dga_eval/results_fp_independent.md)
(`agents/dga_eval/fp_independent.py`) scores Cisco Umbrella's top 1M DNS names as the
resolver does, treating every name as new: 0.315% would raise a DGA alert (Majestic
0.300%, a Tranco sample 0.503%), so the thresholds stay as shipped. Skipping names whose
registrable domain is a Tranco top-1M site brings that to **0.098%** (745 of 761,951 names,
488 registrable domains) without hiding a single name from the 25 DGA families. The guard
holds 8 MiB. The threat feed reads only the top 100k of the same list, so a malware domain
that ranks lower stays listed. On a real network fewer names are new, so fewer alert.

**Failed lookups (`nx_burst`).** [results_nx_sim.md](agents/dga_eval/results_nx_sim.md)
(`agents/dga_eval/nx_sim.py`) feeds each public DGA family's names through the real
resolver, one every 2 to 60 seconds, assuming they all fail (NXDOMAIN). `nx_burst` fired
for all 25 families on the 10th lookup, including the four word-based ones the models
almost never flag (suppobox, matsnu, gozi, nymaim). When 5% of the names resolve and the
implant stops at the first one that does, it fires first in about 59% of runs. A
simulation: there is no home traffic in this repo to measure its false positives, so
each guard against them has a unit test instead.

Replaying 12.9 days of the author's network (115,549 queries, before the
dynamic-DNS fix and the behaviour rules added since) gave 17 alerts: 4 test lookups the
author made, 3 devices using DNS-over-HTTPS, 9 random-looking ad-redirect and pop-up
style domains on the author's computers and phone, and 1 false positive (a weather
script polling every 15 minutes). That is one network: please
[open an issue](https://github.com/TRXAlpha/ghostwall/issues) with what you see on yours.
Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#detection).

## How it works

```
devices ──DNS──▶ AdGuard Home or Pi-hole ──▶ internet
                     │ querylog.json / pihole.log
                     ▼
               ghost-dns (shadow) ── scores + detectors ──▶ events.jsonl ──▶ dashboard, Telegram
                     │
               control API 127.0.0.1:5380  (status, allow, isolate, lockdown, learning)
```

`ghost-dns` is the decision core. It scores the registrable part of each name with two
models and averages them: a ~108k-parameter recursive neural net (ONNX) and a hashed
character n-gram logistic regression (pure numpy). The neural net is the better of the
two at low false-positive rates (62% vs 55% caught at 1%; 58% vs 51% on names unseen
in training); the average ranks best overall. Then it runs the behavioural detectors. In inline mode the same core answers
DNS itself, with AdGuard as its upstream, and can sinkhole.
Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). API, event format and
config keys: [docs/REFERENCE.md](docs/REFERENCE.md).

Without onnxruntime (no build for your platform, e.g. 32-bit ARM), scoring falls back
to the n-gram model alone, which catches about 5 points fewer DGA names at the same
false-positive rate; `"models": "v3-public"` is made for that case. (Up to
v0.2.0-beta.2 such installs wrote no score-based alerts at all: building the alert failed
on the missing model's empty score.)

## What was found and fixed

Every version so far started with somebody trying to break the previous one: a code
audit, a field test on a real home network, real AdGuard Home and Pi-hole servers in CI,
83 replayed malware infections. This is the list of what that turned up, in plain words.
The full text with dates is in [CHANGELOG.md](CHANGELOG.md).

**Things that silently did not work**

| Flaw | What it meant | Fix |
|---|---|---|
| Upgrading stopped half-way on every AdGuard setup with a clean config | DNS kept working but nothing was scored until a script was re-run by hand | the warning loop can no longer end the script; tested |
| `dns_beacon` could never fire in shadow mode on AdGuard Home | AdGuard writes its log in batches, and the rule timed queries by when they were read | every timing rule now uses the query's own time from the log |
| Telegram dropped alerts after one failed send | one outage silenced every later alert while commands still answered | alerts queue, retry in order, survive restarts, say "sent late" |
| `install.sh` stopped at step 1 on Python 3.10 and 3.11 | no fresh install on Debian 12, Raspberry Pi OS or Ubuntu 22.04 | fixed; CI installs for real on five distributions |
| Without onnxruntime no score-based alert was ever written | 32-bit ARM installs detected nothing by score | falls back to the n-gram model; `"models": "v3-public"` |
| The generated gateway firewall never loaded | `destroy table` needs nftables 1.0.8, the Pi ships 1.0.6; a redirect sat in a filter chain | rewritten; CI loads it on 1.0.6 |
| ghost-flow never saw a packet; capture exited after 5 minutes | the documented queue rule was invalid; tcpdump flags were wrong | fixed; tested on a real kernel queue with real tcpdump |
| Docker: `ghostwall telegram` set everything up and sent nothing | the image had no bot | the image ships and starts it; CI checks an alert arrives |
| Three AdGuard settings broke Ghostwall without a word | query log off, memory-only, or "Anonymize client IP" | the installer names each; ghost-dns warns |
| `replay_querylog.py` used the defaults, not your settings | "replay your history first" showed the wrong thing | uses your config, feed and popular list |

**Detection that could be dodged or blinded**

| Flaw | Fix |
|---|---|
| Names under dynamic DNS (`<random>.ddns.net`) were scored as the provider's name, hiding whole malware families | the label under the provider is scored (53.4% to 60.3% on the public benchmark) |
| `nx_burst` could be blinded by AdGuard's own empty AAAA answers | empty answers (NODATA) prove nothing |
| `nx_burst` could be dodged by repeating one dead domain | the window keeps each name once |
| `nx_burst` ignored DGAs on newer TLDs | every TLD in the root zone counts (IANA's list) |
| A CNAME to a dead name counted as an unregistered domain | it does not |
| Pi-hole replies logged a moment after their query were lost | queries wait up to 3 s for their reply |
| Queries in the last moments before a log rotation were skipped | read from the `.1` file first |
| A name on the phishing list could not be trusted | trusting the listed name works; a listed subdomain of a trusted name still alerts |
| The firewall's DoH list (19 addresses) and ghost-flow's had drifted apart | one shared list, 91 addresses |
| A detected destination stayed open for every other device | `contain` (this release) |
| Blocked addresses were only dropped outbound; the Pi itself could still talk to them | dropped to and from, in the forward, input and output chains (this release) |

**False alarms**

| Flaw | Fix |
|---|---|
| Popular sites raised DGA alerts on their score alone | Tranco top-1M guard: 0.315% to 0.098% of Umbrella names, no DGA family hidden |
| The threat lists named whole popular sites and shared platforms | dropped at download time (top 100k); hosts under them stay |
| `dns_tunnel` flagged a game launcher (4 alerts in 20 field days) | under a popular domain only long random labels count |
| `dns_beacon` flagged weather and course-page polling (3 of 3 field alerts) | never under a popular site |
| A phone with Private DNS raised the same alert every day | once a month per device and provider, and says it is no sign of infection |
| Device names stuck to addresses, so "isolate laptop" could cut off the TV | names follow the MAC, IPv6 privacy addresses included |
| Trust on a tunnel alert trusted one throw-away subdomain | it trusts the zone |

**Security of Ghostwall itself**

- Control API: loopback only, refuses requests from web pages, actions need a token only
  the `ghostwall` user can read; the device list needs the token too.
- Dashboard: HTTPS, a password, a limit on wrong passwords, a content security policy.
- Telegram commands count only from the owner, in a private chat.
- `state.json` keeps what your household visits as keyed hashes, not as a readable list.
- A web page cannot flood you: alerts are capped per device per minute, state writes are throttled.
- The Docker container runs with no capabilities, a read-only filesystem and pinned images;
  Python dependencies are hash-locked and checked weekly against the OSV database.
- Everything that reaches `nft` as root is parsed again first: addresses, networks (never
  private, never wider than a /8), device names never reach a command line.
- Blocking fails safe: a list that fails to download keeps the old one; a firewall
  transaction applies whole or not at all; a bug in scoring forwards the query (fail open).

## Limits

- **It is not an antivirus and does not stop every virus.** It sees the network, not the
  device: [what still gets through](#what-happens-when-a-device-gets-infected).
- **Containment is new and only lab-tested.** `contain` has unit tests for every guard and
  path, and the firewall rules load in CI, but it has not blocked a real infection on a
  real network. Run `"contain": "dry-run"` first. Its address block needs gateway mode
  and, in shadow mode, AdGuard Home's log (Pi-hole's log has no full answers); it holds
  IPv4 only (the gateway forwards no IPv6). A contained name stays refused by your DNS
  server until Ghostwall's next state write after it ends (within a minute or so on a
  network in use).
- **Identity is an address and a MAC, and both can be faked.** Per-device rules, IoT
  sets and isolation follow a device's MAC and address. `antispoof` (gateway mode) stops a
  device borrowing a named device's address; nothing on a network can tell a cloned MAC
  from the real one. A phone using a random ("private") MAC per network is one device;
  one that rotates it looks like a new device each time.
- **Isolation trusts the sender address on a lookup, and that can be forged.** So
  `auto_isolate` only acts while the gateway firewall's `antispoof` is on, which binds each
  named device's address to its MAC, for forwarded traffic and for lookups sent to the Pi.
  Without it another device could send lookups under your laptop's address and get the
  laptop cut off. A cloned MAC is still not caught.
- **A listed name isolates only when two lists carry it** (`auto_isolate_min_sources`).
  Some lists take submissions from anyone; one entry must not be a remote off switch.
- **The caps can still be used up.** At most 2 automatic isolations an hour and 20
  behaviour containments a day, on purpose (a bad list must not take the house offline).
  Past them Ghostwall only alerts and says so. Listed names no longer count toward the
  containment cap.
- **Unnamed devices are never isolated automatically,** because a release works on names.
  Name every device (`sudo ghostwall name`); a guest device stays alert-only.
- **A page that reloads can still confirm itself.** `confirm_seconds` stops a single
  lookup from acting; a page left open that looks the name up again five minutes later
  looks the same as malware doing it.
- **Customer subdomains of big hosting platforms** (app hosts, serverless hosts) sit under
  a popular domain, so their random-looking names raise no score alert. The lists, tunnels
  and bursts still apply.
- **Automatic actions wait for a second sighting.** A web page or an email can make a
  device look up a listed name once. So `auto_isolate` acts when the device reaches for it
  again 5 minutes or more later (`confirm_seconds`); malware that looks a name up exactly
  once and then goes quiet is alerted on, not isolated. Before v0.3.0-beta.5 a single
  hidden image could cut a device off, and a page could get a small site blocked for the
  whole house for a week (`contain` with `dns_tunnel`).
- **The popular-site guard is a blind spot.** A name under a Tranco top-1M domain never
  alerts on its score alone, and a compromised popular site is a common place for malware
  to live. The threat lists, tunnels, bursts and beacons still apply there.
- **The detector fails open.** If ghost-dns or ghost-flow stops, DNS and traffic keep
  flowing unchecked. That is deliberate (a home must not lose its internet to a bug), and
  it means crashing Ghostwall is a way around it. Watch `ghostwall status`.
- **The benign evidence is thin.** 17 normal-traffic captures (3.5 device-days) and one
  home network for 19.5 days are too little to promise a false-positive rate: with no
  false block seen in 3.5 device-days, statistics still allow almost one a day.
- **IPv6 is not filtered, it is switched off.** Gateway mode asks you to disable your
  router's IPv6 advertisements. If you leave them on, devices have an unfiltered way out.
- **Inbound blocking is mostly your router's job.** The Pi drops packets from blocked and
  criminal networks that pass through it or are aimed at it, but replies normally return
  through the router, not the Pi. Dropping the outbound side is what ends a connection.

- **Baselines trust what is already there.** `abused_service` learns each device's usual
  services in its first 3 days, and novelty counts names as normal after a week. A device
  that is already infected when you install Ghostwall teaches it that its malware is
  normal; the threat lists, bursts, tunnels and DoH rules don't depend on a baseline.
- **Detection is name-based.** It sees what a device looks up, not what it does
  afterwards. The models miss about 4 in 10 DGA domains, and nearly all made of
  dictionary words; `nx_burst` catches those by their failed lookups instead, but only
  while most of them fail, and not an implant slower than about one lookup a minute
  (its numbers are a simulation, not field results). Malware that talks to shared
  services (cloud storage, CDNs, chat apps) looks like everyone else, and a device with
  hardcoded DNS-over-HTTPS is invisible in shadow mode unless it looks the server up by name
  (gateway mode catches it by IP: `doh_ip`). Any web
  page can also make your browser look up random-looking names, so an alert means
  "check this device", not proof of infection; alerts are capped per device per
  minute so such a page can't flood you.
- **One DNS client for the whole house hides who did what.** If your router forwards
  every device's DNS to AdGuard or Pi-hole, they all look like the router: per-device
  rules then add up the whole household (ten dead domains from different devices can
  raise one `nx_burst`). Point devices at the box directly (DHCP's DNS server option).
  Tools that check many domains on purpose (link checkers, mail filters, dnstwist) look
  like `nx_burst` too: list that device in `nx_burst_ignore_devices`.
- **Tested on one home network** (Pi 4, AdGuard Home in Docker). The x86_64 install,
  Pi-hole support and the Docker image are new in v0.2 and verified on Ubuntu 24.04
  (x86_64), a Pi 4, the official Pi-hole Docker image and in CI, not yet on many real setups. Expect
  to allowlist a few domains in the first week, and please open an issue with what you see.
- **Inline mode and enforcement are unproven on a real network** (CI tests inline mode
  end to end in a container). The first inline
  deployment broke a workstation's DNS; the resolver was hardened afterwards (TCP,
  IPv6, upstream fallback, fail-open), but run shadow mode for at least a week first.
  Inline mode needs AdGuard Home.
- **Isolating a device and LAN lockdown need gateway mode** (the box routes your LAN's
  traffic). In the default setup the dashboard doesn't offer them and the API refuses.
- **`ghost-flow`** (raw-IP, DoH-by-IP, beacon and JA4 connection checks) and **`capture`**
  (pcap freeze on alert) need gateway mode too. CI runs them in a lab container (a device
  and a "wan" in network namespaces): the generated firewall loads on nftables 1.0.6,
  isolation and lockdown change it, ghost-flow reads a real kernel queue, capture runs
  real tcpdump. Not yet on a real network.
- **The dashboard is HTTPS with a self-signed certificate** (the installer makes it and
  prints its fingerprint; browsers warn once) and a password. Fine on a home LAN or a
  tailnet; never expose it to the internet. The control API
  listens on loopback only, refuses requests from web pages, and takes actions only with
  a token that only the `ghostwall` user can read.
- **Telegram alerts go through Telegram's servers.** They name the device and domain,
  unless you set `FW_BOT_PRIVACY=minimal` in `/etc/ghostwall/fw_bot.env`: then they say
  only which device and what kind of alert, and the rest stays on the dashboard.

## Tests

Stdlib `unittest`, no network needed (`numpy` and `onnxruntime` for the scoring tests).
[CI](https://github.com/TRXAlpha/ghostwall/actions/workflows/tests.yml) runs on every push:

- unit tests on x86_64 and arm64 with Python 3.10, 3.13 and 3.14, and pyflakes;
- `tests/installer_e2e.sh`: `install.sh` for real under systemd on Debian 12 and 13 and
  Ubuntu 22.04, 24.04 and 26.04 (inline mode, update and uninstall included), and an upgrade
  over v0.2.0-beta.2 that must keep its alerts, trusted domains, names and thresholds;
- `tests/gateway_e2e.sh`: ghost-flow on a real kernel queue, capture with real tcpdump, the
  generated nftables ruleset;
- `tests/realdns_e2e.py`: real AdGuard Home and Pi-hole containers: answer codes, one
  `nx_burst`, and that a listed name is refused while a trusted one is not;
- the Docker image on both CPUs, with no capabilities, including Telegram alerts;
- weekly, every pinned Python package against the OSV vulnerability database.

To run the unit tests yourself:

```bash
for d in agents/ghost_dns/tests agents/ghost_flow/tests agents/fw_bot/tests agents/capture/tests agents/web_ui/tests; do
  python -m unittest discover -s "$d" || break
done
python agents/netconf/test_gen.py
```

## Repository layout

```
install.sh, uninstall.sh   systemd install (shadow mode) and removal
Dockerfile, compose.yaml   container image; Ghostwall + AdGuard Home in one compose file
agents/ghost_dns/   the decision core: resolver, scoring, detectors, shadow follower, control API
agents/web_ui/      dashboard, and the demo generated by the real detector
agents/fw_bot/      Telegram alerts and /fw commands
agents/ghost_flow/  connection inspector (gateway mode)
agents/capture/     per-device pcap ring + freeze on alert (gateway mode)
agents/netconf/     generator for the Pi-as-gateway configs (dnsmasq, nftables, sysctl)
agents/dga_eval/    evaluation: shipped models on DRIFT (eval_shipped.py -> results_shipped.md),
                    public benchmark (public_bench.py -> results_public.md), LSTM rematch
                    (fair_lstm.py), simple baselines (baselines.py -> results_baselines.md)
tests/              installer, upgrade and gateway end-to-end tests, OSV audit
ghostwall/          shipped models + the numpy LR trainer
trm/                neural-net training code
```

## Contributing

What changed between versions: [CHANGELOG.md](CHANGELOG.md).

Bug reports with your setup (DNS server, how it is installed, OS, CPU) are the most
useful thing right now. A false positive? Include the domain and the alert line. Pull
requests welcome; please run the tests first.

## License

[MIT](LICENSE) © Morogan Christian.
