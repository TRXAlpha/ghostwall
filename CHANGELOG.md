# Changelog

## Unreleased

Found by a field test of v0.3.0-beta.2 on one home network (Raspberry Pi 4, AdGuard Home
in Docker, shadow mode) on 2026-11-07: [docs/FIELD_RESULTS.md](docs/FIELD_RESULTS.md).

### Fixed

- **The upgrade stopped half-way and left ghost-dns stopped** on every AdGuard Home setup
  with nothing to warn about. `go_shadow.sh` (run by `install.sh`) printed AdGuard's
  settings warnings in a loop whose last test was false for an empty line, which
  `set -e -o pipefail` turned into an exit; DNS kept working (AdGuard serves it), but
  nothing was scored until `go_shadow.sh` was re-run by hand. The warnings can no longer
  stop the script, and `adguard_conf.py --check` prints nothing for a clean config. If
  your upgrade ended right after "DNS answers on :53", run
  `sudo bash /opt/ghostwall/agents/ghost_dns/go_shadow.sh` once after updating.
- **`replay_querylog.py` replayed with the wrong settings and lists.** It ignored
  `/etc/ghostwall/ghost_dns.json`, so "replay your history first" showed the defaults, not
  your thresholds; and on installs upgraded from before 0.2.0b2 it used the stale feed left
  next to the code and then found no popular list beside it, so the popular-domain guard
  was off in the replay. It now uses your config, the feed it names (else
  `/var/lib/ghostwall/threat_feed.txt`) and the popular list next to that.
- Replayed alerts carry the time of the query that raised them, not the time of the
  replay, and the summary counts them per day.
- **`dns_tunnel` flagged a game launcher.** Its "many distinct subdomains" test needs only
  30 names averaging 14+ characters, and a big site's own word-based service names
  pass it: 4 false
  alerts in 20 days on the field network, all one launcher. Under a domain on the
  popular list only the long random labels a tunnel's payload needs count now; any other
  domain is checked as before. On the field log: 27 alerts before, 23 after, the 4
  launcher alerts gone and nothing else changed.
- **`dns_beacon` could never fire in shadow mode on AdGuard Home.** The timing rules used
  the time ghost-dns *read* each query, and AdGuard writes its log in batches (10 queries
  since the installer's change), so lookups asked a minute apart arrived together and the
  beacon rule took them for retries. They now use each query's own time from the log
  (`T`), so beacon, tunnel, `nx_burst` and `dga_burst` windows match what the devices
  did. On the field network a live test (9 lookups, 31 s apart) raised nothing; the same
  queries replayed by their own times raise `dns_beacon`. Pi-hole was not affected (it
  writes each line as it happens). Expect the beacon alerts the replay already showed:
  3 in 20 days on the field network, all scripts polling a site on a timer (trust them
  with `ghostwall allow`).
- `ghostwall version` named the wrong release: release tags are lightweight and the
  installer's `git describe` skipped them (v0.3.0-beta.2 showed as
  `v0.2.0-beta.1-86-g...`).
- **`ghostwall status` timed out after the daily feed update** (shadow mode): the status
  request itself reloaded the changed lists, about a minute for the top 1M on a Pi 4.
  Status now reports what is loaded and the next scored query reloads; ghost-dns loads
  both lists at start, with the control API already answering.
- REFERENCE.md said popular sites' names still count toward `dga_burst`; since 0.3.0b2
  they don't (as this changelog says below).
- The control API no longer prints a `BrokenPipeError` traceback into ghost-dns's journal
  when a client hangs up before the answer (a status poll that timed out).

### New

- **Automatic isolation (opt-in, gateway mode).** `auto_isolate` `"off"` / `"dry-run"` /
  `"on"` cuts off a device behind an exact malware-list hit (not under a popular site, not on
  phishing lists only) or a DNS tunnel. Exempt list, at most `auto_isolate_max_per_hour` (2)
  an hour kept across restarts, and a Release device button in Telegram (also the dashboard
  and `sudo ghostwall release NAME`). `/release` is idempotent and finds a device that moved;
  isolations come back after a reboot. The dashboard tags alerts isolated / would isolate /
  isolation failed.
- **Default-deny for IoT devices (opt-in).** Mark a device `"profile": "iot"`
  (`sudo ghostwall profile NAME iot`): Ghostwall learns the domains it uses for
  `iot_learn_days` (7; hashed in `state.json`), then raises `iot_new_domain` for any other.
  `iot_enforce` `"off"` / `"dry-run"` / `"on"`: "on" refuses those names in inline mode with
  learning off; events carry `would_block` when they would have been. Trust on such an alert
  (Telegram, dashboard, `ghostwall allow DOMAIN --device NAME`) allows it for that device
  only; `ghostwall untrust DOMAIN --device NAME` and `ghostwall relearn NAME` undo.
  `ghostwall status` and the dashboard show IoT devices and their learning state.

### Changed

- **Gateway mode blocks DoH to about 90 public resolver addresses** (91, was 19): one list,
  `agents/netconf/doh_ips.txt`, for the firewall's `doh_ip4` / `doh_ip6` sets and
  ghost-flow's `doh_ip` alert, which had drifted apart. Adds Cloudflare's security and
  family resolvers, NextDNS, Mullvad, Control D, CIRA, dns0.eu, DNS.SB and more; only
  addresses dedicated to DNS. Re-run `gen.py` to apply.
- Privacy mode: the Trust reply no longer names a tunnel's or IoT alert's parent domain.
- **`dns_beacon` skips popular sites.** All 3 `dns_beacon` alerts in the field test were
  false: a script polling a weather site every 15 min (2) and a course website polled
  every 10 min, all on the popular list. Now that shadow mode times queries correctly
  these would fire live, so a name under a domain on the popular list no longer raises
  `dns_beacon` (the list is only asked when the timing test would fire). Odd-looking
  names and rare TLDs on domains that aren't on it alert as before.
- `replay_querylog.py --set KEY=VALUE` tries another value for one replay without
  editing your config (`--set nx_burst_min_distinct=15`, repeatable); `--config FILE` or
  `--no-config` picks the settings; `--events-out FILE` keeps every alert.

## v0.3.0-beta.2 (2026-11-07)

Update as usual: `git pull && sudo ./install.sh` (Docker: `git pull && docker compose up -d --build`).
Your settings, alerts, allowlist and thresholds are kept. The daily feed update now also
downloads the Tranco top 1M (about 20 MB, kept as `/var/lib/ghostwall/popular_domains.txt`).

### New detection

- **`nx_burst`: malware hunting for its server.** A device that fails to resolve (NXDOMAIN)
  10 or more different unregistered domains within 10 minutes is flagged: what malware
  cycling through generated domain names (DGA) looks like, including word-based ones such
  as suppobox and matsnu that the models miss. Works from AdGuard's and Pi-hole's logs and
  inline. Typos, probes under real domains, local and search-domain names, Chrome's random
  probes and anything your DNS server blocked never count; nor does a domain that has
  resolved on your network before (kept hashed in `state.json`). New settings
  `nx_burst_enabled`, `nx_burst_min_distinct`, `nx_burst_window`. In a simulation on the
  public Netlab 360 DGA list it fired for all 25 families within 10 lookups
  ([results_nx_sim.md](agents/dga_eval/results_nx_sim.md)); a simulation, not a field result.
- **Malware and C2 lists.** The threat feed adds URLhaus (malware) and HaGeZi TIF mini
  (malware, C2, phishing) to Phishing Army: 267,422 domains on 2026-11-07. They are held as
  sorted 64-bit hashes: 3.3 MiB in memory (23 MiB as strings), loaded beside the old list
  in inline mode so no answer waits for a reload.
  Alerts name the list (`on URLhaus (malware)`).
- **Popular sites are never flagged by the feed as a whole.** An entry that is a Tranco
  top-100k domain or a shared platform (`github.io`, `drive.google.com`) is dropped at
  download time (179 that day); hosts under them (`evil.github.io`) stay
  ([results_feeds.md](agents/dga_eval/results_feeds.md)).
- **Popular sites no longer raise DGA alerts on their score alone.** A name whose
  registrable domain is on the cached Tranco top 1M (`popular_domains.txt`, kept in rank
  order) skips `dga_high`, `dga_suspect` and `dga_corroborated`; the feed, tunnel, beacon,
  `dga_burst` and `nx_burst` rules still apply. On Cisco Umbrella's top 1M (not used to set
  the thresholds) DGA alerts drop from 0.315% to 0.098% of names, with no DGA family's
  names hidden ([results_fp_independent.md](agents/dga_eval/results_fp_independent.md)).
  The guard holds 8 MiB. New keys `popular_path`, `popular_top_n`; no list means the old
  behaviour. `ghostwall status` shows the list's size.

### Changed

- A feed source that fails, or shrinks to less than half, keeps its previous contents for
  up to 14 days while the others update (one dead URL no longer freezes the whole feed or
  marks the daily job failed). The update now also needs the Tranco list (cached as
  `/var/lib/ghostwall/popular_domains.txt`); with neither a download nor a cache it keeps
  the old feed.
- In learning mode, inline queries are scored once the answer is back, so the answer code
  reaches `nx_burst`; the answer itself is not delayed.
- New setting `nx_burst_ignore_devices`: a box that fails lookups on purpose (a link
  checker, a mail filter) can be left out of `nx_burst`.
- Popular sites' names never count toward `dga_burst` (a portal loading several brand
  domains that look random is not malware), and one lookup storm raises one alert:
  `dga_burst` or `nx_burst`, not both.
- The threat feed is held as sorted hashes: 3.3 MiB instead of 23 MiB. In inline mode
  the feed and the popular list load in the background, so a daily reload never delays
  an answer; a list that fails to load keeps the previous one.

### Fixed

- `nx_burst` could be blinded: AdGuard's own empty answer to an AAAA query (with IPv6
  resolving off) marked the domain as registered. Empty answers (NODATA) now prove nothing.
- `nx_burst` could be dodged by looking up one dead domain over and over (it pushed the
  others out of the window); the window now keeps each name once.
- `nx_burst` ignored DGAs on newer TLDs (.science, .bond, .party...): every TLD in the root
  zone now counts (IANA's list, `agents/ghost_dns/tlds.txt`).
- A CNAME to a name that no longer exists counted as an unregistered domain.
- Pi-hole: a reply logged a moment after its query (in the next read) was lost; queries
  now wait up to 3 s for it. `replay_querylog.py` pairs replies the same way.
- Feed update: the file is flushed to disk before it replaces the old one (no half-written
  feed after a power cut), no temporary files are left on a failed write, a typo in a
  number setting warns instead of stopping every daily run, and a list that shrank stays
  accepted once its 14-day carry-over has run out.

### Tests

- New CI job: real AdGuard Home and Pi-hole containers with a real upstream log a storm
  of made-up domains, a normal lookup, a missing name under a real domain and a name the
  server blocks itself (answered NXDOMAIN); Ghostwall must read every answer code right
  and raise exactly one `nx_burst` (`tests/realdns_e2e.py`).

## v0.3.0-beta.1 (2026-11-03)

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
  new `compose.yaml` if you copied the old one. Images are pinned. The Ghostwall container now
  runs with no capabilities; if you run AdGuard as a non-root user, add
  `cap_add: [DAC_OVERRIDE]` to it (the container tells you when it can't read the log).

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
- A phone with "Private DNS" on (or a browser with "secure DNS") raised the same
  "bypassing your DNS filter" alert every day. It now comes once a month per device and
  provider, and says that it is not a sign of infection by itself.
- In shadow mode a query log Ghostwall may not read (it belongs to the user AdGuard runs
  as) was skipped in silence; it is now said once, with the fix. The installer says when it
  restarts AdGuard (and `ADGUARD_FLUSH_EVERY=0` skips that).
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
- Three AdGuard settings broke Ghostwall without a word: the query log off, kept in memory
  only (no file), or *Anonymize client IP* on (every device then looked like one). The
  installer now names each, and ghost-dns warns when client addresses arrive anonymized.
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
every site your household visits (converted, and the file rewritten, on the first start); tighter systemd sandboxes; hash-locked Python dependencies; `events.jsonl` rotates.
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
  `agents/dga_eval/results_public.md`, with a fairer LSTM rematch in `results_lstm_fair.md`
  and simple baselines in `results_baselines.md` (character entropy: 11.6% at 1% false
  positives, against 60.3% for the shipped models).
- CI installs Ghostwall for real under systemd (Debian 12 and 13, Ubuntu 22.04, 24.04 and
  26.04), inline mode included.
- CI upgrades a v0.2.0-beta.2 install with history in it (an alert, a trusted domain, a
  named device, a threshold) and checks it all survives. Its first run found the readable
  list of visited domains left in `state.json` after the upgrade until a new domain came.
- CI lints the code (pyflakes, pinned). Its first run found a gateway test (the LAN
  interface setting) that had never run, and two tests that checked nothing; all fixed.
