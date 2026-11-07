# Field results

What Ghostwall did on a real network, as opposed to the simulations in
`agents/dga_eval/`. **One home network, 2026-11-07**: a field test of v0.3.0-beta.2 by
the author. It is one network, so it says little about yours; please
[open an issue](https://github.com/TRXAlpha/ghostwall/issues) with your own numbers
(counts and rates are enough, never your domains or addresses).

Nothing here can be reproduced from the repo: the query log is private. What can be
reproduced is the method: `replay_querylog.py` on your own log, with `--set` for the
threshold comparisons, and the live tests below against your own DNS server.

## Setup

- Raspberry Pi 4 (4 GB), Debian 13 arm64, AdGuard Home in Docker (host network),
  Ghostwall installed natively with `install.sh`, shadow mode, learning on.
- Upgraded in place from v0.2.0-beta.2.
- Threat feed 267,422 names from 3 lists (URLhaus 1,942, Phishing Army 145,700, HaGeZi TIF
  189,383 after the popularity guard; 179 popular names dropped); popular list 995,166
  registrable domains from the Tranco top 1M.
- The clients were 5 tailnet devices and the box itself. In this setup the LAN's own
  devices did not use the box for DNS (most likely the router's DHCP names another server; not checked), so they are
  not in these numbers, and MAC-based naming had nothing to work on (tailnet addresses
  carry no MAC). Devices that use the box as a Tailscale exit node appear as the box
  itself (127.0.0.1).

## Replay of the history (v0.3.0-beta.2)

260,409 queries over 469 hours (19.5 days); 6,458 NXDOMAIN answers.

| | alerts | what they were |
|---|---|---|
| `abused_service` | 7 | false positives: first use of a chat app's file CDN (4), a raw code download, a serverless geo lookup, a file-drop site, on devices whose owners use them |
| `dga_high` | 5 | 3 test lookups by the author (one name on two days), 2 ad-redirect domains registered the same afternoon |
| `doh_bypass` | 4 | expected: browsers and a phone using DNS-over-HTTPS |
| `dns_tunnel` | 4 | false positives: one game launcher's word-based service names (fixed, see below) |
| `dns_beacon` | 3 | false positives: a weather script every 15 min (2), a course website polled every 10 min |
| `dga_suspect` | 2 | 1 ad-redirect domain, 1 test lookup |
| `threat_feed` | 1 | unclear: a CDN host on one list, in the same browsing session as the ad-redirect domains |
| `dga_corroborated` | 1 | test lookup |
| `nx_burst` | 0 | |
| `dga_burst` | 0 | |
| **total** | **27** | 1.4 a day |

False positives (alerts with a benign cause; tests, DoH and ad junk not counted): 14,
or 0.72 a day and 0.54 per 10,000 queries. By rule: `abused_service` 0.36 a day (0.27 per
10k), `dns_tunnel` 0.20 (0.15), `dns_beacon` 0.15 (0.12). With the `dns_tunnel` fix: 23
alerts, 10 false positives, 0.51 a day, 0.38 per 10k.

The popular-domain guard stopped 172 would-be alerts (repeats included). The replay
without it (the bug below: an old feed and no popular list) had 31 alerts: 4 more
`dga_suspect` and 1 more `dga_burst`, all on names in the Tranco top 1M, and no
`threat_feed` hit (the old feed lacked the malware lists).

### nx_burst on real traffic

No `nx_burst` alert in 19.5 days at the default 10 names, nor at 8, 5 or even 3. Of the
6,458 NXDOMAIN answers, the only ones for a registrable domain itself (the only kind that
counts) were 8 test lookups by the author, at most 2 different in any 10 minutes. The
rest were names the rule skips by design: WPAD and other search-domain names (about
4,400 from one device), `_service` and Kerberos SRV records, reverse lookups, `.invalid`
and `.local` names, and subdomains of real domains.

### Thresholds compared (`--set`)

| setting | alerts | change |
|---|---|---|
| defaults | 27 | |
| `popular_top_n=100000` | 29 | +2 `dga_suspect` (one ad-redirect domain ranked between 100k and 1M, on two devices); guard stopped 120 instead of 172 |
| `nx_burst_min_distinct` 3, 5, 8 or 15 | 27 | none |

The defaults stay: the top 1M is the better guard here, and `nx_burst` has a wide margin
both ways on this network.

## Live tests through the real pipeline

One test client on the tailnet, lookups through AdGuard Home; time to alert is from the
lookup that should trigger it to the alert in `events.jsonl`. AdGuard writes its log
every 10 queries (the installer's setting), so on a quiet network an alert can wait for
the next 10 queries.

| test | expected | result | time |
|---|---|---|---|
| `nx_burst`: 15 made-up word domains, A + AAAA, 5 s apart | one alert | pass: one alert, at the 10th name | 5.7 s |
| `nx_burst` guards: 5 missing names under a real domain, 5 single labels, 5 `.lan` names, then 9 storm names | no alert | pass | |
| `dga_burst`: 6 random-letter names, 10 s apart | one alert, no `nx_burst` | pass (plus 2 single-name DGA alerts) | 61 s (log buffer) |
| `threat_feed`: one name from each list | 3 alerts naming the right lists | pass | 24 s |
| popular guard: 20 random-looking names from the top 20k | no DGA alert | pass (guard counter +19) | |
| `doh_bypass`: two DoH providers | one alert each, or monthly dedupe | pass: 1 new, 1 deduped (seen the day before) | 2.0 s |
| `dns_tunnel`: 35 random 45-character labels under one made-up domain | one alert | pass, at the 12th label | 0.6 s |
| trust: `ghostwall allow` one new random name, then look up it and a control | alert for the control only | pass | 12 s |
| `dns_beacon`: one made-up name every 31 s, 9 times | one alert | none seen within 4 min of the last lookup: inconclusive (31 s is at the detector's 30 s minimum, and the log buffer may not have flushed) | |

## Resilience

- Restart of ghost-dns: active at once, control API answering after about 6 s, scoring
  again after about 7 s; no old alert repeated.
- ghost-dns stopped for 30 s: DNS answered 30 of 30 lookups (shadow mode never carries it).
- Feed update: exit 0, 267,630 names from 3 sources, 179 popular names dropped, 11 s.
- Disk: 21 MB in `/var/lib/ghostwall`; the alert log far below its 32 MiB rotation size.
- DNS answer times before and after the tests were the same (median 0 ms cached, 15 ms
  uncached, on the box).

## Bugs this found

All fixed in the same change ([CHANGELOG](../CHANGELOG.md), "Unreleased"):

- the upgrade stopped half-way on a clean AdGuard config and left ghost-dns stopped
  (DNS itself was never affected: AdGuard serves it);
- the replay ignored `ghost_dns.json`, and on upgraded installs replayed with a stale feed
  and without the popular-domain guard; its alerts carried the replay's time;
- `dns_tunnel` flagged a game launcher's service names;
- `ghostwall status` timed out after the daily feed update (the request reloaded the lists);
- `ghostwall version` named the wrong release; a harmless traceback in the journal.
