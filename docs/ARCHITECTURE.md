# Architecture

How Ghostwall is built and why. For running it see [OPERATIONS.md](OPERATIONS.md);
for the API, event format and config keys see [REFERENCE.md](REFERENCE.md).

## Goals and constraints

Detect, and optionally stop, the network side of a compromised home device:

- **Malware command-and-control**, often via algorithmically generated domains (DGA)
  or hardcoded IPs.
- **DNS tunnelling**: data smuggled out in long random subdomains.
- **DNS filter bypass**: a device using DNS-over-HTTPS to skip the LAN resolver.
- **Known-bad destinations**: phishing and malware domains on public lists.

Constraints: runs on a Raspberry Pi CPU (or any small x86_64/arm64 box or VM) in well
under 1 GB of RAM; no traffic or
telemetry leaves the network; every decision is explained; and it must never be able
to silently break the network. That last one drives most of the design.

## Two ways to run

| | Shadow mode (recommended) | Inline mode |
|---|---|---|
| Who answers DNS | AdGuard Home or Pi-hole on :53 | ghost-dns on :53, AdGuard behind it on :5300 |
| What ghost-dns sees | AdGuard's `querylog.json` or Pi-hole's `pihole.log`, tailed | every query, live |
| Can it block | no | yes, once learning is off |
| If ghost-dns crashes | nothing happens to DNS | DNS stops for every device |

Both modes run the same `Resolver.decide()`; shadow mode feeds it from the query log
(`shadow.py`) and never acts on the result, so alerts and history are identical.

## Components

```
                 ┌──────────── shadow: querylog.json ◀── AdGuard Home ◀── devices
                 ▼
          [ ghost-dns ]  decide() ──▶ events.jsonl ──▶ web_ui, fw_bot (Telegram)
           │   inline: UDP/TCP :53, v4+v6, forwards to AdGuard, sinkholes blocks
           ├──▶ control API 127.0.0.1:5380 ◀── web_ui, fw_bot
           ├──▶ resolved_ips.jsonl ──▶ ghost-flow   (gateway mode)
           └──▶ POST /freeze ────────▶ capture      (gateway mode)

enforcement (opt-in, nftables table `ghostwall`): isolated_dev set, blocked_ip set, lockdown rule
```

Only `ghost-dns` decides allow or block for a domain. Everything else feeds it or is
driven by it.

| Component | Path | What it does |
|---|---|---|
| ghost-dns | `agents/ghost_dns/` | resolver, scoring, detectors, state, control API, shadow follower, threat-feed updater |
| web_ui | `agents/web_ui/` | stdlib dashboard: devices, recent decisions, allow box, learning and lockdown toggles |
| fw_bot | `agents/fw_bot/` | Telegram: alerts with signed buttons, `/fw` commands, daily digest |
| ghost-flow | `agents/ghost_flow/` | first-packet inspector on NFQUEUE 100: raw-IP, beacon, JA4 |
| capture | `agents/capture/` | per-device rolling pcap ring in tmpfs, freezes 5 min either side of an alert |
| netconf | `agents/netconf/` | renders dnsmasq, nftables and sysctl configs for the Pi-as-gateway topology |

## ghost-dns

### Decision pipeline (`resolver.py`)

For each query, in order. The first rule that returns wins.

1. **Threat feed** (`detectors.ThreatFeed`). An exact match beats the allowlist; a
   parent-domain match respects it. → `threat_feed`, high.
2. **DoH lookup** (`DohDetector`): the name is a known DNS-over-HTTPS endpoint.
   → `doh_bypass`, warn.
3. **Allowlist** (exact or parent). → allow, no event.
4. **Internal names** (`is_internal`): single labels, `.local`, `.lan`, `.home.arpa`,
   `.internal`, `.ts.net`, reverse lookups, `_service` records. → allow, never scored.
5. **Blocklist** (confirmed blocks). → block (inline) or recommend (shadow).
6. **Score** the registrable label and record novelty (`first_seen`).
7. **Behaviour**: `TunnelDetector` (many distinct long high-entropy subdomains of one
   apex in 10 minutes) and `BeaconDetector` (a name repeated on a near-constant
   interval, only if it scores ≥ 0.5 or uses a rare TLD, because apps poll on timers).
8. **DGA burst** (`DgaBurst`): one device, ≥ 5 different names scoring ≥ 0.80 within
   10 minutes. This catches DGA malware even when each name is only moderately odd.
9. **Single high score**: ≥ `block_threshold` (0.995) and new → `dga_high`; it blocks
   only in inline mode with learning off. ≥ `recommend_threshold` (0.96) and new →
   `dga_suspect`.
10. **Corroborated**: ≥ 0.80 on a rarely-legitimate TLD → `dga_corroborated`.
11. Otherwise allow.

A score alone never blocks an established domain: blocking needs a new name (first
seen within `novelty_days`, default 7), learning mode off, and inline mode. Recommend
events are deduplicated per device, registrable domain and rule for 24 hours.

### Scoring (`tokenizer.py`, `scoring.py`)

The score is the mean of two models over the registrable label (dots stripped, the
same tokenizer as training):

- **TRM** (`ghostwall/models/trm_dga_v2.onnx`): a tiny recursive model, ~108k
  parameters, run with onnxruntime on the CPU.
- **LR** (`lr_coef.npy`, `lr_meta.json`): hashed character 1–3-gram logistic
  regression, reimplemented in numpy so the Pi needs no scikit-learn.

If one model is missing the other is used; if both are, a lexical-entropy heuristic
keeps the pipeline running.

### Serving (inline mode)

UDP and TCP on IPv4 and IPv6, a thread pool so a slow upstream cannot stall other
clients, a primary upstream plus fallbacks (default `9.9.9.9`) with a retry back-off,
and **fail-open**: if scoring raises, the query is forwarded unscored. Blocks return a
sinkhole address (`0.0.0.0` / `::`) or NXDOMAIN; upstream failure returns SERVFAIL.

### State, events, enforcement

- `state.py`: one `GhostState` (allowlist, blocklist, isolated devices, lockdown,
  learning, per-domain `first_seen`) persisted atomically to `state.json`; novelty is
  flushed at most every 5 s and on shutdown.
- `events.py`: line-atomic JSONL writer; every event passes `fw_bot/validate_events.py`.
- `enforce.py`: `NullBackend` (default; records intent only) or `NftBackend` (device
  isolation, blocked IPs, LAN lockdown via the `ghostwall` nftables table; every IP is
  validated before it reaches the `nft` command line). Domain blocking happens in the
  resolver, not the kernel.

## Detection

### Models

Trained on 2017–2019 benign and DGA domains (the DRIFT eSLD dataset) and evaluated
**frozen** on 2020–2025, to measure how well a model survives time rather than how
well it fits one year. AUC falls from ~0.985 (2020) to ~0.963 (2025). The TRM is no
better than the plain n-gram LR on its own; the shipped scorer averages the two.

Thresholds were set by measurement on 20,000 benign plus 20,000 DGA domains from the
frozen 2024–2025 years:

| Score ≥ | Normal domains flagged | DGA domains caught |
|---|---|---|
| 0.60 | ~6.5% | — |
| 0.90 | ~2.0% | — |
| **0.96** (alert) | ~1% | ~60% |
| **0.995** (block) | ~0.1% | ~40% |

A single score cannot do better, so most of the detection value comes from the
evidence and behaviour rules above: the threat feed, bursts, tunnelling, beacons and
novelty. Evaluation code and results are in `agents/dga_eval/`; the LR trainer is
`ghostwall/train_lr.py`; the TRM training code is in `trm/`.

### Measured on a real network

- **Replay** (`replay_querylog.py`): 70,615 real queries over 8.7 days from one home
  network gave 13 alerts, against roughly 50 a day with the first thresholds.
- **Simulation** (`eval_detection.py`, labelled data): a normal device went from 20.5
  to 3.0 alerts a day, while an infected device was still caught.

### What it cannot see

What a device does after the lookup; connections to hardcoded IPs (ghost-flow covers
that in gateway mode); devices that use their own DNS-over-HTTPS (flagged when they
look it up, not blocked); and DGA names that look like words.

## Gateway mode (ghost-flow, capture, netconf)

For connection-level checks the Pi must forward the LAN's traffic. `netconf` renders
the configs for an asymmetric topology: the Pi becomes DHCP server, DNS server and
default gateway, while the existing router keeps NAT:

```
outbound:  device ──▶ Pi ──▶ router ──▶ internet
return:    internet ──▶ router ──▶ device   (directly, bypassing the Pi)
```

That is why the nftables ruleset uses loose `rp_filter`, sends no ICMP redirects and
captures only `src host <device>`.

- **ghost-flow** reads the first packet of each new forwarded flow from NFQUEUE 100
  (`queue ... bypass`, so traffic flows if the daemon is down). It flags a connection
  to a public IP that ghost-dns never resolved (`raw_ip`), regular call-home
  intervals (`beacon`), and attaches a JA4 TLS fingerprint. It accepts every packet
  unless enforcement, learning-off and `--autoblock` are all set, and even then drops
  only confirmed beacons.
- **capture** keeps a 5-minute per-device pcap ring in RAM and, on a high-severity
  alert, freezes 5 minutes before and after into an incident folder (2 GB retention).

Both are tested on crafted and recorded traffic only.

## Safety model

- Defaults are safe: loopback binds, learning on, null enforcement, shadow mode in the
  installer.
- Blocking needs inline mode, learning off and a new domain; kernel enforcement needs
  `enforce: "nft"` as well.
- Inline mode fails open on scoring errors and falls back to a second upstream.
- `ghost-flow` never drops by default; its queue rule uses `bypass`.
- Everything is reversible: `go_shadow.sh` returns DNS to AdGuard, and
  `ghostwall-breakglass` removes the nftables table and restores sysctl.
- Inputs that reach the kernel or the filesystem are validated: IPs before `nft`,
  event ids before capture writes, callback buttons by HMAC with a constant-time check.
- The control API and capture API have no authentication by design and listen on
  loopback only. The dashboard needs a password (HTTP Basic, constant-time compare) on
  any address but loopback and refuses to start without one; it accepts actions only
  as JSON from its own origin, and without a password it answers only IP or
  `localhost` Host headers, which stops DNS rebinding.
