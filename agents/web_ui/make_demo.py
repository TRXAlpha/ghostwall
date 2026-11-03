#!/usr/bin/env python3
"""Write demo_events.json by running the real detector over one made-up day.

    python make_demo.py        # needs numpy and onnxruntime, like ghost-dns itself

Five invented devices browse ordinary sites all day, and a few scripted incidents
happen in between. Every alert in the file comes out of ghost-dns's own
Resolver.decide() with the shipped models, allowlist, thresholds and dedupe; only
the device names and the one-line threat feed are made up. tests/test_demo.py
regenerates it and fails if the committed file no longer matches, so the demo
dashboard (demo.py) can't show anything the product wouldn't.
"""
from __future__ import annotations

import json
import os
import random
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GHOST_DNS = os.path.join(os.path.dirname(HERE), "ghost_dns")
OUT = os.path.join(HERE, "demo_events.json")

DEVICES = [
    {"name": "laptop", "ip": "192.168.1.10", "mac": "02:00:00:00:00:10"},
    {"name": "phone", "ip": "192.168.1.11", "mac": "02:00:00:00:00:11"},
    {"name": "tv", "ip": "192.168.1.12", "mac": "02:00:00:00:00:12"},
    {"name": "printer", "ip": "192.168.1.13", "mac": "02:00:00:00:00:13"},
    {"name": "console", "ip": "192.168.1.14", "mac": "02:00:00:00:00:14"},
]
FEED = ["parcel-redelivery-k7f2.top"]   # stands in for the daily phishing list
NORMAL = """
www.google.com fonts.googleapis.com i.ytimg.com www.youtube.com github.com api.spotify.com
www.netflix.com graph.facebook.com www.icloud.com login.live.com en.wikipedia.org
www.reddit.com www.bbc.co.uk www.nytimes.com stackoverflow.com duckduckgo.com weather.com
www.theguardian.com news.ycombinator.com www.twitch.tv api.openweathermap.org www.amazon.de
cdn.jsdelivr.net www.paypal.com www.ebay.com connectivitycheck.gstatic.com time.cloudflare.com
pool.ntp.org www.linkedin.com cdn.cookielaw.org www.dropbox.com
""".split()
DAY = 86400


def script(rng: random.Random) -> list[tuple[float, str, str]]:
    """(seconds into the day, device, domain), in time order. Incident times count
    back from the end of the day, which the demo shows as "now"."""
    q = []
    for d in DEVICES:   # ordinary traffic: ~1,800 lookups per device, at random gaps
        t = rng.uniform(0, 60)
        while t < DAY:
            q.append((t, d["name"], rng.choice(NORMAL)))
            t += rng.expovariate(1 / 48)
    ago = lambda minutes: DAY - minutes * 60  # noqa: E731
    # tv: an implant cycling through generated domains (one burst, plus each name)
    for i, dom in enumerate(["xjw4kqpz7rmd.top", "pzq8vnhy2kxc.top", "kfq9zv2wxnbt.xyz",
                             "hv7qkz3mwpxr.biz", "zrqk4vhw9tjx.info"]):
        q.append((ago(9) + 45 * i, "tv", dom))
    q.append((ago(41), "phone", "dns.google"))                   # DNS-over-HTTPS
    q.append((ago(130), "tv", "api.telegram.org"))               # the implant's commands, via a bot
    q.append((ago(96), "laptop", "qzxkvwjhplrtm5746.top"))       # one very random new name
    for i in range(12):                                          # a call-home every 5 minutes
        q.append((ago(240) + 300 * i, "printer", "sync.xpqv.com"))
    q.append((ago(310), "phone", "trkqvz.com"))                  # random-looking new name
    q.append((ago(425), "laptop", FEED[0]))                      # on the threat feed
    for i in range(14):                                          # data out in long subdomains
        label = "".join(rng.choice("0123456789abcdef") for _ in range(48))
        q.append((ago(660) + 12 * i, "console", f"{label}.cdn-pkt7.net"))
    q.append((ago(960), "console", "vrtxq.xyz"))                 # odd name on a risky TLD
    return sorted(q)


def generate(seed: int = 7) -> dict:
    sys.path.insert(0, GHOST_DNS)
    import config as config_mod
    from devices import DeviceMap
    from enforce import Enforcer, NullBackend
    from resolver import Resolver
    from scoring import Scorer
    from state import GhostState

    work = tempfile.mkdtemp(prefix="ghostwall-demo-")
    feed = os.path.join(work, "feed.txt")
    with open(feed, "w", encoding="utf-8") as f:
        f.write("\n".join(FEED) + "\n")
    cfg = config_mod.load_config(None, {
        "state_path": os.path.join(work, "state.json"), "events_path": os.path.join(work, "e.jsonl"),
        "resolved_ips_path": None, "threat_feed_path": feed, "shadow": True})
    clock = {"t": 0.0}

    class Recorder:  # stands in for EventLog, noting the scripted time of each alert
        events: list = []

        def write(self, evt):
            self.events.append((clock["t"], evt))

    state = GhostState(cfg["state_path"], learning_default=True)
    state.load_allowlist_file(cfg["allowlist_path"])
    # The demo day's own clock (a fixed date), and devices that have been on the network
    # for a week, so per-device baselines (abused_service) are over, as they would be.
    from datetime import datetime, timedelta, timezone
    day0 = datetime(2026, 10, 30, tzinfo=timezone.utc)
    state.clock = lambda: day0 + timedelta(seconds=clock["t"])
    for d in DEVICES:
        state.device_since[d["name"]] = (day0 - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    scorer = Scorer(cfg["onnx_model"], cfg["lr_coef"], cfg["lr_meta"])
    memo: dict = {}
    score_one = scorer.score_one
    scorer.score_one = lambda d: memo[d] if d in memo else memo.setdefault(d, score_one(d))
    rec = Recorder()
    r = Resolver(cfg, state, scorer, Enforcer(NullBackend()), DeviceMap.from_json(DEVICES), rec)
    r.clock = lambda: clock["t"]
    ips = {d["name"]: d["ip"] for d in DEVICES}
    queries = script(random.Random(seed))
    for t, dev, dom in queries:
        clock["t"] = t
        r.decide(ips[dev], dom, "A")
    events = []
    for t, e in rec.events:
        e = {k: v for k, v in e.items() if k not in ("time", "event_id")}
        events.append({"minutes_ago": round((DAY - t) / 60), **e})
    events.sort(key=lambda e: e["minutes_ago"])
    return {"queries": len(queries), "models": scorer.backend, "events": events}


def main() -> int:
    data = generate()
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
        f.write("\n")
    print(f"{len(data['events'])} alerts from {data['queries']} queries -> {OUT}")
    for e in data["events"]:
        print(f"  {e['minutes_ago']:5d} min ago  {e['device']:8s} {e['rule']:17s} {e['domain'][:60]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
