#!/usr/bin/env python3
"""ghostwall: everyday commands for an installed Ghostwall. Stdlib only.

    ghostwall status                 mode, models, queries scored, feed, devices
    ghostwall alerts [-n 20]         the latest alerts, newest first
    ghostwall allow DOMAIN           trust a domain network-wide (no more alerts for it)
    ghostwall unblock DOMAIN         take a domain off the blocklist (inline mode)
    ghostwall learning on|off        alerts only (on) or allow blocking (off, inline mode)
    ghostwall password               the dashboard password
    ghostwall telegram               set up Telegram alerts step by step
    ghostwall calibrate [--apply]    thresholds from YOUR network's history, not a dataset's

install.sh puts this on the PATH; actions need sudo (the control-API token and the
alert log are readable only by the ghostwall user). In Docker:
    docker compose exec ghostwall python agents/ghost_dns/ghostwall_cli.py status
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

ETC = os.environ.get("GHOSTWALL_ETC", "/etc/ghostwall")
DATA = os.environ.get("GHOSTWALL_DATA", "/var/lib/ghostwall")
CONTROL = os.environ.get("GHOSTWALL_CONTROL", "http://127.0.0.1:5380")
TELEGRAM = os.environ.get("GHOSTWALL_TELEGRAM_API", "https://api.telegram.org")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$")


class CliError(Exception):
    pass


# --------------------------------------------------------------------------- control API
def _token() -> str | None:
    path = os.path.join(DATA, "control_token")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip() or None
    except PermissionError:
        raise CliError(f"can't read {path}: run this with sudo")
    except FileNotFoundError:
        return None


def control(path: str, body: dict | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if body is not None:
        tok = _token()
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(CONTROL + path, method="GET" if body is None else "POST",
                                 data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error") or e.reason
        except (ValueError, OSError):
            msg = e.reason
        raise CliError(f"ghost-dns refused: {msg}")
    except (urllib.error.URLError, OSError) as e:
        raise CliError(f"ghost-dns is not answering on {CONTROL} ({e}). "
                       "Check: systemctl status ghostwall-dns")


# --------------------------------------------------------------------------- commands
def _ago(iso: str | None) -> str:
    if not iso:
        return "never"
    try:
        t = time.mktime(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
    except ValueError:
        return iso
    s = max(0, time.time() - t)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return f"{int(s // n)}{unit} ago"
    return "just now"


def cmd_status(_a) -> int:
    st = control("/status")
    mode = ("shadow (reads your DNS server's log, can't block)" if st.get("shadow")
            else "inline, alerts only" if st.get("learning") else "inline, BLOCKING")
    stats = st.get("stats") or {}
    feed = st.get("feed") or {}
    print(f"mode:     {mode}")
    print(f"models:   {st.get('models', '?')}")
    print(f"scored:   {stats.get('queries', 0):,} queries since start, "
          f"{stats.get('recommended', 0)} alerts, {stats.get('blocked', 0)} blocks")
    if feed:
        print(f"feed:     {feed.get('domains', 0):,} phishing domains, updated {_ago(feed.get('updated'))}")
    devs = st.get("devices") or []
    print(f"devices:  {len(devs)} named" + ("" if devs else f" (add them to {ETC}/devices.json)"))
    for d in devs:
        iso = " ISOLATED" if d.get("isolated") else ""
        print(f"  {d.get('name'):<16} {d.get('ip'):<16} last query {_ago(d.get('last_seen'))}{iso}")
    if stats.get("queries", 0) == 0:
        print("\nNothing scored yet. If that stays so for minutes: journalctl -u ghostwall-dns -n 30")
    return 0


def _read_alerts(n: int) -> list[dict]:
    out = []
    for p in (os.path.join(DATA, "events.jsonl"), os.path.join(DATA, "events.jsonl.1")):
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except PermissionError:
            raise CliError(f"can't read {p}: run this with sudo")
        except FileNotFoundError:
            continue
        for line in reversed(lines):
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
            if len(out) >= n:
                return out
    return out


def cmd_alerts(a) -> int:
    alerts = _read_alerts(a.n)
    if not alerts:
        print("No alerts yet.")
        return 0
    for e in alerts:
        score = (e.get("scores") or {}).get("dga")
        sc = f"  score {score:.2f}" if isinstance(score, (int, float)) else ""
        print(f"{e.get('time', '?')}  {e.get('severity', 'warn'):<4}  {e.get('device', '?'):<16} "
              f"{e.get('domain', '?')}  [{e.get('rule')}]{sc}")
        if e.get("reasons"):
            print(f"{'':22}{'; '.join(e['reasons'][:3])}")
    return 0


def _domain(d: str) -> str:
    d = d.strip().rstrip(".").lower()
    if not DOMAIN_RE.match(d):
        raise CliError(f"not a domain name: {d!r}")
    return d


def cmd_allow(a) -> int:
    r = control("/allow", {"domain": _domain(a.domain)})
    print(f"Trusted {r.get('domain')}: no more alerts for it or its subdomains.")
    return 0


def cmd_unblock(a) -> int:
    r = control("/unblock", {"domain": _domain(a.domain)})
    print(f"Unblocked {r.get('domain')}.")
    return 0


def cmd_learning(a) -> int:
    r = control("/learning", {"enabled": a.state == "on"})
    print("Learning on: alerts only, nothing is blocked." if r.get("learning")
          else "Learning off: high-confidence new names are blocked (inline mode only).")
    return 0


def _env_value(path: str, key: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip().strip("'\"")
    except PermissionError:
        raise CliError(f"can't read {path}: run this with sudo")
    except FileNotFoundError:
        pass
    return None


def cmd_password(_a) -> int:
    pw = _env_value(os.path.join(ETC, "ghostwall.env"), "GHOSTWALL_WEB_PASSWORD")
    if pw is None and os.path.exists(os.path.join(DATA, "web_password")):  # Docker
        with open(os.path.join(DATA, "web_password"), encoding="utf-8") as f:
            pw = f.read().strip()
    if not pw:
        raise CliError("no dashboard password set (the dashboard is then loopback only)")
    print(f"user ghostwall, password {pw}")
    return 0


# --------------------------------------------------------------------------- telegram
def tg(token: str, method: str, params: dict | None = None) -> dict:
    data = json.dumps(params or {}).encode()
    req = urllib.request.Request(f"{TELEGRAM}/bot{token}/{method}", data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=35) as r:
            out = json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise CliError("Telegram says that token is wrong. Copy it again from @BotFather.")
        raise CliError(f"Telegram error: HTTP {e.code}")
    except (urllib.error.URLError, OSError) as e:
        raise CliError(f"can't reach Telegram ({e})")
    if not out.get("ok"):
        raise CliError(f"Telegram error: {out.get('description')}")
    return out["result"]


def find_private_chat(token: str, bot_name: str, wait: float = 120.0, ask=print) -> tuple[int, str]:
    """Wait for someone to message the bot privately; return (chat id, their name)."""
    ask(f"Now open Telegram, find @{bot_name} and send it any message (e.g. hello).")
    offset, deadline = 0, time.monotonic() + wait
    while time.monotonic() < deadline:
        for upd in tg(token, "getUpdates", {"offset": offset, "timeout": 20}):
            offset = upd["update_id"] + 1
            msg = upd.get("message") or {}
            chat, sender = msg.get("chat") or {}, msg.get("from") or {}
            if chat.get("type") == "private" and chat.get("id") == sender.get("id"):
                # mark it read, so fw_bot doesn't see it as a command later
                tg(token, "getUpdates", {"offset": offset, "timeout": 0})
                return int(chat["id"]), sender.get("first_name") or sender.get("username") or "you"
    raise CliError("no message arrived. Run `sudo ghostwall telegram` again and message the bot.")


def write_private(path: str, text: str, group: str | None = "ghostwall") -> None:
    """Write a secret file: root-owned, readable by the ghostwall group only."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    if group and os.geteuid() == 0:
        import grp
        try:
            os.chown(tmp, 0, grp.getgrnam(group).gr_gid)
        except KeyError:
            pass
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def cmd_telegram(a, token: str | None = None, start_service: bool = True) -> int:
    print("Telegram alerts, in three steps. Your alerts (device + domain) go through Telegram's servers.\n")
    if start_service and shutil_which("systemctl"):
        # a running bot polls the same token, and Telegram allows one poller at a time
        subprocess.run(["systemctl", "stop", "ghostwall-fw-bot"], check=False, capture_output=True)
    print("1. In Telegram, message @BotFather, send /newbot, pick a name. It replies with a token.")
    token = token or getpass.getpass("   Paste the token here (it won't be shown): ").strip()
    if not re.fullmatch(r"\d+:[A-Za-z0-9_-]{20,}", token):
        raise CliError("that doesn't look like a bot token (it is like 123456:ABC-...)")
    me = tg(token, "getMe")
    print(f"   OK: the bot is @{me.get('username')}.\n")
    print("2. ", end="")
    chat_id, who = find_private_chat(token, me.get("username", "your bot"), wait=a.wait)
    print(f"   Got it: {who} (chat {chat_id}). Only this account can give commands.\n")
    os.makedirs(ETC, exist_ok=True)
    write_private(os.path.join(ETC, "fw_bot.env"),
                  f"FW_BOT_TELEGRAM_TOKEN={token}\nFW_BOT_CALLBACK_SECRET={secrets.token_hex(32)}\n")
    write_private(os.path.join(ETC, "owner.json"), json.dumps({"chat_id": chat_id, "user": who}) + "\n")
    print(f"3. Saved {ETC}/fw_bot.env and {ETC}/owner.json (readable by root and ghostwall only).")
    if start_service and shutil_which("systemctl"):
        subprocess.run(["systemctl", "enable", "--now", "ghostwall-fw-bot"], check=False)
        subprocess.run(["systemctl", "restart", "ghostwall-fw-bot"], check=False)
        tg(token, "sendMessage", {"chat_id": chat_id, "text": "Ghostwall is connected. Alerts will arrive here; "
                                                             "send /fw help for commands."})
        print("   Started ghostwall-fw-bot and sent you a test message.")
    return 0


def shutil_which(cmd: str) -> str | None:
    import shutil
    return shutil.which(cmd)


# --------------------------------------------------------------------------- calibrate
def _querylog_from_env() -> str | None:
    env = os.path.join(ETC, "ghostwall.env")
    src = _env_value(env, "DNS_SOURCE") or "adguard"
    if src == "pihole":
        return _env_value(env, "PIHOLE_LOG") or "/var/log/pihole/pihole.log"
    return _env_value(env, "ADGUARD_QUERYLOG") or "/opt/AdGuardHome/data/querylog.json"


def calibrate(querylog: str, cfg_path: str | None, targets=(0.002, 0.005, 0.01), top: int = 15) -> dict:
    """Score every distinct name in a query log the way ghost-dns would and return the
    share each threshold flags, plus suggested thresholds for the target shares."""
    import config as config_mod
    from detectors import is_internal
    from scoring import Scorer
    from shadow import PARSERS, detect_format
    from tokenizer import registrable_label, registrable_part
    cfg = config_mod.load_config(cfg_path)
    allow = set()
    if cfg.get("allowlist_path") and os.path.exists(cfg["allowlist_path"]):
        with open(cfg["allowlist_path"], encoding="utf-8") as f:
            allow = {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}
    parse = PARSERS[detect_format(querylog)]
    labels: dict[str, str] = {}
    paths = [p for p in (querylog + ".1", querylog) if os.path.exists(p)]
    if not paths:
        raise CliError(f"no query log at {querylog}")
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                got = parse(line.strip())
                if not got:
                    continue
                host = got[1]
                if not host or is_internal(host):
                    continue
                reg = registrable_part(host)
                if host in allow or reg in allow:
                    continue
                labels.setdefault(registrable_label(host), reg)
    if not labels:
        raise CliError("no scorable names in the log yet; let it run for a day first")
    sc = Scorer(cfg.get("onnx_model"), cfg.get("lr_coef"), cfg.get("lr_meta"))
    scored = sorted(((sc.score_one(reg)["dga"], reg) for reg in labels.values()), reverse=True)
    vals = [v for v, _ in scored]
    n = len(vals)
    current = {k: float(cfg[k]) for k in ("recommend_threshold", "block_threshold", "corroborated_threshold")}
    flagged = {k: sum(v >= t for v in vals) for k, t in current.items()}
    suggest = {}
    for tgt in targets:
        k = max(1, int(n * tgt))
        suggest[tgt] = round(min(0.9999, vals[min(k, n - 1)] + 1e-4), 4) if n > k else 0.9999
    return {"names": n, "models": sc.backend, "current": current, "flagged": flagged,
            "suggest": suggest, "top": scored[:top]}


def cmd_calibrate(a) -> int:
    log = a.querylog or _querylog_from_env()
    cfg_path = os.path.join(ETC, "ghost_dns.json")
    target = a.target / 100.0
    r = calibrate(log, cfg_path if os.path.exists(cfg_path) else None,
                  targets=tuple(sorted({0.002, 0.005, 0.01, target})))
    n = r["names"]
    print(f"{n:,} distinct names from {log} (allowlisted and internal names left out), models {r['models']}\n")
    print("Right now:")
    for k, t in r["current"].items():
        c = r["flagged"][k]
        print(f"  {k:<24} {t:<7} would flag {c} of them ({100 * c / n:.2f}%)")
    print("\nThresholds for a target share of your names (recommend_threshold):")
    for tgt, thr in r["suggest"].items():
        print(f"  {100 * tgt:.1f}%  ->  {thr}")
    print(f"\nYour {len(r['top'])} highest-scoring names. Most are harmless (CDNs, trackers); a name you")
    print("don't recognise from a device that shouldn't need it is worth a look:")
    for v, reg in r["top"]:
        print(f"  {v:.3f}  {reg}")
    if n < 2000:
        print(f"\nOnly {n} names: suggestions are rough until the log covers a week or so.")
    if a.apply:
        thr = r["suggest"][target]
        cfg_path = os.path.join(ETC, "ghost_dns.json")
        try:
            with open(cfg_path, encoding="utf-8") as f:
                cfg = json.load(f)
        except FileNotFoundError:
            cfg = {}
        cfg["recommend_threshold"] = max(thr, float(r["current"]["corroborated_threshold"]))
        tmp = cfg_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, cfg_path)
        old = r["current"]["recommend_threshold"]
        new = cfg["recommend_threshold"]
        how = ("raised: fewer alerts" if new > old else "LOWERED: more alerts" if new < old else "unchanged")
        print(f"\nSet recommend_threshold {old} -> {new} in {cfg_path} ({a.target:g}% of your names; {how}).")
        print("Apply it: sudo systemctl restart ghostwall-dns")
    else:
        print(f"\nTo alert on about {a.target:g}% of your names: sudo ghostwall calibrate --apply"
              + ("" if a.target == 0.5 else f" --target {a.target:g}"))
    return 0


# --------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ghostwall", description="Everyday Ghostwall commands.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="mode, models, queries, feed, devices").set_defaults(fn=cmd_status)
    p = sub.add_parser("alerts", help="latest alerts")
    p.add_argument("-n", type=int, default=20)
    p.set_defaults(fn=cmd_alerts)
    p = sub.add_parser("allow", help="trust a domain")
    p.add_argument("domain")
    p.set_defaults(fn=cmd_allow)
    p = sub.add_parser("unblock", help="take a domain off the blocklist")
    p.add_argument("domain")
    p.set_defaults(fn=cmd_unblock)
    p = sub.add_parser("learning", help="alerts only (on) or allow blocking (off)")
    p.add_argument("state", choices=["on", "off"])
    p.set_defaults(fn=cmd_learning)
    sub.add_parser("password", help="the dashboard password").set_defaults(fn=cmd_password)
    p = sub.add_parser("calibrate", help="thresholds from your own network's query log")
    p.add_argument("--querylog", help="default: the log in /etc/ghostwall/ghostwall.env")
    p.add_argument("--target", type=float, default=0.5,
                   help="share of your distinct names, in %%, that may raise a plain score alert (default 0.5)")
    p.add_argument("--apply", action="store_true", help="write that recommend_threshold to ghost_dns.json")
    p.set_defaults(fn=cmd_calibrate)
    p = sub.add_parser("telegram", help="set up Telegram alerts")
    p.add_argument("--wait", type=float, default=180.0, help="seconds to wait for your message")
    p.set_defaults(fn=cmd_telegram)
    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except CliError as e:
        print(f"ghostwall: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
