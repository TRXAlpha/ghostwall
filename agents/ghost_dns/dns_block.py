#!/usr/bin/env python3
"""Let your DNS server block what Ghostwall knows is bad. Ghostwall stays out of the DNS path.

    python dns_block.py run                 keep the blocklists in AdGuard Home / Pi-hole up to date
    python dns_block.py once                one pass (the CI test, or after editing the settings)
    python dns_block.py unregister          take Ghostwall's lists and exceptions out of the DNS server
    python dns_block.py upstream            apply DNS_PROTECTIVE_UPSTREAM (or put the old upstream back)

What it does, from threat_feed.txt (already past update_feed.py's popularity guard), the names
Ghostwall's own blocklist holds, and what you trusted or unblocked:

  dns_block_feed "on"       builds a blocklist in the DNS server's format (AdGuard: `||name^`, which also
                            covers subdomains; Pi-hole: plain names, exact match only), serves it on
                            dns_block_bind:dns_block_port (loopback unless you say otherwise) and registers
                            that URL through the DNS server's API. Every feed update, and every Trust or
                            `ghostwall unblock`, is pushed within a minute or two.
  dns_block_feed "dry-run"  builds the same list and writes dns_block_report.json (counts, what your devices
                            asked for that is on it); registers nothing and makes no API call at all.
  dns_block_ads "pro"|"ultimate"
                            registers HaGeZi's Multi Pro / Ultimate ad and tracker list (the DNS server
                            downloads it itself; Ghostwall never sees or redistributes it).
  exceptions                Trust (`ghostwall allow`) and `ghostwall unblock` become exceptions: AdGuard rules
                            `@@||name^` in a marked block of its custom rules, Pi-hole regex allow entries.
                            Your own rules and entries are never touched.

Settings come from the environment (ghostwall.env) over ghost_dns.json: DNS_BLOCK_FEED, DNS_BLOCK_ADS,
DNS_SOURCE (adguard or pihole), ADGUARD_URL / ADGUARD_USER / ADGUARD_PASSWORD, PIHOLE_URL /
PIHOLE_PASSWORD (a Pi-hole app password), DNS_BLOCK_BIND / DNS_BLOCK_PORT / DNS_BLOCK_URL. The
credentials are used only for the DNS server's API, never printed, logged or written to disk.

If the DNS server's API fails (wrong password, down, a new version), Ghostwall keeps running: the
problem is logged once, the pass is retried with a growing delay, and the lists already registered
stay in force (the DNS server keeps its downloaded copy).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import config as config_mod  # noqa: E402

SERVED = "ghostwall-blocklist.txt"
FEED_LIST = "Ghostwall threat feed"
ADS_PREFIX = "Ghostwall ads: "
COMMENT = "Ghostwall"                      # marks what this script created in Pi-hole
RULES_BEGIN = "! >>> Ghostwall exceptions (managed by Ghostwall; edit outside this block) >>>"
RULES_END = "! <<< Ghostwall exceptions <<<"
FEED_MODES = ("off", "dry-run", "on")
ADS_MODES = ("off", "pro", "ultimate")
_RAW = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main"
# HaGeZi (GPL-3.0). AdGuard reads its adblock syntax (subdomains included); Pi-hole gets the
# plain-domain version (it matches exact names only, so HaGeZi lists subdomains one by one).
ADS = {
    "pro": ("HaGeZi Multi PRO", f"{_RAW}/adblock/pro.txt", f"{_RAW}/wildcard/pro-onlydomains.txt"),
    "ultimate": ("HaGeZi Multi ULTIMATE", f"{_RAW}/adblock/ultimate.txt", f"{_RAW}/wildcard/ultimate-onlydomains.txt"),
}
UPSTREAMS = {   # AdGuard speaks DoH; Pi-hole takes plain addresses only
    "quad9": {"adguard": ["https://dns.quad9.net/dns-query"], "pihole": ["9.9.9.9", "149.112.112.112"]},
    "cloudflare": {"adguard": ["https://security.cloudflare-dns.com/dns-query"], "pihole": ["1.1.1.2", "1.0.0.2"]},
}
BYPASS_NAME = "Ghostwall bypass: HaGeZi DoH/VPN/TOR/Proxy Bypass"
BYPASS = (f"{_RAW}/adblock/doh-vpn-proxy-bypass.txt", f"{_RAW}/wildcard/doh-vpn-proxy-bypass-onlydomains.txt")
# Names that make a device use the network's DNS: Firefox turns its own DNS-over-HTTPS off when
# use-application-dns.net does not resolve (Mozilla's canary), and Apple devices drop iCloud
# Private Relay for the network when the two mask hosts fail.
CANARY_FIREFOX = ("use-application-dns.net",)
CANARY_RELAY = ("mask.icloud.com", "mask-h2.icloud.com")
POLL = 15.0           # seconds between looks at the feed and the trust list
RETRY_MAX = 900.0
_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")


class ApiError(Exception):
    """A DNS-server API call failed. The text never holds a credential."""


# ------------------------------------------------------------------ settings
def load_settings(env=None, config_path: str | None = None) -> dict:
    """ghost_dns.json (if any), then the environment over it."""
    env = os.environ if env is None else env
    cfg = config_mod.load_config(config_path) if config_path else dict(config_mod.DEFAULTS)
    data = os.path.dirname(os.path.abspath(cfg.get("state_path") or config_mod.DEFAULTS["state_path"]))
    port = int(env.get("DNS_BLOCK_PORT") or cfg.get("dns_block_port") or 5382)
    s = {
        "feed": (env.get("DNS_BLOCK_FEED") or cfg.get("dns_block_feed") or "off").strip().lower(),
        "ads": (env.get("DNS_BLOCK_ADS") or cfg.get("dns_block_ads") or "off").strip().lower(),
        "bypass": (env.get("DNS_BLOCK_BYPASS") or cfg.get("dns_block_bypass") or "off").strip().lower(),
        "canaries": (env.get("DNS_BLOCK_CANARIES") or cfg.get("dns_block_canaries") or "on").strip().lower(),
        "server": (env.get("DNS_SOURCE") or ("pihole" if str(cfg.get("querylog_format")) == "pihole" else "adguard")).strip().lower(),
        "bind": env.get("DNS_BLOCK_BIND") or cfg.get("dns_block_bind") or "127.0.0.1",
        "port": port,
        "url": env.get("DNS_BLOCK_URL") or cfg.get("dns_block_url") or f"http://127.0.0.1:{port}/{SERVED}",
        "adguard_url": (env.get("ADGUARD_URL") or "http://127.0.0.1:3000").rstrip("/"),
        "adguard_user": env.get("ADGUARD_USER") or "",
        "adguard_password": env.get("ADGUARD_PASSWORD") or "",
        "pihole_url": (env.get("PIHOLE_URL") or "http://127.0.0.1").rstrip("/"),
        "pihole_password": env.get("PIHOLE_PASSWORD") or "",
        "upstream": (env.get("DNS_PROTECTIVE_UPSTREAM") or "off").strip().lower(),
        "feed_path": cfg.get("threat_feed_path") or os.path.join(data, "threat_feed.txt"),
        "state_path": cfg.get("state_path") or os.path.join(data, "state.json"),
        "events_path": cfg.get("events_path") or os.path.join(data, "events.jsonl"),
        "allowlist_path": cfg.get("allowlist_path"),
        "data": data,
        "popular_path": cfg.get("popular_path"),
    }
    return s


def settings_problems(s: dict) -> list[str]:
    """What is wrong with the settings, in plain words (an empty list: fine)."""
    out = []
    if s["feed"] not in FEED_MODES:
        out.append(f"DNS_BLOCK_FEED must be off, dry-run or on, not {s['feed']!r}")
    if s["ads"] not in ADS_MODES:
        out.append(f"DNS_BLOCK_ADS must be off, pro or ultimate, not {s['ads']!r}")
    if s["bypass"] not in ("off", "on"):
        out.append(f"DNS_BLOCK_BYPASS must be off or on, not {s['bypass']!r}")
    if s["canaries"] not in ("on", "no-relay", "off"):
        out.append(f"DNS_BLOCK_CANARIES must be on, no-relay or off, not {s['canaries']!r}")
    if s["server"] not in ("adguard", "pihole"):
        out.append(f"DNS_SOURCE must be adguard or pihole, not {s['server']!r}")
    if s["upstream"] not in ("off", *UPSTREAMS):
        out.append(f"DNS_PROTECTIVE_UPSTREAM must be off, quad9 or cloudflare, not {s['upstream']!r}")
    return out


# ------------------------------------------------------------------ the blocklist
def read_feed(path: str) -> tuple[set[str], dict[str, int]]:
    """(every listed name, {source label: names}) from update_feed.py's file."""
    names: set[str] = set()
    counts: dict[str, int] = {}
    label = "threat feed"
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("#@source\t"):
                    p = line.rstrip("\n").split("\t") + ["", "", "", ""]
                    label = f"{p[3]} ({p[4]})" if p[3] and p[4] else (p[3] or "threat feed")
                    counts.setdefault(label, 0)
                    continue
                line = line.strip().lower()
                if line and not line.startswith(("#", "!")) and _DOMAIN.match(line) and "." in line:
                    names.add(line)
                    counts[label] = counts.get(label, 0) + 1
    except OSError:
        pass
    return names, counts


def under(name: str, parent: str) -> bool:
    return name == parent or name.endswith("." + parent)


def parents(name: str):
    while "." in name:
        name = name.split(".", 1)[1]
        if "." in name:
            yield name


def prune_children(names: set[str]) -> set[str]:
    """Drop a name when a parent of it is listed too: AdGuard's `||parent^` covers it."""
    return {n for n in names if not any(p in names for p in parents(n))}


def drop_under(names: set[str], exceptions) -> set[str]:
    """Pi-hole has no exception syntax in a list: leave out what the exceptions cover."""
    exc = set(exceptions)
    if not exc:
        return names
    return {n for n in names if n not in exc and not any(p in exc for p in parents(n))}


def canary_names(mode: str) -> tuple[str, ...]:
    return () if mode == "off" else CANARY_FIREFOX if mode == "no-relay" else CANARY_FIREFOX + CANARY_RELAY


def render_adguard(names: set[str], canaries: str = "off") -> str:
    body = "\n".join(f"||{n}^" for n in sorted(prune_children(names)))
    if canaries != "off":    # always NXDOMAIN, whatever AdGuard's blocking mode is
        body += "\n" + "\n".join(f"||{n}^$dnsrewrite=NXDOMAIN" for n in canary_names(canaries))
    return ("! Title: Ghostwall threat feed\n"
            "! Description: known malware, command-and-control and phishing domains, from the feeds "
            "Ghostwall downloads (popular sites removed). Exceptions you trusted are in AdGuard's "
            "custom rules.\n" + body + "\n")


def render_pihole(names: set[str], exceptions) -> str:
    kept = sorted(drop_under(names, exceptions))
    return "# Title: Ghostwall threat feed\n# Exact names only (Pi-hole does not block subdomains of a listed name)\n" \
           + "\n".join(kept) + "\n"


def exceptions_adguard_rules(exceptions) -> list[str]:
    return [f"@@||{d}^" for d in sorted(exceptions)]


def pihole_regex(domain: str) -> str:
    return r"(\.|^)" + re.escape(domain) + "$"


def load_view(s: dict) -> dict:
    """{"trusted", "exceptions", "blocked", "starter"} as ghost-dns keeps it in dns_view.json next
    to state.json; from state.json itself if ghost-dns has not written the view yet."""
    view = os.path.join(os.path.dirname(os.path.abspath(s["state_path"])), "dns_view.json")
    try:
        with open(view, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            return {k: [str(x) for x in d.get(k, [])] for k in ("trusted", "exceptions", "blocked", "starter")}
    except (OSError, ValueError):
        pass
    d = {}
    try:
        with open(s["state_path"], encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        pass
    starter = set()
    try:
        with open(s.get("allowlist_path") or "", encoding="utf-8") as f:
            starter = {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}
    except OSError:
        pass
    allow = {str(x) for x in d.get("allowlist", [])}
    return {"trusted": sorted(allow - starter), "exceptions": [str(x) for x in d.get("dns_exceptions", [])],
            "blocked": [str(x) for x in d.get("blocklist", [])], "starter": sorted(starter)}


def build(s: dict) -> dict:
    """Everything one pass needs: names, exceptions, counts and the text to serve."""
    feed_names, counts = read_feed(s["feed_path"])
    view = load_view(s)
    names = feed_names | {n for n in view["blocked"] if _DOMAIN.match(n) and "." in n}
    # Trust and unblock are exceptions. The starter allowlist (big sites, as a whole) is not:
    # Ghostwall alerts on a listed host under a starter name too; an exact match is honoured.
    exc = set(view["trusted"]) | set(view["exceptions"]) | (set(view["starter"]) & feed_names)
    canaries = s["canaries"] if s["feed"] == "on" and s["canaries"] in ("on", "no-relay") else "off"
    text = render_adguard(names, canaries) if s["server"] == "adguard" else render_pihole(names, exc)
    return {"names": names, "counts": counts, "exceptions": exc, "text": text,
            "hash": hashlib.sha256(text.encode()).hexdigest()[:16]}


def recent_hits(events_path: str, days: float = 7.0) -> list[str]:
    """Distinct domains with a threat_feed alert in the last `days` (the names that would
    have been blocked), most recent first."""
    cutoff = time.time() - days * 86400
    seen: dict[str, float] = {}
    for p in (events_path + ".1", events_path):
        try:
            size = os.path.getsize(p)
            with open(p, "rb") as f:
                f.seek(max(0, size - 8 * 1024 * 1024))
                for raw in f:
                    try:
                        e = json.loads(raw)
                        if e.get("rule") != "threat_feed":
                            continue
                        t = time.mktime(time.strptime(e["time"][:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
                    except (ValueError, KeyError, TypeError, AttributeError):
                        continue
                    if t >= cutoff:
                        seen[str(e.get("domain"))] = t
        except OSError:
            continue
    return [d for d, _ in sorted(seen.items(), key=lambda kv: -kv[1])]


# ------------------------------------------------------------------ HTTP
class Http:
    """The one place a request leaves the process (tests replace it)."""

    def request(self, method: str, url: str, headers: dict | None = None, body: bytes | None = None,
                timeout: float = 30.0) -> tuple[int, bytes]:
        req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(32 * 1024 * 1024)
        except urllib.error.HTTPError as e:
            return e.code, e.read(65536)
        except (urllib.error.URLError, OSError, ValueError) as e:
            reason = getattr(e, "reason", e)
            raise ApiError(f"{method} {urllib.parse.urlsplit(url).netloc}: {type(reason).__name__}: {reason}") from None


class Api:
    """JSON calls against a DNS server's API; errors carry the status and the server's own
    message, never what was sent."""

    def __init__(self, base: str, http: Http, headers: dict | None = None, redact=()):
        self.base, self.http, self.headers, self.redact = base, http, dict(headers or {}), [r for r in redact if r]

    def clean(self, text: str) -> str:
        for r in self.redact:
            text = text.replace(r, "***")
        return text

    def call(self, method: str, path: str, body=None, timeout: float = 60.0, ok=(200, 201, 204)):
        data = None if body is None else json.dumps(body).encode()
        h = dict(self.headers)
        h.setdefault("Accept", "application/json")
        if data is not None:
            h["Content-Type"] = "application/json"
        try:
            status, raw = self.http.request(method, self.base + path, h, data, timeout)
        except ApiError as e:
            raise ApiError(self.clean(str(e))) from None
        if status not in ok:
            msg = ""
            try:
                j = json.loads(raw)
                m = j.get("error") if isinstance(j, dict) else None
                msg = (m.get("message") if isinstance(m, dict) else m) or (j.get("message") if isinstance(j, dict) else "") or ""
            except (ValueError, AttributeError):
                msg = raw[:160].decode("utf-8", "replace").strip()
            raise ApiError(self.clean(f"{method} {path} -> HTTP {status}" + (f": {str(msg)[:200]}" if msg else "")))
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            return {"text": raw[:200].decode("utf-8", "replace")}   # AdGuard answers some calls "OK"


# ------------------------------------------------------------------ AdGuard Home
class AdGuard:
    def __init__(self, s: dict, http: Http):
        tok = base64.b64encode(f"{s['adguard_user']}:{s['adguard_password']}".encode()).decode()
        self.api = Api(s["adguard_url"], http, {"Authorization": "Basic " + tok},
                       redact=(s["adguard_password"], tok))

    def status(self) -> dict:
        return self.api.call("GET", "/control/filtering/status")

    def lists(self, st: dict) -> dict[str, dict]:
        return {f["url"]: f for f in (st.get("filters") or []) if isinstance(f, dict) and f.get("url")}

    def add(self, name: str, url: str) -> None:
        self.api.call("POST", "/control/filtering/add_url", {"name": name, "url": url, "whitelist": False}, timeout=180)

    def enable(self, name: str, url: str) -> None:
        self.api.call("POST", "/control/filtering/set_url_params",
                      {"url": url, "whitelist": False, "data": {"name": name, "url": url, "enabled": True}}, timeout=180)

    def remove(self, url: str) -> None:
        self.api.call("POST", "/control/filtering/remove_url", {"url": url, "whitelist": False})

    def refresh(self) -> None:
        self.api.call("POST", "/control/filtering/refresh", {"whitelist": False}, timeout=300)

    def set_rules(self, rules: list[str]) -> None:
        self.api.call("POST", "/control/filtering/set_rules", {"rules": rules})

    def sync(self, s: dict, want: dict[str, str], exceptions, changed: bool) -> list[str]:
        """Make the registered lists `want` ({url: name}); exceptions go into a marked block of
        the custom rules. Returns what was done, [] when nothing needed doing."""
        st = self.status()
        done = []
        have = self.lists(st)
        added = False
        for url, name in want.items():
            f = have.get(url)
            if f is None:
                self.add(name, url)
                done.append(f"added {name}")
                added = True
            elif f.get("enabled") is False:
                self.enable(name, url)
                done.append(f"enabled {name}")
                added = True
        for url, f in have.items():
            if url not in want and str(f.get("name", "")).startswith(("Ghostwall",)):
                self.remove(url)
                done.append(f"removed {f.get('name')}")
        if changed and not added and any(u in want for u in have):
            self.refresh()
            done.append("refreshed")
        rules = [str(r) for r in (st.get("user_rules") or [])]
        keep = strip_block(rules)
        new = keep + ([RULES_BEGIN, *exceptions_adguard_rules(exceptions), RULES_END] if exceptions and want else [])
        if new != rules:
            self.set_rules(new)
            done.append(f"{len(exceptions) if want else 0} exceptions")
        if st.get("enabled") is False and want:
            done.append("WARNING: filtering is switched off in AdGuard (Settings > General settings)")
        return done

    def upstreams(self) -> list[str]:
        return list(self.api.call("GET", "/control/dns_info").get("upstream_dns") or [])

    def set_upstreams(self, ups: list[str]) -> None:
        self.api.call("POST", "/control/dns_config", {"upstream_dns": ups})


def strip_block(rules: list[str]) -> list[str]:
    """The custom rules without Ghostwall's marked block."""
    out, skip = [], False
    for r in rules:
        if r == RULES_BEGIN:
            skip = True
        elif r == RULES_END:
            skip = False
        elif not skip:
            out.append(r)
    return out


# ------------------------------------------------------------------ Pi-hole v6
class PiHole:
    def __init__(self, s: dict, http: Http):
        self.password = s["pihole_password"]
        self.api = Api(s["pihole_url"] + "/api", http, redact=(self.password,))
        self.sid = None

    def login(self) -> None:
        if not self.password:
            return       # a Pi-hole without a password lets the API in
        r = self.api.call("POST", "/auth", {"password": self.password})
        sess = r.get("session") or {}
        if not sess.get("valid") or not sess.get("sid"):
            raise ApiError("Pi-hole did not accept the password (PIHOLE_PASSWORD; use an app password if two-factor login is on)")
        self.sid = sess["sid"]
        self.api.headers["X-FTL-SID"] = self.sid
        self.api.redact.append(self.sid)

    def logout(self) -> None:
        if self.sid:
            try:
                self.api.call("DELETE", "/auth")
            except ApiError:
                pass
            self.api.headers.pop("X-FTL-SID", None)
            self.sid = None

    def lists(self) -> dict[str, dict]:
        r = self.api.call("GET", "/lists?type=block")
        return {x["address"]: x for x in (r.get("lists") or []) if isinstance(x, dict) and x.get("address")}

    def regexes(self) -> dict[str, dict]:
        r = self.api.call("GET", "/domains/allow/regex")
        return {x["domain"]: x for x in (r.get("domains") or []) if isinstance(x, dict) and x.get("domain")}

    def sync(self, s: dict, want: dict[str, str], exceptions, changed: bool) -> list[str]:
        self.login()
        try:
            done, added = [], False
            have = self.lists()
            for url, name in want.items():
                f = have.get(url)
                if f is None:
                    self.api.call("POST", "/lists?type=block", {"address": url, "type": "block", "comment": name,
                                                                "groups": [0], "enabled": True})
                    done.append(f"added {name}")
                    added = True
                elif f.get("enabled") is False:
                    self.api.call("PUT", "/lists/" + urllib.parse.quote(url, safe="") + "?type=block",
                                  {"comment": name, "groups": f.get("groups") or [0], "enabled": True})
                    done.append(f"enabled {name}")
                    added = True
            for url, f in have.items():
                if url not in want and str(f.get("comment", "")).startswith(COMMENT):
                    self.api.call("DELETE", "/lists/" + urllib.parse.quote(url, safe="") + "?type=block")
                    done.append(f"removed {f.get('comment')}")
                    added = True
            want_rx = {pihole_regex(d): d for d in exceptions} if want else {}
            have_rx = self.regexes()
            for rx, d in want_rx.items():
                if rx not in have_rx:
                    self.api.call("POST", "/domains/allow/regex", {"domain": rx, "comment": COMMENT + ": " + d,
                                                                   "groups": [0], "enabled": True})
                    done.append(f"exception {d}")
            for rx, x in have_rx.items():
                if rx not in want_rx and str(x.get("comment", "")).startswith(COMMENT):
                    self.api.call("DELETE", "/domains/allow/regex/" + urllib.parse.quote(rx, safe=""))
                    done.append("exception removed")
            if s["feed"] == "on" and s["canaries"] != "off":
                # FTL answers these NXDOMAIN itself (its "special domains"); on by default, made sure of here
                special = {"mozillaCanary": True, "iCloudPrivateRelay": s["canaries"] == "on"}
                try:    # they are on by default, so a Pi-hole that will not say is not a failure
                    cur = (((self.api.call("GET", "/config/dns/specialDomains").get("config") or {}).get("dns") or {})
                           .get("specialDomains")) or {}
                    if any(cur.get(k) is not v and (k != "iCloudPrivateRelay" or v) for k, v in special.items()):
                        self.api.call("PATCH", "/config", {"config": {"dns": {"specialDomains": special}}})
                        done.append("canary domains on")
                except ApiError:
                    pass
            if (changed or added) and want:
                self.api.call("POST", "/action/gravity", timeout=900)    # downloads and rebuilds the lists
                done.append("gravity updated")
            return done
        finally:
            self.logout()

    def upstreams(self) -> list[str]:
        self.login()
        try:
            r = self.api.call("GET", "/config/dns/upstreams")
            return list((((r.get("config") or {}).get("dns") or {}).get("upstreams")) or [])
        finally:
            self.logout()

    def set_upstreams(self, ups: list[str]) -> None:
        self.login()
        try:
            self.api.call("PATCH", "/config", {"config": {"dns": {"upstreams": ups}}})
        finally:
            self.logout()


# ------------------------------------------------------------------ serving the list
class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ghostwall-dnsblock"

    def log_message(self, *a):    # no request log: the DNS server fetches it every few hours
        pass

    def _send(self, head_only: bool):
        if self.path.split("?", 1)[0] != "/" + SERVED:
            self.send_error(404)
            return
        body = self.server.content.encode()          # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def do_GET(self):
        self._send(False)

    def do_HEAD(self):
        self._send(True)


class Server:
    def __init__(self, bind: str, port: int):
        self.httpd = http.server.ThreadingHTTPServer((bind, port), _Handler)
        self.httpd.content = ""
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def set(self, text: str) -> None:
        self.httpd.content = text

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


# ------------------------------------------------------------------ the loop
def write_json(path: str, obj) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


class Syncer:
    def __init__(self, s: dict, http: Http | None = None, log=None, serve: bool = True):
        self.s = s
        self.http = http or Http()
        self._log = log or (lambda m: print(m, flush=True))
        self.state_file = os.path.join(s["data"], "dns_block_state.json")
        self.report_file = os.path.join(s["data"], "dns_block_report.json")
        self.state = load_json(self.state_file)
        self.warned: set[str] = set()
        self.failures = 0
        self.next_try = 0.0
        self.server: Server | None = None
        self.serve = serve
        self.sig = None

    # -- messages: secrets never get this far, and are blanked if they do
    def say(self, msg: str) -> None:
        for secret in (self.s["adguard_password"], self.s["pihole_password"]):
            if secret:
                msg = msg.replace(secret, "***")
        self._log(f"[dns-block] {msg}")

    def warn_once(self, key: str, msg: str) -> None:
        if key not in self.warned:
            self.warned.add(key)
            self.say("WARNING " + msg)

    def client(self):
        return AdGuard(self.s, self.http) if self.s["server"] == "adguard" else PiHole(self.s, self.http)

    def wanted(self, mode_feed: str) -> dict[str, str]:
        want = {}
        if mode_feed == "on":
            want[self.s["url"]] = FEED_LIST
        if self.s["ads"] in ADS:
            title, ag, ph = ADS[self.s["ads"]]
            want[ag if self.s["server"] == "adguard" else ph] = ADS_PREFIX + title
        if self.s["bypass"] == "on":
            want[BYPASS[0] if self.s["server"] == "adguard" else BYPASS[1]] = BYPASS_NAME
        return want

    def signature(self):
        out = []
        for p in (self.s["feed_path"], os.path.join(os.path.dirname(os.path.abspath(self.s["state_path"])), "dns_view.json"),
                  self.s["state_path"]):
            try:
                st = os.stat(p)
                out.append((st.st_mtime_ns, st.st_size))
            except OSError:
                out.append(None)
        return tuple(out)

    def sync_once(self) -> bool:
        """One pass. True when it finished (or has nothing to do); False when the DNS server's API failed."""
        s = self.s
        for p in settings_problems(s):
            self.warn_once("settings:" + p, p + "; treating the bad value as off")
        feed = s["feed"] if s["feed"] in FEED_MODES else "off"
        ads = s["ads"] if s["ads"] in ADS_MODES else "off"
        bypass = s["bypass"] if s["bypass"] in ("off", "on") else "off"
        s = dict(s, feed=feed, ads=ads, bypass=bypass,
                 canaries=s["canaries"] if s["canaries"] in ("on", "no-relay", "off") else "on")
        self.s = s
        if feed == "off" and ads == "off" and bypass == "off":
            return self.leave()
        b = build(s)
        report = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode_feed": feed, "mode_ads": ads, "mode_bypass": bypass,
                  "server": s["server"], "names": len(b["names"]), "exceptions": len(b["exceptions"]),
                  "sources": b["counts"], "registered": False, "list_hash": b["hash"]}
        if feed != "off":
            try:
                with open(os.path.join(s["data"], SERVED), "w", encoding="utf-8") as f:
                    f.write(b["text"])
                os.chmod(os.path.join(s["data"], SERVED), 0o644)
            except OSError as e:
                self.warn_once("write", f"can't write the blocklist file in {s['data']}: {e.strerror or e}")
        if feed == "dry-run":
            hits = recent_hits(s["events_path"])
            report.update(hits_week=len(hits), would_block_recent=hits[:10])
            write_json(self.report_file, report)
            self.say(f"dry-run: would block {len(b['names'])} names ({len(b['exceptions'])} exceptions); "
                     f"{len(hits)} of them were asked for in the last 7 days. Nothing is registered. "
                     f"Details: {self.report_file}")
            if ads != "off" or bypass != "off":
                self.say("dry-run: the ad and bypass lists are not registered either")
            return True
        if feed == "on" and not b["names"]:
            self.warn_once("empty", f"{s['feed_path']} has no names yet (the feed has not downloaded?); "
                           "nothing is registered")
            report["warning"] = "no feed yet"
            write_json(self.report_file, report)
            return True
        if feed == "on" and self.serve and self.server is None:
            try:
                self.server = Server(s["bind"], s["port"])
            except OSError as e:
                self.warn_once("bind", f"can't serve the blocklist on {s['bind']}:{s['port']} ({e.strerror or e}); "
                               "change DNS_BLOCK_PORT")
                report["warning"] = "blocklist server not running"
                write_json(self.report_file, report)
                return False
        if self.server is not None:
            self.server.set(b["text"])
        changed = self.state.get("pushed_hash") != b["hash"]
        try:
            done = self.client().sync(s, self.wanted(feed), b["exceptions"], changed)
        except ApiError as e:
            self.failures += 1
            self.next_try = time.monotonic() + min(RETRY_MAX, 60.0 * 2 ** (self.failures - 1))
            self.warn_once("api:" + str(e)[:80], f"the {s['server']} API failed ({e}); lists already registered stay in force. "
                           "Check ADGUARD_URL/ADGUARD_USER/ADGUARD_PASSWORD (or PIHOLE_URL/PIHOLE_PASSWORD) in "
                           "/etc/ghostwall/ghostwall.env. Retrying with a growing delay.")
            report["warning"] = "the DNS server's API failed; see the log"
            write_json(self.report_file, report)
            return False
        if self.failures:
            self.say("the DNS server's API answers again")
            self.failures = 0
            self.warned = {w for w in self.warned if not w.startswith("api:")}
        for d in done:
            if d.startswith("WARNING"):
                self.warn_once(d, d[len("WARNING "):])
        real = [d for d in done if not d.startswith("WARNING")]
        if real:
            self.say(f"{s['server']}: " + ", ".join(real) + f" ({len(b['names'])} names)")
        self.state.update(pushed_hash=b["hash"], registered_feed=feed == "on", registered_ads=ads,
                          registered_bypass=bypass == "on", server=s["server"])
        write_json(self.state_file, self.state)
        report.update(registered=bool(self.wanted(feed)), pushed=real)
        write_json(self.report_file, report)
        return True

    def leave(self) -> bool:
        """Both modes off. If lists were registered before, take them out (once); else do nothing at all."""
        if not (self.state.get("registered_feed") or self.state.get("registered_bypass")
                or self.state.get("registered_ads", "off") != "off"):
            return True
        self.say("blocking is off now: removing Ghostwall's lists from the DNS server")
        return self.unregister()

    def unregister(self) -> bool:
        if not (self.state.get("registered_feed") or self.state.get("registered_bypass")
                or self.state.get("registered_ads", "off") != "off"
                or "on" in (self.s["feed"], self.s["bypass"]) or self.s["ads"] != "off"):
            return True       # nothing was ever registered: no API call
        try:
            done = self.client().sync(self.s, {}, set(), False)
        except ApiError as e:
            self.warn_once("unreg:" + str(e)[:80], f"could not remove Ghostwall's lists from {self.s['server']} ({e}); "
                           "remove them there by hand (names starting 'Ghostwall')")
            return False
        self.state.update(registered_feed=False, registered_ads="off", registered_bypass=False, pushed_hash=None)
        write_json(self.state_file, self.state)
        try:
            os.remove(self.report_file)
        except OSError:
            pass
        if done:
            self.say(f"{self.s['server']}: " + ", ".join(done))
        return True

    def apply_upstream(self) -> bool:
        """DNS_PROTECTIVE_UPSTREAM: set the DNS server's upstream once per setting; "off" puts the
        previous one back if Ghostwall had changed it and nobody has changed it since."""
        want, rec = self.s["upstream"], self.state.get("upstream") or {}
        try:
            c = self.client()
            if want == "off":
                if rec.get("applied") and rec.get("previous"):
                    now = c.upstreams()
                    if now == rec.get("set"):
                        c.set_upstreams(rec["previous"])
                        self.say(f"{self.s['server']}: upstream put back to {', '.join(rec['previous'])}")
                    else:
                        self.say("the upstream was changed by hand since; leaving it alone")
                    self.state["upstream"] = {}
                    write_json(self.state_file, self.state)
                return True
            if want not in UPSTREAMS:
                return True
            target = UPSTREAMS[want][self.s["server"]]
            if rec.get("applied") == want:
                return True
            now = c.upstreams()
            if now == target:
                self.state["upstream"] = {"applied": want, "set": target, "previous": rec.get("previous") or []}
            else:
                c.set_upstreams(target)
                self.say(f"{self.s['server']}: upstream is now {', '.join(target)} ({want}); it was "
                         f"{', '.join(now) or 'unset'}")
                self.state["upstream"] = {"applied": want, "set": target, "previous": now}
            write_json(self.state_file, self.state)
            return True
        except ApiError as e:
            self.warn_once("upstream", f"could not set the upstream ({e}); nothing was changed")
            return False

    def run(self) -> None:
        self.say(f"started: feed={self.s['feed']} ads={self.s['ads']} server={self.s['server']}")
        while True:
            now = time.monotonic()
            sig = self.signature()
            if (sig != self.sig and now >= self.next_try) or (self.failures and now >= self.next_try):
                try:
                    ok = self.sync_once()
                except Exception as e:  # noqa: BLE001 - one bad pass must not end the service
                    ok = False
                    self.warn_once("crash:" + type(e).__name__, f"pass failed: {type(e).__name__}: {e}")
                    self.next_try = time.monotonic() + 60
                if ok:
                    self.sig = sig
            time.sleep(POLL)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["run", "once", "unregister", "upstream"])
    ap.add_argument("--config", default=os.environ.get("GHOSTWALL_CONFIG") or
                    ("/etc/ghostwall/ghost_dns.json" if os.path.exists("/etc/ghostwall/ghost_dns.json") else None))
    a = ap.parse_args(argv)
    s = load_settings(config_path=a.config)
    sy = Syncer(s)
    if a.cmd == "run":
        sy.apply_upstream() if s["upstream"] != "off" else None
        sy.run()
        return 0
    if a.cmd == "upstream":
        return 0 if sy.apply_upstream() else 1
    if a.cmd == "unregister":
        return 0 if sy.unregister() else 1
    ok = sy.sync_once()
    if sy.server is not None:
        sy.server.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
