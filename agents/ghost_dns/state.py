"""Shared, persistent runtime state for the resolver and the control API.

One GhostState instance is created by the app and handed to both the DNS
resolver thread and the control-API thread, so a `/allow` from the Telegram bot
is visible to the resolver on the very next query. All mutating methods take an
internal lock and persist atomically (temp file + os.replace).

Persisted keys: allowlist, blocklist, isolated devices (and the addresses isolated),
automatic isolation times (auto_isolate's hourly cap), lockdown, learning,
per-domain first-seen (novelty), which domain families have resolved (nx_burst),
each IoT device's learned domain families (hashed, iot_new_domain),
block confirmations (auto-promote), and a bounded map of recent events (so an
alert's Unblock button can find its domain).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from datetime import datetime, timezone

from tokenizer import registrable_part

_MAX_EVENTS = 5000
_MAX_FIRST_SEEN = 200000
_MAX_RECENT_ALERTS = 20000
_MAX_RESOLVED = 50000
_MAX_IOT_LEARNED = 512     # domains learned per IoT device ...
_MAX_IOT_TOTAL = 1024      # ... and with the ones you allowed by hand
_MAX_IOT_DEVICES = 1000


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class GhostState:
    def __init__(self, path: str, learning_default: bool = True):
        self.path = path
        # Wall clock for first-seen dates, novelty and device baselines; the history
        # replay points it at the log's own timestamps.
        self.clock = lambda: datetime.now(timezone.utc)
        self._lock = threading.RLock()
        self.allowlist: set[str] = set()
        self.static_allow: set[str] = set()   # from allowlist.txt: reloaded at start, not "yours"
        self.blocklist: set[str] = set()
        self.isolated: set[str] = set()
        self.isolated_ips: dict[str, list[str]] = {}    # device -> the addresses put in the nft set
        self.auto_isolations: list[float] = []          # epoch of each automatic isolation (the cap)
        self.lockdown: bool = False
        self.learning: bool = learning_default
        self.first_seen: dict[str, str] = {}
        self.confirmations: dict[str, int] = {}
        self.events: dict[str, dict] = {}
        self.device_since: dict[str, str] = {}          # device -> first query (ISO)
        self.device_services: dict[str, list] = {}      # device -> abused services it has used
        self.recent_alerts: dict[str, float] = {}       # "device|domain family|rule" -> epoch of last alert
        self.resolved: dict[str, str] = {}              # domain family (hashed) -> last day it resolved
        # IoT default-deny: device -> {"since": ISO, "domains": [hashed domain families]}
        self.iot: dict[str, dict] = {}
        # note_seen() fires on every brand-new domain; persisting each one would
        # be a disk write per query, so it is throttled: mark dirty, flush at
        # most every _flush_interval seconds (and on explicit flush()/shutdown).
        # Novelty is counted in days, so losing a minute of it in a crash costs
        # nothing, while rewriting the file every few seconds wears an SD card.
        self._dirty = False
        self._last_flush = 0.0
        self._flush_interval = 60.0
        # first_seen stores keyed hashes, not names: novelty needs "seen before, and when",
        # and state.json should not be a readable history of every site the household uses.
        self._nkey_secret = self._load_secret(os.path.join(os.path.dirname(os.path.abspath(path)), "novelty_key"))
        self._legacy_names = False
        self._load()
        if self._legacy_names:
            # Rewrite at once: waiting for the next save could leave the readable list of
            # every site on disk for as long as the network stays quiet.
            self.save()

    @staticmethod
    def _load_secret(path: str) -> bytes:
        try:
            with open(path, "rb") as f:
                key = f.read().strip()
            if len(key) >= 32:
                return key
        except OSError:
            pass
        key = secrets.token_hex(32).encode()
        try:
            fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key + b"\n")
            os.replace(path + ".tmp", path)
        except OSError:
            pass  # read-only place (tests, replays): a per-run key works the same
        return key

    def _nkey(self, reg: str) -> str:
        return hmac.new(self._nkey_secret, reg.encode("utf-8"), hashlib.sha256).hexdigest()[:24]

    def set_first_seen(self, domain: str, iso: str) -> None:
        """When `domain`'s family was first seen (for tests and imports)."""
        with self._lock:
            self.first_seen[self._nkey(registrable_part(domain))] = iso

    def was_seen(self, domain: str) -> bool:
        with self._lock:
            return self._nkey(registrable_part(domain)) in self.first_seen

    # -- persistence ------------------------------------------------------
    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if not isinstance(d, dict):
                raise ValueError("not a JSON object")
        except (OSError, ValueError) as exc:
            # Starting empty would silently drop the allowlist and isolations; keep the
            # broken file for a look and say so.
            bad = f"{self.path}.broken-{int(time.time())}"
            try:
                os.replace(self.path, bad)
            except OSError:
                bad = "(could not move it)"
            print(f"[ghost-dns] WARNING {self.path} unreadable ({exc}); starting empty, kept as {bad}",
                  file=sys.stderr, flush=True)
            return
        self.allowlist = set(d.get("allowlist", []))
        self.blocklist = set(d.get("blocklist", []))
        self.isolated = set(d.get("isolated", []))
        self.isolated_ips = {str(k): [str(i) for i in v] for k, v in dict(d.get("isolated_ips", {})).items()
                             if k in self.isolated and isinstance(v, list)}
        self.auto_isolations = [float(t) for t in d.get("auto_isolations", [])
                                if isinstance(t, (int, float))][-100:]
        self.lockdown = bool(d.get("lockdown", False))
        self.learning = bool(d.get("learning", self.learning))
        self.first_seen = {}
        for k, v in dict(d.get("first_seen", {})).items():
            # older versions stored the names themselves: hash them on the way in
            if "." in k:
                self._legacy_names = True
                k = self._nkey(k)
            self.first_seen[k] = v
        self.confirmations = dict(d.get("confirmations", {}))
        self.events = dict(d.get("events", {}))
        self.device_since = dict(d.get("device_since", {}))
        self.device_services = {k: list(v) for k, v in dict(d.get("device_services", {})).items()}
        self.recent_alerts = {k: float(v) for k, v in dict(d.get("recent_alerts", {})).items()}
        self.resolved = {str(k): str(v) for k, v in dict(d.get("resolved", {})).items()}
        self.iot = {str(k): {"since": str(v.get("since", "")), "domains": [str(x) for x in v.get("domains", [])]}
                    for k, v in dict(d.get("iot", {})).items() if isinstance(v, dict)}

    def _save_locked(self) -> None:
        # Keep the persisted file bounded.
        if len(self.events) > _MAX_EVENTS:
            keep = sorted(self.events.items(),
                          key=lambda kv: kv[1].get("time", ""))[-_MAX_EVENTS:]
            self.events = dict(keep)
        if len(self.resolved) > _MAX_RESOLVED:
            keep = sorted(self.resolved.items(), key=lambda kv: kv[1])[-_MAX_RESOLVED:]
            self.resolved = dict(keep)
        if len(self.first_seen) > _MAX_FIRST_SEEN:
            keep = sorted(self.first_seen.items(), key=lambda kv: kv[1])[-_MAX_FIRST_SEEN:]
            self.first_seen = dict(keep)
        data = {
            "allowlist": sorted(self.allowlist),
            "blocklist": sorted(self.blocklist),
            "isolated": sorted(self.isolated),
            "isolated_ips": self.isolated_ips,
            "auto_isolations": self.auto_isolations[-100:],
            "lockdown": self.lockdown,
            "learning": self.learning,
            "first_seen": self.first_seen,
            "confirmations": self.confirmations,
            "events": self.events,
            "device_since": self.device_since,
            "device_services": self.device_services,
            "recent_alerts": self.recent_alerts,
            "resolved": self.resolved,
            "iot": self.iot,
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())  # a Pi loses power; never leave a half-written state.json
        os.replace(tmp, self.path)
        self._dirty = False
        self._last_flush = time.monotonic()

    def save(self) -> None:
        with self._lock:
            self._save_locked()

    def flush(self) -> None:
        """Persist any throttled note_seen() changes. Call on shutdown."""
        with self._lock:
            if self._dirty:
                self._save_locked()

    def load_allowlist_file(self, path: str) -> None:
        """Merge a static allowlist file (one domain per line, # comments)."""
        if not path or not os.path.exists(path):
            return
        with self._lock, open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    self.allowlist.add(line)
                    self.static_allow.add(line)

    # -- queries ----------------------------------------------------------
    def is_allowed(self, domain: str) -> bool:
        """True if the domain or its registrable part is on the allowlist."""
        with self._lock:
            return domain in self.allowlist or registrable_part(domain) in self.allowlist

    def trusts(self, domain: str) -> bool:
        """True if exactly this name was trusted (not only a parent of it)."""
        with self._lock:
            return domain in self.allowlist

    def is_blocked(self, domain: str) -> bool:
        with self._lock:
            return domain in self.blocklist or registrable_part(domain) in self.blocklist

    def _stamp(self) -> str:
        return self.clock().strftime("%Y-%m-%dT%H:%M:%SZ")

    def seen_alert(self, key: str, window: float) -> bool:
        """True if this alert key fired within `window` seconds; records it otherwise.
        Kept in state.json, so a restart or an update doesn't re-send the day's alerts."""
        now = self.clock().timestamp()
        with self._lock:
            last = self.recent_alerts.get(key)
            if last is not None and now - last < window:
                return True
            self.recent_alerts[key] = now
            if len(self.recent_alerts) > _MAX_RECENT_ALERTS:
                keep = sorted(self.recent_alerts.items(), key=lambda kv: kv[1])[-(_MAX_RECENT_ALERTS // 2):]
                self.recent_alerts = {k: v for k, v in keep if now - v < window}
            self._touch_locked()
            return False

    def _touch_locked(self) -> None:
        """Mark changed; write at most every _flush_interval seconds. For data that is
        cheap to lose in a crash and can change once per query."""
        self._dirty = True
        if time.monotonic() - self._last_flush >= self._flush_interval:
            self._save_locked()

    def note_seen(self, domain: str) -> bool:
        """Record a domain sighting. Returns True if this is the FIRST time the
        registrable part has ever been seen."""
        reg = self._nkey(registrable_part(domain))
        with self._lock:
            if reg in self.first_seen:
                return False
            self.first_seen[reg] = self._stamp()
            self._touch_locked()
            return True

    def note_resolved(self, domain: str) -> None:
        """A name under this domain family got a real answer (NOERROR): the domain is
        registered, so an NXDOMAIN for a name in it later is a typo or a probe, not a
        domain-generating implant (nx_burst). Hashed like first_seen; the date is
        refreshed once a day so pruning drops the families not used for longest."""
        key = self._nkey(registrable_part(domain))
        day = self.clock().strftime("%Y-%m-%d")
        with self._lock:
            if self.resolved.get(key) != day:
                self.resolved[key] = day
                self._touch_locked()

    def has_resolved(self, domain: str) -> bool:
        with self._lock:
            return self._nkey(registrable_part(domain)) in self.resolved

    def first_service_use(self, device: str, service: str, baseline_days: float) -> bool | None:
        """Record that `device` used `service`. True: first use after the device's
        baseline (alert). False: seen before. None: still in the baseline (learned)."""
        with self._lock:
            now = self.clock()
            since = self.device_since.get(device)
            if since is None:
                if len(self.device_since) >= 10000:   # a LAN has far fewer devices
                    return False
                self.device_since[device] = since = self._stamp()
                self._touch_locked()
            used = self.device_services.setdefault(device, [])
            if service in used:
                return False
            if len(used) < 200:
                used.append(service)
            self._touch_locked()
            try:
                age = (now - _parse_iso(since)).total_seconds() / 86400
            except ValueError:
                age = baseline_days
            return True if age >= baseline_days else None

    def iot_observe(self, device: str, domain: str, learn_days: float) -> str:
        """An IoT device looked up `domain`. "learned": still in its learning window, the
        domain's family is now (or was already) in the device's set. "known": after the
        window, in the set. "new": after the window, not in the set. Domains are kept as
        keyed hashes, like first_seen."""
        key = self._nkey(registrable_part(domain))
        with self._lock:
            rec = self.iot.get(device)
            if rec is None:
                if len(self.iot) >= _MAX_IOT_DEVICES:
                    return "known"
                rec = self.iot[device] = {"since": self._stamp(), "domains": []}
                self._touch_locked()
            try:
                age = (self.clock() - _parse_iso(rec["since"])).total_seconds() / 86400
            except ValueError:
                age = learn_days
            if key in rec["domains"]:
                return "learned" if age < learn_days else "known"
            if age < learn_days:
                if len(rec["domains"]) < _MAX_IOT_LEARNED:
                    rec["domains"].append(key)
                    self._touch_locked()
                return "learned"
            return "new"

    def iot_allow(self, device: str, domain: str) -> None:
        """Add a domain family to one IoT device's set (Trust on an iot_new_domain alert)."""
        key = self._nkey(registrable_part(domain))
        with self._lock:
            rec = self.iot.setdefault(device, {"since": self._stamp(), "domains": []})
            if key not in rec["domains"] and len(rec["domains"]) < _MAX_IOT_TOTAL:
                rec["domains"].append(key)
            self._save_locked()

    def iot_forget(self, device: str, domain: str) -> bool:
        """Undo iot_allow (or a learned domain). False if it is not in the device's set."""
        key = self._nkey(registrable_part(domain))
        with self._lock:
            rec = self.iot.get(device)
            if rec is None or key not in rec["domains"]:
                return False
            rec["domains"].remove(key)
            self._save_locked()
            return True

    def iot_relearn(self, device: str) -> bool:
        """Forget a device's set: its learning window starts again with its next lookup."""
        with self._lock:
            if self.iot.pop(device, None) is None:
                return False
            self._save_locked()
            return True

    def iot_count(self, device: str) -> int:
        with self._lock:
            return len(self.iot.get(device, {}).get("domains", ()))

    def iot_since(self, device: str) -> str | None:
        """When the device's learning window started (ISO), None before its first lookup."""
        with self._lock:
            return (self.iot.get(device) or {}).get("since") or None

    def note_device(self, device: str) -> None:
        """Start a device's baseline on its first query."""
        with self._lock:
            if device not in self.device_since and len(self.device_since) < 10000:
                self.device_since[device] = self._stamp()
                self._touch_locked()

    def is_new(self, domain: str, novelty_days: int) -> bool:
        """True if the registrable part was first seen within novelty_days."""
        reg = self._nkey(registrable_part(domain))
        with self._lock:
            ts = self.first_seen.get(reg)
        if not ts:
            return True
        try:
            age = self.clock() - _parse_iso(ts)
        except ValueError:
            return False
        return age.days < novelty_days

    # -- mutations (persist) ---------------------------------------------
    def add_block(self, domain: str) -> None:
        """Automatic (score-based) block. Throttled like note_seen: a device can produce
        one per query, and the block is in force in memory at once either way."""
        with self._lock:
            self.blocklist.add(domain)
            self.allowlist.discard(domain)
            self._touch_locked()

    def confirm_block(self, domain: str, threshold: int) -> bool:
        """Count a block confirmation; promote to the blocklist at threshold.
        Returns True once the domain is (now or already) blocked."""
        with self._lock:
            if domain in self.blocklist:
                return True
            n = self.confirmations.get(domain, 0) + 1
            self.confirmations[domain] = n
            promoted = n >= threshold
            if promoted:
                self.blocklist.add(domain)
                self.confirmations.pop(domain, None)
            self._save_locked()
            return promoted

    def allow(self, domain: str) -> None:
        with self._lock:
            self.allowlist.add(domain)
            self.blocklist.discard(domain)
            self.confirmations.pop(domain, None)
            self._save_locked()

    def trusted(self) -> list[str]:
        """Domains trusted through the dashboard, Telegram or the CLI (not the starter file)."""
        with self._lock:
            return sorted(self.allowlist - self.static_allow)

    def untrust(self, domain: str) -> bool:
        """Undo a Trust. False if it isn't trusted, or comes from the starter file."""
        with self._lock:
            if domain not in self.allowlist or domain in self.static_allow:
                return False
            self.allowlist.discard(domain)
            self._save_locked()
            return True

    def unblock(self, domain: str) -> None:
        with self._lock:
            self.blocklist.discard(domain)
            self.confirmations.pop(domain, None)
            self._save_locked()

    def set_learning(self, enabled: bool) -> None:
        with self._lock:
            self.learning = bool(enabled)
            self._save_locked()

    def set_lockdown(self, on: bool) -> None:
        with self._lock:
            self.lockdown = bool(on)
            self._save_locked()

    def isolate(self, name: str, ip: str | None = None) -> None:
        """ip: the address that went into the nft set, so release and a restart know it
        even after the device's address changed."""
        with self._lock:
            self.isolated.add(name)
            if ip:
                ips = self.isolated_ips.setdefault(name, [])
                if ip not in ips:
                    ips.append(ip)
            self._save_locked()

    def release(self, name: str) -> list[str]:
        """Returns the addresses recorded for it (to take out of the nft set)."""
        with self._lock:
            self.isolated.discard(name)
            ips = self.isolated_ips.pop(name, [])
            self._save_locked()
            return ips

    def isolated_addresses(self, name: str) -> list[str]:
        with self._lock:
            return list(self.isolated_ips.get(name, []))

    def auto_isolations_within(self, seconds: float) -> int:
        """How many automatic isolations happened in the last `seconds` (wall clock, kept
        in state.json: a restart, or a crash loop, does not reset auto_isolate_max_per_hour).
        A time in the future counts too (a Pi has no clock battery and can boot with an old
        time): the cap errs towards isolating less. More than a day ahead is ignored."""
        now = self.clock().timestamp()
        with self._lock:
            return sum(1 for t in self.auto_isolations if -86400 < now - t < seconds)

    def note_auto_isolation(self) -> None:
        now = self.clock().timestamp()
        with self._lock:
            self.auto_isolations = [t for t in self.auto_isolations if -86400 < now - t < 86400][-99:] + [now]
            self._save_locked()

    def recently(self, key: str, window: float) -> bool:
        """Like seen_alert(), but only looks: records nothing."""
        now = self.clock().timestamp()
        with self._lock:
            last = self.recent_alerts.get(key)
            return last is not None and now - last < window

    def is_isolated(self, name: str) -> bool:
        with self._lock:
            return name in self.isolated

    def record_event(self, event: dict) -> None:
        with self._lock:
            self.events[event["event_id"]] = {
                "domain": event.get("domain"),
                "device": event.get("device"),
                "ip": event.get("ip"),
                "time": event.get("time"),
            }
            # One per alert, and alerts can come in floods; only Unblock buttons read it.
            self._touch_locked()

    def event(self, event_id: str) -> dict | None:
        with self._lock:
            return self.events.get(event_id)
