"""Shared, persistent runtime state for the resolver and the control API.

One GhostState instance is created by the app and handed to both the DNS
resolver thread and the control-API thread, so a `/allow` from the Telegram bot
is visible to the resolver on the very next query. All mutating methods take an
internal lock and persist atomically (temp file + os.replace).

Persisted keys: allowlist, blocklist, isolated devices, lockdown, learning,
per-domain first-seen (novelty), block confirmations (auto-promote), and a
bounded map of recent events (so an alert's Unblock button can find its
domain).
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone

from tokenizer import registrable_part

_MAX_EVENTS = 5000
_MAX_FIRST_SEEN = 200000


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class GhostState:
    def __init__(self, path: str, learning_default: bool = True):
        self.path = path
        self._lock = threading.RLock()
        self.allowlist: set[str] = set()
        self.blocklist: set[str] = set()
        self.isolated: set[str] = set()
        self.lockdown: bool = False
        self.learning: bool = learning_default
        self.first_seen: dict[str, str] = {}
        self.confirmations: dict[str, int] = {}
        self.events: dict[str, dict] = {}
        # note_seen() fires on every brand-new domain; persisting each one would
        # be a disk write per query, so it is throttled: mark dirty, flush at
        # most every _flush_interval seconds (and on explicit flush()/shutdown).
        self._dirty = False
        self._last_flush = 0.0
        self._flush_interval = 5.0
        self._load()

    # -- persistence ------------------------------------------------------
    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            return
        self.allowlist = set(d.get("allowlist", []))
        self.blocklist = set(d.get("blocklist", []))
        self.isolated = set(d.get("isolated", []))
        self.lockdown = bool(d.get("lockdown", False))
        self.learning = bool(d.get("learning", self.learning))
        self.first_seen = dict(d.get("first_seen", {}))
        self.confirmations = dict(d.get("confirmations", {}))
        self.events = dict(d.get("events", {}))

    def _save_locked(self) -> None:
        # Keep the persisted file bounded.
        if len(self.events) > _MAX_EVENTS:
            keep = sorted(self.events.items(),
                          key=lambda kv: kv[1].get("time", ""))[-_MAX_EVENTS:]
            self.events = dict(keep)
        if len(self.first_seen) > _MAX_FIRST_SEEN:
            keep = sorted(self.first_seen.items(), key=lambda kv: kv[1])[-_MAX_FIRST_SEEN:]
            self.first_seen = dict(keep)
        data = {
            "allowlist": sorted(self.allowlist),
            "blocklist": sorted(self.blocklist),
            "isolated": sorted(self.isolated),
            "lockdown": self.lockdown,
            "learning": self.learning,
            "first_seen": self.first_seen,
            "confirmations": self.confirmations,
            "events": self.events,
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
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

    # -- queries ----------------------------------------------------------
    def is_allowed(self, domain: str) -> bool:
        """True if the domain or its registrable part is on the allowlist."""
        with self._lock:
            return domain in self.allowlist or registrable_part(domain) in self.allowlist

    def is_blocked(self, domain: str) -> bool:
        with self._lock:
            return domain in self.blocklist or registrable_part(domain) in self.blocklist

    def note_seen(self, domain: str) -> bool:
        """Record a domain sighting. Returns True if this is the FIRST time the
        registrable part has ever been seen."""
        reg = registrable_part(domain)
        with self._lock:
            if reg in self.first_seen:
                return False
            self.first_seen[reg] = _now()
            self._dirty = True
            if time.monotonic() - self._last_flush >= self._flush_interval:
                self._save_locked()
            return True

    def is_new(self, domain: str, novelty_days: int) -> bool:
        """True if the registrable part was first seen within novelty_days."""
        reg = registrable_part(domain)
        with self._lock:
            ts = self.first_seen.get(reg)
        if not ts:
            return True
        try:
            age = datetime.now(timezone.utc) - _parse_iso(ts)
        except ValueError:
            return False
        return age.days < novelty_days

    # -- mutations (persist) ---------------------------------------------
    def add_block(self, domain: str) -> None:
        with self._lock:
            self.blocklist.add(domain)
            self.allowlist.discard(domain)
            self._save_locked()

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

    def isolate(self, name: str) -> None:
        with self._lock:
            self.isolated.add(name)
            self._save_locked()

    def release(self, name: str) -> None:
        with self._lock:
            self.isolated.discard(name)
            self._save_locked()

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
            self._save_locked()

    def event(self, event_id: str) -> dict | None:
        with self._lock:
            return self.events.get(event_id)
