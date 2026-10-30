"""Alert grouping and rate limiting. Stdlib only."""
from __future__ import annotations

import time


def severity_of(event: dict) -> str:
    sev = event.get("severity", "warn")
    return sev if sev in ("info", "warn", "high", "critical") else "warn"


def group_key(event: dict) -> tuple:
    """Collapse key: device + primary reason (rule), per spec."""
    rule = str(event.get("rule", ""))
    return (str(event.get("device", "?")), rule, severity_of(event))


class GroupState:
    """One collapsed alert: counters, first/last seen, representative event."""

    def __init__(self, event: dict, now: float):
        self.key = group_key(event)
        self.count = 1
        self.first = now
        self.last = now
        self.event = event
        self.message_id: int | None = None

    def hit(self, event: dict, now: float) -> None:
        self.count += 1
        self.last = now
        self.event = event  # latest occurrence wins for display


class AlertGrouper:
    """Collapses same device+reason alerts within a window; rate-limits sends.

    feed(event, now) -> ("new", GroupState) | ("update", GroupState)
                        | ("digest", event) for info-severity events.
    Expired groups are dropped on access; a fresh alert after expiry makes a
    new group (rate limit = one message per window per key).
    """

    def __init__(self, window_minutes: int = 10, clock=time.time):
        self.window = window_minutes * 60.0
        self.clock = clock
        self.groups: dict[tuple, GroupState] = {}

    def feed(self, event: dict, now: float | None = None) -> tuple[str, object]:
        if now is None:
            now = self.clock()
        if severity_of(event) == "info":
            return ("digest", event)
        key = group_key(event)
        grp = self.groups.get(key)
        if grp is not None and now - grp.first < self.window:
            grp.hit(event, now)
            return ("update", grp)
        # expired (or first): start a new group — this is the rate limit gate
        grp = GroupState(event, now)
        self.groups[key] = grp
        return ("new", grp)

    def counters(self) -> dict:
        return {k: g.count for k, g in self.groups.items()}
