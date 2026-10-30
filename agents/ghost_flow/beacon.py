"""Beacon detection: find connections that repeat at a near-constant interval.

C2 implants "call home" on a timer. We bucket new connections by
(src, dst, dport), keep a sliding window of their start times, and flag a key
whose inter-arrival gaps are many and low-jitter (coefficient of variation
below a threshold). Jittered beacons with small random spread still fall under
a loose CV; very bursty or very irregular traffic does not.
"""
from __future__ import annotations

import statistics
import time


class BeaconDetector:
    def __init__(self, min_samples: int = 5, window_seconds: int = 3600,
                 max_cv: float = 0.15, min_interval: float = 5.0):
        self.min_samples = min_samples
        self.window = window_seconds
        self.max_cv = max_cv
        self.min_interval = min_interval
        self._hist: dict[tuple, list[float]] = {}

    def observe(self, src: str, dst: str, dport: int, when: float | None = None) -> str | None:
        """Record a new connection; return a reason string if it beacons."""
        now = when if when is not None else time.time()
        key = (src, dst, dport)
        hist = self._hist.setdefault(key, [])
        hist.append(now)
        cutoff = now - self.window
        while hist and hist[0] < cutoff:
            hist.pop(0)
        if len(hist) < self.min_samples:
            return None
        gaps = [b - a for a, b in zip(hist, hist[1:])]
        mean = statistics.fmean(gaps)
        if mean < self.min_interval:
            return None  # too fast to be a beacon -- that's just a busy flow
        stdev = statistics.pstdev(gaps)
        cv = stdev / mean if mean else 1.0
        if cv <= self.max_cv:
            return (f"beacon to {dst}:{dport} every ~{mean:.0f}s "
                    f"(n={len(hist)}, jitter cv={cv:.2f})")
        return None
