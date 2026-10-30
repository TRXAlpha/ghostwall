"""Tests for beacon.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from beacon import BeaconDetector


class BeaconTests(unittest.TestCase):
    def test_regular_interval_fires(self):
        d = BeaconDetector(min_samples=5, max_cv=0.15, min_interval=5.0)
        reason = None
        for k in range(5):
            reason = d.observe("192.168.1.30", "1.2.3.4", 443, when=1000.0 + 60 * k)
        self.assertIsNotNone(reason)
        self.assertIn("beacon", reason)

    def test_insufficient_samples(self):
        d = BeaconDetector(min_samples=5)
        for k in range(4):
            r = d.observe("a", "b", 443, when=1000.0 + 60 * k)
        self.assertIsNone(r)

    def test_irregular_does_not_fire(self):
        d = BeaconDetector(min_samples=5, max_cv=0.15, min_interval=5.0)
        times = [0, 60, 65, 400, 410, 900]  # wildly uneven
        r = None
        for i, t in enumerate(times):
            r = d.observe("a", "b", 443, when=float(t))
        self.assertIsNone(r)

    def test_too_fast_is_not_a_beacon(self):
        d = BeaconDetector(min_samples=5, max_cv=0.15, min_interval=5.0)
        r = None
        for k in range(6):
            r = d.observe("a", "b", 443, when=1000.0 + 1.0 * k)  # 1s apart
        self.assertIsNone(r)

    def test_jittered_beacon_within_cv_fires(self):
        d = BeaconDetector(min_samples=5, max_cv=0.2, min_interval=5.0)
        times = [0, 60, 119, 181, 240, 299]  # ~60s with small jitter
        r = None
        for t in times:
            r = d.observe("a", "b", 443, when=float(t))
        self.assertIsNotNone(r)

    def test_window_evicts_old(self):
        d = BeaconDetector(min_samples=5, window_seconds=100, max_cv=0.15, min_interval=5.0)
        # old samples outside the 100s window are dropped, so <5 remain
        for t in (0, 10, 20, 30):
            d.observe("a", "b", 443, when=float(t))
        r = d.observe("a", "b", 443, when=1000.0)
        self.assertIsNone(r)


if __name__ == "__main__":
    unittest.main()
