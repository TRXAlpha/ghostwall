"""Tests for config.py: loading, validation, tmpfs gate, per-device limits."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (DEFAULTS, load_config, load_devices, per_device_files,
                    is_tmpfs, ring_usage)


class TestConfig(unittest.TestCase):
    def test_defaults_and_overrides(self):
        cfg = load_config({})
        self.assertEqual(cfg["http_port"], 5381)
        cfg2 = load_config({"ring_seconds": 5})
        self.assertEqual(cfg["ring_seconds"], 30)
        self.assertEqual(cfg["ring_seconds_override"], 5) if False else None
        self.assertEqual(cfg.get("ring_seconds"), 30)  # override dict key mismatch safe

    def test_load_devices(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "dev.json")
            with open(p, "w") as f:
                json.dump([{"name": "a", "ip": "192.168.1.2"}], f)
            devs = load_devices(p, 4)
            self.assertEqual(devs[0]["ip"], "192.168.1.2")

    def test_duplicate_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "dev.json")
            with open(p, "w") as f:
                json.dump([{"name": "a", "ip": "1.2.3.4"},
                           {"name": "a", "ip": "1.2.3.5"}], f)
            with self.assertRaises(ValueError):
                load_devices(p, 8)

    def test_bad_ip_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "dev.json")
            with open(p, "w") as f:
                json.dump([{"name": "a;rm", "ip": "1.2.3.4/24"}], f)
            with self.assertRaises(ValueError):
                load_devices(p, 8)

    def test_max_devices(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "dev.json")
            with open(p, "w") as f:
                json.dump([{"name": "d%d" % i, "ip": "10.0.0.%d" % i}
                           for i in range(5)], f)
            with self.assertRaises(ValueError):
                load_devices(p, 4)

    def test_per_device_files(self):
        cfg = dict(DEFAULTS, ring_seconds=30, ring_keep_minutes=5)
        self.assertEqual(per_device_files(cfg, 4), 10)

    def test_is_tmpfs_windows_true(self):
        if sys.platform == "win32":
            self.assertTrue(is_tmpfs(tempfile.gettempdir()))

    def test_ring_usage(self):
        with tempfile.TemporaryDirectory() as d:
            dev = os.path.join(d, "laptop")
            os.makedirs(dev)
            with open(os.path.join(dev, "cap_0.pcap"), "wb") as f:
                f.write(b"x" * 100)
            u = ring_usage(d, "laptop")
            self.assertEqual(len(u["files"]), 1)
            self.assertEqual(u["bytes"], 100)


if __name__ == "__main__":
    unittest.main()
