"""Tests for devices.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from devices import DeviceMap


class DeviceMapTests(unittest.TestCase):
    def test_netconf_shape(self):
        raw = {"devices": [{"name": "dell", "ip": "192.168.1.30",
                            "mac": "aa:bb:cc:dd:ee:01", "profile": "normal"}],
               "_pending": [{"name": "ps4", "ip": "192.168.1.40", "mac": None}]}
        dm = DeviceMap.from_json(raw)
        self.assertEqual(dm.device_for_ip("192.168.1.30").name, "dell")
        self.assertEqual(dm.device_for_name("dell").mac, "aa:bb:cc:dd:ee:01")
        self.assertEqual(dm.device_for_name("ps4").ip, "192.168.1.40")  # pending is named
        self.assertEqual(sorted(dm.names()), ["dell", "ps4"])

    def test_list_shape(self):
        raw = [{"name": "laptop", "ip": "192.168.1.51", "mac": "aa:bb:cc:dd:ee:02"}]
        dm = DeviceMap.from_json(raw)
        self.assertEqual(dm.device_for_ip("192.168.1.51").name, "laptop")

    def test_unknown_ip_fallback(self):
        dm = DeviceMap.from_json([])
        d = dm.device_for_ip("192.168.1.99")
        self.assertEqual(d.name, "192.168.1.99")
        self.assertIsNone(d.mac)

    def test_skips_entries_without_ip_or_name(self):
        dm = DeviceMap.from_json([{"name": "x"}, {"ip": "1.2.3.4"},
                                  {"name": "ok", "ip": "192.168.1.5"}])
        self.assertEqual(dm.names(), ["ok"])


if __name__ == "__main__":
    unittest.main()
