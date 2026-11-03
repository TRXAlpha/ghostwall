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


class FollowByMacTests(unittest.TestCase):
    """DHCP can give the laptop's old address to the TV: names belong to MACs."""

    def setUp(self):
        self.dm = DeviceMap.from_json({"devices": [], "_pending": [
            {"name": "laptop", "ip": "192.168.1.20", "mac": "02:00:00:00:00:AA"},
            {"name": "printer", "ip": "192.168.1.40", "mac": None}]})

    def test_the_name_follows_the_mac_to_a_new_address(self):
        d = self.dm.device_for_ip("192.168.1.21", "02:00:00:00:00:aa")
        self.assertEqual((d.name, d.ip), ("laptop", "192.168.1.21"))
        self.assertEqual(self.dm.device_for_name("laptop").ip, "192.168.1.20")   # map untouched

    def test_an_old_address_now_used_by_another_device_loses_the_name(self):
        d = self.dm.device_for_ip("192.168.1.20", "02:00:00:00:00:bb")
        self.assertEqual(d.name, "192.168.1.20")
        self.assertEqual(d.mac, "02:00:00:00:00:bb")

    def test_without_neighbour_info_names_stay_with_addresses(self):
        self.assertEqual(self.dm.device_for_ip("192.168.1.20").name, "laptop")
        self.assertEqual(self.dm.device_for_ip("192.168.1.40", "02:00:00:00:00:cc").name, "printer")  # no MAC kept

    def test_mac_spellings(self):
        self.assertEqual(self.dm.device_for_ip("192.168.1.9", "02-00-00-00-00-AA").name, "laptop")
        self.assertEqual(self.dm.device_for_ip("192.168.1.9", "00:00:00:00:00:00").name, "192.168.1.9")


class NeighbourTableTests(unittest.TestCase):
    ARP = ("IP address       HW type     Flags       HW address            Mask     Device\n"
           "192.168.1.20     0x1         0x2         02:00:00:00:00:aa     *        eth0\n"
           "192.168.1.21     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
           "192.168.1.22     0x1         0x6         02:00:00:00:00:CC     *        eth0\n")

    def setUp(self):
        import tempfile
        self.path = os.path.join(tempfile.mkdtemp(), "arp")
        with open(self.path, "w") as f:
            f.write(self.ARP)

    def test_reads_complete_entries_only(self):
        from neighbours import read_arp
        self.assertEqual(read_arp(self.path), {"192.168.1.20": "02:00:00:00:00:aa",
                                               "192.168.1.22": "02:00:00:00:00:cc"})
        self.assertEqual(read_arp(self.path + ".missing"), {})

    def test_cache_rereads_for_a_new_address(self):
        from neighbours import Neighbours
        t = [0.0]
        n = Neighbours(self.path, ttl=30, miss_ttl=2, clock=lambda: t[0])
        self.assertEqual(n.mac("192.168.1.20"), "02:00:00:00:00:aa")
        with open(self.path, "a") as f:
            f.write("192.168.1.23     0x1         0x2         02:00:00:00:00:dd     *        eth0\n")
        self.assertIsNone(n.mac("192.168.1.23"))          # just read: not again at once
        t[0] = 2.5
        self.assertEqual(n.mac("192.168.1.23"), "02:00:00:00:00:dd")


if __name__ == "__main__":
    unittest.main()
