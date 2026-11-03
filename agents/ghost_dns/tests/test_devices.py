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


class Ipv6FollowTests(unittest.TestCase):
    def test_a_phone_keeps_its_name_across_privacy_addresses(self):
        dm = DeviceMap.from_json([{"name": "phone", "ip": "FD00:0:0:0::A", "mac": "02:00:00:00:00:66"}])
        self.assertEqual(dm.device_for_ip("fd00::a").name, "phone")                  # one spelling
        d = dm.device_for_ip("fd00::1234:5678", "02:00:00:00:00:66")                  # tomorrow's address
        self.assertEqual((d.name, d.ip), ("phone", "fd00::1234:5678"))


def neigh_msg(family, addr: bytes, mac: bytes | None, state: int) -> bytes:
    """One RTM_NEWNEIGH message as the kernel sends it."""
    import struct
    attrs = struct.pack("=HH", 4 + len(addr), 1) + addr + b"\0" * (-len(addr) % 4)
    if mac is not None:
        attrs += struct.pack("=HH", 4 + len(mac), 2) + mac + b"\0" * (-len(mac) % 4)
    body = struct.pack("=BxxxiHBB", family, 2, state, 0, 1) + attrs
    return struct.pack("=LHHLL", 16 + len(body), 28, 2, 1, 0) + body


class NetlinkTests(unittest.TestCase):
    def test_parses_a_neighbour_dump(self):
        import socket
        import struct
        from neighbours import parse_neigh_dump
        v4 = socket.inet_pton(socket.AF_INET, "192.168.1.20")
        v6 = socket.inet_pton(socket.AF_INET6, "fd00::1234")
        data = (neigh_msg(socket.AF_INET, v4, bytes.fromhex("0200000000aa"), 0x02)          # REACHABLE
                + neigh_msg(socket.AF_INET6, v6, bytes.fromhex("0200000000bb"), 0x04)      # STALE
                + neigh_msg(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, "fd00::9"), None, 0x01)   # INCOMPLETE
                + neigh_msg(socket.AF_INET, socket.inet_pton(socket.AF_INET, "0.0.0.0"), bytes(6), 0x40)  # NOARP
                + struct.pack("=LHHLL", 20, 3, 2, 1, 0) + b"\0" * 4)                    # DONE
        self.assertEqual(parse_neigh_dump(data), ({"192.168.1.20": "02:00:00:00:00:aa",
                                                   "fd00::1234": "02:00:00:00:00:bb"}, True))

    def test_reads_this_machines_table(self):
        import socket
        from neighbours import read_netlink
        if not hasattr(socket, "AF_NETLINK"):
            self.skipTest("no netlink here")
        table = read_netlink()                      # whatever is there, without an error
        self.assertTrue(all(":" in mac for mac in table.values()))

    def test_one_spelling_per_address(self):
        from neighbours import canonical_ip
        self.assertEqual(canonical_ip("FD00:0:0::5"), "fd00::5")
        self.assertEqual(canonical_ip("::ffff:192.168.1.5"), "192.168.1.5")
        self.assertEqual(canonical_ip("not-an-ip"), "not-an-ip")


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
