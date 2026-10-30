"""Tests for packet.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import packet
from _helpers import ipv4_tcp, ipv4_udp, ipv6_tcp, SYN, PSH_ACK


class PacketTests(unittest.TestCase):
    def test_v4_tcp(self):
        p = packet.parse(ipv4_tcp("192.168.1.30", "8.8.8.8", 51000, 443, SYN))
        self.assertEqual(p.version, 4)
        self.assertEqual(p.proto, packet.PROTO_TCP)
        self.assertEqual(p.src, "192.168.1.30")
        self.assertEqual(p.dst, "8.8.8.8")
        self.assertEqual(p.dport, 443)
        self.assertTrue(p.is_syn_only)

    def test_v4_tcp_synack_not_syn_only(self):
        p = packet.parse(ipv4_tcp("192.168.1.30", "8.8.8.8", 51000, 443, PSH_ACK))
        self.assertFalse(p.is_syn_only)

    def test_v4_udp(self):
        p = packet.parse(ipv4_udp("192.168.1.30", "8.8.8.8", 51000, 53, b"\x00"))
        self.assertEqual(p.proto, packet.PROTO_UDP)
        self.assertEqual(p.dport, 53)
        self.assertEqual(p.flags, 0)

    def test_v6_tcp(self):
        p = packet.parse(ipv6_tcp("fe80::1", "2606:4700:4700::1111", 51000, 443, SYN))
        self.assertEqual(p.version, 6)
        self.assertEqual(p.dst, "2606:4700:4700::1111")

    def test_ethernet_stripped(self):
        inner = ipv4_tcp("192.168.1.30", "8.8.8.8", 51000, 443, SYN)
        frame = b"\xaa" * 12 + b"\x08\x00" + inner  # dst+src mac, ethertype IPv4
        p = packet.parse(frame)
        self.assertEqual(p.dst, "8.8.8.8")

    def test_payload_extracted(self):
        p = packet.parse(ipv4_tcp("192.168.1.30", "8.8.8.8", 51000, 443, PSH_ACK, b"hello"))
        self.assertEqual(p.payload, b"hello")

    def test_garbage_returns_none(self):
        self.assertIsNone(packet.parse(b"\x00\x01\x02"))
        self.assertIsNone(packet.parse(b""))


if __name__ == "__main__":
    unittest.main()
