"""Tests for dnsmsg.py"""
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dnsmsg


def build_query(name: str, qtype: int = 1) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + q + struct.pack(">HH", qtype, 1)


class DnsMsgTests(unittest.TestCase):
    def test_parse_question(self):
        q = dnsmsg.parse_question(build_query("www.example.com", 1))
        self.assertEqual(q.name, "www.example.com")
        self.assertEqual(q.qtype_name, "A")

    def test_parse_too_short(self):
        self.assertIsNone(dnsmsg.parse_question(b"\x00\x01"))

    def test_nxdomain_flags(self):
        pkt = build_query("bad.example", 1)
        q = dnsmsg.parse_question(pkt)
        resp = dnsmsg.build_nxdomain(pkt, q.end)
        flags = struct.unpack(">H", resp[2:4])[0]
        self.assertTrue(flags & 0x8000)            # QR
        self.assertEqual(flags & 0x000F, 3)        # RCODE NXDOMAIN
        self.assertEqual(resp[:2], pkt[:2])        # same transaction id

    def test_servfail(self):
        pkt = build_query("x.example", 1)
        q = dnsmsg.parse_question(pkt)
        resp = dnsmsg.build_servfail(pkt, q.end)
        self.assertEqual(struct.unpack(">H", resp[2:4])[0] & 0x000F, 2)

    def test_sinkhole_a_record(self):
        pkt = build_query("bad.example", 1)
        q = dnsmsg.parse_question(pkt)
        resp = dnsmsg.build_sinkhole(pkt, q, "192.168.1.20")
        # 1 answer, rdata is the sinkhole IP
        self.assertEqual(struct.unpack(">H", resp[6:8])[0], 1)
        self.assertEqual(resp[-4:], socket.inet_aton("192.168.1.20"))

    def test_sinkhole_nodata_for_txt(self):
        pkt = build_query("bad.example", 16)  # TXT
        q = dnsmsg.parse_question(pkt)
        resp = dnsmsg.build_sinkhole(pkt, q, "192.168.1.20")
        self.assertEqual(struct.unpack(">H", resp[6:8])[0], 0)  # no answers

    def test_extract_answer_ips_roundtrip(self):
        pkt = build_query("example.com", 1)
        q = dnsmsg.parse_question(pkt)
        # craft a reply with one A answer = 93.184.216.34
        header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        question = pkt[12:q.end]
        rdata = socket.inet_aton("93.184.216.34")
        answer = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + rdata
        reply = header + question + answer
        self.assertEqual(dnsmsg.extract_answer_ips(reply), ["93.184.216.34"])

    def test_extract_answer_ips_never_raises(self):
        self.assertEqual(dnsmsg.extract_answer_ips(b"\x00\x01\x02"), [])


if __name__ == "__main__":
    unittest.main()
