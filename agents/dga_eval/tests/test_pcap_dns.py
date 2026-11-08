"""pcap_dns: DNS queries and their answers out of a capture (used by real_malware.py)."""
import io
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pcap_dns  # noqa: E402
import real_malware  # noqa: E402


def dns_msg(txid: int, name: str, qtype: int = 1, reply: bool = False, rcode: int = 0) -> bytes:
    flags = 0x8180 | rcode if reply else 0x0100
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", qtype, 1)
    return struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0) + q


def udp_frame(src: str, sport: int, dst: str, dport: int, payload: bytes) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes(int(x) for x in src.split(".")), bytes(int(x) for x in dst.split(".")))
    return b"\x00" * 12 + b"\x08\x00" + ip + udp


def pcap(frames) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for t, fr in frames:
        out += struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(fr), len(fr)) + fr
    return out


class PcapDnsTest(unittest.TestCase):
    def test_query_answer_and_retry(self):
        cap = pcap([
            (100.0, udp_frame("10.0.0.5", 5000, "10.0.0.1", 53, dns_msg(7, "xkqz.example"))),
            (100.5, udp_frame("10.0.0.5", 5000, "10.0.0.1", 53, dns_msg(7, "xkqz.example"))),   # retry
            (100.6, udp_frame("10.0.0.1", 53, "10.0.0.5", 5000, dns_msg(7, "xkqz.example", reply=True, rcode=3))),
            (101.0, udp_frame("10.0.0.5", 5001, "10.0.0.1", 53, dns_msg(8, "noanswer.example", 28))),
            (102.0, udp_frame("10.0.0.5", 5002, "10.0.0.1", 5353, dns_msg(9, "mdns.local"))),  # not port 53
        ])
        recs = list(pcap_dns.dns_queries(io.BytesIO(cap)))
        self.assertEqual([r["name"] for r in recs], ["xkqz.example", "noanswer.example"])
        self.assertEqual(recs[0]["client"], "10.0.0.5")
        self.assertEqual(recs[0]["reply"][3] & 0x0F, 3)        # the NXDOMAIN answer, verbatim
        self.assertIsNone(recs[1]["reply"])
        self.assertEqual(recs[1]["qtype"], "AAAA")
        self.assertEqual(pcap_dns.servers(recs), {"10.0.0.1"})

    def test_garbage_is_refused_not_trusted(self):
        with self.assertRaises(pcap_dns.CaptureError):
            list(pcap_dns.dns_queries(io.BytesIO(b"PK\x03\x04 not a capture")))
        bad = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 0, 0, 1 << 30, 0)
        with self.assertRaises(pcap_dns.CaptureError):
            list(pcap_dns.dns_queries(io.BytesIO(bad)))

    def test_ioc_hosts_refangs(self):
        got = real_malware.ioc_hosts("- hxxps[:]//evil-c2[.]example[.]com/gate.php\n- payload.exe\n- bad[.]top")
        self.assertIn("evil-c2.example.com", got)
        self.assertIn("bad.top", got)
        self.assertNotIn("payload.exe", got)
        self.assertTrue(real_malware.on_ioc("a.evil-c2.example.com", got))
        self.assertFalse(real_malware.on_ioc("example.com", got))


if __name__ == "__main__":
    unittest.main()
