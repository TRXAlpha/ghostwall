"""Tests for pcapmerge.py: header parse, pure merge, linktype mismatch."""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapmerge import (MAGIC_BYTES_BE, MAGIC_BYTES_LE, PKT_HDR, read_header,
                       merge_pcaps_pure, merge_pcaps)

PCAP_HDR = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 1)


def make_pcap(path, npackets=3, linktype=1):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, linktype))
        for k in range(npackets):
            f.write(PKT_HDR.pack(1000 + k, k, 60, 60))
            f.write(b"\x11" * 60)


class TestPcapMerge(unittest.TestCase):
    def test_read_header(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.pcap")
            make_pcap(p)
            lt, end = read_header(p)
            self.assertEqual(lt, 1)
            self.assertEqual(end, "<")

    def test_merge_pure_counts_packets(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = os.path.join(d, "a.pcap"), os.path.join(d, "b.pcap")
            make_pcap(a, 3)
            make_pcap(b, 2)
            out = os.path.join(d, "m.pcap")
            merge_pcaps_pure([a, b], out)
            data = open(out, "rb").read()
            self.assertEqual(data[:4], MAGIC_BYTES_LE)
            self.assertEqual((len(data) - 24) / (16 + 60), 5)

    def test_merge_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = os.path.join(d, "a.pcap"), os.path.join(d, "b.pcap")
            make_pcap(a, 1, linktype=1)
            make_pcap(b, 1, linktype=113)  # LINKTYPE_LINUX_SLL
            with self.assertRaises(ValueError):
                merge_pcaps_pure([a, b], os.path.join(d, "m.pcap"))

    def test_merge_skips_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.pcap")
            make_pcap(a, 1)
            out = os.path.join(d, "m.pcap")
            method = merge_pcaps([a, os.path.join(d, "nope.pcap")], out)
            self.assertEqual(method, "pure-python")
            self.assertGreater(os.path.getsize(out), 24)

    def test_no_files_raises(self):
        with self.assertRaises(ValueError):
            merge_pcaps_pure([], "unused")


if __name__ == "__main__":
    unittest.main()
