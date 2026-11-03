#!/usr/bin/env python3
"""Fake tcpdump for Windows tests: parses enough of the real CLI (-i, -s, -w,
-G, -W, -n, filter) and writes small valid classic-pcap files, rotating per -G
seconds (accelerated) and wrapping after -W files.

Writes argv.txt into the output dir for debugging. Sleeps until SIGINT/kill.
"""
import os
import signal
import struct
import sys
import time

PCAP_HDR = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 1)  # LINKTYPE_ETHERNET
PKT = struct.Struct("<IIII")


def parse_args(argv):
    o = {"interface": "eth0", "snaplen": "68", "w": None, "G": 0, "W": 1}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-i", "-s", "-w", "-G", "-W"):
            o[a[1]] = argv[i + 1]
            i += 2
        elif a == "-n":
            i += 1
        else:
            i += 1  # filter expression (src host X)
    return o


def rotate_file(out_dir):
    ts = time.time()
    return os.path.join(out_dir, "cap_%d.pcap" % int(ts))


def write_pcap(path, npackets=3):
    with open(path, "wb") as f:
        f.write(PCAP_HDR)
        for k in range(npackets):
            # ts, tus, incl_len, orig_len + 60 bytes of dummy ethernet frame
            f.write(PKT.pack(int(time.time()), k * 100, 60, 60))
            f.write(b"\x00" * 60)


def main():
    """Behaves like the real tcpdump: with -G and a strftime pattern in -w, a new file
    every G seconds (accelerated here), forever; with -W as well, it EXITS after W files
    (that is what -W means together with -G)."""
    argv = sys.argv[1:]
    o = parse_args(argv)
    out_dir = os.path.dirname(o["w"]) or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "argv.txt"), "w") as f:
        f.write(" ".join(argv))
    interval = max(1, int(o["G"])) if o["G"] else 0
    limit = int(o["W"]) if "-W" in argv else 0
    stop = {"flag": False}

    def handler(sig, frm):
        stop["flag"] = True
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    n = 0
    while not stop["flag"]:
        name = time.strftime(os.path.basename(o["w"])) if interval else os.path.basename(o["w"])
        write_pcap(os.path.join(out_dir, name))
        n += 1
        if limit and n >= limit:
            print("Maximum file limit reached: %d" % limit, file=sys.stderr)
            return
        if not interval:
            while not stop["flag"]:
                time.sleep(0.2)
            return
        t = time.time()
        while not stop["flag"] and time.time() - t < interval:
            time.sleep(0.05)


if __name__ == "__main__":
    main()
