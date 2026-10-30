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
    argv = sys.argv[1:]
    o = parse_args(argv)
    out_dir = os.path.dirname(o["w"]) or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "argv.txt"), "w") as f:
        f.write(" ".join(argv))
    interval = max(1, int(o["G"]))
    count = max(1, int(o["W"]))
    rotating = o["G"] not in (0, None)
    idx = 0
    stop = {"flag": False}

    def handler(sig, frm):
        stop["flag"] = True
    try:
        import signal
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
    except (ImportError, ValueError):
        pass
    # first file immediately
    path = rotate_file(out_dir)
    with open(path, "wb") as f:
        f.write(PCAP_HDR)
        for k in range(3):
            f.write(PKT.pack(int(time.time()), k, 60, 60))
            f.write(b"\x00" * 60)
    if not rotating:
        while not stop["flag"]:
            time.sleep(0.2)
        return
    n = 1
    while not stop["flag"] and n < count:
        time.sleep(interval)
        if stop["flag"]:
            break
        # rotate: reuse same names in a ring (cap_%d), oldest overwritten
        path = os.path.join(out_dir, "cap_%d.pcap" % (n % count))
        with open(path, "wb") as f:
            f.write(PCAP_HDR)
            for k in range(3):
                f.write(PKT.pack(int(time.time()), k, 60, 60))
                f.write(b"\x00" * 60)
        n += 1
    while not stop["flag"]:
        time.sleep(0.2)


if __name__ == "__main__":
    main()
