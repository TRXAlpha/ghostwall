"""Pure-Python classic-pcap concatenation; mergecap used if available."""
import os
import shutil
import struct
import subprocess

PCAP_MAGIC_LE = 0xA1B2C3D4   # little-endian magic as seen in file
MAGIC_BYTES_LE = b"\xd4\xc3\xb2\xa1"
MAGIC_BYTES_BE = b"\xa1\xb2\xc3\xd4"
PKT_HDR = struct.Struct("<IIII")
PKT_HDR_BE = struct.Struct(">IIII")


def find_mergecap(name: str = "mergecap") -> str:
    return shutil.which(name) or ""


def read_header(path: str):
    """Return (linktype, endian) from a classic pcap file, or raise ValueError."""
    with open(path, "rb") as f:
        hdr = f.read(24)
    if len(hdr) < 24:
        raise ValueError("short pcap header: %s" % path)
    if hdr[:4] == MAGIC_BYTES_LE:
        end = "<"
    elif hdr[:4] == MAGIC_BYTES_BE:
        end = ">"
    else:
        raise ValueError("not a classic pcap file: %s" % path)
    linktype = struct.unpack(end + "I", hdr[20:24])[0]
    return linktype, end


def merge_pcaps_pure(paths: list, out_path: str) -> None:
    """Concatenate classic pcaps: copy the first file's global header, then
    append every packet record (byte-swapping when endianness differs)."""
    if not paths:
        raise ValueError("no pcap files to merge")
    linktype, end0 = read_header(paths[0])
    tmp = out_path + ".tmp"
    with open(tmp, "wb") as out:
        out.write(struct.pack(end0 + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0,
                              linktype))
        for p in paths:
            lt, end = read_header(p)
            if lt != linktype:
                raise ValueError("linktype mismatch in %s (%d != %d)"
                                 % (p, lt, linktype))
            pkt = PKT_HDR if end == "<" else PKT_HDR_BE
            with open(p, "rb") as f:
                f.seek(24)
                while True:
                    h = f.read(16)
                    if not h:
                        break
                    if len(h) < 16:
                        break  # truncated tail: drop
                    ts, tus, incl, orig = pkt.unpack(h)
                    data = f.read(incl)
                    if len(data) < incl:
                        break
                    if end != end0:
                        ts, tus, incl, orig = int(ts), int(tus), int(incl), int(orig)
                        out.write(PKT_HDR.pack(ts, tus, incl, orig))
                    else:
                        out.write(h)
                    out.write(data)
    os.replace(tmp, out_path)


def merge_pcaps(paths: list, out_path: str, mergecap_bin: str = "") -> str:
    """Merge with mergecap if available, else pure Python. Returns method used."""
    paths = [p for p in paths if os.path.isfile(p) and os.path.getsize(p) > 24]
    if not paths:
        raise ValueError("no valid pcap files to merge")
    if mergecap_bin and os.path.exists(mergecap_bin):
        tmp = out_path + ".tmp"
        r = subprocess.run([mergecap_bin, "-w", tmp] + paths,
                           capture_output=True, timeout=120)
        if r.returncode == 0 and os.path.isfile(tmp):
            os.replace(tmp, out_path)
            return "mergecap"
    merge_pcaps_pure(paths, out_path)
    return "pure-python"
