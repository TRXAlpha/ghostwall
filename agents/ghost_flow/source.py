"""Packet sources feeding the inspector.

  - NfqueueSource : the real Pi path. Binds nftables queue num 100 (the slot
                    reserved in agents/netconf/out/ghostwall.nft) and applies
                    the inspector's verdict to each packet. Needs Linux, root,
                    and the `netfilterqueue` module -- all imported lazily so
                    this file loads fine on the Windows dev box.
  - replay        : drive the inspector from a list of raw packets (tests, demo).
  - read_pcap     : pull raw frames out of a classic .pcap file (stdlib only).
"""
from __future__ import annotations

import struct


class NfqueueSource:
    def __init__(self, queue_num: int = 100):
        self.queue_num = queue_num

    def run(self, inspect_fn) -> None:
        from netfilterqueue import NetfilterQueue  # lazy: Linux only

        def _cb(pkt):
            verdict = inspect_fn(pkt.get_payload())
            if verdict == "drop":
                pkt.drop()
            else:
                pkt.accept()

        nfq = NetfilterQueue()
        nfq.bind(self.queue_num, _cb)
        try:
            nfq.run()
        finally:
            nfq.unbind()


def replay(raw_packets, inspect_fn, timestamps=None) -> list[str]:
    """Feed raw packets to inspect_fn; return the list of verdicts. If
    timestamps is given (one epoch per packet) they are passed through so the
    beacon detector sees the real spacing."""
    verdicts = []
    for i, raw in enumerate(raw_packets):
        when = timestamps[i] if timestamps is not None else None
        verdicts.append(inspect_fn(raw, when) if when is not None else inspect_fn(raw))
    return verdicts


def read_pcap(path: str):
    """Yield raw frame bytes from a classic (not pcapng) .pcap. Link-layer bytes
    are left on; packet.parse() strips Ethernet automatically."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = hdr[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        else:
            return
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            _ts, _us, incl, _orig = struct.unpack(endian + "IIII", rec)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield data
