from dataclasses import dataclass
import socket
import struct
from typing import Callable


@dataclass
class DNSDecision:
    block: bool
    reason: str | None = None


def _parse_qname(packet: bytes, offset: int = 12) -> tuple[str, int]:
    labels = []
    while True:
        if offset >= len(packet):
            return "", offset
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(packet[offset : offset + length].decode("ascii", errors="ignore"))
        offset += length
    return ".".join(labels), offset


def parse_query(packet: bytes) -> tuple[str, str, int]:
    qname, offset = _parse_qname(packet, 12)
    if offset + 4 > len(packet):
        return qname.lower(), "UNKNOWN", offset
    qtype = struct.unpack(">H", packet[offset : offset + 2]
    )[0]
    qtype_name = {
        1: "A",
        28: "AAAA",
        15: "MX",
        16: "TXT",
        5: "CNAME",
        12: "PTR",
        6: "SOA",
    }.get(qtype, str(qtype))
    return qname.lower(), qtype_name, offset + 4


def build_nxdomain_response(packet: bytes, question_end: int) -> bytes:
    if len(packet) < 12:
        return packet
    transaction_id = packet[:2]
    flags = struct.unpack(">H", packet[2:4])[0]
    rd = flags & 0x0100
    response_flags = 0x8000 | rd | 0x0080 | 0x0003
    header = transaction_id + struct.pack(">H", response_flags)
    header += struct.pack(">HHHH", 1, 0, 0, 0)
    question = packet[12:question_end]
    return header + question


class DNSProxy:
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        upstream: str,
        timeout_seconds: float = 2.0,
        on_query: Callable[[str, str, str], DNSDecision] | None = None,
        block_response: str = "nxdomain",
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream = upstream
        self.timeout_seconds = timeout_seconds
        self.on_query = on_query
        self.block_response = block_response

    def _forward(self, packet: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
            upstream_sock.settimeout(self.timeout_seconds)
            upstream_sock.sendto(packet, (self.upstream, 53))
            return upstream_sock.recvfrom(4096)[0]

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((self.listen_host, self.listen_port))
            while True:
                packet, addr = sock.recvfrom(4096)
                client_ip = addr[0]
                domain, qtype, question_end = parse_query(packet)
                decision = DNSDecision(block=False)
                if self.on_query:
                    decision = self.on_query(client_ip, domain, qtype)
                if decision.block and self.block_response == "nxdomain":
                    response = build_nxdomain_response(packet, question_end)
                else:
                    try:
                        response = self._forward(packet)
                    except (OSError, socket.timeout):
                        response = build_nxdomain_response(packet, question_end)
                sock.sendto(response, addr)
