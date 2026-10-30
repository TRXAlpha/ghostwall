"""Shared packet/ClientHello builders for ghost-flow tests."""
import socket
import struct

SYN = 0x02
PSH_ACK = 0x18


def ipv4_tcp(src, dst, sport, dport, flags, payload=b""):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, (5 << 4), flags, 65535, 0, 0) + payload
    ip = (struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0)
          + socket.inet_aton(src) + socket.inet_aton(dst))
    return ip + tcp


def ipv4_udp(src, dst, sport, dport, payload=b""):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = (struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0)
          + socket.inet_aton(src) + socket.inet_aton(dst))
    return ip + udp


def ipv6_tcp(src, dst, sport, dport, flags, payload=b""):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, (5 << 4), flags, 65535, 0, 0) + payload
    ip = (struct.pack(">IHBB", (6 << 28), len(tcp), 6, 64)
          + socket.inet_pton(socket.AF_INET6, src)
          + socket.inet_pton(socket.AF_INET6, dst))
    return ip + tcp


def client_hello(sni=b"example.com",
                 ciphers=(0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030),
                 grease=False):
    cs = list(ciphers)
    if grease:
        cs = [0x0a0a] + cs  # a GREASE cipher that must be excluded by JA4
    cipher_bytes = b"".join(struct.pack(">H", c) for c in cs)

    def ext(t, d):
        return struct.pack(">HH", t, len(d)) + d

    sni_ext = ext(0x0000, struct.pack(">H", len(sni) + 3) + b"\x00"
                  + struct.pack(">H", len(sni)) + sni)
    alpn_list = b"\x02h2\x08http/1.1"
    alpn = ext(0x0010, struct.pack(">H", len(alpn_list)) + alpn_list)
    supver = ext(0x002b, b"\x02\x03\x04")  # TLS 1.3
    sigalgs = ext(0x000d, struct.pack(">H", 4) + struct.pack(">HH", 0x0403, 0x0804))
    exts = sni_ext + alpn + supver + sigalgs
    body = (struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00"
            + struct.pack(">H", len(cipher_bytes)) + cipher_bytes + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
