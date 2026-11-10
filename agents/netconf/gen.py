#!/usr/bin/env python3
"""gen.py - render netconf template files into an output directory."""
import argparse
import ipaddress
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"

# RFC 1123 hostname label: ASCII letters/digits/hyphens, 1-63 chars,
# must not start or end with a hyphen.
HOSTNAME_RE = re.compile(r"^(?=.{1,63}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


class GenError(Exception):
    pass


def validate_device(d, seen_macs, seen_ips, pi_ip):
    # MAC must be a real, complete MAC (no placeholders leak into leases)
    mac = (d.get("mac") or "").strip().lower().replace("-", ":")
    if not MAC_RE.match(mac):
        raise GenError(f"device {d.get('name')!r}: invalid MAC {d.get('mac')!r}")
    if mac in seen_macs:
        raise GenError(f"duplicate MAC {mac}")
    seen_macs.add(mac)

    ip = d.get("ip") or ""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as e:
        raise GenError(f"device {d.get('name')!r}: bad IPv4 {ip!r}") from e
    if ip in seen_ips:
        raise GenError(f"duplicate IP {ip}")
    seen_ips.add(ip)
    if ip == pi_ip:
        raise GenError(f"device {d.get('name')!r}: {ip} is the Pi itself; it must never be a DHCP lease")

    # RFC 1123 hostname label check (this is what dnsmasq --test enforces
    # as "bad DHCP host name").
    name = d.get("name") or ""
    if not isinstance(name, str) or not HOSTNAME_RE.match(name):
        raise GenError(
            f"device {ip!r}: bad DHCP hostname {name!r} - RFC 1123 label required "
            "(ASCII letters/digits/hyphens, 1-63 chars, no leading/trailing hyphen)"
        )


def resolve_devices_path(dev_path=None):
    """Explicit path, else the real devices.json, else the committed example
    (so a fresh clone with no private devices.json still renders)."""
    if dev_path:
        return Path(dev_path)
    real = HERE / "devices.json"
    return real if real.exists() else HERE / "devices.example.json"


def load_ctx(dev_path=None, cfg_path=None):
    cfg = json.loads(Path(cfg_path or HERE / "config.json").read_text(encoding="utf-8"))
    dev = json.loads(resolve_devices_path(dev_path).read_text(encoding="utf-8"))
    pi_ip = cfg["pi_ip"]
    seen_macs, seen_ips = set(), set()

    static_lines, iot_ips = [], []
    cfg["_ip_mac"] = []            # (address, MAC) of every named device, for "antispoof"
    for d in dev.get("devices", []):
        validate_device(d, seen_macs, seen_ips, pi_ip)
        if d.get("profile") == "iot":
            iot_ips.append(d["ip"])
        mac = d["mac"].lower().replace("-", ":")
        cfg["_ip_mac"].append((d["ip"], mac))
        static_lines.append(
            f"dhcp-host={mac},{d['ip']},{d['name']},{d.get('lease_time', cfg['default_lease_time'])}"
        )
    for d in dev.get("_pending", []):
        # Commented-out placeholder: NO lease is generated until a real MAC
        # is filled in and the entry moves into "devices".
        validate_device({**d, "mac": "00:00:00:00:00:00"}, set(), seen_ips, pi_ip)
        static_lines.append(
            f"# TODO: fill in MAC - dhcp-host=<MAC>,{d['ip']},{d['name']}  ({d.get('profile')} profile)"
        )
    return cfg, "\n".join(static_lines) + ("\n" if static_lines else ""), iot_ips

TEMPLATES = [
    ("dnsmasq.conf.j2", "dnsmasq.conf"),
    ("sysctl.d-99-ghostwall.conf.j2", "99-ghostwall.conf"),
    ("nftables-ghostwall.conf.j2", "ghostwall.nft"),
    ("breakglass.sh.j2", "breakglass.sh"),
    ("health.sh.j2", "health.sh"),
]

def doh_ips(path=HERE / "doh_ips.txt"):
    """(IPv4, IPv6) resolver addresses from doh_ips.txt, de-duplicated, in file order.
    Anything that doesn't parse as a single public address is refused: it would end up
    inside a firewall rule."""
    v4, v6 = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        for tok in line.split("#", 1)[0].split():
            try:
                ip = ipaddress.ip_address(tok)
            except ValueError as e:
                raise GenError(f"doh_ips.txt: {tok!r} is not an IP address") from e
            if not ip.is_global:
                raise GenError(f"doh_ips.txt: {tok} is not a public address")
            out = v4 if ip.version == 4 else v6
            if str(ip) not in out:
                out.append(str(ip))
    if not v4 or not v6:
        raise GenError("doh_ips.txt needs IPv4 and IPv6 resolver addresses")
    return v4, v6


# Ports no home device needs toward the internet: Telnet (Mirai and friends spread over
# it), SMTP (spam bots; mail apps use 587/465), Windows RPC, NetBIOS and SMB (worms,
# ransomware, leaking file shares), UPnP. Dropped for LAN devices going out, never between
# LAN devices. "egress_block_tcp" / "egress_block_udp" in config.json replace these.
EGRESS_TCP = [23, 25, 135, 139, 445, 2323]
EGRESS_UDP = [137, 138, 1900]
# An IoT device (devices.json "profile": "iot") with iot_egress_lock may only reach the
# internet on these: web, MQTT over TLS (most device clouds), DNS-over-QUIC/HTTP/3, time.
IOT_TCP = [80, 443, 8883]
IOT_UDP = [123, 443]


def _ports(cfg, key, default):
    ports = cfg.get(key, default)
    if not isinstance(ports, list) or not all(isinstance(p, int) and not isinstance(p, bool)
                                              and 1 <= p <= 65535 for p in ports):
        raise GenError(f"{key} must be a list of port numbers (1-65535), not {ports!r}")
    return sorted(set(ports))


def egress_rules(cfg, lan_iface, lan_cidr, pi_ip, iot_ips):
    """The forward-chain lines for the egress policy (see EGRESS_TCP and IOT_TCP)."""
    pad, out = "        ", []
    to_net = f'iifname "{lan_iface}" ip daddr != {lan_cidr}'
    for key, default in (("egress_block_tcp", EGRESS_TCP), ("egress_block_udp", EGRESS_UDP),
                         ("iot_allowed_tcp", IOT_TCP), ("iot_allowed_udp", IOT_UDP)):
        _ports(cfg, key, default)          # a typo fails here even while that part is off
    if cfg.get("egress_block", True):
        for proto, key, default in (("tcp", "egress_block_tcp", EGRESS_TCP), ("udp", "egress_block_udp", EGRESS_UDP)):
            ports = _ports(cfg, key, default)
            if ports:
                out.append(f"{pad}{to_net} {proto} dport {{ {', '.join(map(str, ports))} }} counter drop")
    mode = cfg.get("iot_egress_lock", "off")
    if mode not in ("off", "log", "on"):
        raise GenError(f'iot_egress_lock must be "off", "log" or "on", not {mode!r}')
    if mode != "off" and iot_ips:
        verdict = "counter drop" if mode == "on" else 'limit rate 6/minute log prefix "ghostwall iot-egress: " counter'
        base = f"{to_net} ip saddr @iot_dev ip daddr != {pi_ip} ip daddr != 100.64.0.0/10"
        for proto, key, default in (("tcp", "iot_allowed_tcp", IOT_TCP), ("udp", "iot_allowed_udp", IOT_UDP)):
            ports = _ports(cfg, key, default)
            out.append(f"{pad}{base} meta l4proto {proto} {proto} dport != {{ {', '.join(map(str, ports))} }} {verdict}")
        out.append(f"{pad}{base} meta l4proto != {{ tcp, udp }} {verdict}")
    return "\n".join(out) if out else f"{pad}# (egress policy off)"


def _elements(ips):
    return ",\n".join(f"            {ip}" for ip in ips)


def input_rules(cfg, lan_iface, lan_cidr):
    """Accept rules for this box's own web interfaces, and the input chain's policy."""
    policy = cfg.get("input_policy", "accept")
    if policy not in ("accept", "drop"):
        raise GenError(f'input_policy must be "accept" or "drop", not {policy!r}')
    ports = cfg.get("lan_services_tcp", [3000, 8088])
    if not isinstance(ports, list) or not all(isinstance(p, int) and not isinstance(p, bool)
                                              and 1 <= p <= 65535 for p in ports):
        raise GenError("lan_services_tcp must be a list of port numbers, e.g. [3000, 8088]")
    lines = []
    if ports:
        plist = ", ".join(str(p) for p in sorted(set(ports)))
        lines.append(f'        iifname "{lan_iface}" ip saddr {lan_cidr} tcp dport {{ {plist} }} accept')
        lines.append(f'        iifname "tailscale0" tcp dport {{ {plist} }} accept')
    return policy, "\n".join(lines)


def antispoof(cfg, lan_iface):
    """("named device addresses" set, "address . MAC" set, rule). antispoof "log" or "on": a
    packet from the LAN that carries a named device's address but not that device's MAC is
    logged or dropped, so another device cannot borrow its identity (and with it its
    profile, its allowances or its clean record) by taking its address. A cloned MAC is
    not caught: nothing on the network can tell that apart."""
    mode = cfg.get("antispoof", "off")
    if mode not in ("off", "log", "on"):
        raise GenError(f'antispoof must be "off", "log" or "on", not {mode!r}')
    pairs = cfg.get("_ip_mac") or []
    for ip, mac in pairs:           # these end up inside firewall rules: parse them again
        ipaddress.IPv4Address(ip)
        if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            raise GenError(f"{mac!r} is not a MAC address")
    ips = f"        elements = {{ {', '.join(ip for ip, _ in pairs)} }}" if pairs else ""
    macs = f"        elements = {{ {', '.join(f'{ip} . {mac}' for ip, mac in pairs)} }}" if pairs else ""
    rule = ""
    if mode != "off" and pairs:
        match = f'iifname "{lan_iface}" ip saddr @named_dev ip saddr . ether saddr != @named_mac'
        rule = (f'        {match} limit rate 6/minute log prefix "ghostwall antispoof: "\n'
                + (f"        {match} counter drop\n" if mode == "on" else ""))
    return ips, macs, rule.rstrip("\n")


def render(name, ctx):
    text = (HERE / "templates" / name).read_text(encoding="utf-8")
    for k, v in ctx.items():
        text = text.replace("{{ " + k + " }}", v)
    return text

def main(argv=None):
    ap = argparse.ArgumentParser(description="render netconf template files")
    ap.add_argument("--devices", help="devices JSON (default: devices.json, else devices.example.json)")
    ap.add_argument("--out", help="output directory (default: ./out)")
    ap.add_argument("--config", help="network settings (default: config.json next to gen.py)")
    args = ap.parse_args(argv)
    out_dir = Path(args.out) if args.out else OUT

    cfg, static_leases, iot_ips = load_ctx(args.devices, args.config)
    lan_iface = str(cfg.get("lan_iface", "eth0"))
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", lan_iface):   # it ends up inside firewall rules
        raise SystemExit(f"lan_iface {lan_iface!r} is not an interface name")
    v4, v6 = doh_ips()
    in_policy, in_rules = input_rules(cfg, lan_iface, cfg["lan_cidr"])
    named_ips, named_macs, spoof_rule = antispoof(cfg, lan_iface)
    ctx = {
        "named_dev_elements": named_ips,
        "named_mac_elements": named_macs,
        "antispoof_rule": spoof_rule,
        "input_policy": in_policy,
        "input_rules": in_rules,
        "lan_iface": lan_iface,
        "pi_ip": cfg["pi_ip"],
        "lan_cidr": cfg["lan_cidr"],
        "dhcp_start": cfg["dhcp_start"],
        "dhcp_end": cfg["dhcp_end"],
        "default_lease_time": cfg["default_lease_time"],
        "static_leases": static_leases,
        "lease_log_file": cfg["lease_log_file"],
        "doh_ip4_elements": _elements(v4),
        "iot_dev_elements": (f"        elements = {{ {', '.join(iot_ips)} }}" if iot_ips else ""),
        "egress_rules": egress_rules(cfg, lan_iface, cfg["lan_cidr"], cfg["pi_ip"], iot_ips),
        "doh_ip6_elements": _elements(v6),
    }
    if out_dir.exists():
        # Don't rmtree: on Windows the out/ dir may be open (explorer/cwd)
        # and that aborts generation; just overwrite files in place.
        for p in out_dir.iterdir():
            try:
                p.unlink()
            except IsADirectoryError:
                shutil.rmtree(p, ignore_errors=True)
    else:
        out_dir.mkdir(parents=True)
    for src, dst in TEMPLATES:
        text = render(src, ctx)
        p = out_dir / dst
        p.write_text(text, encoding="utf-8", newline="\n")
        if dst.endswith(".sh"):
            p.chmod(0o755)
        print(f"wrote {p}")
    print("done.")

if __name__ == "__main__":
    try:
        sys.exit(main())
    except GenError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
