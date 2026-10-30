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


def load_ctx(dev_path=None):
    cfg = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
    dev = json.loads(resolve_devices_path(dev_path).read_text(encoding="utf-8"))
    pi_ip = cfg["pi_ip"]
    seen_macs, seen_ips = set(), set()

    static_lines = []
    for d in dev.get("devices", []):
        validate_device(d, seen_macs, seen_ips, pi_ip)
        mac = d["mac"].lower().replace("-", ":")
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
    return cfg, "\n".join(static_lines) + ("\n" if static_lines else "")

TEMPLATES = [
    ("dnsmasq.conf.j2", "dnsmasq.conf"),
    ("sysctl.d-99-ghostwall.conf.j2", "99-ghostwall.conf"),
    ("nftables-ghostwall.conf.j2", "ghostwall.nft"),
    ("breakglass.sh.j2", "breakglass.sh"),
    ("health.sh.j2", "health.sh"),
]

def render(name, ctx):
    text = (HERE / "templates" / name).read_text(encoding="utf-8")
    for k, v in ctx.items():
        text = text.replace("{{ " + k + " }}", v)
    return text

def main(argv=None):
    ap = argparse.ArgumentParser(description="render netconf template files")
    ap.add_argument("--devices", help="devices JSON (default: devices.json, else devices.example.json)")
    ap.add_argument("--out", help="output directory (default: ./out)")
    args = ap.parse_args(argv)
    out_dir = Path(args.out) if args.out else OUT

    cfg, static_leases = load_ctx(args.devices)
    ctx = {
        "pi_ip": cfg["pi_ip"],
        "lan_cidr": cfg["lan_cidr"],
        "dhcp_start": cfg["dhcp_start"],
        "dhcp_end": cfg["dhcp_end"],
        "default_lease_time": cfg["default_lease_time"],
        "static_leases": static_leases,
        "lease_log_file": cfg["lease_log_file"],
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
