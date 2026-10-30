"""Config, paths, devices JSON loading, tmpfs check for capture_mgr."""
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULTS = {
    "devices_json": os.path.join(HERE, "devices.json"),
    "ring_dir": "/run/ghostwall/cap",
    "incidents_dir": "/var/lib/ghostwall/incidents",
    # ring buffer: ~5 min per device, total ~256 MB
    "ring_seconds": 30,          # -G rotation interval
    "ring_keep_minutes": 5,      # how much history the ring holds
    "total_ring_mb": 256,        # total cap across devices
    "freeze_extra_minutes": 5,   # keep capturing after a freeze trigger
    "retention_mb": 2048,        # incidents retention cap
    "http_host": "127.0.0.1",
    "http_port": 5381,
    "snaplen": 128,
    "interface": "eth0",
    "max_devices": 32,           # bound the process count
    "tcpdump": "tcpdump",
    "mergecap": "mergecap",      # found via PATH, optional
}


def load_config(argv_overrides: dict) -> dict:
    cfg = dict(DEFAULTS)
    path = os.path.join(HERE, "capture_conf.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    cfg.update({k: v for k, v in argv_overrides.items() if v is not None})
    return cfg


def load_devices(path: str, max_devices: int) -> list:
    """devices JSON: list of {name, ip[, mac, profile]}."""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    devices = []
    seen_names, seen_ips = set(), set()
    for d in raw:
        name = str(d.get("name", "")).strip()
        ip = str(d.get("ip", "")).strip()
        if not name or not ip:
            raise ValueError("device entry missing name or ip: %r" % (d,))
        if name in seen_names or ip in seen_ips:
            raise ValueError("duplicate device name or ip: %s/%s" % (name, ip))
        if "/" in ip or " " in ip or ";" in ip:
            raise ValueError("suspicious ip value: %r" % (ip,))
        seen_names.add(name)
        seen_ips.add(ip)
        devices.append({"name": name, "ip": ip,
                        "mac": d.get("mac"), "profile": d.get("profile")})
    if not devices:
        raise ValueError("devices JSON is empty")
    if len(devices) > max_devices:
        raise ValueError("too many devices (%d > max %d)" % (len(devices), max_devices))
    return devices


def is_tmpfs(path: str) -> bool:
    """True if path is on tmpfs. On non-Linux (Windows dev) returns True so
    tests can run; real enforcement happens on the Pi."""
    if sys.platform == "win32":
        return True
    try:
        out = subprocess.run(["stat", "-f", "-c", "%T", path],
                             capture_output=True, text=True, timeout=5)
        return out.returncode == 0 and out.stdout.strip() == "tmpfs"
    except (OSError, subprocess.TimeoutExpired):
        return False


def check_ring_dir(cfg: dict, allow_nontmpfs: bool) -> None:
    rd = cfg["ring_dir"]
    if not os.path.isdir(rd):
        raise SystemExit("ring directory %s does not exist (mount tmpfs there)" % rd)
    if not is_tmpfs(rd) and not allow_nontmpfs:
        raise SystemExit(
            "refusing to start: %s is not on tmpfs (use --allow-nontmpfs to override)"
            % rd)


def per_device_files(cfg: dict, n_devices: int) -> int:
    """tcpdump -W count so each device's ring covers ring_keep_minutes."""
    return max(2, int(cfg["ring_keep_minutes"] * 60 / cfg["ring_seconds"]))


def ring_usage(ring_dir: str, safe_name: str) -> dict:
    """Per-device ring usage: file count + bytes for a device prefix."""
    d = os.path.join(ring_dir, safe_name)
    files, total = [], 0
    if os.path.isdir(d):
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if os.path.isfile(p):
                files.append(p)
                try:
                    total += os.path.getsize(p)
                except OSError:
                    pass
    return {"dir": d, "files": files, "bytes": total}
