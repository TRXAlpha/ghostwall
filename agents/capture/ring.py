"""Ring buffer manager: one tcpdump per device, -G/-W rotation into tmpfs."""
import os
import re
import signal
import shutil
import subprocess
import time

from config import per_device_files, ring_usage  # noqa: F401 (per_device_files kept for callers)

_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def safe_name(name: str) -> str:
    s = _SAFE.sub("_", name)[:40] or "device"
    return s


class RingManager:
    """One tcpdump process per device writing pcap files into
    <ring_dir>/<safe_name>/ with -G seconds rotation and -W count files."""

    def __init__(self, cfg: dict, devices: list, tcpdump_cmd=None):
        self.cfg = cfg
        self.devices = devices
        self.tcpdump_cmd = tcpdump_cmd or cfg["tcpdump"]
        self.procs = {}          # name -> subprocess.Popen
        self.count = per_device_files(cfg, len(devices))

    def tcpdump_args(self, dev: dict, out_dir: str) -> list:
        """A new file every ring_seconds, named by time. No -W: with -G, tcpdump's -W
        means "exit after W files", not "wrap around" (that's -C), so capture would
        stop for good after one ring. Old files are deleted by prune() instead."""
        c = self.cfg
        return [
            self.tcpdump_cmd,
            "-i", c["interface"],
            "-s", str(c["snaplen"]),          # headers only
            "-U",                              # write each packet at once: a freeze sees the last seconds
            "-w", os.path.join(out_dir, "cap-%Y%m%d-%H%M%S.pcap"),
            "-G", str(c["ring_seconds"]),     # a new file every N seconds
            "-n",                              # no DNS lookups
            "src", "host", dev["ip"],
        ]

    def prune(self, now: float | None = None) -> int:
        """Keep each device's ring to ring_keep_minutes (plus the file being written)
        and to its share of total_ring_mb. Returns how many files were deleted."""
        now = time.time() if now is None else now
        keep_s = float(self.cfg.get("ring_keep_minutes", 5)) * 60 + float(self.cfg.get("ring_seconds", 30))
        cap = float(self.cfg.get("total_ring_mb", 256)) * 2**20 / max(1, len(self.devices))
        deleted = 0
        for dev in self.devices:
            d = os.path.join(self.cfg["ring_dir"], safe_name(dev["name"]))
            try:
                files = sorted((os.stat(os.path.join(d, f)).st_mtime, os.path.join(d, f))
                               for f in os.listdir(d) if f.endswith(".pcap"))
            except OSError:
                continue
            sizes = {p: os.path.getsize(p) for _, p in files}
            total = sum(sizes.values())
            for i, (mtime, p) in enumerate(files[:-1]):     # never the newest: tcpdump writes it
                if now - mtime > keep_s or total > cap:
                    try:
                        os.remove(p)
                        total -= sizes[p]
                        deleted += 1
                    except OSError:
                        pass
        return deleted

    def start_one(self, dev: dict) -> None:
        name = dev["name"]
        if name in self.procs and self.procs[name].poll() is None:
            return
        out_dir = os.path.join(self.cfg["ring_dir"], safe_name(name))
        os.makedirs(out_dir, exist_ok=True)
        argv = self.tcpdump_args(dev, out_dir)
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL)
        self.procs[name] = proc

    def start_all(self) -> int:
        started = 0
        for dev in self.devices:
            self.start_one(dev)
            started += 1
        return started

    def stop_all(self, timeout: float = 5.0) -> None:
        """Clean shutdown: SIGINT (tcpdump flushes its buffer on INT), then wait."""
        for name, proc in list(self.procs.items()):
            if proc.poll() is None:
                try:
                    if hasattr(signal, "CTRL_C_EVENT"):
                        proc.send_signal(signal.CTRL_C_EVENT)
                    else:
                        proc.send_signal(signal.SIGINT)
                except (OSError, ProcessLookupError):
                    pass
        deadline = time.monotonic() + timeout
        for proc in self.procs.values():
            try:
                proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                proc.kill()
        self.procs.clear()

    def alive(self, name: str) -> bool:
        p = self.procs.get(name)
        return p is not None and p.poll() is None

    def status(self) -> list:
        rows = []
        for dev in self.devices:
            u = ring_usage(self.cfg["ring_dir"], safe_name(dev["name"]))
            rows.append({
                "name": dev["name"], "ip": dev["ip"],
                "capturing": self.alive(dev["name"]),
                "ring_files": len(u["files"]),
                "ring_bytes": u["bytes"],
            })
        return rows

    @staticmethod
    def find_tcpdump() -> str:
        p = shutil.which("tcpdump")
        return p or "tcpdump"

    def device_ip(self, name: str):
        for d in self.devices:
            if d["name"] == name:
                return d["ip"]
        return None
