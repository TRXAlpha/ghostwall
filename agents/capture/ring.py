"""Ring buffer manager: one tcpdump per device, -G/-W rotation into tmpfs."""
import os
import re
import signal
import shutil
import subprocess
import time

from config import per_device_files, ring_usage

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
        c = self.cfg
        return [
            self.tcpdump_cmd,
            "-i", c["interface"],
            "-s", str(c["snaplen"]),          # headers only
            "-w", os.path.join(out_dir, "cap.pcap"),
            "-G", str(c["ring_seconds"]),     # rotate every N seconds
            "-W", str(self.count),            # wrap after count files
            "-n",                              # no DNS lookups
            "src", "host", dev["ip"],
        ]

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
