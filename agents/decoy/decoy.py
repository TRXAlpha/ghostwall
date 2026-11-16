"""ghost-decoy: honeypot TCP ports on spare LAN addresses. Opt-in (decoy "on").

Nothing legitimate should connect to a decoy port, so a LAN device that connects
and sends data is probably scanning. The service writes one `decoy_touch` event
per device per port per dedupe window to the shared events.jsonl. It never sends
anything back.

A connection counts as a touch only when the peer is on the LAN, is not exempt,
and sends at least one byte within listen_seconds. A connection that sends nothing
is counted in the stats and writes no event.

    python decoy.py [--config decoy.json] [--check]

With "decoy": "off" (the default) the service exits 0 without binding anything.
A bad config is refused at start with exit 2 and a message that names the key.
"""
from __future__ import annotations

import argparse
import asyncio
import difflib
import ipaddress
import json
import os
import signal
import sys
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

HERE = os.path.dirname(os.path.abspath(__file__))
GHOST_DNS = os.path.join(os.path.dirname(HERE), "ghost_dns")
sys.path.insert(0, GHOST_DNS)  # events, devices, neighbours live with ghost-dns

from devices import DeviceMap          # noqa: E402
from events import EventLog, make_event  # noqa: E402
from neighbours import canonical_ip    # noqa: E402

RULE = "decoy_touch"
# 445 (SMB) is left out on purpose: Windows network browsing and printer discovery knock on
# it all day, so a touch there is not evidence of scanning. Add it only on a spare address.
DEFAULT_PORTS = (23, 2323, 3389, 5900)
MODES = ("off", "on")
MAX_PORTS = 32
MAX_EXEMPT = 64
MAX_NAME = 64
HOUR = 3600.0
PRUNE_AT = 4096  # bound the in-memory dedupe and rate tables

DEFAULTS = {
    "decoy": "off",
    "bind": "0.0.0.0",
    "ports": list(DEFAULT_PORTS),
    "listen_seconds": 5,           # how long to wait for the first byte
    "max_bytes": 512,              # hard cap on what is read from one connection
    "max_connections": 64,         # open connections at once, all ports
    "max_per_address": 4,          # open connections at once, one peer address
    "dedupe_seconds": 3600,        # one event per device per port per this window
    "max_events_per_device_hour": 6,
    "exempt": [],                  # device names or addresses that may touch decoys
    "stats_seconds": 3600,         # log a stats line this often (0: only at stop)
    "events_path": os.path.join(GHOST_DNS, "events.jsonl"),
    "devices_json": os.path.join(os.path.dirname(HERE), "netconf", "devices.json"),
}

# key: (low, high, whole number only)
_NUMBERS = {
    "listen_seconds": (0.5, 30, False),
    "max_bytes": (1, 4096, True),
    "max_connections": (1, 1024, True),
    "max_per_address": (1, 64, True),
    "dedupe_seconds": (1, 86400, True),
    "max_events_per_device_hour": (1, 1000, True),
    "stats_seconds": (0, 86400, True),
}


class ConfigError(ValueError):
    """The config file is refused. The message names the key and what it wants."""


class DecoyBindError(RuntimeError):
    """A decoy port could not be opened (in use, or the address is not ours)."""


@dataclass(frozen=True)
class Settings:
    on: bool
    bind: str
    ports: tuple
    listen_seconds: float
    max_bytes: int
    max_connections: int
    max_per_address: int
    dedupe_seconds: int
    max_events_per_device_hour: int
    exempt: tuple
    stats_seconds: int
    events_path: str
    devices_json: str


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _check_text_item(key: str, item) -> str:
    if not isinstance(item, str) or not (1 <= len(item) <= MAX_NAME):
        raise ConfigError(f"{key}: each entry must be text of 1 to {MAX_NAME} characters, not {item!r}")
    if item != item.strip() or any(ord(c) < 32 or ord(c) == 127 for c in item):
        raise ConfigError(f"{key}: {item!r} has spaces at the ends or control characters")
    return item


def parse_config(raw) -> Settings:
    """Validate a parsed config object. Keys starting with "_" are comments and are skipped."""
    if not isinstance(raw, dict):
        raise ConfigError('the config must be a JSON object, e.g. {"decoy": "on"}')
    for key in raw:
        if key.startswith("_"):
            continue
        if key not in DEFAULTS:
            near = difflib.get_close_matches(key, list(DEFAULTS), n=1)
            hint = f' (did you mean "{near[0]}"?)' if near else ""
            raise ConfigError(f'unknown key "{key}"{hint}')
    cfg = dict(DEFAULTS)
    cfg.update({k: v for k, v in raw.items() if not k.startswith("_")})

    if cfg["decoy"] not in MODES:
        raise ConfigError(f'decoy must be "off" or "on", not {cfg["decoy"]!r}')

    bind = cfg["bind"]
    try:
        if not isinstance(bind, str):
            raise ValueError
        ipaddress.ip_address(bind)
    except ValueError:
        raise ConfigError(
            f'bind must be an IP address, e.g. "192.168.1.250", not {bind!r}') from None
    if cfg["decoy"] == "on" and ipaddress.ip_address(bind).is_unspecified:
        # every address would include this box's real one, where ordinary devices talk to
        # real services: a decoy only means something on an address nothing else uses
        raise ConfigError(f'bind must be one spare LAN address that nothing else uses (e.g. '
                          f'"192.168.1.250"), not {bind!r}: a decoy on every address would catch normal traffic')

    ports = cfg["ports"]
    if not isinstance(ports, list) or not ports or len(ports) > MAX_PORTS:
        raise ConfigError(f"ports must be a list of 1 to {MAX_PORTS} port numbers, e.g. [23, 3389]")
    for p in ports:
        if not isinstance(p, int) or isinstance(p, bool) or not (1 <= p <= 65535):
            raise ConfigError(f"ports: {p!r} is not a port number from 1 to 65535")
    if len(set(ports)) != len(ports):
        raise ConfigError("ports: a port is listed twice")

    for key, (low, high, whole) in _NUMBERS.items():
        v = cfg[key]
        ok = _is_num(v) and low <= v <= high and (not whole or isinstance(v, int))
        if not ok:
            kind = "a whole number" if whole else "a number"
            raise ConfigError(f"{key} must be {kind} from {low} to {high}, not {v!r}")

    exempt = cfg["exempt"]
    if not isinstance(exempt, list) or len(exempt) > MAX_EXEMPT:
        raise ConfigError('exempt must be a list of device names or addresses, e.g. ["owner-scanner"]')
    exempt = tuple(_check_text_item("exempt", e) for e in exempt)

    for key in ("events_path", "devices_json"):
        v = cfg[key]
        if not isinstance(v, str) or not v.strip():
            raise ConfigError(f"{key} must be a file path")

    return Settings(
        on=cfg["decoy"] == "on",
        bind=bind,
        ports=tuple(ports),
        listen_seconds=float(cfg["listen_seconds"]),
        max_bytes=int(cfg["max_bytes"]),
        max_connections=int(cfg["max_connections"]),
        max_per_address=int(cfg["max_per_address"]),
        dedupe_seconds=int(cfg["dedupe_seconds"]),
        max_events_per_device_hour=int(cfg["max_events_per_device_hour"]),
        exempt=exempt,
        stats_seconds=int(cfg["stats_seconds"]),
        events_path=cfg["events_path"],
        devices_json=cfg["devices_json"],
    )


def load_config(path: str | None) -> Settings:
    """A missing file (or no path) means the defaults, which is decoy off."""
    if not path or not os.path.exists(path):
        return parse_config({})
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from None
    return parse_config(raw)


def _strip_scope(ip: str) -> str:
    return ip.split("%", 1)[0].strip()


def lan_peer(ip: str) -> bool:
    """True for a private-range peer (RFC 1918, IPv6 ULA and link-local), not loopback."""
    try:
        a = ipaddress.ip_address(_strip_scope(str(ip)))
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return bool(a.is_private) and not (a.is_loopback or a.is_unspecified)


class Decoy:
    """The listeners and the rules that decide what becomes an event.

    `ports` overrides settings.ports (tests pass 0 for an ephemeral port). `is_lan`
    and `clock` are injectable so tests can use 127.0.0.1 and a fake clock.
    """

    def __init__(self, settings: Settings, devices: DeviceMap, event_log: EventLog, *,
                 ports=None, is_lan: Callable[[str], bool] = lan_peer,
                 clock: Callable[[], float] = time.monotonic):
        self.s = settings
        self.devices = devices
        self.event_log = event_log
        self.ports = tuple(settings.ports if ports is None else ports)
        self.is_lan = is_lan
        self.clock = clock
        self.actual_ports: list[int] = []
        self.stats: dict[str, int] = {}
        self._exempt_names: set[str] = set()
        self._exempt_addrs: set[str] = set()
        for item in settings.exempt:
            try:
                self._exempt_addrs.add(canonical_ip(ipaddress.ip_address(item).compressed))
            except ValueError:
                self._exempt_names.add(item)
        self._servers: list = []
        self._tasks: set = set()
        self._active = 0
        self._per_addr: dict[str, int] = {}
        self._last_event: dict[tuple, float] = {}
        self._hourly: dict[str, deque] = {}

    # ----- lifecycle -------------------------------------------------------

    async def start(self) -> None:
        for port in self.ports:
            try:
                srv = await asyncio.start_server(self._handle, host=self.s.bind, port=port)
            except OSError as exc:
                await self.stop()
                raise DecoyBindError(
                    f"cannot listen on {self.s.bind} port {port}: {exc.strerror or exc}. "
                    "Another service may use that port, or the bind address is not on this box."
                ) from None
            self._servers.append(srv)
            self.actual_ports.append(srv.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        for srv in self._servers:
            srv.close()
        tasks = list(self._tasks)
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._servers = []

    def stats_line(self) -> str:
        return " ".join(f"{k}={v}" for k, v in sorted(self.stats.items()))

    @property
    def active(self) -> int:
        return self._active

    # ----- per connection --------------------------------------------------

    def _count(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n

    async def _handle(self, reader, writer) -> None:
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            await self._serve(reader, writer)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # bad input must never take the service down
            self._count("errors")
            print(f"[decoy] error on a connection: {type(exc).__name__}", flush=True)
        finally:
            self._tasks.discard(task)
            try:
                writer.close()
            except Exception:
                pass

    async def _serve(self, reader, writer) -> None:
        self._count("connections")
        peer = writer.get_extra_info("peername")
        local = writer.get_extra_info("sockname")
        if not peer or not local:
            self._count("bad_peer")
            return
        ip = _strip_scope(str(peer[0]))
        dst = _strip_scope(str(local[0]))
        port = int(local[1])

        if not self.is_lan(ip):
            self._count("not_lan")
            return
        device = self.devices.device_for_ip(ip)
        if self._is_exempt(ip, device.name):
            self._count("exempt")
            return
        if self._active >= self.s.max_connections:
            self._count("over_capacity")
            return
        if self._per_addr.get(ip, 0) >= self.s.max_per_address:
            self._count("per_address_limit")
            return

        self._active += 1
        self._per_addr[ip] = self._per_addr.get(ip, 0) + 1
        try:
            await self._read_and_record(reader, ip, device, port, dst)
        finally:
            self._active -= 1
            left = self._per_addr.get(ip, 1) - 1
            if left > 0:
                self._per_addr[ip] = left
            else:
                self._per_addr.pop(ip, None)

    async def _read_and_record(self, reader, ip: str, device, port: int, dst: str) -> None:
        try:
            # read() returns as soon as any bytes arrive; max_bytes bounds the memory used.
            data = await asyncio.wait_for(reader.read(self.s.max_bytes), timeout=self.s.listen_seconds)
        except asyncio.TimeoutError:
            data = b""
        except (ConnectionError, OSError):
            data = b""
        if not data:
            self._count("silent")
            return

        self._count("touched")
        self._count("bytes_seen", len(data))
        if not self._claim(device.name, port):
            return

        evt = make_event(
            device=device.name,
            domain=f"decoy-port-{port}.decoy.invalid",
            rule=RULE,
            action="recommend",
            severity="high",
            ip=ip,
            dst_ip=dst,
            reasons=[f"sent {len(data)} byte(s) to decoy port {port}; nothing legitimate uses it"],
        )
        try:
            await asyncio.to_thread(self.event_log.write, evt)
        except OSError as exc:
            self._count("write_errors")
            print(f"[decoy] could not write an event: {exc}", flush=True)
            return
        self._count("events")
        print(f"[decoy] touch: {device.name} ({ip}) on port {port}", flush=True)

    def _is_exempt(self, ip: str, name: str) -> bool:
        return canonical_ip(ip) in self._exempt_addrs or name in self._exempt_names

    def _claim(self, name: str, port: int) -> bool:
        """Reserve an event slot for this device and port, or count why not."""
        now = self.clock()
        key = (name, port)
        last = self._last_event.get(key)
        if last is not None and now - last < self.s.dedupe_seconds:
            self._count("deduped")
            return False
        q = self._hourly.setdefault(name, deque())
        while q and now - q[0] >= HOUR:
            q.popleft()
        if len(q) >= self.s.max_events_per_device_hour:
            self._count("rate_limited")
            return False
        q.append(now)
        self._last_event[key] = now
        self._prune(now)
        return True

    def _prune(self, now: float) -> None:
        if len(self._last_event) > PRUNE_AT:
            cutoff = now - self.s.dedupe_seconds
            self._last_event = {k: v for k, v in self._last_event.items() if v > cutoff}
        if len(self._hourly) > PRUNE_AT:
            self._hourly = {k: q for k, q in self._hourly.items() if q and now - q[-1] < HOUR}


async def run(decoy: Decoy) -> None:
    """Listen until SIGINT or SIGTERM, then close and log the final stats."""
    await decoy.start()
    print(f"[decoy] listening on {decoy.s.bind} ports {decoy.actual_ports}", flush=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError, ValueError):
            pass
    ticker = None
    if decoy.s.stats_seconds:
        ticker = asyncio.ensure_future(_tick(decoy))
    try:
        await stop.wait()
    finally:
        if ticker is not None:
            ticker.cancel()
        await decoy.stop()
        print(f"[decoy] stopped: {decoy.stats_line()}", flush=True)


async def _tick(decoy: Decoy) -> None:
    while True:
        await asyncio.sleep(decoy.s.stats_seconds)
        print(f"[decoy] stats: {decoy.stats_line()}", flush=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ghost-decoy: honeypot TCP ports (opt-in)")
    ap.add_argument("--config", help="JSON config (see decoy.example.json)")
    ap.add_argument("--check", action="store_true",
                    help="validate the config and exit; binds nothing")
    args = ap.parse_args(argv)

    if args.config and not os.path.exists(args.config):
        print(f"[decoy] no config at {args.config}: decoy stays off", flush=True)
        return 0
    try:
        settings = load_config(args.config)
    except ConfigError as exc:
        print(f"[decoy] config refused: {exc}", file=sys.stderr, flush=True)
        return 2
    if args.check:
        print("[decoy] config ok" + ("" if settings.on else " (decoy is off)"), flush=True)
        return 0
    if not settings.on:
        print('[decoy] off: set "decoy": "on" in the config to listen. Exiting.', flush=True)
        return 0

    try:
        devices = (DeviceMap.load(settings.devices_json)
                   if os.path.exists(settings.devices_json) else DeviceMap([]))
        event_log = EventLog(settings.events_path)
    except (OSError, ValueError) as exc:
        print(f"[decoy] config refused: cannot load devices or events: {exc}", file=sys.stderr, flush=True)
        return 2
    decoy = Decoy(settings, devices, event_log)
    print(f"[decoy] on: events->{settings.events_path}", flush=True)
    try:
        asyncio.run(run(decoy))
    except DecoyBindError as exc:
        print(f"[decoy] {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
