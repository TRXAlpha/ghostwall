"""Device map: IP <-> friendly name <-> MAC <-> profile.

Accepts either the netconf devices.json shape ({"devices": [...], "_pending":
[...]}) or a bare list (the capture devices format). Only active devices (with
an IP) are indexed. Unknown clients fall back to their IP string as the name so
events are still emitted.
"""
from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class Device:
    name: str
    ip: str
    mac: str | None = None
    profile: str = "normal"


class DeviceMap:
    def __init__(self, devices: list[Device]):
        self._by_ip: dict[str, Device] = {}
        self._by_name: dict[str, Device] = {}
        for d in devices:
            if d.ip:
                self._by_ip[d.ip] = d
            if d.name:
                self._by_name[d.name] = d

    @classmethod
    def from_json(cls, raw) -> "DeviceMap":
        if isinstance(raw, dict):
            # Named-but-unleased devices live in "_pending" (no MAC yet). They are
            # indexed too, so events show their name; gen.py still makes no lease.
            raw = list(raw.get("devices", [])) + list(raw.get("_pending", []))
        devices = []
        for d in raw:
            ip = str(d.get("ip", "")).strip()
            name = str(d.get("name", "")).strip()
            if not ip or not name:
                continue  # entries need both a name and an address
            devices.append(Device(
                name=name, ip=ip,
                mac=(d.get("mac") or None),
                profile=str(d.get("profile") or "normal"),
            ))
        return cls(devices)

    @classmethod
    def load(cls, path: str) -> "DeviceMap":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_json(json.load(f))

    def device_for_ip(self, ip: str) -> Device:
        d = self._by_ip.get(ip)
        if d is not None:
            return d
        # Unknown client: synthesise a device named after its IP.
        return Device(name=ip, ip=ip, mac=None, profile="normal")

    def device_for_name(self, name: str) -> Device | None:
        return self._by_name.get(name)

    def names(self) -> list[str]:
        return list(self._by_name.keys())

    def all(self) -> list[Device]:
        return list(self._by_ip.values())
