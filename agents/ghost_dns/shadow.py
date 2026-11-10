"""Shadow mode: score the queries AdGuard Home or Pi-hole already answered.

The firewall stays OUT of the DNS path. The DNS server keeps port 53, so if
anything in Ghostwall crashes or misbehaves, DNS is untouched. This follower
tails the DNS server's query log and feeds each query to the same
Resolver.decide() policy, so events, the dashboard and Telegram alerts work
exactly as in inline mode.

Two log formats:
  - AdGuard Home querylog.json: one JSON object per line. AdGuard buffers
    `querylog.size_memory` entries (1000 by default) before writing, so
    go_shadow.sh lowers that; otherwise alerts can lag by hours.
  - Pi-hole pihole.log (dnsmasq/FTL): one text line per event, written at once.

Nothing can be blocked, which is the point: this is the safe way to prove the
models and the allowlist before ever going inline.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sys
import threading
import time
from datetime import datetime

import dnsmsg

# AdGuard's Result.Reason values that mean the answer came from the upstream server:
# 0 not filtered, 1 allowed by a rule, 2 filtering error. Every other reason is
# AdGuard's own answer (3-8 blocked, 9-11 rewritten: a `$dnsrewrite=NXDOMAIN` rule or
# a hosts entry), whose rcode says nothing about whether a domain is registered.
_ADGUARD_UPSTREAM_REASONS = (None, 0, 1, 2)


def adguard_rcode(j: dict, host: str, blocked: bool, no_soa_filters: bool = False) -> tuple[str | None, str | None]:
    """(rcode, SOA zone of a negative answer) from an AdGuard entry's `Answer` (base64 of
    the reply message). (None, None) when unknown: no Answer, garbled, a reply to some
    other name, or an answer AdGuard made itself (a block in "NXDOMAIN" blocking mode
    must never count as an unregistered domain). ("FILTERED", None) when the upstream
    resolver (Quad9, Cloudflare security) blocked the name itself: dnsmsg.filtered_by_upstream."""
    res = j.get("Result")
    if blocked or (isinstance(res, dict) and res.get("Reason") not in _ADGUARD_UPSTREAM_REASONS):
        return None, None
    ans = j.get("Answer")
    if not isinstance(ans, str) or not ans:
        return None, None
    try:
        msg = base64.b64decode(ans, validate=True)
    except (ValueError, binascii.Error):
        return None, None
    q = dnsmsg.parse_question(msg)
    rcode = dnsmsg.reply_status(msg)
    if q is None or rcode is None or q.name != host:
        return None, None
    if dnsmsg.filtered_by_upstream(msg, no_soa_filters):
        return "FILTERED", None
    return rcode, (dnsmsg.negative_zone(msg) if rcode == "NXDOMAIN" else None)


def adguard_answer_ips(line: str) -> tuple[str, list[str]] | None:
    """(name, addresses) of an upstream answer in one AdGuard query log line; None for a
    blocked or rewritten one, or a line without an answer."""
    try:
        j = json.loads(line)
    except ValueError:
        return None
    if not isinstance(j, dict):
        return None
    res = j.get("Result")
    if isinstance(res, dict) and (res.get("IsFiltered") or res.get("Reason") not in _ADGUARD_UPSTREAM_REASONS):
        return None
    ans, host = j.get("Answer"), str(j.get("QH") or "").rstrip(".").lower()
    if not host or not isinstance(ans, str) or not ans:
        return None
    try:
        ips = dnsmsg.extract_answer_ips(base64.b64decode(ans, validate=True))
    except (ValueError, binascii.Error):
        return None
    return (host, ips) if ips else None


# AdGuard writes up to 9 fraction digits ("...:08.12345+02:00", trailing zeros dropped);
# Python 3.10's fromisoformat wants exactly 3 or 6
_FRAC = re.compile(r"\.(\d+)")


def parse_time(s) -> float | None:
    """An AdGuard `T` value (RFC 3339) -> Unix time, or None."""
    try:
        s = _FRAC.sub(lambda m: "." + (m[1] + "00000")[:6], str(s).replace("Z", "+00:00"), count=1)
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return None


def parse_adguard_entry(line: str, no_soa_filters: bool = False):
    """AdGuard querylog line -> (client_ip, host, qtype, blocked_by_adguard, rcode, nx_zone)
    or None. AdGuard marks what it blocked with Result.IsFiltered (rewrites don't set it);
    rcode and nx_zone are None when unknown (see adguard_rcode)."""
    e = parse_adguard_timed(line, no_soa_filters)
    return e[0] if e else None


def parse_adguard_timed(line: str, no_soa_filters: bool = False):
    """AdGuard querylog line -> (parse_adguard_entry's tuple, Unix time of the query or
    None), or None. One JSON parse for both."""
    try:
        j = json.loads(line)
    except ValueError:
        return None
    if not isinstance(j, dict):
        return None
    host = j.get("QH")
    ip = j.get("IP")
    if not host or not ip:
        return None
    res = j.get("Result")
    blocked = isinstance(res, dict) and res.get("IsFiltered") is True
    host = str(host).rstrip(".").lower()
    entry = (str(ip), host, str(j.get("QT") or "A"), blocked) + adguard_rcode(j, host, blocked, no_soa_filters)
    return entry, parse_time(j.get("T"))


def parse_adguard_line(line: str):
    """AdGuard querylog line -> (client_ip, host, qtype) or None."""
    e = parse_adguard_entry(line)
    return e[:3] if e else None


parse_line = parse_adguard_line  # older name, used by replay_querylog and tests

# `Oct 31 12:00:00 dnsmasq[123]: query[A] example.com from 192.168.1.10`, and the
# log-queries=extra form with a serial and client/port before `query`. Anchored after
# the `<process>[pid]:` tag and at the end of the line: the name is whatever a device
# asked for, so a crafted one must not be able to name a different client.
_PIHOLE_QUERY = re.compile(r"\]:\s+(?:\d+\s+\S+\s+)?query\[(?P<qt>[A-Za-z0-9]+)\]\s+"
                           r"(?P<host>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)\s*$")


def parse_pihole_line(line: str):
    """Pi-hole log line -> (client_ip, host, qtype) or None (replies, forwards, blocks)."""
    m = _PIHOLE_QUERY.search(line)
    if not m:
        return None
    return m["ip"], m["host"].rstrip(".").lower(), m["qt"].upper()


# Pi-hole logs its own block on the line after the query, e.g.
#   dnsmasq[812]: gravity blocked ads.example.com is 0.0.0.0   (v6: "... denied")
_PIHOLE_BLOCKED = re.compile(r"\]:\s+(?:\d+\s+\S+\s+)?(?:gravity blocked|exactly blacklisted|regex blacklisted|"
                             r"exactly denied|regex denied|gravity denied)\s+(?P<host>\S+)\s+is\s")


def pihole_blocked_host(line: str) -> str | None:
    m = _PIHOLE_BLOCKED.search(line)
    return m["host"].rstrip(".").lower() if m else None


# The upstream's answer, also on a later line: `reply some.name is NXDOMAIN`, or `cached`
# when dnsmasq answers from an earlier upstream reply. `config` (local=/lan/ and other
# local rules), `/etc/hosts`, `special domain` and the blocked forms above are the DNS
# server's own answers, and are not matched.
_PIHOLE_REPLY = re.compile(r"\]:\s+(?:\d+\s+\S+\s+)?(?:reply|cached|cached-stale)\s+(?P<host>\S+)\s+is\s+"
                           r"(?P<what>\S+)\s*$")
_ADDRESS = re.compile(r"^(?:[0-9.]+|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)$")


def pihole_reply(line: str) -> tuple[str, str] | None:
    """Pi-hole reply line -> (host, rcode) or None. An address or `<CNAME>` is NOERROR
    (the name exists); NODATA is "NODATA", which proves nothing either way."""
    m = _PIHOLE_REPLY.search(line)
    if not m:
        return None
    what = m["what"]
    if what in ("0.0.0.0", "::"):
        rcode = "FILTERED"   # a protective upstream's block (Pi-hole's own are logged as blocked)
    elif what == "NXDOMAIN":
        rcode = "NXDOMAIN"
    elif what in ("SERVFAIL", "REFUSED"):
        rcode = what
    elif what.startswith("NODATA"):
        rcode = "NODATA"
    elif what.startswith("<") or _ADDRESS.match(what):
        rcode = "NOERROR"
    else:
        return None
    return m["host"].rstrip(".").lower(), rcode


PARSERS = {"adguard": parse_adguard_line, "pihole": parse_pihole_line}
# with "was it already blocked by the DNS server", rcode and nx_zone (Pi-hole logs the
# first two on later lines; it never logs the SOA)
ENTRY_PARSERS = {"adguard": parse_adguard_entry,
                 "pihole": lambda line: (lambda p: p + (False, None, None) if p else None)(parse_pihole_line(line))}
# the same, with the query's Unix time when the log has one (AdGuard). Pi-hole writes each
# line as it happens, so the time it is read is the time it was asked.
TIMED_PARSERS = {"adguard": parse_adguard_timed,
                 "pihole": lambda line: (lambda p: (p, None) if p else None)(ENTRY_PARSERS["pihole"](line))}


def detect_format(path: str) -> str:
    """'adguard' or 'pihole', from the first line of the log, else from its name."""
    try:
        with open(path, "rb") as f:
            for raw in f.read(8192).splitlines():
                line = raw.decode("utf-8", "replace").strip()
                if line.startswith("{"):
                    return "adguard"
                if "dnsmasq" in line or "query[" in line:
                    return "pihole"
    except OSError:
        pass
    return "adguard" if path.endswith(".json") or "pihole" not in path.lower() else "pihole"


class QueryLogFollower:
    """Tail a query log. Starts at the current end (no history replay)."""

    def __init__(self, resolver, path: str, poll_seconds: float = 2.0, fmt: str = "auto"):
        self.resolver = resolver
        self.path = path
        self.fmt = detect_format(path) if fmt in (None, "", "auto") else fmt
        if self.fmt not in PARSERS:
            raise ValueError(f"querylog_format must be adguard, pihole or auto, not {fmt!r}")
        self.parse = TIMED_PARSERS[self.fmt]
        if self.fmt == "adguard":
            # Quad9 answers a blocked name NXDOMAIN with no SOA (genuine NXDOMAINs have one)
            no_soa = str(getattr(resolver, "cfg", {}).get("protective_upstream") or "").lower() == "quad9"
            self.parse = lambda line: parse_adguard_timed(line, no_soa)
        # AdGuard writes its log in batches (querylog.size_memory queries at a time), so
        # on a quiet network queries asked a minute apart are read here together. The
        # timing rules get each query's own time, mapped onto the resolver's clock.
        self._last_when = None
        self.poll = poll_seconds
        # Pi-hole: queries waiting for their "blocked" or "reply" line, kept across polls
        # (the reply can land in the next one) for at most `hold` seconds.
        self._pending: list[list] = []
        self.hold = 3.0
        self.offset = os.path.getsize(path) if os.path.exists(path) else 0
        self._head = self._read_head()
        self._stop = threading.Event()
        self.seen = 0
        self.missing = False  # True while the querylog can't be seen; warned once per outage
        self.unreadable = False  # True while it exists but can't be opened (permissions)
        self.said_anonymized = False

    def _read_head(self) -> bytes:
        try:
            with open(self.path, "rb") as f:
                return f.read(64)
        except OSError:
            return b""

    def _rotated(self, size: int) -> bool:
        """The file was replaced/truncated. A size check alone misses a new file
        that has already grown past our old offset, so also compare its first bytes."""
        if size < self.offset:
            return True
        head = self._read_head()
        known = self._head
        if known and head[:len(known)] != known:
            return True
        if len(head) > len(known):
            self._head = head  # remember more of the header as the file grows
        return False

    def poll_once(self) -> int:
        """Process any new complete lines. Returns how many queries were scored."""
        if not os.path.exists(self.path):
            # A missing log means the firewall is blind (wrong path, or systemd ProtectHome
            # hiding it). Say so once instead of silently scoring nothing.
            if not self.missing:
                print(f"[ghost-dns:shadow] WARNING querylog not found: {self.path} -- nothing is being scored",
                      file=sys.stderr, flush=True)
                self.missing = True
            return 0
        if self.missing:
            print(f"[ghost-dns:shadow] querylog is back: {self.path}", file=sys.stderr, flush=True)
            self.missing = False
        size = os.path.getsize(self.path)
        done = 0
        if self._rotated(size):
            # AdGuard renames the log to .1, Pi-hole's logrotate copies it there and
            # truncates: either way the lines written since our last look are in .1 now.
            old = self.path + ".1"
            if self._head and self._head_of(old)[:len(self._head)] == self._head:
                done += self._read_from(old)
            self.offset = 0
            self._head = self._read_head()
        done += self._read_from(self.path, main=True)
        self.seen += done
        return done

    def _head_of(self, path: str) -> bytes:
        try:
            with open(path, "rb") as f:
                return f.read(64)
        except OSError:
            return b""

    def _read_from(self, path: str, main: bool = False) -> int:
        """Score the complete lines of `path` after self.offset (advancing it)."""
        done = 0
        pending = self._pending
        try:
            f = open(path, "rb")
        except OSError as exc:
            if main and not self.unreadable:   # blind, so say so (once), with the usual cause
                print(f"[ghost-dns:shadow] WARNING can't read {path} ({exc.strerror or exc}) -- nothing is "
                      "being scored. It belongs to the user your DNS server runs as; Docker: add "
                      "cap_add: [DAC_OVERRIDE] to the ghostwall service", file=sys.stderr, flush=True)
                self.unreadable = True
            return 0
        if main and self.unreadable:
            print(f"[ghost-dns:shadow] {path} is readable again", file=sys.stderr, flush=True)
            self.unreadable = False
        with f:
            f.seek(self.offset)
            for raw in f:
                if not raw.endswith(b"\n"):
                    break  # partial line: wait for the rest
                self.offset += len(raw)
                line = raw.decode("utf-8", "replace").strip()
                if self.fmt == "pihole":
                    host = pihole_blocked_host(line)
                    if host:
                        for q in pending:
                            if q[1] == host:
                                q[3] = True
                        continue
                    rep = pihole_reply(line)
                    if rep:
                        for q in pending:   # the oldest query of that name still waiting
                            if q[1] == rep[0] and q[4] is None:
                                q[4] = rep[1]
                                break
                        continue
                parsed = self.parse(line)
                if not parsed:
                    continue
                if self._want_ips():
                    got = adguard_answer_ips(line)
                    if got:
                        self.resolver.note_ips(*got)
                pending.append(list(parsed[0]) + [time.monotonic(), parsed[1]])
                if self.fmt != "pihole" or len(pending) > 64:
                    done += self._decide(pending.pop(0))
        # Pi-hole writes a query and its block in one go, and its reply right after:
        # decide what has its answer, or has waited long enough for one.
        now, keep = time.monotonic(), []
        for q in pending:
            if q[3] or q[4] is not None or now - q[6] >= self.hold:
                done += self._decide(q)
            else:
                keep.append(q)
        pending[:] = keep
        return done

    def _want_ips(self) -> bool:
        """contain with addresses, gateway mode, AdGuard's log (Pi-hole's has no full answers)."""
        ready = getattr(self.resolver, "_ip_block_ready", None)
        return self.fmt == "adguard" and ready is not None and ready()

    def _when(self, asked: float | None) -> float | None:
        """The query's time on the resolver's clock: now, minus how long ago it was asked
        (never in the future, never before the previous query). None if unknown."""
        if asked is None:
            return None
        when = self.resolver.clock() - max(0.0, time.time() - asked)
        if self._last_when is not None and when < self._last_when:
            when = self._last_when
        self._last_when = when
        return when

    def _decide(self, q) -> int:
        ip, host, qtype, blocked, rcode, zone = q[:6]
        if not self.said_anonymized and self.fmt == "adguard" and str(ip).endswith(".0") and str(ip).count(".") == 3:
            # AdGuard's "Anonymize client IP" zeroes the last part of every address:
            # each /24 of devices then looks like one device here.
            print(f"[ghost-dns:shadow] WARNING client {ip} ends in .0: AdGuard's 'Anonymize client IP' "
                  "looks on (dns.anonymize_client_ip), so every device looks like the same one. "
                  "Turn it off: Settings > General settings > Logs configuration", file=sys.stderr, flush=True)
            self.said_anonymized = True
        try:
            # the rcode only when there is a real upstream answer to report
            extra = {"rcode": rcode, "nx_zone": zone} if rcode and not blocked else {}
            when = self._when(q[7] if len(q) > 7 else None)
            if when is not None:
                extra["when"] = when
            self.resolver.decide(ip, host, qtype, upstream_blocked=blocked, **extra)
        except Exception as exc:  # noqa: BLE001 - never die on one bad line
            print(f"[ghost-dns:shadow] decide failed for {host}: {exc!r}", file=sys.stderr, flush=True)
        self.resolver.stats["queries"] += 1
        return 1

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except OSError as exc:
                print(f"[ghost-dns:shadow] read error: {exc}", file=sys.stderr, flush=True)
            time.sleep(self.poll)

    def stop(self) -> None:
        self._stop.set()
