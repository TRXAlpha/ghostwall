"""Freeze + incidents: copy ring files, wait, merge, write metadata, retention."""
import json
import os
import shutil
import time

from pcapmerge import merge_pcaps
from ring import safe_name


def recent_ring_files(ring_dir: str, device: str, max_files: int) -> list:
    """The ring files currently in the device dir (newest last by mtime)."""
    d = os.path.join(ring_dir, safe_name(device))
    if not os.path.isdir(d):
        return []
    paths = []
    for fn in os.listdir(d):
        p = os.path.join(d, fn)
        if os.path.isfile(p):
            try:
                st = os.stat(p)
            except OSError:
                continue
            paths.append((st.st_mtime, p))
    paths.sort()
    return [p for _, p in paths][-max_files:] if max_files else [p for _, p in paths]


def enforce_retention(incidents_dir: str, retention_mb: float) -> list:
    """Delete oldest incident dirs until total <= cap. Only inside incidents_dir."""
    if not os.path.isdir(incidents_dir):
        return []
    entries = []
    total = 0
    for name in os.listdir(incidents_dir):
        d = os.path.join(incidents_dir, name)
        if not os.path.isdir(d):
            continue
        size = 0
        for root, _dirs, files in os.walk(d):
            for fn in files:
                try:
                    size += os.path.getsize(os.path.join(root, fn))
                except OSError:
                    pass
        entries.append((os.path.getmtime(d), d, size))
        total += size
    cap = retention_mb * 1024 * 1024
    deleted = []
    for mtime, d, size in sorted(entries):
        if total <= cap:
            break
        shutil.rmtree(d, ignore_errors=True)
        total -= size
        deleted.append(d)
    return deleted


def write_dns_history(path: str, dns_history) -> None:
    """dns_history: list of records or a dict; stored as-is under 'queries'."""
    payload = {
        "queries": dns_history if dns_history is not None else [],
        "written_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def freeze_incident(cfg: dict, device: str, event_id: str, dns_history,
                    ring_manager, logger=print) -> dict:
    """Freeze flow: snapshot ring now, keep capturing freeze_extra_minutes,
    then copy the second half, merge everything into one pcap, write metadata.
    Blocking: takes freeze_extra_minutes on the Pi; tests pass a stubbed
    ring_manager/short wait."""
    import re
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", event_id):
        raise ValueError("event_id must match [A-Za-z0-9_-]{1,64}")
    inc_dir = os.path.join(cfg["incidents_dir"], event_id)
    os.makedirs(inc_dir, exist_ok=True)

    # phase 1: copy current ring contents (the last ~5 minutes)
    snapshot_ts = time.time()
    first_half = os.path.join(inc_dir, "part1")
    os.makedirs(first_half, exist_ok=True)
    n1 = _copy_ring(cfg, device, first_half, ring_manager)
    logger("freeze %s: copied %d ring files (past %d min)" %
           (event_id, n1, cfg["ring_keep_minutes"]))

    # phase 2: keep capturing for freeze_extra_minutes
    wait_s = cfg["freeze_extra_minutes"] * 60
    logger("freeze %s: continuing capture for %d min" %
           (event_id, cfg["freeze_extra_minutes"]))
    time.sleep(wait_s)

    # copy what accumulated during the wait
    second_half = os.path.join(inc_dir, "part2")
    os.makedirs(second_half, exist_ok=True)
    n2 = _copy_ring(cfg, device, second_half, ring_manager, since=snapshot_ts)
    logger("freeze %s: copied %d more ring files" % (event_id, n2))

    paths = [os.path.join(first_half, f) for f in sorted(os.listdir(first_half))] \
        if os.path.isdir(first_half) else []
    paths += [os.path.join(second_half, f) for f in sorted(os.listdir(second_half))] \
        if os.path.isdir(second_half) else []
    out_pcap = os.path.join(inc_dir, "%s.pcap" % event_id)
    method = merge_pcaps(paths, out_pcap, cfg.get("mergecap", ""))

    meta = {
        "event_id": event_id,
        "device": device,
        "ip": (ring_manager.device_ip(device) if ring_manager else None),
        "pcap": out_pcap,
        "merge_method": method,
        "part1_files": n1,
        "part2_files": n2,
        "frozen_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(inc_dir, "incident.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    write_dns_history(os.path.join(inc_dir, "dns_history.json"), dns_history)
    shutil.rmtree(first_half, ignore_errors=True)
    shutil.rmtree(second_half, ignore_errors=True)

    deleted = enforce_retention(cfg["incidents_dir"], cfg["retention_mb"])
    if deleted:
        logger("retention: deleted %d old incidents" % len(deleted))
    meta["deleted_for_retention"] = len(deleted)
    return meta


def _copy_ring(cfg: dict, device: str, dest: str, ring_manager,
               since: float = 0.0) -> int:
    """Copy the device's ring files into dest.

    - 'since': only copy files with mtime >= since (used for the post-wait
      pass so already-copied files are not merged twice).
    - Skips the newest file if it is actively being written (mtime within one
      ring interval of now): tcpdump holds it open and it may be partial.
    Returns the number of files copied."""
    src = os.path.join(cfg["ring_dir"], safe_name(device))
    if not os.path.isdir(src):
        return 0
    files = [os.path.join(src, fn) for fn in os.listdir(src)]
    files = [f for f in files if os.path.isfile(f)]
    files.sort(key=lambda p: (os.stat(p).st_mtime, p))
    if since > 0:
        files = [f for f in files
                 if os.stat(f).st_mtime > since]
    # Skip the newest file only if it is actively being written (mtime within
    # one ring interval of now): tcpdump holds it open and it may be partial.
    if ring_manager is not None and files:
        newest_age = time.time() - os.stat(files[-1]).st_mtime
        if newest_age < cfg.get("ring_seconds", 30) and len(files) > 1:
            files = files[:-1]
    n = 0
    for p in files:
        dst = os.path.join(dest, os.path.basename(p))
        try:
            shutil.copyfile(p, dst)
            n += 1
        except OSError:
            pass
    return n
