import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class EnforcementResult:
    ok: bool
    message: str


def _run_powershell(command: str) -> EnforcementResult:
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return EnforcementResult(False, (result.stderr or result.stdout).strip())
    return EnforcementResult(True, result.stdout.strip())


def _rule_name(rule_prefix: str, program_path: str) -> str:
    digest = hashlib.sha256(program_path.encode("utf-8")).hexdigest()[:12]
    return f"{rule_prefix} {digest}"


def ensure_firewall_block(program_path: str, rule_prefix: str) -> EnforcementResult:
    if not program_path:
        return EnforcementResult(False, "No program path provided")
    rule_name = _rule_name(rule_prefix, program_path)
    escaped_path = program_path.replace('"', '""')
    command = (
        f"if (-not (Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue)) "
        f"{{ New-NetFirewallRule -DisplayName '{rule_name}' -Direction Outbound -Action Block -Program '{escaped_path}' -Profile Any | Out-Null; "
        f"New-NetFirewallRule -DisplayName '{rule_name} (Inbound)' -Direction Inbound -Action Block -Program '{escaped_path}' -Profile Any | Out-Null }}"
    )
    return _run_powershell(command)


def _find_defender_mpcmdrun() -> str | None:
    if shutil.which("MpCmdRun.exe"):
        return shutil.which("MpCmdRun.exe")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    candidates = [
        os.path.join(program_files, "Windows Defender", "MpCmdRun.exe"),
    ]
    program_data = os.environ.get("ProgramData")
    if program_data:
        platform_root = Path(program_data) / "Microsoft" / "Windows Defender" / "Platform"
        if platform_root.exists():
            for child in sorted(platform_root.iterdir(), reverse=True):
                candidate = child / "MpCmdRun.exe"
                if candidate.exists():
                    candidates.append(str(candidate))
                    break
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def defender_scan_file(path: str, mp_cmd_path: str | None = None) -> EnforcementResult:
    mp_cmd = mp_cmd_path or _find_defender_mpcmdrun()
    if not mp_cmd:
        return EnforcementResult(False, "MpCmdRun.exe not found")
    result = subprocess.run(
        [mp_cmd, "-Scan", "-ScanType", "3", "-File", path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return EnforcementResult(False, (result.stderr or result.stdout).strip())
    return EnforcementResult(True, result.stdout.strip())


def update_hosts_blocklist(domains: list[str], hosts_path: str) -> EnforcementResult:
    if not domains:
        return EnforcementResult(True, "No domains provided")
    marker_begin = "# AI_FIREWALL_TRM BEGIN"
    marker_end = "# AI_FIREWALL_TRM END"
    path = Path(hosts_path)
    content = path.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()
    start = None
    end = None
    for idx, line in enumerate(lines):
        if line.strip() == marker_begin:
            start = idx
        if line.strip() == marker_end:
            end = idx
            break
    block_lines = [marker_begin]
    for domain in sorted(set(domains)):
        block_lines.append(f"0.0.0.0 {domain}")
        block_lines.append(f":: {domain}")
    block_lines.append(marker_end)
    if start is not None and end is not None and end > start:
        new_lines = lines[:start] + block_lines + lines[end + 1 :]
    else:
        new_lines = lines + [""] + block_lines
    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return EnforcementResult(True, "Hosts updated")
