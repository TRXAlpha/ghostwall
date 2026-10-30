"""Parsing and replies for /fw commands. Stdlib only."""
from __future__ import annotations

from control_client import ControlClient, ControlError


def parse_command(text: str) -> tuple[str, list[str]]:
    """Return (subcommand, args) from '/fw ...' text, or ('', []) if not /fw."""
    parts = text.strip().split()
    if not parts or not parts[0].startswith("/fw"):
        return "", []
    # /fw@botname style
    if parts[0] not in ("/fw",) and not parts[0].split("@")[0] == "/fw":
        return "", []
    return (parts[1].lower() if len(parts) > 1 else "status"), parts[2:]


def _fmt_status(res: dict) -> str:
    if not res:
        return "fw: control API returned no data"
    lockdown = "ON" if res.get("lockdown") else "off"
    learning = "on" if res.get("learning") else "off"
    lines = [f"ghostwall status \u2014 lockdown: {lockdown}, learning: {learning}"]
    for d in res.get("devices", []):
        iso = " [ISOLATED]" if d.get("isolated") else ""
        blocked = f", blocked: {', '.join(d.get('blocked_domains', []))}" if d.get("blocked_domains") else ""
        lines.append(f"- {d.get('name', '?')} ({d.get('ip', '?')}){iso}{blocked}")
    return "\n".join(lines)


def _fmt_device(res: dict) -> str:
    iso = "yes" if res.get("isolated") else "no"
    blocked = ", ".join(res.get("blocked_domains", [])) or "none"
    return (
        f"device {res.get('name', '?')}\n"
        f"ip: {res.get('ip', '?')}\nmac: {res.get('mac', '?')}\n"
        f"isolated: {iso}\nblocked domains: {blocked}\n"
        f"last seen: {res.get('last_seen', '?')}"
    )


def handle_command(text: str, client: ControlClient) -> str:
    """Execute one /fw command against the control API; return plain text reply."""
    sub, args = parse_command(text)
    if not sub and not args and not text.strip().startswith("/fw"):
        return ""
    try:
        if sub == "status":
            return _fmt_status(client.status())
        if sub == "device":
            if not args:
                return "usage: /fw device <name>"
            return _fmt_status_of_one(client.device(args[0]))
        if sub == "isolate":
            if not args:
                return "usage: /fw isolate <name>"
            r = client.isolate(args[0])
            return f"{r.get('name', args[0])} isolated."
        if sub == "release":
            if not args:
                return "usage: /fw release <name>"
            r = client.release(args[0])
            return f"{r.get('name', args[0])} released."
        if sub == "allow":
            if len(args) < 1:
                return "usage: /fw allow <domain>"
            r = client.allow(args[0])
            return f"{r.get('domain', args[0])} added to allowlist."
        if sub == "lockdown":
            r = client.lockdown()
            state = "ON" if r.get("lockdown") else "OFF"
            return f"Lockdown {state}."
        if sub == "learning":
            if args and args[0].lower() in ("on", "off"):
                enabled = args[0].lower() == "on"
                r = client.learning(enabled)
                return f"Learning mode {'on' if r.get('learning') else 'off'}."
            return "usage: /fw learning on|off"
        if sub == "status":
            return _fmt_status(client.status())
        if sub == "help" or sub == "":
            return _HELP
        return f"unknown subcommand: {sub}\n" + _HELP
    except ControlError as exc:
        return f"fw error: {exc}"
    except (ValueError, TypeError) as exc:
        return f"fw error: bad request: {exc}"


_HELP = (
    "commands:\n"
    "/fw status\n"
    "/fw device <name>\n"
    "/fw isolate <name>\n"
    "/fw release <name>\n"
    "/fw allow <domain>\n"
    "/fw lockdown\n"
    "/fw learning on|off"
)

# alias kept stable for handle_command
_HELP = _HELP


def _fmt_status_of_one(res: dict) -> str:
    iso = "yes" if res.get("isolated") else "no"
    blocked = ", ".join(res.get("blocked_domains", [])) or "none"
    return (
        f"{res.get('name', '?')}:\n"
        f"ip: {res.get('ip', '?')}\n"
        f"mac: {res.get('mac', '?')}\n"
        f"isolated: {iso}\n"
        f"blocked domains: {blocked}\n"
        f"last seen: {res.get('last_seen', '?')}"
    )
