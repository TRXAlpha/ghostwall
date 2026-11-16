"""First-contact verdict: allow, hold or block for one (device, destination) lookup.

Pure: no I/O, no clock, no state. resolver.decide() gathers the evidence and calls judge().
In this phase the verdict is measured only (config "verdict": "dry-run"): it is recorded on
the event and in stats, and it never changes a decision.

Evidence is grouped into families. Two signals count as independent only when they come from
two different families:

  name     the name itself: a random-looking score, a rarely-legitimate TLD, a lookalike
  age      the registrable domain is on the newly registered domains list
  list     the threat feed: an exact host hit is proof-grade, a listed parent is not
  history  new to the whole network; or an IoT device outside its learned domains
  service  an abused or shared service (bot APIs, paste sites, tunnels, file drops)

Deliberately not used: TLS fingerprints, companion traffic and idle time (research only).

Each family has a level: none, weak or strong. A device counts a family when the level reaches
its bar: an IoT device at weak or above (it holds on one risky family), any other device only
at strong (a normal device needs the family to be strong).

Outcome, first match wins:
  local name, trusted by you (or the allowlist), used by this device before, popular site,
    or no connection would follow:           allow
  exact threat-feed hit, not popular and not a shared service (proof-grade): block
  destination the network has used for novelty_days (not new to the network): allow
  two or more counting families:             block
  one counting family:                       hold
  otherwise:                                 allow

Thresholds are not in this file. They are read from the config keys named in Thresholds, so
the verdict and the rest of ghost-dns agree on what a risky score is. The only number here is
the level scale, and it is an order, not a measurement.
"""
from __future__ import annotations

from dataclasses import dataclass, field

NONE, WEAK, STRONG = 0, 1, 2
LEVEL_NAMES = ("none", "weak", "strong")
FAMILIES = ("name", "age", "list", "history", "service")

# A device counts a family at this level or above. IoT devices hold on one risky family;
# other devices need a strong one.
IOT_BAR = WEAK
NORMAL_BAR = STRONG


@dataclass(frozen=True)
class Thresholds:
    """Read from config by resolver.py. There are no defaults here on purpose.

    recommend_dga    config recommend_threshold: a name at or above this is random-looking (weak)
    corroborated_dga config corroborated_threshold: with a rarely-legitimate TLD it is strong
    block_dga        config block_threshold: a name at or above this is strong on its own
    young_days       config novelty_days: a newly registered domain this young is strong
    """
    recommend_dga: float
    corroborated_dga: float
    block_dga: float
    young_days: int


@dataclass(frozen=True)
class Evidence:
    """What is known about one lookup. Built by resolver.py from state and detectors."""
    domain: str
    iot: bool = False                  # the device is marked "profile": "iot"
    local_name: bool = False           # a name on your own network (.local, .lan, ...)
    trusted: bool = False              # on the allowlist (your Trust, or the starter list)
    known_to_device: bool = False      # this device looked this domain up before
    popular: bool = False              # the registrable domain is on the Tranco top list
    no_connection: bool = False        # the DNS server or upstream refused it, or it does not exist
    new_to_network: bool = False       # not used on this network for novelty_days or more
    dga: float | None = None           # random-looking score, 0 to 1 (None: not scored)
    rare_tld: bool = False             # a rarely-legitimate TLD
    lookalike: bool = False            # letters from another alphabet that imitate a popular site
    list_hit: str = ""                 # threat feed: "exact", "parent" or "" (no hit)
    list_name: str = ""                # what the feed matched, for the reason text
    young_days: int | None = None      # days since registration, from the newly registered list
    shared_service: str = ""           # label of an abused or shared service, or ""
    iot_outside_set: bool = False      # IoT device, past its learning window, domain not in its set


@dataclass(frozen=True)
class Verdict:
    outcome: str                       # "allow" | "hold" | "block"
    score: int                         # families that count for this device (0 to 5)
    families: dict = field(default_factory=dict)   # family -> "none" | "weak" | "strong"
    reasons: tuple = ()                # plain-language lines, most important first
    proof: bool = False                # block on one proof-grade signal

    @property
    def line(self) -> str:
        """The one reason line an event gets: what the verdict would have done, and why."""
        verb = {"hold": "would hold", "block": "would block"}.get(self.outcome, "would allow")
        return f"dry-run verdict: {verb}: " + "; ".join(self.reasons)


def _name(ev: Evidence, th: Thresholds):
    if ev.lookalike:
        return STRONG, ["a lookalike of a popular site (a common phishing trick)"]
    dga = ev.dga or 0.0
    if ev.dga is None and not ev.rare_tld and not ev.lookalike:
        return NONE, []
    if dga >= th.block_dga or (dga >= th.corroborated_dga and ev.rare_tld):
        level = STRONG
    elif dga >= th.recommend_dga or ev.rare_tld:
        level = WEAK
    else:
        return NONE, []
    texts = []
    if ev.dga is not None and dga >= th.recommend_dga:
        texts.append(f"random-looking name (score {dga:.2f})")
    if ev.rare_tld:
        texts.append("a rarely-legitimate top-level domain")
    return level, texts


def _age(ev: Evidence, th: Thresholds):
    if ev.young_days is None:
        return NONE, []
    days = ev.young_days
    when = "registered today" if days <= 0 else f"registered {days} day{'s' if days != 1 else ''} ago"
    level = STRONG if days <= th.young_days else WEAK
    return level, [f"{when} (newly registered domains list)"]


def _list(ev: Evidence, th: Thresholds):
    if ev.list_hit == "exact":
        return STRONG, [f"{ev.list_name} is on the threat feed"]
    if ev.list_hit == "parent":
        return WEAK, [f"{ev.list_name}, a parent of this name, is on the threat feed"]
    return NONE, []


def _history(ev: Evidence, th: Thresholds):
    texts = []
    if ev.new_to_network:
        texts.append("new to your network")
    if ev.iot_outside_set:
        texts.append("an IoT device outside the domains it normally uses")
    if ev.new_to_network and ev.iot_outside_set:
        return STRONG, texts
    return (WEAK, texts) if texts else (NONE, [])


def _service(ev: Evidence, th: Thresholds):
    if ev.shared_service:
        return WEAK, [f"a shared service ({ev.shared_service})"]
    return NONE, []


_FAMILY_FUNCS = (("name", _name), ("age", _age), ("list", _list), ("history", _history),
                 ("service", _service))


def _proof(ev: Evidence) -> bool:
    """One signal that may block alone: an exact threat-feed name, not a popular site or a
    shared service (those are where a listed name is most often a mistake)."""
    return ev.list_hit == "exact" and not ev.popular and not ev.shared_service


def judge(ev: Evidence, th: Thresholds) -> Verdict:
    """The verdict for one lookup. See the module docstring for the rules."""
    found = {name: fn(ev, th) for name, fn in _FAMILY_FUNCS}
    levels = {name: level for name, (level, _) in found.items()}
    shown = {name: LEVEL_NAMES[level] for name, level in levels.items()}
    bar = IOT_BAR if ev.iot else NORMAL_BAR
    counting = [name for name in FAMILIES if levels[name] >= bar]
    texts = [t for name in counting for t in found[name][1]]

    if ev.local_name:
        return Verdict("allow", 0, shown, ("a name on your own network",))
    if ev.trusted:
        return Verdict("allow", 0, shown, ("on your allowlist (you trust it, or the starter list)",))
    if ev.known_to_device:
        return Verdict("allow", len(counting), shown, ("this device has used this name before",))
    if ev.popular:
        return Verdict("allow", 0, shown, ("a popular site (Tranco top list): its name alone never counts",))
    if ev.no_connection:
        return Verdict("allow", 0, shown, ("no connection would follow: refused by your DNS server or "
                                           "upstream filter, or the name does not exist",))
    if _proof(ev):
        return Verdict("block", max(len(counting), 1), shown,
                       (f"{ev.list_name} is on the threat feed by exact name (proof on its own)",),
                       proof=True)
    if not ev.new_to_network:
        return Verdict("allow", len(counting), shown,
                       ("your network has used it for novelty_days or more: only an exact threat-feed "
                        "hit can act on it",) + tuple(texts))
    if len(counting) >= 2:
        return Verdict("block", len(counting), shown,
                       (f"{len(counting)} risky families agree on a destination new to this device",)
                       + tuple(texts))
    if len(counting) == 1:
        return Verdict("hold", 1, shown,
                       ("one risky family on a destination new to this device",) + tuple(texts))
    return Verdict("allow", 0, shown, ("no family is risky enough for this device",))
