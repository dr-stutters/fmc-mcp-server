"""Which show commands FMC passes through to a device (`devices/devicerecords/{id}/operational/commands`).

FMC's API Explorer documents the endpoint's allowlist in the `command` parameter ("Supported CLIs:- show
version, show route <?-option>, show crypto <?-option>, ..."), and the endpoint takes at most two words in
`command`; the rest goes in `parameters` ('show route' + 'bgp'). The list is read from the spec index at
run time (so a newer FMC that allows more is picked up), with FMC 10.0.1's list built in as the fallback.
A command FMC doesn't allow is refused here, before any call, with the supported commands and the tool
that covers it instead (FMC answers such commands with a bare 400 "Either command is not supported ...").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from fmc_mcp._core import InvalidRequest
from fmc_mcp.spec_index import spec_index

COMMANDS_OP = (
    "/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords/{containerUUID}/operational/commands"
)
# The command API takes at most two words in `command`; the rest go in `parameters`.
COMMAND_WORDS = 2
UNSAFE = re.compile(r"[|;&`$<>\n\r]")

# FMC 10.0.1's API Explorer, `command` parameter of GET .../operational/commands (verbatim list).
FALLBACK_CLIS = (
    "show version, show version <?-option>, show failover, show failover <?-option>, show dhcpd state, "
    "show ip, show ip <?-option>, show aaa-server, show aaa-server <?-option>, show logging, "
    "show logging <?-some_option_only>, show snmp-server <?-option>, show ssl, show ssl <?-option>, "
    "show firewall, show logging, show logging <?-some_option_only>, show route, show route <?-option>, "
    "show vpn-sessiondb, show vpn-sessiondb <?-option>, show crypto <?-option>, show rule <?-option>, "
    "show access-list <?-option>, show network, show ntp, show banner, show snort3 status"
)
# Not in the spec's list but answered by FMC 10.0.1 in the live runs ('show interface ip brief',
# 'show running-config nat|logging|snmp-server|ssh'; plain 'show running-config' is refused).
LIVE_CLIS = "show interface, show interface <?-option>, show running-config <?-option>"

# Where to look instead, for commands people (and the docs of other tools) often reach for.
ALTERNATIVES: dict[str, str] = {
    "show bgp": "'show route bgp' (BGP-learned routes); neighbours and AS settings: fmc_get_routing",
    "show ospf": "'show route ospf' (OSPF-learned routes); OSPF settings: fmc_get_routing",
    "show path-monitoring": "fmc_ftdsdwan_status (WAN links and tunnels per branch) and fmc_device_health",
    "show policy-route": "fmc_get_routing (policy-based routes), fmc_ftdsdwan_status (app routes) and "
    "'show route' for the routing table",
    "show conn": "fmc_live_connections (connections from the device's syslog buffer), fmc_packet_tracer for "
    "a verdict, or the device CLI (SSH / cml_run_commands)",
    "show local-host": "fmc_live_connections(host=...) for a host's connections",
    "show user-identity": "fmc_user_identity_sessions (FMC's active identity sessions: user <-> IP); the FTD "
    "CLI has no 'show user-identity'",
    "show xlate": "fmc_list_nat_rules, or the device CLI (SSH / cml_run_commands)",
    "show nat": "fmc_list_nat_rules or 'show running-config nat'",
    "show arp": "the device CLI (SSH / cml_run_commands)",
    "show access-list": "'show access-list <name>', fmc_list_access_rules or fmc_get_hit_counts",
    "show running-config": "'show running-config <section>' (nat, route, interface, logging, ...)",
    "show crypto": "'show crypto ikev2 sa', 'show crypto ipsec sa', 'show crypto ikev2 stats'",
    "show interface": "'show interface ip brief'",
    "show managers": "fmc_get_device / fmc_list_devices (registration and health)",
}


@dataclass
class Rule:
    """One allowed `command` (first two words) and the parameters FMC accepts with it."""

    bare: bool = False  # 'show route' alone
    any_option: bool = False  # 'show route <?-option>'
    fixed: set[str] = field(default_factory=set)  # 'show snort3 status' -> {"status"}

    def accepts(self, params: str | None) -> bool:
        if not params:
            return self.bare
        if self.any_option:
            return True
        p = params.lower()
        return any(p == f or p.startswith(f + " ") for f in self.fixed)

    def forms(self, head: str) -> list[str]:
        out = [head] if self.bare else []
        if self.any_option:
            out.append(f"{head} <option>")
        out += [f"{head} {f}" for f in sorted(self.fixed)]
        return out


@dataclass
class Supported:
    rules: dict[str, Rule]
    source: str  # "spec" | "built-in"

    def listing(self) -> str:
        return ", ".join(f for head in sorted(self.rules) for f in self.rules[head].forms(head))


def parse_clis(text: str, into: dict[str, Rule] | None = None) -> dict[str, Rule]:
    """'show version, show route <?-option>, show snort3 status' -> {head: Rule}."""
    rules = {} if into is None else into
    for raw in re.split(r",", text):
        words = re.sub(r"<[^>]*>", " <opt> ", raw).lower().split()
        if len(words) < 2 or words[0] != "show":
            continue
        head = " ".join(words[:COMMAND_WORDS])
        rule = rules.setdefault(head, Rule())
        rest = words[COMMAND_WORDS:]
        if not rest:
            rule.bare = True
        elif rest[0] == "<opt>":
            rule.any_option = True
        else:
            rule.fixed.add(" ".join(w for w in rest if w != "<opt>"))
    return rules


def clis_from_description(description: str) -> str | None:
    """The comma-separated list after 'Supported CLIs:-' in the `command` parameter's description."""
    m = re.search(r"Supported CLIs?\s*:-?\s*(.+)", description, re.I | re.S)
    if not m:
        return None
    text = re.sub(r"<(?!\?)[^>]+>", " ", m.group(1))  # HTML tags, not the <?-option> placeholders
    return text if "show " in text.lower() else None


def build(spec_clis: str | None) -> Supported:
    rules = parse_clis(spec_clis or FALLBACK_CLIS)
    parse_clis(LIVE_CLIS, rules)
    return Supported(rules, "spec" if spec_clis else "built-in")


FALLBACK = build(None)
_parsed: list[tuple[Any, Supported]] = []  # (index, its allowlist): the index is kept so its id isn't reused


def from_index(index: Any) -> Supported:
    """The allowlist an FMC spec index documents; the built-in one when the operation or list is missing."""
    for idx, sup in _parsed:
        if idx is index:
            return sup
    clis: str | None = None
    for op in index.operations_at(COMMANDS_OP):
        if op.method.upper() != "GET":
            continue
        for p in op.params:
            if p.name == "command":
                clis = clis_from_description(p.description or p.summary)
    if not clis:
        return FALLBACK
    result = build(clis)
    _parsed[:] = [(index, result)]  # one appliance per process in practice; don't hold old indexes
    return result


async def supported_commands(ctx: Any) -> Supported:
    """The allowlist from the spec index (loaded once, disk-cached by core); FMC 10.0.1's when the spec
    isn't available. A first spec load that takes longer than spec_index.SPEC_WAIT_S keeps going in the
    background."""
    index = await spec_index(ctx, "show-command list")
    return FALLBACK if index is None else from_index(index)


def _expand(word: str, choices: list[str]) -> str | None:
    if word in choices:
        return word
    hits = [c for c in choices if c.startswith(word)]
    return hits[0] if len(hits) == 1 else None


def check_command(command: str, supported: Supported | None = None) -> tuple[str, str | None]:
    """Validate a show command against FMC's allowlist and split it the way the API wants:
    'show route bgp' -> ('show route', 'bgp'). An unambiguous abbreviation of the second word is
    expanded ('show run nat' -> ('show running-config', 'nat')). Raises InvalidRequest, before any
    call to FMC, for anything FMC doesn't pass through."""
    sup = supported or FALLBACK
    text = " ".join(command.strip().split())
    if not text.lower().startswith("show "):
        raise InvalidRequest("Only 'show ...' commands are supported (FMC runs them on the device).")
    if UNSAFE.search(text):
        raise InvalidRequest("Pipes, redirects and command separators are not allowed; use `match`.")
    words = text.split(" ")
    seconds = sorted({h.split(" ", 1)[1] for h in sup.rules})
    second = _expand(words[1].lower(), seconds)
    head = f"show {second}" if second else " ".join(words[:COMMAND_WORDS]).lower()
    params = " ".join(words[COMMAND_WORDS:]) or None
    rule = sup.rules.get(head)
    if rule is not None and rule.accepts(params):
        return head, params
    asked = " ".join(words).lower()
    detail = f" (FMC runs {head!r} only as {', '.join(rule.forms(head))})" if rule is not None else ""
    hint = next((v for k, v in ALTERNATIVES.items() if asked == k or asked.startswith(k + " ")), None)
    if hint is None:
        hint = ALTERNATIVES.get(head)
    msg = f"{asked!r} is not supported by FMC's command API{detail}, so it wasn't sent. "
    if hint:
        msg += f"Instead: {hint}. "
    where = "from the FMC API spec" if sup.source == "spec" else "FMC 10.0.1 list"
    msg += f"Supported ({where}): {sup.listing()}."
    raise InvalidRequest(msg)
