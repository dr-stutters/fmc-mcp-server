"""FMC's show-command allowlist (operational/commands): parsed from the API spec, built-in FMC 10.0.1
fallback, two-word command + parameters split, and refusals with alternatives before any call."""

import re

import pytest
from fastmcp import Client

from fmc_mcp._core import InvalidRequest
from fmc_mcp._core.spec.index import build_index
from fmc_mcp.server import create_server
from fmc_mcp.tools import show_commands
from fmc_mcp.tools.show_commands import (
    COMMANDS_OP,
    FALLBACK,
    build,
    check_command,
    clis_from_description,
    from_index,
    parse_clis,
)

from .conftest import make_settings

# The `command` parameter's description as FMC 10.0.1's API Explorer has it (HTML included).
SPEC_DESCRIPTION = (
    "The command filter query parameter should have value of show commands. The maximum word size of this "
    "field is 2. For eg: show failover, show snmp-server, show logging etc.<br/><b>Note:- This API endpoint "
    "retrieves outputs from devices ...</b><br/><code>Supported CLIs:- </code><i>"
    + show_commands.FALLBACK_CLIS
    + "</i>"
)


def spec_doc(description: str) -> dict:
    return {
        "swagger": "2.0",
        "info": {"version": "10.9.9"},
        "paths": {
            COMMANDS_OP: {
                "get": {
                    "operationId": "getCommands",
                    "parameters": [
                        {
                            "name": "command",
                            "in": "query",
                            "required": True,
                            "type": "string",
                            "description": description,
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }


@pytest.mark.parametrize(
    ("command", "split"),
    [
        ("show route", ("show route", None)),
        ("show route bgp", ("show route", "bgp")),
        ("  show   crypto ikev2   sa ", ("show crypto", "ikev2 sa")),
        ("show crypto ikev2 stats", ("show crypto", "ikev2 stats")),
        ("show interface ip brief", ("show interface", "ip brief")),
        ("show running-config access-group", ("show running-config", "access-group")),
        ("show run nat", ("show running-config", "nat")),  # unambiguous abbreviation expanded
        ("SHOW Failover", ("show failover", None)),
        ("show failover history details", ("show failover", "history details")),
        ("show snort3 status", ("show snort3", "status")),
        ("show access-list mcp-acl", ("show access-list", "mcp-acl")),
        ("show dhcpd state", ("show dhcpd", "state")),
    ],
)
def test_supported_commands_split(command: str, split: tuple[str, str | None]) -> None:
    assert check_command(command) == split


@pytest.mark.parametrize(
    ("command", "hint"),
    [
        ("show bgp summary", "'show route bgp'"),
        ("show bgp neighbors", "'show route bgp'"),
        ("show path-monitoring", "fmc_ftdsdwan_status"),
        ("show policy-route", "fmc_get_routing"),
        ("show ospf neighbor", "'show route ospf'"),
        ("show conn count", "fmc_packet_tracer"),
        ("show nat detail", "fmc_list_nat_rules"),
        ("show xlate", "fmc_list_nat_rules"),
        ("show running-config", "<section>"),  # plain running-config: an option is required
        ("show access-list", "show access-list <name>"),
        ("show crypto", "ikev2 sa"),
        ("show snort3", None),
        ("show r", None),  # ambiguous: route, rule, running-config
    ],
)
def test_unsupported_commands_refused_with_alternatives(command: str, hint: str | None) -> None:
    with pytest.raises(InvalidRequest) as e:
        check_command(command)
    msg = str(e.value)
    assert "not supported by FMC's command API" in msg and "wasn't sent" in msg
    assert "Supported (FMC 10.0.1 list): " in msg and "show route <option>" in msg
    if hint:
        assert hint in msg


def test_non_show_and_unsafe_refused() -> None:
    for bad in ("configure terminal", "ping 1.1.1.1", "show"):
        with pytest.raises(InvalidRequest, match="Only 'show"):
            check_command(bad)
    for bad in ("show run | include x", "show route; reload", "show route `x`"):
        with pytest.raises(InvalidRequest, match="Pipes"):
            check_command(bad)


def test_parse_clis_forms() -> None:
    rules = parse_clis("show version, show version <?-option>, show crypto <?-option>, show snort3 status")
    assert rules["show version"].bare and rules["show version"].any_option
    assert not rules["show crypto"].bare and rules["show crypto"].any_option
    assert rules["show snort3"].fixed == {"status"} and not rules["show snort3"].bare
    assert rules["show snort3"].accepts("status") and not rules["show snort3"].accepts("x")
    # FMC 10.0.1's documented list plus the live-verified interface / running-config
    assert {"show interface", "show running-config", "show route", "show crypto"} <= set(FALLBACK.rules)
    assert "show bgp" not in FALLBACK.rules and "show path-monitoring" not in FALLBACK.rules


def test_clis_from_spec_description() -> None:
    clis = clis_from_description(SPEC_DESCRIPTION)
    assert clis is not None and "<i>" not in clis and "<?-option>" in clis
    assert build(clis).rules.keys() == FALLBACK.rules.keys()
    assert clis_from_description("no list here") is None


def test_allowlist_from_the_spec_index() -> None:
    """A newer FMC that lists more commands is picked up from its spec; a spec without the list falls back."""
    newer = build_index(
        spec_doc(SPEC_DESCRIPTION.replace("show banner", "show banner, show path-monitoring"))
    )
    sup = from_index(newer)
    assert sup.source == "spec" and from_index(newer) is sup
    assert check_command("show path-monitoring", sup) == ("show path-monitoring", None)
    with pytest.raises(InvalidRequest, match="from the FMC API spec"):
        check_command("show bgp summary", sup)
    assert from_index(build_index(spec_doc("Show commands."))) is FALLBACK
    assert from_index(build_index({"swagger": "2.0", "info": {"version": "1"}, "paths": {}})) is FALLBACK


async def test_tool_description_matches_the_allowlist() -> None:
    """fmc_run_show_command's description: every example passes the built-in (FMC 10.0.1) allowlist and
    every command it names as refused is refused (the 0.13.0 text offered 'show nat detail' and
    'show conn count' as examples)."""

    async with Client(create_server(make_settings())) as c:
        tool = next(t for t in await c.list_tools() if t.name == "fmc_run_show_command")
    examples = re.findall(r"'(show [^']+)'", tool.input_schema["properties"]["command"]["description"])
    assert len(examples) >= 4
    for cmd in examples:
        check_command(cmd, FALLBACK)
    doc = " ".join((tool.description or "").split())
    refused = re.search(r"Anything else \(([^)]+)\) is refused", doc)
    assert refused
    for cmd in refused.group(1).split(", "):
        cmd = cmd.removeprefix("plain ")
        with pytest.raises(InvalidRequest):
            check_command(cmd, FALLBACK)
    assert "access-list <name>" in doc  # allowed with a name (spec: show access-list <?-option>)
    check_command("show access-list mcp-acl", FALLBACK)
