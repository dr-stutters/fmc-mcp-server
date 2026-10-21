"""F79 live finding (W6N live-B): a rule a child access policy inherits was reported twice, once under its own
policy and again under the child with the child's index, with nothing saying it is the base's rule.

FMC 10.0.1 lists a child's inherited rules in the child's accessrules (the parent's rule ids, the child's
rule index, metadata.accessPolicy = the base; tests/fixtures/child_policy_rules_fmc10.json, recorded by live-A
2026-10-21). fmc_find_indicator and fmc_find_address now label those rows "[inherited from <base>]"; the
child's own rules and the base's own listing read as before."""

import copy
from typing import Any

import httpx
import respx

from fmc_mcp._core.testing import call_tool
from fmc_mcp.server import create_server
from fmc_mcp.tools.find_address import _rule_where, inherited_from

from .conftest import CFG, empty, fixture, items, make_settings

LIVE = fixture("child_policy_rules_fmc10")
FX = fixture("find_indicator")
PARENT = FX["acp"]  # mcp-w6-acp (the base live, same id)
CHILD = {"type": "AccessPolicy", "name": LIVE["child_acp"]["name"], "id": LIVE["child_acp"]["id"]}
OWN, INHERITED = LIVE["child_rules_expanded"]["items"]


def child_rules() -> dict[str, Any]:
    """The child's expanded accessrules as FMC 10.0.1 lists them: its own rule first (index 1), then the
    parent's rules with the parent's ids, the child's index and metadata.accessPolicy = the parent."""
    own = {**copy.deepcopy(OWN), "action": "ALLOW", "enabled": True}
    rows = [own]
    for r in copy.deepcopy(FX["accessrules"]["items"]):
        meta = r.get("metadata") or {}
        r["metadata"] = {
            **meta,
            "ruleIndex": meta["ruleIndex"] + 1,
            "accessPolicy": copy.deepcopy(INHERITED["metadata"]["accessPolicy"]),
        }
        rows.append(r)
    return {"items": rows, "paging": {"count": len(rows)}}


def parent_rules() -> dict[str, Any]:
    rows = copy.deepcopy(FX["accessrules"]["items"])
    for r in rows:
        r["metadata"] = {**(r.get("metadata") or {}), "accessPolicy": {**PARENT}}
    return {"items": rows, "paging": {"count": len(rows)}}


def mount(fmc: respx.MockRouter) -> None:
    for name in ("object/fqdns", "object/urls", "object/urlgroups"):
        fmc.get(f"{CFG}/{name}").mock(return_value=httpx.Response(200, json=FX[name]))
    fmc.get(f"{CFG}/object/networkgroups").mock(return_value=empty())
    for name in ("object/networkaddresses", "object/ranges"):
        fmc.get(f"{CFG}/{name}").mock(return_value=empty())
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([PARENT, CHILD]))
    fmc.get(f"{CFG}/policy/accesspolicies/{PARENT['id']}/accessrules").mock(
        return_value=httpx.Response(200, json=parent_rules())
    )
    fmc.get(f"{CFG}/policy/accesspolicies/{CHILD['id']}/accessrules").mock(
        return_value=httpx.Response(200, json=child_rules())
    )


def test_the_recorded_shape() -> None:
    assert OWN["metadata"]["accessPolicy"]["id"] == CHILD["id"]
    assert INHERITED["metadata"]["accessPolicy"] == {
        "name": "mcp-w6-acp",
        "id": PARENT["id"],
        "type": "AccessPolicy",
    }
    assert LIVE["child_acp"]["metadata"]["parentPolicy"]["id"] == PARENT["id"]
    assert inherited_from(OWN, CHILD["id"]) is None
    assert inherited_from(INHERITED, CHILD["id"]) == "mcp-w6-acp"
    assert inherited_from(INHERITED, PARENT["id"].upper()) is None  # ids compare case-insensitively
    assert inherited_from(INHERITED, None) is None  # no policy id given: as before
    assert _rule_where("mcp-w6-child-acp", INHERITED, "BLOCK", CHILD["id"]) == (
        "mcp-w6-child-acp #2 mcp-w6-quarantine-block (BLOCK) [inherited from mcp-w6-acp]"
    )


async def test_find_indicator_labels_the_inherited_row(fmc: respx.MockRouter) -> None:
    mount(fmc)
    data = await call_tool(
        create_server(make_settings()),
        "fmc_find_indicator",
        {"value": "cisco.com", "areas": ["access_rules"], "response_format": "json"},
    )
    wheres = [r["where"] for r in data["results"] if r["area"] == "access_rules"]
    assert wheres == [
        "mcp-w6-acp #1 mcp-w6-fqdn-allow (ALLOW)",
        "mcp-w6-child-acp #2 mcp-w6-fqdn-allow (ALLOW) [inherited from mcp-w6-acp]",
    ]
    assert "inherited from <base>" in data["limits"]


async def test_find_indicator_on_the_child_alone(fmc: respx.MockRouter) -> None:
    """Narrowed to the child (as device= on an FTD running it): the base's rule is still found, as the
    child's, and says where it comes from."""
    mount(fmc)
    fmc.get(f"{CFG}/policy/accesspolicies/{CHILD['id']}").mock(return_value=httpx.Response(200, json=CHILD))
    data = await call_tool(
        create_server(make_settings()),
        "fmc_find_indicator",
        {
            "value": "cisco.com",
            "areas": ["access_rules"],
            "access_policy": CHILD["id"],
            "response_format": "json",
        },
    )
    wheres = [r["where"] for r in data["results"] if r["area"] == "access_rules"]
    assert wheres == ["mcp-w6-child-acp #2 mcp-w6-fqdn-allow (ALLOW) [inherited from mcp-w6-acp]"]


async def test_find_address_labels_the_inherited_row(fmc: respx.MockRouter) -> None:
    mount(fmc)
    data = await call_tool(
        create_server(make_settings()),
        "fmc_find_address",
        {"address": "192.0.2.10", "areas": ["access_rules"], "response_format": "json"},
    )
    wheres = [r["where"] for r in data["results"] if r["area"] == "access_rules"]
    assert wheres == [
        "mcp-w6-acp #4 mcp-w6-ip-only (ALLOW)",
        "mcp-w6-child-acp #5 mcp-w6-ip-only (ALLOW) [inherited from mcp-w6-acp]",
    ]
    assert "inherited from <base>" in data["limits"]
