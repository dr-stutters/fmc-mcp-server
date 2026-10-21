"""Inheritance (F76 #171) on the shapes FMC 10.0.1 answered in the W6N live-A proof
(tests/fixtures/inheritance_fmc10.json): a child's policy record, its inheritance setting, its rule list with
the base's rules in it, and the PUT answers when the base is cleared and set again. The spec-built entries
in policy_structure_fmc10.json stay for the cases the lab didn't record."""

import copy
import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, DOMAIN, fixture, items, make_settings

FX = fixture("inheritance_fmc10")


def live(key: str) -> dict[str, Any]:
    out = copy.deepcopy(FX[key])
    out.pop("_source", None)
    return dict(out)


CHILD = live("child_acp")
CHILD["metadata"]["domain"]["id"] = DOMAIN  # owned by the test login's domain
CHILD_ID = CHILD["id"]
BASE_ID = CHILD["metadata"]["parentPolicy"]["id"]
BASE = {"id": BASE_ID, "name": "mcp-w6-acp", "type": "AccessPolicy", "metadata": {"inherit": False}}
SETTING = f"{CFG}/policy/accesspolicies/{CHILD_ID}/inheritancesettings"


def test_recorded_shapes() -> None:
    assert CHILD["metadata"]["inherit"] is True and CHILD["metadata"]["parentPolicy"]["name"] == "mcp-w6-acp"
    assert FX["child_inheritance"]["items"][0]["basePolicy"]["name"] == "mcp-w6-acp"  # GET names it
    assert "name" not in FX["base_back_put"]["response"]["basePolicy"]  # the PUT answer doesn't
    assert "basePolicy" not in FX["base_inheritance"]["items"][0]
    assert "basePolicy" not in FX["clear_base_put"]["request"]
    owners = [r["metadata"]["accessPolicy"]["name"] for r in FX["child_rules"]["items"]]
    assert owners == ["mcp-w6-child-acp", "mcp-w6-acp"]


def mock_child(fmc: respx.MockRouter) -> respx.Route:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([CHILD, BASE]))
    fmc.get(f"{CFG}/policy/accesspolicies/{CHILD_ID}").mock(return_value=httpx.Response(200, json=CHILD))
    fmc.get(f"{CFG}/policy/accesspolicies/{BASE_ID}").mock(return_value=httpx.Response(200, json=BASE))
    fmc.get(f"{CFG}/policy/accesspolicies/{CHILD_ID}/accessrules").mock(
        return_value=httpx.Response(200, json=live("child_rules"))
    )
    fmc.get(f"{CFG}/policy/accesspolicies/{BASE_ID}/inheritancesettings").mock(
        return_value=httpx.Response(200, json=live("base_inheritance"))
    )
    fmc.get(f"{CFG}/policy/accesspolicies/{CHILD_ID}/categories").mock(return_value=items([]))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    return fmc.get(SETTING).mock(return_value=httpx.Response(200, json=live("child_inheritance")))


async def test_get_access_policy_of_a_live_child(fmc: respx.MockRouter) -> None:
    mock_child(fmc)
    async with Client(create_server(make_settings())) as c:
        out = (await c.call_tool("fmc_get_access_policy", {"policy": "mcp-w6-child-acp"})).structured_content
    assert out is not None
    assert out["parent_policy"] == "mcp-w6-acp" and "base_chain" not in out  # one level
    assert out["lock"] == {"status": "UNLOCKED"}
    assert out["rules"]["total"] == 2  # the child's rule list holds the base's rules too


async def test_clear_the_base_with_the_live_answers(fmc: respx.MockRouter) -> None:
    mock_child(fmc)
    one = f"{SETTING}/{CHILD_ID}"
    put = fmc.put(one).mock(return_value=httpx.Response(200, json=FX["clear_base_put"]["response"]))
    fmc.get(one).mock(return_value=httpx.Response(200, json=FX["clear_base_put"]["response"]))
    args = {"policy": "mcp-w6-child-acp", "base": "none"}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("fmc_set_base_policy", args)).structured_content
        assert preview is not None and preview["status"] == "preview", preview
        assert preview["preview"]["base"] == {"from": "mcp-w6-acp", "to": None}
        done = (
            await c.call_tool("fmc_set_base_policy", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert json.loads(put.calls.last.request.content) == FX["clear_base_put"]["request"]  # live-A's body
    assert done is not None and done["result"]["base_policy"] is None and "warning" not in done["result"]
