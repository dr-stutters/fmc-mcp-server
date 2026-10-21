"""A child access policy's Logging settings (F76 #171, W6N live-A finding 2).

FMC 10.0.1 keeps a policy's own Logging settings when it gets a base through the REST API, and refused the
first deployment of such a child: the base's rules send syslog through the Logging settings, the child's
own have no syslog destination. PUT loggingsettings inheritFromParent true fixed it (FMC answers with the
base's setting). Recorded live: tests/fixtures/child_logging_fmc10.json.
"""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from .conftest import ACP_ID, CFG, fixture, items
from .test_policy_structure import (
    ACP,
    CHILD,
    CHILD_ACP,
    FX,
    acp_list,
    base_logging,
    child_and_parent,
    no_base,
    preview_apply,
    preview_only,
    with_base,
)

LIVE = fixture("child_logging_fmc10")
OWN = LIVE["child_loggingsettings"]["items"][0]  # FMC's defaults for a new policy
SETTINGS = f"{CFG}/policy/accesspolicies/{CHILD}/loggingsettings"


def test_recorded_shapes() -> None:
    parent = LIVE["parent_loggingsettings"]["items"][0]
    assert parent["syslogConfigFromPlatformSetting"] is True
    assert OWN["syslogConfigFromPlatformSetting"] is False and OWN["inheritFromParent"] is False
    answer = LIVE["inherit_put"]["response"]
    assert answer["id"] == parent["id"] != OWN["id"]  # FMC answers with the base's setting
    assert answer["metadata"]["inheritedPolicy"]["name"] == "mcp-w6-acp"
    assert LIVE["child_loggingsettings_base_cleared"]["items"][0] == OWN  # its own come back
    assert "Logging configuration is invalid" in LIVE["first_deploy_error"]["description"]


def child_settings(fmc: respx.MockRouter, setting: dict[str, Any]) -> respx.Route:
    fmc.get(SETTINGS).mock(return_value=items([setting]))
    return fmc.put(f"{SETTINGS}/{setting['id']}").mock(
        return_value=httpx.Response(200, json=LIVE["inherit_put"]["response"])
    )


def base_set(fmc: respx.MockRouter) -> None:
    child_and_parent(fmc)
    no_base(fmc, ACP_ID)
    fmc.get(f"{CFG}/policy/accesspolicies/{CHILD}/inheritancesettings").mock(
        return_value=httpx.Response(200, json=FX["inheritance_none_live"])
    )
    path = f"{CFG}/policy/accesspolicies/{CHILD}/inheritancesettings/{CHILD}"
    fmc.put(path).mock(return_value=httpx.Response(200, json=FX["inheritance_with_base_spec"]))
    fmc.get(path).mock(return_value=httpx.Response(200, json=FX["inheritance_with_base_spec"]))


async def test_create_with_a_base_inherits_the_base_logging(fmc: respx.MockRouter) -> None:
    acp_list(fmc, ACP)
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(200, json=fixture("accessrules"))
    )
    fmc.post(f"{CFG}/policy/accesspolicies").mock(return_value=httpx.Response(201, json=CHILD_ACP))
    path = f"{CFG}/policy/accesspolicies/{CHILD}/inheritancesettings/{CHILD}"
    fmc.put(path).mock(return_value=httpx.Response(200, json=FX["inheritance_with_base_spec"]))
    fmc.get(path).mock(return_value=httpx.Response(200, json=FX["inheritance_with_base_spec"]))
    put = child_settings(fmc, OWN)
    preview, done = await preview_apply(
        "fmc_create_access_policy", {"name": "mcp-w6-child-acp", "base_policy": "mcp-test-acp"}
    )
    assert preview["preview"]["logging"] == "inherited from 'mcp-test-acp'"
    assert any("Logging settings inherit from the base" in s for s in preview["side_effects"])
    assert json.loads(put.calls.last.request.content) == LIVE["inherit_put"]["request"]  # live-A's fix
    assert done["result"]["logging"] == "inherited from 'mcp-w6-acp'"  # FMC's answer names the base
    assert "warning" not in done["result"]


async def test_set_base_inherits_logging_when_fmc_needs_it(fmc: respx.MockRouter) -> None:
    """live-A's case: the base sends syslog through its Logging settings and the policy's own (FMC's
    defaults) have no syslog destination, so FMC would refuse the deployment: the default inherits."""
    base_set(fmc)
    put = child_settings(fmc, OWN)
    preview, done = await preview_apply(
        "fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "mcp-test-acp"}
    )
    assert preview["preview"]["logging"] == {
        "now": "its own (no syslog destination: FMC's defaults)",
        "after": "inherited from 'mcp-test-acp'",
    }
    assert any("inherit from the base from now on" in s for s in preview["side_effects"])
    assert any(
        "They inherit because FMC needs it: the base's Logging settings send syslog (connection syslog "
        "to the platform-settings servers)" in s
        for s in preview["side_effects"]
    )
    assert json.loads(put.calls.last.request.content)["inheritFromParent"] is True
    assert done["result"]["base_policy"] == "mcp-test-acp"
    assert done["result"]["logging"] == "inherited from 'mcp-w6-acp'"


async def test_set_base_keeps_own_logging_that_sends_syslog(fmc: respx.MockRouter) -> None:
    base_set(fmc)
    own = {**copy.deepcopy(OWN), "syslogConfigFromPlatformSetting": True}
    put = child_settings(fmc, own)
    preview, done = await preview_apply(
        "fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "mcp-test-acp"}
    )
    now = "its own (connection syslog to the platform-settings servers)"
    assert preview["preview"]["logging"] == {"now": now, "after": f"{now}, unchanged"}
    assert not any("Logging settings" in s for s in preview["side_effects"])
    assert put.call_count == 0 and "logging" not in done["result"]
    # asked for: inherit anyway
    _, done = await preview_apply(
        "fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "mcp-test-acp", "inherit_logging": True}
    )
    assert put.call_count == 1 and done["result"]["logging"] == "inherited from 'mcp-w6-acp'"


CORP = "00000000-0000-0ed3-0000-0000000000c0"


def moved_to_corp(fmc: respx.MockRouter, base_setting: dict[str, Any]) -> respx.Route:
    """mcp-w6-child-acp (base mcp-test-acp, assigned to mcp-ftd1) gets mcp-w6-corp-acp as its base; the new
    base's Logging settings are `base_setting`. Returns the inheritance PUT."""
    corp = {**copy.deepcopy(ACP), "id": CORP, "name": "mcp-w6-corp-acp"}
    child_and_parent(fmc)
    acp_list(fmc, ACP, CHILD_ACP, corp)
    base_logging(fmc, CORP, base_setting)
    fmc.get(f"{CFG}/policy/accesspolicies/{CORP}/accessrules").mock(return_value=items([]))
    with_base(fmc, CHILD, ACP_ID)
    no_base(fmc, ACP_ID)
    no_base(fmc, CORP)
    path = f"{CFG}/policy/accesspolicies/{CHILD}/inheritancesettings/{CHILD}"
    after = {
        **FX["inheritance_with_base_spec"],
        "id": CHILD,
        "basePolicy": {"id": CORP, "type": "AccessPolicy"},
    }
    fmc.get(path).mock(return_value=httpx.Response(200, json=after))
    return fmc.put(path).mock(return_value=httpx.Response(200, json=after))


async def test_moving_a_healthy_child_to_another_base_leaves_its_logging_alone(fmc: respx.MockRouter) -> None:
    """Review of #298: an existing (maybe deployed) child whose own Logging settings send no syslog, moved
    to a base whose Logging settings send none either, deploys as it is: its logging is not touched."""
    quiet = {
        **copy.deepcopy(LIVE["parent_loggingsettings"]["items"][0]),
        "syslogConfigFromPlatformSetting": False,
    }
    base_put = moved_to_corp(fmc, quiet)
    put = child_settings(fmc, OWN)
    preview, done = await preview_apply(
        "fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "mcp-w6-corp-acp"}
    )
    assert preview["preview"]["chain"]["to"] == ["mcp-w6-child-acp", "mcp-w6-corp-acp"]
    now = "its own (no syslog destination: FMC's defaults)"
    assert preview["preview"]["logging"] == {"now": now, "after": f"{now}, unchanged"}
    assert not any("Logging settings" in s for s in preview["side_effects"])
    assert base_put.call_count == 1 and put.call_count == 0
    assert done["result"]["base_policy"] == "mcp-w6-corp-acp" and "logging" not in done["result"]
    # inherit_logging=True: inherit even so
    preview, done = await preview_apply(
        "fmc_set_base_policy",
        {"policy": "mcp-w6-child-acp", "base": "mcp-w6-corp-acp", "inherit_logging": True},
    )
    assert preview["preview"]["logging"]["after"] == "inherited from 'mcp-w6-corp-acp'"
    assert any("inherit from the base from now on" in s for s in preview["side_effects"])
    assert put.call_count == 1 and json.loads(put.calls.last.request.content)["inheritFromParent"] is True


async def test_a_child_that_already_inherits_keeps_inheriting_from_the_new_base(
    fmc: respx.MockRouter,
) -> None:
    moved_to_corp(fmc, LIVE["parent_loggingsettings"]["items"][0])
    put = child_settings(fmc, LIVE["inherit_put"]["response"])
    preview, done = await preview_apply(
        "fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "mcp-w6-corp-acp"}
    )
    assert preview["preview"]["logging"] == {
        "now": "inherited from the base policy",
        "after": "inherited from 'mcp-w6-corp-acp'",
    }
    assert put.call_count == 0 and "logging" not in done["result"]
    # inherit_logging=False doesn't un-inherit (not recorded over REST): the preview says so, nothing is PUT
    preview, _ = await preview_apply(
        "fmc_set_base_policy",
        {"policy": "mcp-w6-child-acp", "base": "mcp-w6-corp-acp", "inherit_logging": False},
    )
    assert any("inherit_logging=False doesn't stop that" in s for s in preview["side_effects"])
    assert put.call_count == 0


async def test_set_base_inherit_logging_false_keeps_fmc_defaults(fmc: respx.MockRouter) -> None:
    base_set(fmc)
    put = child_settings(fmc, OWN)
    preview, _ = await preview_apply(
        "fmc_set_base_policy",
        {"policy": "mcp-w6-child-acp", "base": "mcp-test-acp", "inherit_logging": False},
    )
    now = "its own (no syslog destination: FMC's defaults)"
    assert preview["preview"]["logging"] == {"now": now, "after": f"{now}, unchanged"}
    assert any(s.startswith("Keeps its own Logging settings") for s in preview["side_effects"])
    assert any("fmc_set_access_logging use_platform_syslog=True" in s for s in preview["side_effects"])
    assert put.call_count == 0
    with pytest.raises(ToolError, match="inherit_logging goes with a base policy"):
        await preview_only(
            "fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "none", "inherit_logging": True}
        )


async def test_unreadable_base_logging_leaves_the_policy_alone(fmc: respx.MockRouter) -> None:
    base_set(fmc)
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/loggingsettings").mock(
        return_value=httpx.Response(500, json={"error": {"messages": [{"description": "boom"}]}})
    )
    put = child_settings(fmc, OWN)
    preview, _ = await preview_apply(
        "fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "mcp-test-acp"}
    )
    assert any("The base's Logging settings couldn't be read" in s for s in preview["side_effects"])
    assert put.call_count == 0


async def test_fmc_refusing_the_logging_change_is_a_warning(fmc: respx.MockRouter) -> None:
    base_set(fmc)
    put = child_settings(fmc, OWN)
    put.mock(return_value=httpx.Response(422, json={"error": {"messages": [{"description": "Not allowed"}]}}))
    _, done = await preview_apply(
        "fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "mcp-test-acp"}
    )
    assert done["result"]["base_policy"] == "mcp-test-acp"  # the base is set either way
    assert done["result"]["logging"] == "its own (unchanged)"
    assert "fmc_set_access_logging(use_platform_syslog=True)" in done["result"]["warning"]
