"""F51d: device templates (list, get, create from a device or parameters, delete, apply).

Template responses replay tests/fixtures/devicetemplates.json (FMC 10.0.1 spec examples until re-recorded
with `scripts/capture_fixtures.py --templates`); the device is the recorded FTDv (ftd_device.json)."""

import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

import fmc_mcp._core.policy
from fmc_mcp.server import create_server
from fmc_mcp.tools.templates import check_value

from .conftest import CFG, fixture, items, make_settings

REC = {k: v for k, v in fixture("devicetemplates").items() if k.startswith("/api/")}
TID = "b02a4b38-c000-11ee-b131-635e66f9d48b"
BASE = f"{CFG}/templates/devicetemplates/{TID}"
DEV = {**fixture("ftd_device"), "id": "5e1f0000-0000-0000-0000-000000000002", "name": "mcp-sdwan-t1-spoke2"}
SRC = {**fixture("ftd_device"), "id": "cf7fa0b2-bf30-11ee-be1a-ab9df8d04efd", "name": "mcp-sdwan-t1-spoke1"}
ACP = {"id": "0050568A-02BD-0ed3-0000-008589934661", "name": "mcp-sdwan-acp", "type": "AccessPolicy"}
TEMPLATE = "mcp-sdwan-spoke-tmpl"


def server(**kw: Any) -> Any:
    return create_server(
        make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, rate_limit=100000, **kw)
    )


async def run(c: Client[Any], name: str, args: dict[str, Any], **kw: Any) -> Any:
    r = await c.call_tool(name, args, **kw)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def replay(fmc: respx.MockRouter, *, pairs: list[Any] | None = None) -> respx.MockRouter:
    for path, body in REC.items():
        fmc.get(path).mock(return_value=httpx.Response(200, json=body))
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([SRC, DEV]))
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items(pairs or []))
    fmc.get(f"{CFG}/deviceclusters/ftddevicecluster").mock(return_value=items([]))
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    return fmc


def test_check_value() -> None:
    assert check_value("AS_NUMBER", "65001") is None and check_value("AS_NUMBER", "65000.1") is None
    assert check_value("AS_NUMBER", "0") and check_value("AS_NUMBER", "abc")
    assert check_value("IPV4_HOST", "10.1.1.1/24") is None and check_value("IPV4_HOST", "10.1.1.300")
    assert check_value("ROUTER_ID", "1.1.1.1") is None and check_value("ROUTER_ID", "1.1.1.1/32")
    assert check_value("IPV4_NETWORK", "10.10.1.0/24") is None and check_value(
        "IPV4_NETWORK", "2001:db8::/32"
    )
    assert check_value("IPV6_HOST", "2001:db8::1") is None and check_value("IPV6_NETWORK", "10.0.0.0/8")
    assert check_value("IPV4_RANGE", "10.0.0.10-10.0.0.20") is None and check_value(
        "IPV4_RANGE", "10.0.0.20-10.0.0.1"
    )
    assert check_value("FQDN", "branch1.example.com") is None and check_value("FQDN", "not a name")
    assert check_value("STRING", "x") is None and check_value("PASSWORD", " ")
    assert check_value("HOST", "192.0.2.1") is None and check_value("NETWORK", "nope")


async def test_list_templates(fmc: respx.MockRouter) -> None:
    replay(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_list_device_templates", {"response_format": "json"})
    rows = {r["name"]: r for r in out["results"]}
    assert rows[TEMPLATE]["firewall_mode"] == "ROUTED" and rows[TEMPLATE]["access_policy"] == "mcp-sdwan-acp"
    assert rows["mcp-sdwan-transparent-tmpl"]["firewall_mode"] == "TRANSPARENT"


async def test_get_template_in_full_masks_passwords(fmc: respx.MockRouter) -> None:
    replay(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_get_device_template", {"template": TEMPLATE})
    text = json.dumps(out)
    assert "tmpl-default-secret" not in text and "spoke1-secret" not in text
    variables = {v["name"]: v for v in out["variables"]}
    assert (
        variables["localPassword"]["default"] == "********" and variables["bgpAsnumber"]["default"] == "65001"
    )
    assert "default" not in variables["wanIp"]
    assert out["interfaces"][0]["ipv4"] == "${wanIp}" and out["interfaces"][0]["zone"] == "mcp-sdwan-outside"
    vpn = out["vpn_settings"][0]
    assert vpn["topology"] == "mcp-sdwan-t1" and vpn["role"] == "SPOKE"
    assert vpn["connections"][0]["ipv4"] == "${wanIp}"
    assert out["model_mappings"][0]["interfaces"]["Ethernet1/1"] == "GigabitEthernet0/0"
    assert [o["name"] for o in out["object_overrides"]] == ["mcp-sdwan-branch-gw", "mcp-sdwan-branch-lan"]
    dev = out["devices"][0]
    assert dev["device"] == "mcp-sdwan-t1-spoke1" and dev["last_applied"] == "SUCCESS"
    assert dev["variables"] == {"wanIp": "192.0.2.11/29", "localPassword": "********"}
    assert "mcp-sdwan-nat (FTDNatPolicy)" in out["other_policies"]


async def test_get_template_masks_every_device_value_when_variables_fail(fmc: respx.MockRouter) -> None:
    replay(fmc)
    fmc.get(f"{BASE}/variables").mock(return_value=httpx.Response(500, json={"error": "boom"}))
    async with Client(server()) as c:
        out = await run(c, "fmc_get_device_template", {"template": TEMPLATE})
    assert "error" in out["variables"]
    assert out["devices"][0]["variables"] == {"wanIp": "********", "localPassword": "********"}


async def test_create_from_device_waits_for_task(fmc: respx.MockRouter) -> None:
    replay(fmc)
    fmc.get(f"{CFG}/templates/devicetemplates").mock(
        side_effect=[
            httpx.Response(200, json=REC[f"{CFG}/templates/devicetemplates"]),
            httpx.Response(200, json=REC[f"{CFG}/templates/devicetemplates"]),
            items(
                [
                    {
                        "id": "new-1",
                        "name": "mcp-sdwan-spoke-gen",
                        "firewallMode": "ROUTED",
                        "accessPolicy": ACP,
                    }
                ]
            ),
        ]
    )
    post = fmc.post(f"{CFG}/templates/devicetemplates/operational/generatetemplate").mock(
        return_value=httpx.Response(
            202,
            json={"metadata": {"task": {"id": "81604391786", "taskType": "DEVICE_TEMPLATE_CREATION"}}},
        )
    )
    fmc.get(f"{CFG}/job/taskstatuses/81604391786").mock(
        return_value=httpx.Response(200, json={"id": "81604391786", "status": "SUCCESS"})
    )
    args = {
        "name": "mcp-sdwan-spoke-gen",
        "source_device": "mcp-sdwan-t1-spoke1",
        "description": "from spoke1",
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_device_template", args)
        assert preview["status"] == "preview", preview
        assert preview["preview"]["from_device"]["name"] == "mcp-sdwan-t1-spoke1"
        assert preview["preview"]["access_policy"] == "mcp-test-ftd-acp"  # the device's own
        assert not post.called
        done = await run(c, "fmc_create_device_template", {**args, "confirm": preview["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "name": "mcp-sdwan-spoke-gen",
        "source": {"id": SRC["id"], "type": "Device"},
        "description": "from spoke1",
    }
    assert done["result"]["task"]["status"] == "SUCCESS"
    assert done["result"]["template"]["id"] == "new-1"


async def test_create_from_parameters(fmc: respx.MockRouter) -> None:
    replay(fmc)
    post = fmc.post(f"{CFG}/templates/devicetemplates").mock(
        return_value=httpx.Response(
            201,
            json={"id": "new-2", "name": "mcp-sdwan-empty", "firewallMode": "ROUTED", "accessPolicy": ACP},
        )
    )
    args = {"name": "mcp-sdwan-empty", "access_policy": "mcp-sdwan-acp"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_device_template", args)
        done = await run(c, "fmc_create_device_template", {**args, "confirm": preview["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "name": "mcp-sdwan-empty",
        "type": "DeviceTemplate",
        "firewallMode": "ROUTED",
        "accessPolicy": {"id": ACP["id"], "type": "AccessPolicy"},
    }
    assert done["result"]["template"]["name"] == "mcp-sdwan-empty"


async def test_create_blocked_for_duplicate_and_ha_member(fmc: respx.MockRouter) -> None:
    pair = {"id": "ha-1", "name": "mcp-sdwan-t3-hub", "primary": {"id": SRC["id"]}, "secondary": {"id": "x"}}
    replay(fmc, pairs=[pair])
    async with Client(server()) as c:
        out = await run(c, "fmc_create_device_template", {"name": TEMPLATE, "source_device": SRC["name"]})
        with pytest.raises(Exception, match="source_device"):
            await run(c, "fmc_create_device_template", {"name": "x"})
    assert out["status"] == "blocked"
    assert any("already exists" in b for b in out["blockers"])
    assert any("HA pair 'mcp-sdwan-t3-hub'" in b for b in out["blockers"])


async def test_delete_template(fmc: respx.MockRouter) -> None:
    replay(fmc)
    delete = fmc.delete(BASE).mock(return_value=httpx.Response(200, json=REC[BASE]))
    async with Client(server()) as c:
        preview = await run(c, "fmc_delete_device_template", {"template": TEMPLATE})
        assert any("mcp-sdwan-t1-spoke1" in s for s in preview["side_effects"])
        assert "spoke1-secret" not in json.dumps(preview)
        done = await run(
            c, "fmc_delete_device_template", {"template": TEMPLATE, "confirm": preview["confirm"]}
        )
    assert delete.called and done["result"]["deleted"] == TEMPLATE


APPLY = {
    "template": TEMPLATE,
    "device": "mcp-sdwan-t1-spoke2",
    "variables": {"wanIp": "192.0.2.12/29", "localPassword": "spoke2-secret"},
    "overrides": {"mcp-sdwan-branch-lan": "10.10.2.0/24"},
}


async def test_apply_preview_lists_every_variable_and_override(fmc: respx.MockRouter) -> None:
    replay(fmc)
    post = fmc.post(f"{BASE}/operational/apply")
    async with Client(server()) as c:
        preview = await run(c, "fmc_apply_device_template", APPLY)
    assert preview["status"] == "preview", preview
    assert not post.called
    assert "spoke2-secret" not in json.dumps(preview) and "tmpl-default-secret" not in json.dumps(preview)
    p = preview["preview"]
    rows = {v["name"]: v for v in p["variables"]}
    assert rows["wanIp"] == {
        "name": "wanIp",
        "type": "IPV4_HOST",
        "value": "192.0.2.12/29",
        "source": "given",
    }
    assert rows["insideIp"]["source"] == "template default" and rows["insideIp"]["value"] == "10.10.1.1/24"
    assert rows["bgpAsnumber"]["value"] == "65001"
    assert rows["localPassword"]["value"] == "********" and rows["localPassword"]["default"] == "********"
    ov = {o["name"]: o for o in p["object_overrides"]}
    assert ov["mcp-sdwan-branch-lan"] == {
        "name": "mcp-sdwan-branch-lan",
        "type": "Network",
        "current": "10.10.1.0/24",
        "value": "10.10.2.0/24",
    }
    assert ov["mcp-sdwan-branch-gw"]["current"] == "10.10.1.254" and ov["mcp-sdwan-branch-gw"][
        "value"
    ].startswith("keep")
    assert p["current_template"] is None and p["device"]["name"] == "mcp-sdwan-t1-spoke2"
    effects = " ".join(preview["side_effects"])
    assert "Replaces 'mcp-sdwan-t1-spoke2'" in effects and "VPN topology 'mcp-sdwan-t1' as SPOKE" in effects
    assert "No model mapping for 'Cisco Secure Firewall Threat Defense for KVM'" in effects
    assert "fmc_deploy" in effects


async def test_apply_confirm_posts_and_waits(fmc: respx.MockRouter) -> None:
    replay(fmc)
    post = fmc.post(f"{BASE}/operational/apply").mock(
        return_value=httpx.Response(
            202, json={"metadata": {"task": {"id": "25769804964", "taskType": "DEVICE_TEMPLATE_APPLY"}}}
        )
    )
    fmc.get(f"{CFG}/job/taskstatuses/25769804964").mock(
        return_value=httpx.Response(200, json={"id": "25769804964", "status": "SUCCESS"})
    )
    args = {**APPLY, "deploy": True}
    async with Client(server()) as c:
        preview = await run(c, "fmc_apply_device_template", args)
        assert any("postApplyAction=DEPLOY" in s for s in preview["side_effects"])
        done = await run(c, "fmc_apply_device_template", {**args, "confirm": preview["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "applyToDevices": [
            {
                "device": {"id": DEV["id"], "type": "Device"},
                "variableValues": [
                    {"key": "localPassword", "value": "spoke2-secret"},
                    {"key": "wanIp", "value": "192.0.2.12/29"},
                ],
                "postApplyAction": "DEPLOY",
                "overriddenValues": {
                    "networks": [
                        {
                            "name": "mcp-sdwan-branch-lan",
                            "id": "0050568C-0030-0ed3-0000-034359738418",
                            "type": "Network",
                            "value": "10.10.2.0/24",
                        }
                    ]
                },
            }
        ]
    }
    assert done["result"]["task"]["status"] == "SUCCESS"
    assert "fmc_list_deployments" in done["result"]["next"]
    assert "spoke2-secret" not in json.dumps(done)


async def test_apply_blocks_bad_input(fmc: respx.MockRouter) -> None:
    replay(fmc)
    args = {
        "template": TEMPLATE,
        "device": "mcp-sdwan-t1-spoke2",
        "variables": {"bgpAsnumber": "not-an-as", "wanIp": "", "typo": "1", "localPassword": "s3cret-pw"},
        "overrides": {"mcp-sdwan-branch-gw": "10.0.0.0/8/9", "nope": "1.1.1.1"},
    }
    async with Client(server()) as c:
        out = await run(c, "fmc_apply_device_template", args)
    assert out["status"] == "blocked"
    text = " | ".join(out["blockers"])
    assert (
        "no variable(s) typo" in text and "bgpAsnumber (AS_NUMBER) = 'not-an-as' is not an AS number" in text
    )
    assert "wanIp (IPV4_HOST) = '' is not a non-empty value" in text
    assert "no overridable object(s) nope" in text and "mcp-sdwan-branch-gw (Host)" in text
    assert "s3cret-pw" not in json.dumps(out)


async def test_apply_blocks_missing_variable_mode_and_ha(fmc: respx.MockRouter) -> None:
    pair = {"id": "ha-1", "name": "mcp-sdwan-t3-hub", "primary": {"id": DEV["id"]}, "secondary": {"id": "x"}}
    replay(fmc, pairs=[pair])
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([SRC, {**DEV, "ftdMode": "TRANSPARENT"}]))
    async with Client(server()) as c:
        out = await run(c, "fmc_apply_device_template", {"template": TEMPLATE, "device": DEV["name"]})
    text = " | ".join(out["blockers"])
    assert "wanIp (IPV4_HOST) has no template default" in text
    assert "is ROUTED but 'mcp-sdwan-t1-spoke2' runs TRANSPARENT" in text
    assert "member of HA pair 'mcp-sdwan-t3-hub'" in text


async def test_apply_outside_deploy_window_is_blocked(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    replay(fmc)
    # Wednesday 12:00 UTC; the window is Saturday nights only
    monkeypatch.setattr(fmc_mcp._core.policy, "_now", lambda: datetime(2026, 10, 14, 12, 0, tzinfo=UTC))
    async with Client(server(deploy_window="Sat 22:00-04:00 UTC")) as c:
        out = await run(c, "fmc_apply_device_template", APPLY)
    assert out["status"] == "blocked" and any("deploy window" in b for b in out["blockers"])


async def test_apply_needs_dangerous_tier(fmc: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        names = {t.name for t in await c.list_tools()}
    assert "fmc_create_device_template" in names and "fmc_apply_device_template" not in names
