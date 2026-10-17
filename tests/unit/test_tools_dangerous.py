"""Dangerous tools. The lab FMC manages no devices, so deploy/registration/HA are tested here only."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.dangerous import task_state

from .conftest import ACP_ID, CFG, empty, items, make_settings

DEV = {"id": "11111111-0000-0000-0000-000000000001", "name": "ftd1", "type": "Device", "hostName": "10.0.0.1"}
DEV2 = {
    "id": "11111111-0000-0000-0000-000000000002",
    "name": "ftd2",
    "type": "Device",
    "hostName": "10.0.0.2",
}
PENDING = {
    "name": "ftd1",
    "version": "1791980000000",
    "canBeDeployed": True,
    "trafficInterruption": "NO",
    "device": {"id": DEV["id"], "name": "ftd1", "type": "Device"},
    "policyStatusList": [{"policy": {"type": "AccessPolicy", "name": "acp"}, "upToDate": False}],
}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def confirm(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        assert preview["status"] == "preview", preview
        return preview, await run(c, name, {**args, "confirm": preview["confirm"]})


def test_task_state() -> None:
    assert task_state({"status": "Deployed"}) == (True, None)
    assert task_state({"status": "Deploying"}) == (False, None)
    done, err = task_state({"status": "Failed", "message": "boom"})
    assert done and err == "Failed: boom"


async def test_deploy_all_pending_and_wait(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([PENDING]))
    post = fmc.post(f"{CFG}/deployment/deploymentrequests").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "t1", "type": "Task"}}})
    )
    fmc.get(f"{CFG}/job/taskstatuses/t1").mock(
        return_value=httpx.Response(200, json={"id": "t1", "status": "Deployed", "message": "ok"})
    )
    preview, done = await confirm("fmc_deploy", {"note": "mcp"})
    assert preview["preview"]["devices"][0]["out_of_date_policies"] == ["AccessPolicy:acp"]
    body = json.loads(post.calls.last.request.content)
    assert body["deviceList"] == [DEV["id"]] and body["version"] == "1791980000000"
    assert body["deploymentNote"] == "mcp" and body["ignoreWarning"] is False
    assert done["result"]["task"]["status"] == "Deployed"


async def test_deploy_failed_task_is_error(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([PENDING]))
    fmc.post(f"{CFG}/deployment/deploymentrequests").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "t2"}}})
    )
    fmc.get(f"{CFG}/job/taskstatuses/t2").mock(
        return_value=httpx.Response(200, json={"id": "t2", "status": "Failed", "message": "validation"})
    )
    async with Client(server()) as c:
        preview = await run(c, "fmc_deploy", {})
        r = await c.call_tool("fmc_deploy", {"confirm": preview["confirm"]}, raise_on_error=False)
    assert r.is_error and "validation" in r.content[0].text  # type: ignore[union-attr]


async def test_deploy_nothing_pending_is_blocked(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=empty())
    async with Client(server()) as c:
        out = await run(c, "fmc_deploy", {})
    assert out["status"] == "blocked"


async def test_register_device_masks_key(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(
        return_value=items([{"id": ACP_ID, "name": "acp", "type": "AccessPolicy"}])
    )
    post = fmc.post(f"{CFG}/devices/devicerecords").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "t3"}}})
    )
    args = {
        "name": "ftd9",
        "host": "10.0.0.9",
        "reg_key": "s3cret-key",
        "access_policy": "acp",
        "wait": False,
    }
    preview, done = await confirm("fmc_register_device", args)
    assert "s3cret-key" not in json.dumps(preview)
    assert json.loads(post.calls.last.request.content)["regKey"] == "s3cret-key"
    assert done["result"] == {"task_id": "t3", "note": "Started; check progress with fmc_get_task."}


def _register_mocks(fmc: respx.MockRouter) -> respx.Route:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(
        return_value=items([{"id": ACP_ID, "name": "acp", "type": "AccessPolicy"}])
    )
    return fmc.post(f"{CFG}/devices/devicerecords").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "t3"}}})
    )


async def test_register_device_key_from_server_config(fmc: respx.MockRouter) -> None:
    post = _register_mocks(fmc)
    args = {"name": "ftd9", "host": "10.0.0.9", "access_policy": "acp", "wait": False}
    settings = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, ftd_reg_key="cfg-k3y")
    async with Client(create_server(settings)) as c:
        preview = await run(c, "fmc_register_device", args)
        assert preview["status"] == "preview", preview
        assert preview["preview"]["registration_key"] == "from server config (FMC_FTD_REG_KEY)"
        done = await run(c, "fmc_register_device", {**args, "confirm": preview["confirm"]})
    assert "cfg-k3y" not in json.dumps(preview) + json.dumps(done)
    assert json.loads(post.calls.last.request.content)["regKey"] == "cfg-k3y"


async def test_register_device_argument_overrides_server_key(fmc: respx.MockRouter) -> None:
    post = _register_mocks(fmc)
    args = {"name": "ftd9", "host": "10.0.0.9", "access_policy": "acp", "reg_key": "arg-key", "wait": False}
    settings = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, ftd_reg_key="cfg-k3y")
    async with Client(create_server(settings)) as c:
        preview = await run(c, "fmc_register_device", args)
        assert preview["preview"]["registration_key"] == "from argument"
        await run(c, "fmc_register_device", {**args, "confirm": preview["confirm"]})
    assert json.loads(post.calls.last.request.content)["regKey"] == "arg-key"


async def test_register_device_needs_a_key(fmc: respx.MockRouter) -> None:
    post = _register_mocks(fmc)
    args = {"name": "ftd9", "host": "10.0.0.9", "access_policy": "acp"}
    async with Client(server()) as c:
        r = await c.call_tool("fmc_register_device", args, raise_on_error=False)
    assert r.is_error and "FMC_FTD_REG_KEY" in r.content[0].text  # type: ignore[union-attr]
    assert not post.calls


async def test_ha_break(fmc: respx.MockRouter) -> None:
    ha = {"id": "22222222-0000-0000-0000-000000000001", "name": "ha1", "primary": DEV, "secondary": DEV2}
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([ha]))
    put = fmc.put(f"{CFG}/devicehapairs/ftddevicehapairs/{ha['id']}").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "t4"}}})
    )
    preview, _ = await confirm("fmc_ha_action", {"ha_pair": "ha1", "action": "break", "wait": False})
    assert preview["preview"] == {"domain": "Global", "primary": "ftd1", "secondary": "ftd2"}
    assert preview["blast_radius"] == 2
    assert json.loads(put.calls.last.request.content) == {
        "id": ha["id"],
        "action": "HABREAK",
        "forceBreak": False,
    }


async def test_create_ha_pair(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV, DEV2]))
    fmc.get(f"{CFG}/devices/devicerecords/{DEV['id']}/physicalinterfaces").mock(
        return_value=items([{"id": "if7", "name": "GigabitEthernet0/7", "type": "PhysicalInterface"}])
    )
    post = fmc.post(f"{CFG}/devicehapairs/ftddevicehapairs").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "t5"}}})
    )
    await confirm(
        "fmc_create_ha_pair",
        {
            "name": "ha1",
            "primary": "ftd1",
            "secondary": "ftd2",
            "failover_interface": "gigabitethernet0/7",
            "active_ip": "192.0.2.1",
            "standby_ip": "192.0.2.2",
            "subnet_mask": "255.255.255.252",
            "wait": False,
        },
    )
    body = json.loads(post.calls.last.request.content)
    assert body["primary"] == {"id": DEV["id"]} and body["secondary"] == {"id": DEV2["id"]}
    assert body["ftdHABootstrap"]["lanFailover"]["interfaceObject"]["id"] == "if7"


async def test_delete_policy_blocked_when_assigned(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(
        return_value=items([{"id": ACP_ID, "name": "acp", "type": "AccessPolicy"}])
    )
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(return_value=empty())
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items([{"id": ACP_ID, "policy": {"id": ACP_ID, "name": "acp"}, "targets": [DEV]}])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_delete_policy", {"kind": "access", "policy": "acp"})
    assert out["status"] == "blocked" and "ftd1" in out["blockers"][0]


async def test_delete_policy(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(
        return_value=items([{"id": ACP_ID, "name": "acp", "type": "AccessPolicy"}])
    )
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(return_value=items([{"id": "r"}]))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=empty())
    delete = fmc.delete(f"{CFG}/policy/accesspolicies/{ACP_ID}").mock(
        return_value=httpx.Response(200, json={})
    )
    preview, _ = await confirm("fmc_delete_policy", {"kind": "access", "policy": "acp"})
    assert preview["preview"]["rules"] == 1 and delete.call_count == 1


async def test_ha_switch_shows_state_and_rejects_force(fmc: respx.MockRouter) -> None:
    ha = {
        "id": "22222222-0000-0000-0000-000000000001",
        "name": "ha1",
        "primary": DEV,
        "secondary": DEV2,
        "metadata": {
            "primaryStatus": {"currentStatus": "Active"},
            "secondaryStatus": {"currentStatus": "Standby"},
        },
    }
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([ha]))
    put = fmc.put(f"{CFG}/devicehapairs/ftddevicehapairs/{ha['id']}").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "t6"}}})
    )
    preview, done = await confirm("fmc_ha_action", {"ha_pair": "ha1", "action": "switch", "wait": False})
    assert preview["preview"]["primary_status"] == "Active"
    assert json.loads(put.calls.last.request.content) == {"id": ha["id"], "action": "SWITCH"}
    assert done["result"]["task_id"] == "t6"
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_ha_action", {"ha_pair": "ha1", "action": "switch", "force": True}, raise_on_error=False
        )
    assert r.is_error


async def test_delete_device_returns_task(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.delete(f"{CFG}/devices/devicerecords/{DEV['id']}").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "t7"}}})
    )
    _, done = await confirm("fmc_delete_device", {"device": "ftd1"})
    assert done["result"]["task_id"] == "t7"


async def test_deploy_task_failure_names_task(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([PENDING]))
    fmc.post(f"{CFG}/deployment/deploymentrequests").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "t8"}}})
    )
    fmc.get(f"{CFG}/job/taskstatuses/t8").mock(
        return_value=httpx.Response(200, json={"status": "Deploy Failed"})
    )
    async with Client(server()) as c:
        preview = await run(c, "fmc_deploy", {})
        r = await c.call_tool("fmc_deploy", {"confirm": preview["confirm"]}, raise_on_error=False)
    assert r.is_error and "task t8" in r.content[0].text  # type: ignore[union-attr]


async def test_deploy_blocked_while_deploying(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(
        return_value=items([{**PENDING, "isDeploying": True}])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_deploy", {})
    assert out["status"] == "blocked" and "already being deployed" in out["blockers"][0]
