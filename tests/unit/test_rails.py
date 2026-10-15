"""F18 deploy safety rails: device counting, FMC_DEPLOY_WINDOW, ignore_warning policy, rollback depth."""

import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
import stutters_mcp_core.policy
from fastmcp import Client

from fmc_mcp.rails import split_warnings
from fmc_mcp.server import create_server

from .conftest import CFG, items, make_settings

DEV_ID = "11111111-0000-0000-0000-000000000001"
CLUSTER_ID = "33333333-0000-0000-0000-000000000001"
PENDING = {
    "name": "ftd1",
    "version": "7",
    "canBeDeployed": True,
    "device": {"id": DEV_ID, "name": "ftd1", "type": "Device"},
}
CLUSTER = {
    "name": "cl1",
    "version": "8",
    "canBeDeployed": True,
    "device": {"id": CLUSTER_ID, "name": "cl1", "type": "DeviceCluster"},
}
WARN = {
    "error": {
        "messages": [
            {"description": "Errors or warnings present in Device committed policies:"},
            {"description": "Rule 'x' has a duplicate object"},
        ]
    }
}


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, **kw))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def test_split_warnings() -> None:
    text = "FMC rejected the request (400) on POST /api/x/deploymentrequests: A | B c: d"
    assert split_warnings(text) == ["A", "B c: d"]


def test_bad_deploy_window_is_a_settings_error() -> None:
    with pytest.raises(ValueError, match="FMC_DEPLOY_WINDOW"):
        make_settings(deploy_window="Someday 25:00-26:00")


async def test_cluster_counts_its_members_and_blast_limit_blocks(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([CLUSTER]))
    fmc.get(f"{CFG}/deviceclusters/ftddevicecluster/{CLUSTER_ID}").mock(
        return_value=httpx.Response(200, json={"id": CLUSTER_ID, "dataDevices": [{"id": "a"}, {"id": "b"}]})
    )
    async with Client(server(mcp_blast_radius_overrides="fmc_deploy=2")) as c:
        out = await run(c, "fmc_deploy", {})
    assert out["blast_radius"] == 3 and out["preview"]["device_count"] == 3
    assert out["status"] == "blocked" and "blast radius 3" in json.dumps(out)


async def test_deploy_window_blocks_outside(fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([PENDING]))
    # Wednesday 12:00 UTC; the window is Saturday nights only
    monkeypatch.setattr(stutters_mcp_core.policy, "_now", lambda: datetime(2026, 10, 14, 12, 0, tzinfo=UTC))
    async with Client(server(deploy_window="Sat 22:00-04:00 UTC")) as c:
        out = await run(c, "fmc_deploy", {})
        assert out["status"] == "blocked", out
        assert "FMC_DEPLOY_WINDOW" in json.dumps(out) and "next opens" in json.dumps(out)
        # object edits are not limited by the deploy window
        fmc.get(f"{CFG}/object/hosts").mock(return_value=items([]))
        fmc.get(f"{CFG}/object/networkaddresses").mock(return_value=items([]))
        fmc.get(f"{CFG}/object/ranges").mock(return_value=items([]))
        obj = await run(c, "fmc_create_object", {"name": "h1", "type": "host", "value": "10.0.0.1"})
        assert obj["status"] == "preview", obj


async def test_deploy_window_open_allows(fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([PENDING]))
    monkeypatch.setattr(stutters_mcp_core.policy, "_now", lambda: datetime(2026, 10, 17, 23, 0, tzinfo=UTC))
    async with Client(server(deploy_window="Sat 22:00-04:00 UTC")) as c:
        out = await run(c, "fmc_deploy", {})
    assert out["status"] == "preview" and out["preview"]["deploy_window"]["open"] is True


async def test_ignore_warning_disabled_by_default(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([PENDING]))
    async with Client(server()) as c:
        out = await run(c, "fmc_deploy", {"ignore_warning": True})
    assert out["status"] == "blocked" and "FMC_ALLOW_IGNORE_WARNING" in json.dumps(out)


async def test_ignore_warning_needs_seen_warnings_for_same_version(fmc: respx.MockRouter) -> None:
    route = fmc.get(f"{CFG}/deployment/deployabledevices")
    route.mock(return_value=items([PENDING]))
    post = fmc.post(f"{CFG}/deployment/deploymentrequests")
    post.mock(return_value=httpx.Response(400, json=WARN))
    async with Client(server(allow_ignore_warning=True)) as c:
        blind = await run(c, "fmc_deploy", {"ignore_warning": True})
        assert blind["status"] == "blocked" and "deploy without ignore_warning first" in json.dumps(blind)
        first = await run(c, "fmc_deploy", {})
        r = await c.call_tool("fmc_deploy", {"confirm": first["confirm"]}, raise_on_error=False)
        assert r.is_error and "nothing was deployed" in r.content[0].text  # type: ignore[union-attr]
        seen = await run(c, "fmc_deploy", {"ignore_warning": True, "wait": False})
        assert seen["status"] == "preview"
        assert seen["preview"]["warnings_ignored"] == [
            "Errors or warnings present in Device committed policies:",
            "Rule 'x' has a duplicate object",
        ]
        warnings = {"now": WARN}

        def fmc_reply(req: httpx.Request) -> httpx.Response:
            if json.loads(req.content)["ignoreWarning"]:
                return httpx.Response(202, json={"metadata": {"task": {"id": "t9"}}})
            return httpx.Response(400, json=warnings["now"])

        post.mock(side_effect=fmc_reply)
        # FMC's warnings changed after the preview: refused, nothing ignored
        warnings["now"] = {"error": {"messages": [{"description": "A brand-new warning"}]}}
        r = await c.call_tool(
            "fmc_deploy",
            {"ignore_warning": True, "wait": False, "confirm": seen["confirm"]},
            raise_on_error=False,
        )
        assert r.is_error and "changed since the preview" in r.content[0].text  # type: ignore[union-attr]
        assert json.loads(post.calls.last.request.content)["ignoreWarning"] is False
        # back to the reviewed warnings: the re-check matches and the deploy ignores them
        warnings["now"] = WARN
        seen = await run(c, "fmc_deploy", {"ignore_warning": True, "wait": False})
        assert seen["preview"]["warnings_ignored"] == ["A brand-new warning"]  # the latest attempt's set
        r = await c.call_tool(
            "fmc_deploy",
            {"ignore_warning": True, "wait": False, "confirm": seen["confirm"]},
            raise_on_error=False,
        )
        assert r.is_error  # WARN differs from "A brand-new warning" again
        seen = await run(c, "fmc_deploy", {"ignore_warning": True, "wait": False})
        done = await run(c, "fmc_deploy", {"ignore_warning": True, "wait": False, "confirm": seen["confirm"]})
        assert done["status"] == "applied"
        assert json.loads(post.calls.last.request.content)["ignoreWarning"] is True
        # a new pending version (more changes) needs a fresh look at the warnings
        route.mock(return_value=items([{**PENDING, "version": "8"}]))
        again = await run(c, "fmc_deploy", {"ignore_warning": True})
        assert again["status"] == "blocked"


async def test_rollback_lists_undone_deployments(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(
        return_value=items([{"id": DEV_ID, "name": "ftd1", "type": "Device"}])
    )
    jobs = [
        {"id": f"j{i}", "name": f"Deploy_Job_{i}", "status": "SUCCEEDED", "startTime": 1000 + i}
        for i in range(1, 5)
    ]
    fmc.get(f"{CFG}/deployment/deployabledevices/{DEV_ID}/deployments").mock(return_value=items(jobs))
    async with Client(server()) as c:
        default = await run(c, "fmc_rollback_deployment", {"device": "ftd1"})
        assert default["preview"]["undoes_deployments"] == ["Deploy_Job_4"]
        assert default["blast_radius"] == 1 and default["preview"]["domain"] == "Global"
        deep = await run(c, "fmc_rollback_deployment", {"device": "ftd1", "to_job": "Deploy_Job_1"})
    assert deep["preview"]["undoes_deployments"] == ["Deploy_Job_4", "Deploy_Job_3", "Deploy_Job_2"]
    assert any("Undoes 3 successful deployments" in s for s in deep["side_effects"])


async def test_window_rechecked_at_confirm(fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([PENDING]))
    post = fmc.post(f"{CFG}/deployment/deploymentrequests")
    now = {"t": datetime(2026, 10, 17, 23, 0, tzinfo=UTC)}  # Saturday 23:00, inside
    monkeypatch.setattr(stutters_mcp_core.policy, "_now", lambda: now["t"])
    async with Client(server(deploy_window="Sat 22:00-04:00 UTC")) as c:
        out = await run(c, "fmc_deploy", {})
        assert out["status"] == "preview"
        now["t"] = datetime(2026, 10, 18, 5, 0, tzinfo=UTC)  # the window closed meanwhile
        r = await c.call_tool("fmc_deploy", {"confirm": out["confirm"]}, raise_on_error=False)
    assert r.is_error and "deploy window" in r.content[0].text  # type: ignore[union-attr]
    assert not post.called
