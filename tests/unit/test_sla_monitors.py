"""F92: SLA monitor objects and tracked static routes (dual-ISP failover).

Bodies follow the FMC 10.0.1 OpenAPI (SLAMonitor / ISLAMonitorModel, IPv4StaticRouteModel.routeTracking;
the spec's POST example for object/slamonitors). The lab FMC had no SLA monitor when this was written
(GET object/slamonitors: count 0), so the monitor shapes are the spec's; routes are the recorded FTD's."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx

from .conftest import CFG, empty, fixture, items
from .test_tools_ftd import ANY4, DEV, DEVPATH, ZONES, confirm, ftd, preview_of  # noqa: F401  (ftd is a fixture)


@pytest.fixture
def lab(ftd: respx.MockRouter) -> respx.MockRouter:  # noqa: F811
    """The recorded FTD (test_tools_ftd's fixture)."""
    return ftd


OUT_ZONE = ZONES[1]
MON = {
    "id": "0050568a-0c0b-0ed3-0000-021474855001",
    "name": "mcp-sla-isp1",
    "type": "SLAMonitor",
    "slaId": 1,
    "monitorAddress": "192.0.2.10",
    "interfaceObjects": [OUT_ZONE],
    "frequency": 60,
    "threshold": 5000,
    "timeout": 5000,
    "tos": 0,
    "noOfPackets": 1,
    "dataSize": 28,
}
ROUTE = fixture("ftd_ipv4staticroutes")["items"][0]  # any-ipv4 via 192.0.2.10 on outside, metric 1


def routes(fmc: respx.MockRouter, *rows: dict[str, Any]) -> None:
    fmc.get(f"{DEVPATH}/routing/ipv4staticroutes").mock(return_value=items(list(rows)))


def monitors(fmc: respx.MockRouter, *rows: dict[str, Any]) -> None:
    fmc.get(f"{CFG}/object/slamonitors").mock(return_value=items(list(rows)))
    fmc.get(f"{CFG}/object/interfacegroups").mock(return_value=empty())


def route(gateway: str, metric: int, *, iface: str = "inside", tracked: bool = False, rid: str = "r2") -> Any:
    r = copy.deepcopy(ROUTE)
    r.update(
        id=rid,
        interfaceName=iface,
        metricValue=metric,
        gateway={"literal": {"type": "Host", "value": gateway}},
    )
    if tracked:
        r["routeTracking"] = {"id": MON["id"], "type": "SLAMonitor", "name": MON["name"]}
    return r


TRACKED = {
    "device": "mcp-ftd1",
    "interface": "outside",
    "networks": ["0.0.0.0/0"],
    "gateway": "192.0.2.1",
    "track": "mcp-sla-isp1",
}


def network_mocks(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/networks").mock(return_value=items([ANY4]))
    fmc.get(f"{CFG}/object/hosts").mock(return_value=empty())


# --- fmc_create_sla_monitor ------------------------------------------------------------------------


async def test_create_sla_monitor_body_and_next_free_id(lab: respx.MockRouter) -> None:
    monitors(lab, MON)
    post = lab.post(f"{CFG}/object/slamonitors").mock(return_value=httpx.Response(201, json={"id": "m2"}))
    args = {"name": "mcp-sla-isp2", "monitor_address": "198.51.100.1", "interfaces": [OUT_ZONE["name"]]}
    preview, _ = await confirm("fmc_create_sla_monitor", args)
    assert preview["preview"]["monitor"]["sla_id"] == 2
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "name": "mcp-sla-isp2",
        "type": "SLAMonitor",
        "slaId": 2,
        "monitorAddress": "198.51.100.1",
        "interfaceObjects": [{"id": OUT_ZONE["id"], "type": "SecurityZone", "name": OUT_ZONE["name"]}],
        "frequency": 60,
        "threshold": 5000,
        "timeout": 5000,
        "tos": 0,
        "noOfPackets": 1,
        "dataSize": 28,
    }


async def test_create_sla_monitor_blockers(lab: respx.MockRouter) -> None:
    monitors(lab, MON)
    post = lab.post(f"{CFG}/object/slamonitors")
    out = await preview_of(
        "fmc_create_sla_monitor",
        {
            "name": "MCP-SLA-ISP1",
            "monitor_address": "2001:db8::1",
            "interfaces": [OUT_ZONE["name"]],
            "sla_id": 1,
            "frequency": 5,
            "threshold_ms": 6000,
            "timeout_ms": 5500,
        },
    )
    assert out["status"] == "blocked" and not post.called
    text = " ".join(out["blockers"])
    for want in (
        "IPv4 addresses only",
        "already exists",
        "SLA ID 1 is already used",
        "can't exceed timeout_ms",
    ):
        assert want in text, want
    assert "can't exceed the frequency" in text


# --- fmc_create_static_route track= ----------------------------------------------------------------


async def test_tracked_route_writes_route_tracking_and_names_backup(lab: respx.MockRouter) -> None:
    network_mocks(lab)
    monitors(lab, MON)
    routes(lab, route("198.51.100.1", 10))
    post = lab.post(f"{DEVPATH}/routing/ipv4staticroutes").mock(
        return_value=httpx.Response(201, json={"id": "r"})
    )
    preview, _ = await confirm("fmc_create_static_route", TRACKED)
    p = preview["preview"]
    assert p["route"]["tracked_by"] == "mcp-sla-isp1"
    assert [r["gateway"] for r in p["floating_backup"]] == ["198.51.100.1"]
    assert "warnings" not in p
    body = json.loads(post.calls.last.request.content)
    assert body["routeTracking"] == {"id": MON["id"], "type": "SLAMonitor", "name": "mcp-sla-isp1"}
    assert body["metricValue"] == 1


async def test_tracked_route_warns_without_backup(lab: respx.MockRouter) -> None:
    network_mocks(lab)
    monitors(lab, MON)
    routes(lab)
    out = await preview_of("fmc_create_static_route", TRACKED)
    assert out["status"] == "preview"
    assert out["preview"]["floating_backup"] == []
    assert any("No other route to any-ipv4" in w and "metric=10" in w for w in out["preview"]["warnings"])


async def test_tracked_route_warns_on_same_metric_backup(lab: respx.MockRouter) -> None:
    network_mocks(lab)
    monitors(lab, MON)
    routes(lab, route("198.51.100.1", 1))
    out = await preview_of("fmc_create_static_route", TRACKED)
    assert out["status"] == "preview"
    assert any("same metric" in w and "198.51.100.1" in w for w in out["preview"]["warnings"])


async def test_tracking_is_ipv4_only(lab: respx.MockRouter) -> None:
    network_mocks(lab)
    out = await preview_of("fmc_create_static_route", {**TRACKED, "gateway": "2001:db8::1"})
    assert out["status"] == "blocked"
    assert any("IPv4 static routes only" in b for b in out["blockers"])


async def test_floating_route_names_the_tracked_primary(lab: respx.MockRouter) -> None:
    network_mocks(lab)
    routes(lab, route("192.0.2.1", 1, iface="outside", tracked=True))
    args = {"device": "mcp-ftd1", "interface": "inside", "networks": ["0.0.0.0/0"], "gateway": "198.51.100.1"}
    out = await preview_of("fmc_create_static_route", {**args, "metric": 10})
    assert [r["tracked_by"] for r in out["preview"]["backs_up"]] == ["mcp-sla-isp1"]
    assert "warnings" not in out["preview"]
    out = await preview_of("fmc_create_static_route", args)  # metric 1 = the primary's
    assert any("give this route a higher metric" in w for w in out["preview"]["warnings"])


# --- delete, list, where used ----------------------------------------------------------------------


async def test_delete_sla_monitor_blocked_while_a_route_tracks_it(lab: respx.MockRouter) -> None:
    monitors(lab, MON)
    routes(lab, route("192.0.2.1", 1, iface="outside", tracked=True, rid="r-tracked"))
    delete = lab.delete(f"{CFG}/object/slamonitors/{MON['id']}")
    out = await preview_of("fmc_delete_sla_monitor", {"monitor": "mcp-sla-isp1"})
    assert out["status"] == "blocked" and not delete.called
    (blocker,) = out["blockers"]
    assert DEV["name"] in blocker and "r-tracked" in blocker and "fmc_delete_static_route" in blocker
    assert out["preview"]["tracked_by_routes"][0]["gateway"] == "192.0.2.1"
    # the generic delete is blocked the same way
    out = await preview_of("fmc_delete_object", {"object": "mcp-sla-isp1", "type": "sla_monitor"})
    assert out["status"] == "blocked" and any("Still in use" in b for b in out["blockers"])


async def test_delete_unused_sla_monitor(lab: respx.MockRouter) -> None:
    monitors(lab, MON)
    delete = lab.delete(f"{CFG}/object/slamonitors/{MON['id']}").mock(
        return_value=httpx.Response(200, json=MON)
    )
    preview, _ = await confirm("fmc_delete_sla_monitor", {"monitor": "mcp-sla-isp1"})
    assert preview["preview"]["tracked_by_routes"] == []
    assert delete.called


async def test_list_and_where_used(lab: respx.MockRouter) -> None:
    from fastmcp import Client

    from .test_tools_ftd import run, server

    monitors(lab, MON)
    routes(lab, route("192.0.2.1", 1, iface="outside", tracked=True))
    async with Client(server()) as c:
        listed = await run(c, "fmc_list_objects", {"type": "sla_monitor", "response_format": "json"})
        used = await run(c, "fmc_where_used", {"object": "mcp-sla-isp1", "type": "sla_monitor"})
    (row,) = listed["results"]
    assert row["value"] == "192.0.2.10" and row["sla_id"] == 1
    assert used["in_use"] and used["used_by"][0]["device"] == DEV["name"]
