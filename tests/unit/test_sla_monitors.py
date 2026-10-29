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


# --- fmc #364: fmc_update_sla_monitor, and the 'sla monitor' FMC leaves on the device -----------------


def monitor_by_id(fmc: respx.MockRouter, m: dict[str, Any]) -> None:
    fmc.get(f"{CFG}/object/slamonitors/{m['id']}").mock(return_value=httpx.Response(200, json=m))


async def test_update_sla_monitor_puts_the_full_object(lab: respx.MockRouter) -> None:
    current = {**MON, "description": "ISP-1", "metadata": {"timestamp": 1}, "links": {"self": "x"}}
    monitors(lab, current)
    monitor_by_id(lab, current)
    routes(lab, route("192.0.2.1", 1, iface="outside", tracked=True, rid="r-tracked"))
    put = lab.put(f"{CFG}/object/slamonitors/{MON['id']}").mock(return_value=httpx.Response(200, json=MON))
    args = {"monitor": "mcp-sla-isp1", "monitor_address": "203.0.113.99", "frequency": 10, "timeout_ms": 2000}
    args["threshold_ms"] = 1000
    preview, done = await confirm("fmc_update_sla_monitor", args)
    p = preview["preview"]
    assert p["changes"] == {
        "monitor_address": {"from": "192.0.2.10", "to": "203.0.113.99"},
        "frequency_s": {"from": 60, "to": 10},
        "threshold_ms": {"from": 5000, "to": 1000},
        "timeout_ms": {"from": 5000, "to": 2000},
    }
    assert p["tracked_by_routes"][0]["id"] == "r-tracked"
    side = " ".join(preview["side_effects"])
    assert DEV["name"] in side and "next fmc_deploy" in side and "floating backup" in side
    body = json.loads(put.calls.last.request.content)
    assert body == {
        **MON,
        "description": "ISP-1",
        "monitorAddress": "203.0.113.99",
        "frequency": 10,
        "threshold": 1000,
        "timeout": 2000,
    }  # no metadata/links; slaId, zones, tos, packets and size kept
    assert done["status"] == "applied"


async def test_update_sla_monitor_zones_and_blockers(lab: respx.MockRouter) -> None:
    monitors(lab, {**MON, "interfaceNames": ["outside"]})
    routes(lab)
    put = lab.put(f"{CFG}/object/slamonitors/{MON['id']}").mock(return_value=httpx.Response(200, json=MON))
    preview, _ = await confirm(
        "fmc_update_sla_monitor", {"monitor": "mcp-sla-isp1", "interfaces": [ZONES[0]["name"]]}
    )
    assert "No static route tracks this monitor" in " ".join(preview["side_effects"])
    body = json.loads(put.calls.last.request.content)
    assert body["interfaceObjects"] == [
        {"id": ZONES[0]["id"], "type": "SecurityZone", "name": ZONES[0]["name"]}
    ]
    assert "interfaceNames" not in body
    put.reset()
    out = await preview_of(
        "fmc_update_sla_monitor",
        {"monitor": "mcp-sla-isp1", "threshold_ms": 6000, "monitor_address": "224.0.0.5"},
    )
    assert out["status"] == "blocked" and not put.called
    text = " ".join(out["blockers"])
    assert "can't exceed timeout_ms" in text and "can't answer an echo probe" in text
    out = await preview_of("fmc_update_sla_monitor", {"monitor": "mcp-sla-isp1", "frequency": 60})
    assert out["status"] == "blocked" and any("Nothing to change" in b for b in out["blockers"])
    # a description-only change is a change
    args = {"monitor": "mcp-sla-isp1", "description": "ISP-1 probe"}
    out = await preview_of("fmc_update_sla_monitor", args)
    assert out["status"] == "preview", out
    assert out["preview"]["changes"] == {"description": {"from": None, "to": "ISP-1 probe"}}


async def test_update_object_points_to_update_sla_monitor(lab: respx.MockRouter) -> None:
    monitors(lab, MON)
    from fastmcp.exceptions import ToolError

    with pytest.raises(ToolError, match="fmc_update_sla_monitor"):
        await preview_of(
            "fmc_update_object", {"object": "mcp-sla-isp1", "type": "sla_monitor", "value": "192.0.2.9"}
        )


async def test_delete_sla_monitor_names_the_leftover(lab: respx.MockRouter) -> None:
    monitors(lab, MON)
    out = await preview_of("fmc_delete_sla_monitor", {"monitor": "mcp-sla-isp1"})
    side = " ".join(out["side_effects"])
    assert "leaves 'sla monitor 1'" in side and "no sla monitor 1" in side and "reuse SLA ID 1" in side


async def test_delete_last_tracking_route_warns_about_the_leftover(lab: respx.MockRouter) -> None:
    monitors(lab, MON)
    monitor_by_id(lab, MON)
    tracked = route("192.0.2.1", 1, iface="outside", tracked=True)
    tracked["id"] = "0050568a-0c0b-0ed3-0000-021474855101"
    routes(lab, tracked, route("198.51.100.1", 10))
    lab.get(f"{DEVPATH}/routing/ipv4staticroutes/{tracked['id']}").mock(
        return_value=httpx.Response(200, json=tracked)
    )
    args = {"device": "mcp-ftd1", "route_id": tracked["id"]}
    out = await preview_of("fmc_delete_static_route", args)
    side = " ".join(out["side_effects"])
    assert "last route on mcp-ftd1 tracking SLA monitor mcp-sla-isp1" in side
    assert "no sla monitor 1" in side
    # a second route still tracks the monitor on this device: no leftover yet
    other = {**tracked, "id": "0050568a-0c0b-0ed3-0000-021474855102"}
    routes(lab, tracked, other)
    out = await preview_of("fmc_delete_static_route", args)
    assert "sla monitor" not in " ".join(out["side_effects"])


async def test_delete_untracked_route_has_no_sla_note(lab: respx.MockRouter) -> None:
    plain = {**route("198.51.100.1", 10), "id": "0050568a-0c0b-0ed3-0000-021474855103"}
    lab.get(f"{DEVPATH}/routing/ipv4staticroutes/{plain['id']}").mock(
        return_value=httpx.Response(200, json=plain)
    )
    out = await preview_of("fmc_delete_static_route", {"device": "mcp-ftd1", "route_id": plain["id"]})
    assert out["side_effects"] == ["Removed from the device on the next deployment."]


async def test_delete_subinterface_names_it_in_the_action(lab: respx.MockRouter) -> None:
    sub = {"type": "SubInterface", "name": "Ethernet0/3", "subIntfId": 3999, "vlanId": 3999, "id": "sub-3999"}
    lab.get(f"{DEVPATH}/subinterfaces").mock(return_value=items([sub]))
    out = await preview_of("fmc_delete_interface", {"device": "mcp-ftd1", "interface": "Ethernet0/3.3999"})
    assert out["status"] == "preview", out
    assert out["action"] == "Delete subinterface interface Ethernet0/3.3999 on mcp-ftd1"
