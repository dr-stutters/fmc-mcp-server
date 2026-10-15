"""F10: HA status, monitored interfaces and failover MACs (shapes recorded from FMC 10.0.1 + 2 FTDv)."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, items, make_settings

HA = {
    "id": "45a2b2fe-c891-11f1-874c-6cea5174bd84",
    "name": "mcp-test-ha",
    "type": "DeviceHAPair",
    "primary": {"id": "p-1", "name": "mcp-ftd2", "type": "Device"},
    "secondary": {"id": "s-1", "name": "mcp-ftd3", "type": "Device"},
    "metadata": {
        "primaryStatus": {"currentStatus": "Active"},
        "secondaryStatus": {"currentStatus": "Standby"},
    },
    "ftdHABootstrap": {
        "isEncryptionEnabled": False,
        "lanFailover": {
            "interfaceObject": {"name": "Ethernet0/2", "id": "e2"},
            "logicalName": "FAILOVER-LINK",
            "activeIP": "192.168.255.1",
            "standbyIP": "192.168.255.2",
            "subnetMask": "255.255.255.252",
        },
    },
    "ftdHAFailoverTriggerCriteria": {"noOfFailedInterfaceLimit": 1, "peerPollTime": 1},
}
BASE = f"{CFG}/devicehapairs/ftddevicehapairs/{HA['id']}"
INSIDE = {
    "id": "mon-in",
    "name": "inside",
    "type": "FTDHAMonitoredInterfaces",
    "monitorForFailures": True,
    "ipv4Configuration": {"activeIPv4Address": "10.99.2.1", "activeIPv4Mask": "24"},
    "metadata": {"timestamp": 1},
}
MGMT = {"id": "mon-m", "name": "management", "type": "FTDHAMonitoredInterfaces", "monitorForFailures": True}
PHYS = {"id": "eth1", "name": "Ethernet0/1", "ifname": "inside", "type": "PhysicalInterface"}
PHYS_REF = {"id": "eth1", "name": "Ethernet0/1", "type": "PhysicalInterface"}  # as FMC references it


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def mock(fmc: respx.MockRouter, macs: list[Any] | None = None) -> respx.MockRouter:
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([HA]))
    fmc.get(f"{BASE}/monitoredinterfaces").mock(return_value=items([MGMT, INSIDE]))
    fmc.get(f"{BASE}/failoverinterfacemacaddressconfigs").mock(return_value=items(macs or []))
    fmc.get(f"{CFG}/devices/devicerecords/p-1/physicalinterfaces").mock(return_value=items([PHYS]))
    return fmc


async def test_status(fmc: respx.MockRouter) -> None:
    mock(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_get_ha_status", {"ha_pair": "mcp-test-ha"})
    assert out["units"]["primary"] == {"device": "mcp-ftd2", "state": "Active"}
    assert out["failover_link"]["standby_ip"] == "192.168.255.2"
    assert out["monitored_interfaces"][1] == {
        "interface": "inside",
        "monitored": True,
        "active_ip": "10.99.2.1",
        "mask": "24",
        "id": "mon-in",
    }


async def test_standby_ip_and_mac(fmc: respx.MockRouter) -> None:
    mock(fmc)
    put = fmc.put(f"{BASE}/monitoredinterfaces/mon-in").mock(
        side_effect=lambda req: httpx.Response(200, json=json.loads(req.content))
    )
    post = fmc.post(f"{BASE}/failoverinterfacemacaddressconfigs").mock(
        side_effect=lambda req: httpx.Response(201, json=json.loads(req.content) | {"id": "mac-1"})
    )
    args = {
        "ha_pair": "mcp-test-ha",
        "interface": "inside",
        "standby_ip": "10.99.2.2",
        "active_mac": "00:50:56:AA:00:01",
        "standby_mac": "0050.56aa.0002",
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_ha_monitoring", args)
        assert preview["preview"]["changes"]["standby_ip"] == {"from": None, "to": "10.99.2.2"}
        done = await run(c, "fmc_configure_ha_monitoring", {**args, "confirm": preview["confirm"]})
    body = json.loads(put.calls.last.request.content)
    assert body["ipv4Configuration"]["standbyIPv4Address"] == "10.99.2.2" and "metadata" not in body
    mac = json.loads(post.calls.last.request.content)
    assert mac["failoverActiveMac"] == "0050.56aa.0001" and mac["physicalInterface"]["id"] == "eth1"
    assert done["result"]["mac"]["standby_mac"] == "0050.56aa.0002"


async def test_blocks_bad_or_no_change(fmc: respx.MockRouter) -> None:
    mock(fmc)
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_configure_ha_monitoring",
            {"ha_pair": HA["name"], "interface": "inside", "standby_ip": "10.99.3.2"},
        )
        assert out["status"] == "blocked" and "not in the interface network" in out["blockers"][0]
        out = await run(
            c,
            "fmc_configure_ha_monitoring",
            {"ha_pair": HA["name"], "interface": "inside", "monitored": True},
        )
        assert out["status"] == "blocked" and "Nothing to change" in out["blockers"][0]
        r = await c.call_tool(
            "fmc_configure_ha_monitoring",
            {"ha_pair": HA["name"], "interface": "dmz", "monitored": False},
            raise_on_error=False,
        )
        assert r.is_error
        r = await c.call_tool(
            "fmc_configure_ha_monitoring",
            {"ha_pair": HA["name"], "interface": "inside", "active_mac": "zz"},
            raise_on_error=False,
        )
        assert r.is_error


async def test_unmonitor_and_clear_mac(fmc: respx.MockRouter) -> None:
    mac = {
        "id": "mac-1",
        "physicalInterface": PHYS,
        "failoverActiveMac": "0050.56aa.0001",
        "failoverStandbyMac": "0050.56aa.0002",
    }
    mock(fmc, [mac])
    put = fmc.put(f"{BASE}/monitoredinterfaces/mon-in").mock(return_value=httpx.Response(200, json=INSIDE))
    delete = fmc.delete(f"{BASE}/failoverinterfacemacaddressconfigs/mac-1").mock(
        return_value=httpx.Response(200, json={})
    )
    args = {"ha_pair": HA["name"], "interface": "inside", "monitored": False, "clear_mac": True}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_ha_monitoring", args)
        await run(c, "fmc_configure_ha_monitoring", {**args, "confirm": preview["confirm"]})
    assert json.loads(put.calls.last.request.content)["monitorForFailures"] is False and delete.called


async def test_deploy_accepts_ha_pair_and_unit_names(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(
        return_value=items(
            [
                {
                    "name": "mcp-test-ha",
                    "version": "5",
                    "device": {"id": HA["id"], "name": "mcp-test-ha", "type": "DeviceHAPair"},
                }
            ]
        )
    )
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([{"id": "p-1", "name": "mcp-ftd2"}]))
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([HA]))
    async with Client(server()) as c:
        for ref in ("mcp-test-ha", "mcp-ftd2"):
            out = await run(c, "fmc_deploy", {"devices": [ref]})
            assert out["status"] == "preview", out
            assert out.get("blast_radius", 1) == 1


async def test_existing_mac_is_updated_not_duplicated(fmc: respx.MockRouter) -> None:
    mac = {
        "id": "mac-1",
        "physicalInterface": PHYS_REF,
        "failoverActiveMac": "0050.56aa.0001",
        "failoverStandbyMac": "0050.56aa.0002",
    }
    mock(fmc, [mac])
    put = fmc.put(f"{BASE}/failoverinterfacemacaddressconfigs/mac-1").mock(
        side_effect=lambda req: httpx.Response(200, json=json.loads(req.content))
    )
    args = {
        "ha_pair": HA["name"],
        "interface": "inside",
        "active_mac": "0050.56aa.0011",
        "standby_mac": "0050.56aa.0012",
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_ha_monitoring", args)
        assert preview["preview"]["changes"]["mac"]["from"]["active_mac"] == "0050.56aa.0001"
        await run(c, "fmc_configure_ha_monitoring", {**args, "confirm": preview["confirm"]})
        same = await run(
            c,
            "fmc_configure_ha_monitoring",
            {**args, "active_mac": "0050.56aa.0001", "standby_mac": "0050.56aa.0002"},
        )
    assert json.loads(put.calls.last.request.content)["failoverActiveMac"] == "0050.56aa.0011"
    assert same["status"] == "blocked"
