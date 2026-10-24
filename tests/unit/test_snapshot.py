"""F89: fmc_snapshot / fmc_compare_snapshot on core's snapshot contract (C53), replayed from
tests/fixtures/snapshot_fmc10.json (the HA pair and a deployable item recorded live on FMC 10.0.1, F73's
health alerts and spoke1 `show interface ip brief` (healthy and wan_down), the recorded TunnelStatus shape;
see its _source) and the recorded bulkcommands refusal (fleet_show.json). The HA units answer spoke1's
healthy interface output (synthesized reuse)."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp._core.snapshot import MAX_CHARS, digest

from .conftest import CFG, fixture, items, make_server

FX = fixture("snapshot_fmc10")
FLEET = fixture("fleet_show")
DEV = f"{CFG}/devices/devicerecords"
SP1, FTD2, FTD3 = (d["id"] for d in FX["devices/devicerecords"]["items"])


def lab(fmc: respx.MockRouter) -> dict[str, Any]:
    """The recorded estate; edit the returned state to change what FMC answers next."""
    st: dict[str, Any] = {
        "devices": copy.deepcopy(FX["devices/devicerecords"]["items"]),
        "pairs": copy.deepcopy(FX["devicehapairs/ftddevicehapairs"]["items"]),
        "deployable": [],
        "tunnels": copy.deepcopy(FX["health/tunnelstatuses"]["items"]),
        "alerts": copy.deepcopy(FX["health/alerts"]["items"]),
        "show": {SP1: FX["show"]["healthy"], FTD2: FX["show"]["healthy"], FTD3: FX["show"]["healthy"]},
        "fail": set(),
        "groups": [],
    }

    def answer(key: str):  # type: ignore[no-untyped-def]
        def respond(_r: httpx.Request) -> httpx.Response:
            if key in st["fail"]:
                return httpx.Response(500, json={"error": {"messages": [{"description": "boom"}]}})
            return items(st[key])

        return respond

    fmc.get(DEV).mock(side_effect=answer("devices"))
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(side_effect=answer("pairs"))
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(side_effect=answer("deployable"))
    fmc.get(f"{CFG}/health/tunnelstatuses").mock(side_effect=answer("tunnels"))
    fmc.get(f"{CFG}/health/alerts").mock(side_effect=answer("alerts"))
    fmc.get(f"{CFG}/devicegroups/devicegrouprecords").mock(side_effect=answer("groups"))
    fmc.post(f"{DEV}/operational/bulkcommands").mock(
        return_value=httpx.Response(403, json=FLEET["bulk_refused_403"])
    )
    for dev_id in (SP1, FTD2, FTD3):

        def show(request: httpx.Request, dev_id: str = dev_id) -> httpx.Response:
            text = request.url.params["command"] + " " + request.url.params.get("parameters", "")
            return items([{"commandInput": text.strip(), "commandOutput": st["show"][dev_id]}])

        fmc.get(f"{DEV}/{dev_id}/operational/commands").mock(side_effect=show)
    return st


async def snap(c: Client, site: str = "") -> dict[str, Any]:
    out = await c.call_tool("fmc_snapshot", {"site": site})
    data: dict[str, Any] = json.loads(out.content[0].text)  # type: ignore[union-attr]
    return data


async def compare(c: Client, before: dict[str, Any], after: dict[str, Any] | None = None) -> dict[str, Any]:
    args: dict[str, Any] = {"before": before}
    if after is not None:
        args["after"] = after
    out = await c.call_tool("fmc_compare_snapshot", args)
    data: dict[str, Any] = out.structured_content  # type: ignore[assignment]
    return data


async def test_blob_sections_and_items(fmc: respx.MockRouter) -> None:
    lab(fmc)
    async with Client(make_server()) as c:
        blob = await snap(c)
    assert blob["snapshot"] == 1 and blob["prefix"] == "fmc" and blob["server"] == "fmc-mcp-server"
    assert blob["digest"] == digest(blob)
    assert len(json.dumps(blob)) < MAX_CHARS
    s = blob["sections"]
    assert sorted(s) == ["deployment", "ha", "health", "interfaces", "vpn"]
    assert s["deployment"]["items"]["device:mcp-sdwan-t1-spoke1"] == {
        "ok": True,
        "state": "DEPLOYED",
        "pending": False,
    }
    assert s["ha"]["items"]["pair:mcp-test-ha"] == {
        "ok": True,
        "state": "mcp-ftd2 Active, mcp-ftd3 Standby",
        "primary": "mcp-ftd2",
        "secondary": "mcp-ftd3",
        "config_status": "HEALTHY_CONFIG",
    }
    # addressed interfaces only; FTD's internal ones are left out
    spoke = {k for k in s["interfaces"]["items"] if k.startswith("mcp-sdwan-t1-spoke1|")}
    assert spoke == {
        f"mcp-sdwan-t1-spoke1|{i}"
        for i in ("Ethernet0/0", "Ethernet0/1", "Ethernet0/2", "Ethernet0/3", "Management0/0")
    }
    assert s["interfaces"]["items"]["mcp-sdwan-t1-spoke1|Ethernet0/0"] == {
        "ok": True,
        "state": "up",
        "protocol": "up",
        "ip": "192.0.2.2",
    }
    assert s["vpn"]["items"] == {
        "mcp-fw-vti|mcp-ftd2|mcp-sdwan-t1-spoke1": {"ok": True, "state": "TUNNEL_UP"}
    }
    health = s["health"]["items"]
    assert health["device:mcp-ftd2"] == {"ok": True, "state": "green", "connected": True}
    # the recorded RED modules of spoke1; DISABLED ones are left out, readings blanked
    alerts = {k: v for k, v in health.items() if k.startswith("alert:")}
    assert set(alerts) == {
        "alert:mcp-sdwan-t1-spoke1|INTERFACE",
        "alert:mcp-sdwan-t1-spoke1|THREAT_DATA_UPDATES",
    }
    assert all(v["ok"] is False and v["state"] == "RED" for v in alerts.values())
    # nothing volatile: no timestamps, versions or ids anywhere in the items
    text = json.dumps(s)
    for volatile in ("1792", "timestamp", "lastChange", "version", SP1):
        assert volatile not in text


async def test_unchanged_estate_compares_as_no_change(fmc: respx.MockRouter) -> None:
    lab(fmc)
    async with Client(make_server()) as c:
        before = await snap(c)
        after = await snap(c)
        res = await compare(c, before, after)
        fresh = await compare(c, before)  # `after` empty: a fresh snapshot of before's scope
    assert res["verdict"].startswith("No change"), res
    assert not res.get("changes")  # the result is compacted: empty fields are dropped
    assert res["unchanged_items"] > 10
    assert fresh["verdict"].startswith("No change"), fresh
    assert "integrity" not in res and "notes" not in res


async def test_interface_down_is_the_only_major_change(fmc: respx.MockRouter) -> None:
    """The issue's test plan: bring an interface down, the compare names it."""
    st = lab(fmc)
    async with Client(make_server()) as c:
        before = await snap(c)
        st["show"][SP1] = FX["show"]["wan_down"]
        res = await compare(c, before)
    assert res["counts"]["major"] == 1, res
    (change,) = res["changes"]
    assert change["severity"] == "major" and change["kind"] == "degraded"
    assert change["section"] == "interfaces" and change["item"] == "mcp-sdwan-t1-spoke1|Ethernet0/0"
    assert "healthy -> unhealthy" in change["what"] and "state up -> down" in change["what"]


async def test_degraded_estate_names_each_item(fmc: respx.MockRouter) -> None:
    st = lab(fmc)
    async with Client(make_server()) as c:
        before = await snap(c)
        st["tunnels"][0]["state"] = "TUNNEL_DOWN"
        st["pairs"][0]["metadata"]["secondaryStatus"]["currentStatus"] = "Failed"
        st["devices"][2]["isConnected"] = False  # mcp-ftd3: its interfaces are no longer read
        st["deployable"] = [FX["deployment/deployabledevices_item"]]
        st["alerts"] = [a for a in st["alerts"] if a["moduleID"] != "THREAT_DATA_UPDATES"]
        res = await compare(c, before)
    by_item = {(c["section"], c["item"]): c for c in res.get("changes", [])}
    major = {k for k, c in by_item.items() if c["severity"] == "major"}
    assert ("vpn", "mcp-fw-vti|mcp-ftd2|mcp-sdwan-t1-spoke1") in major
    assert ("ha", "pair:mcp-test-ha") in major
    assert ("health", "device:mcp-ftd3") in major
    assert ("deployment", "device:mcp-sdwan-t1-spoke1") in major
    assert ("interfaces", "mcp-ftd3|Ethernet0/0") in major  # gone (was healthy)
    assert (
        "lsp-rel-20261021-1822; mcp-sdwan-acp"
        in by_item[("deployment", "device:mcp-sdwan-t1-spoke1")]["what"]
    )
    assert "mcp-ftd3 Standby -> " in by_item[("ha", "pair:mcp-test-ha")]["what"]
    # a cleared RED alert is good news
    cleared = by_item[("health", "alert:mcp-sdwan-t1-spoke1|THREAT_DATA_UPDATES")]
    assert (cleared["severity"], cleared["kind"]) == ("info", "removed")
    assert not any(k[0] == "interfaces" and k[1].startswith("mcp-sdwan-t1-spoke1") for k in by_item)


async def test_unreadable_section_is_reported_not_diffed(fmc: respx.MockRouter) -> None:
    st = lab(fmc)
    async with Client(make_server()) as c:
        before = await snap(c)
        st["fail"].add("tunnels")
        after = await snap(c)
        res = await compare(c, before, after)
    assert "error" in after["sections"]["vpn"] and after["sections"]["vpn"]["items"] == {}
    assert [(c["severity"], c["kind"], c["section"]) for c in res["changes"]] == [
        ("minor", "unreadable", "vpn")
    ]


async def test_site_scopes_to_a_device_group_or_a_name(fmc: respx.MockRouter) -> None:
    st = lab(fmc)
    st["groups"] = [
        {
            "id": "00000000-0000-4000-8000-0000000000aa",
            "name": "mcp-ha-group",
            "type": "DeviceGroup",
            "members": [
                {
                    "id": FX["devicehapairs/ftddevicehapairs"]["items"][0]["id"],
                    "type": "DeviceHAPair",
                    "name": "mcp-test-ha",
                }
            ],
        }
    ]
    async with Client(make_server()) as c:
        grouped = await snap(c, "mcp-ha-group")
        named = await snap(c, "SPOKE1")
        with pytest.raises(ToolError, match="No device group or device name matches 'nowhere'"):
            await snap(c, "nowhere")
    assert grouped["scope"] == {"site": "mcp-ha-group"}
    assert sorted(grouped["sections"]["deployment"]["items"]) == ["device:mcp-ftd2", "device:mcp-ftd3"]
    assert list(grouped["sections"]["ha"]["items"]) == ["pair:mcp-test-ha"]
    assert list(grouped["sections"]["vpn"]["items"]) == ["mcp-fw-vti|mcp-ftd2|mcp-sdwan-t1-spoke1"]
    assert not any(k.startswith("alert:") for k in grouped["sections"]["health"]["items"])
    assert list(named["sections"]["deployment"]["items"]) == ["device:mcp-sdwan-t1-spoke1"]
    assert named["sections"]["ha"]["items"] == {}


async def test_compare_refuses_another_servers_blob(fmc: respx.MockRouter) -> None:
    lab(fmc)
    async with Client(make_server()) as c:
        blob = await snap(c)
        other = {**blob, "prefix": "ise"}
        with pytest.raises(ToolError, match="taken by 'ise', not 'fmc'"):
            await compare(c, other)


async def test_snapshot_tools_are_read_tier_and_in_core_toolset(fmc: respx.MockRouter) -> None:
    async with Client(make_server(toolsets="policy")) as c:
        names = {t.name for t in await c.list_tools()}
        prompts = {p.name for p in await c.list_prompts()}
    assert {"fmc_snapshot", "fmc_compare_snapshot"} <= names
    assert "suite_change_check" in prompts
