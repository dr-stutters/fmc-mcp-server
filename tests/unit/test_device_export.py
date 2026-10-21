"""F72 device configuration export and compare: replayed from tests/fixtures/device_config_t1.json
(mcp-sdwan-t1-spoke1/spoke2 as FMC 10.0.1 returned them, redacted), the spec-example device template
(devicetemplates.json) and the recorded HA pair (ha_failover.json)."""

import copy
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import yaml
from fastmcp import Client

from fmc_mcp._core import InvalidRequest
from fmc_mcp.server import create_server
from fmc_mcp.tools.device_export import (
    MASK,
    SECTIONS,
    ExportContext,
    export_section,
    mask_cli,
    parse_export,
    select_sections,
    static_routes,
)
from fmc_mcp.tools.prompts import _health_review_text

from .conftest import CFG, DOMAIN, FIXTURES, TOP_CFG, as_leaf, empty, fixture, items, make_settings

SP1 = "1bcefc02-ca81-11f1-9c58-8639fcd7b26d"
SP2 = "1e6635ca-ca81-11f1-8e8d-ed7d3abe955e"
LAB_LEAF = "a1c73df0-8353-8db7-1097-000000000000"
DEV = f"{CFG}/devices/devicerecords"


def recorded() -> dict[str, Any]:
    """The t1 recording, with the lab's leaf domain id swapped for the tests' DOMAIN."""
    text = (FIXTURES / "device_config_t1.json").read_text().replace(LAB_LEAF, DOMAIN)
    data: dict[str, Any] = json.loads(text)
    return data


def scrambled(data: Any) -> Any:
    """The same data with every list and every dict's key order reversed (FMC promises neither)."""
    if isinstance(data, dict):
        return {k: scrambled(data[k]) for k in reversed(list(data))}
    if isinstance(data, list):
        return [scrambled(v) for v in reversed(data)]
    return data


def t1(fmc: respx.MockRouter, data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Serve the recording (spoke2's virtual routers: spoke1's); every other collection the export reads
    answers empty, as it did live. Swap state["data"] (or edit it) to serve something else."""
    as_leaf(fmc)
    state: dict[str, Any] = {"data": data or recorded()}
    for path in list(state["data"]):
        if path.startswith("_"):
            continue
        url = f"{TOP_CFG}/{path[len('global:') :]}" if path.startswith("global:") else f"{CFG}/{path}"
        fmc.get(url).mock(
            side_effect=lambda _req, p=path: httpx.Response(200, json=state["data"][p])  # type: ignore[misc]
        )
    fmc.get(f"{DEV}/{SP2}/routing/virtualrouters").mock(
        side_effect=lambda _req: httpx.Response(
            200, json=state["data"][f"devices/devicerecords/{SP1}/routing/virtualrouters"]
        )
    )
    fmc.get(DEV).mock(
        side_effect=lambda _req: httpx.Response(
            200,
            json={
                "items": [state["data"][f"devices/devicerecords/{i}"] for i in (SP1, SP2)],
                "paging": {"count": 2},
            },
        )
    )
    fmc.get(url__regex=rf"{re.escape(DEV)}/[^/]+/.+").mock(return_value=empty())
    for path in ("policy/ftds2svpns", "object/hosts", "object/networks", "object/ranges", "object/fqdns"):
        fmc.get(f"{CFG}/{path}").mock(return_value=empty())
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=empty())
    fmc.get(f"{CFG}/templates/devicetemplates").mock(return_value=empty())
    return state


def server(**kw: Any) -> Any:
    return create_server(make_settings(rate_limit=100000, **kw))  # an export makes ~30 requests


async def call(tool: str, args: dict[str, Any], **kw: Any) -> dict[str, Any]:
    async with Client(server(**kw)) as c:
        out = (await c.call_tool(tool, args)).structured_content
    assert out is not None
    return out


async def export(device: str = "mcp-sdwan-t1-spoke1", **kw: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    out = await call("fmc_export_device_config", {"device": device}, **kw)
    return out, parse_export(out["export"], None)


def without_stamp(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("exported_at:"))


def keys_in(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in keys_in(v)}
    if isinstance(value, list):
        return {k for v in value for k in keys_in(v)}
    return set()


# --- export ------------------------------------------------------------------------------------


async def test_export_spoke1(fmc: respx.MockRouter) -> None:
    t1(fmc)
    out, doc = await export()
    assert out["device"] == "mcp-sdwan-t1-spoke1" and out["kind"] == "device"
    assert out["domain"] == "Global/mcp-test-leaf" and out["digest"].startswith("sha256:")
    assert out["sections"]["interfaces"] == 5 and out["sections"]["routing"] == 3
    assert out["sections"]["policies"] == 2 and out["sections"]["vpn"] == 0
    assert doc["format"] == "fmc-device-config" and doc["version"] == 1
    meta = doc["meta"]
    assert meta["serial"] == "REDACTED" and meta["host"] == "198.51.100.201" and meta["id"] == SP1
    assert meta["sections"] == [n for n, s in SECTIONS.items() if s.default]
    assert "vpn" not in doc and "nat" not in doc and "ha" not in doc  # empty: listed, not written
    assert doc["device"] == {
        "model": "Cisco Secure Firewall Threat Defense for KVM",
        "version": "10.0.0",
        "mode": "ROUTED",
        "licenses": ["ESSENTIALS"],
        "performance_tier": "FTDv5",
        "snort_engine": "SNORT3",
        "snort_version": "3.9.3.1-61",
        "vdb_version": "Build 426 - 2026-03-24 09:29:08.0",
        "lsp_version": "lsp-rel-20261016-1401",
        "keep_local_events": False,
        "prohibit_packet_transfer": False,
        "analytics_only": False,
        "advanced": {"enableOGS": True},
    }
    assert list(doc["interfaces"]) == [
        "Ethernet0/0",
        "Ethernet0/1",
        "Ethernet0/2",
        "Ethernet0/3",
        "Management0/0",
    ]
    mpls = doc["interfaces"]["Ethernet0/0"]
    assert mpls["kind"] == "physical" and mpls["ifname"] == "mpls"
    assert mpls["securityZone"] == "mcp-sdwan-wan"  # the zone id resolved to its name
    assert mpls["ipv4"] == {"static": {"address": "192.0.2.34", "netmask": "28"}}
    assert mpls["pathMonitoring"] == {"enable": True, "monitoredIp": "192.0.2.33", "type": "PEER_IPV4"}
    assert mpls["priority"] == 1 and "virtualRouter" not in mpls  # the global table isn't named
    assert doc["interfaces"]["Ethernet0/3"]["securityZone"] == "mcp-sdwan-inside"
    assert doc["routing"]["ipv4 route mpls -> mcp-sdwan-mpls-net"] == {
        "networks": ["mcp-sdwan-mpls-net"],
        "interface": "mpls",
        "gateway": "192.0.2.33",
        "metric": 1,
    }
    assert doc["policies"] == {"access": {"name": "mcp-sdwan-acp"}, "health": {"name": "mcp-sdwan-health"}}
    assert not keys_in({k: v for k, v in doc.items() if k != "meta"}) & {
        "id",
        "links",
        "metadata",
        "timestamp",
    }


async def test_export_is_stable(fmc: respx.MockRouter) -> None:
    """FMC's list order and key order don't matter: the same digest and text (but the stamp)."""
    state = t1(fmc)
    first, _ = await export()
    state["data"] = scrambled(recorded())
    second, _ = await export()
    assert first["digest"] == second["digest"]
    assert without_stamp(first["export"]) == without_stamp(second["export"])


async def test_export_markdown(fmc: respx.MockRouter) -> None:
    t1(fmc)
    out = await call("fmc_export_device_config", {"device": SP1, "format": "markdown"})
    md = out["markdown"]
    assert md.startswith("# mcp-sdwan-t1-spoke1 (device, Global/mcp-test-leaf)")
    assert "## interfaces" in md and "- **Ethernet0/0**: kind=physical" in md
    assert "## vpn\n(none)" in md and "export" not in out


async def test_export_file_and_diff_against_live(fmc: respx.MockRouter, tmp_path: Path) -> None:
    """The before/after proof: export spoke1 to FMC_BUNDLE_DIR, add a static route, diff the file with
    live spoke1: one route added, nothing else."""
    state = t1(fmc)
    out = await call(
        "fmc_export_device_config",
        {"device": "mcp-sdwan-t1-spoke1", "include_text": False},
        bundle_dir=tmp_path,
    )
    path = Path(out["file"])
    assert path.parent == tmp_path and re.fullmatch(
        r"device-mcp-sdwan-t1-spoke1-\d{8}T\d{6}Z\.yaml", path.name
    )
    assert "export" not in out and "next_offset" not in out
    same = await call("fmc_diff_device_config", {"a": path.name}, bundle_dir=tmp_path)
    assert same["identical"] is True and same["total"] == 0 and same["b"]["exported_at"] == "live"
    routes = state["data"][f"devices/devicerecords/{SP1}/routing/ipv4staticroutes"]
    routes["items"].append(
        {
            "interfaceName": "inside",
            "selectedNetworks": [{"type": "Network", "name": "mcp-w6-f72-net", "id": "n-1"}],
            "gateway": {"literal": {"type": "Host", "value": "192.0.2.14"}},
            "metricValue": 1,
            "type": "IPv4StaticRoute",
            "isTunneled": False,
            "id": "r-new",
        }
    )
    diff = await call("fmc_diff_device_config", {"a": path.name, "b": "live"}, bundle_dir=tmp_path)
    assert diff["identical"] is False and diff["summary"] == {"routing": {"added": 1}}
    (change,) = diff["changes"]
    assert change["key"] == "ipv4 route inside -> mcp-w6-f72-net"
    assert change["value"]["gateway"] == "192.0.2.14"
    assert diff["a"]["digest"] != diff["b"]["digest"]


async def test_diff_spoke1_with_spoke2(fmc: respx.MockRouter) -> None:
    """Two branches built alike: addresses differ (and spoke1's WAN path monitoring and priorities),
    nothing else; the routes match by interface and destination, the gateway is the changed field."""
    t1(fmc)
    out = await call("fmc_diff_device_config", {"a": "mcp-sdwan-t1-spoke1", "b": "mcp-sdwan-t1-spoke2"})
    assert out["a"]["device"] == "mcp-sdwan-t1-spoke1" and out["b"]["device"] == "mcp-sdwan-t1-spoke2"
    assert out["summary"] == {"interfaces": {"changed": 4}, "routing": {"changed": 3}}
    by_key = {c["key"]: c for c in out["changes"]}
    assert by_key["Ethernet0/0"]["fields"] == {
        "ipv4.static.address": {"from": "192.0.2.34", "to": "192.0.2.50"},
        "pathMonitoring.enable": {"from": True, "to": False},
        "pathMonitoring.monitoredIp": {"from": "192.0.2.33", "to": None},
        "pathMonitoring.type": {"from": "PEER_IPV4", "to": None},
        "priority": {"from": 1, "to": 0},
    }
    assert by_key["Ethernet0/3"]["fields"] == {
        "ipv4.static.address": {"from": "192.0.2.1", "to": "192.0.2.17"}
    }
    assert by_key["ipv4 route lte -> mcp-sdwan-lte-net"]["fields"] == {
        "gateway": {"from": "192.0.2.97", "to": "192.0.2.113"}
    }
    assert "Management0/0" not in by_key  # identical
    assert set(out["compared"]) >= {"device", "policies", "interfaces", "routing"}
    assert "not_compared" not in out


async def test_diff_sections_filter_and_paging(fmc: respx.MockRouter) -> None:
    t1(fmc)
    args = {"a": "mcp-sdwan-t1-spoke1", "b": "mcp-sdwan-t1-spoke2", "sections": ["routing"], "limit": 2}
    out = await call("fmc_diff_device_config", args)
    assert out["compared"] == ["routing"] and out["total"] == 3
    assert len(out["changes"]) == 2 and out["next_offset"] == 2


async def test_masks_secrets(fmc: respx.MockRouter) -> None:
    """BGP neighbor passwords, OSPF keys, SNMP communities, OOB CLI secrets and HA keys never appear, and
    changing one doesn't change the digest."""
    data = recorded()
    data[f"devices/devicerecords/{SP1}/routing/bgp"] = items(
        [
            {
                "id": "bgp-1",
                "type": "bgp",
                "asNumber": "65001",
                "addressFamilyIPv4": {
                    "neighbors": [
                        {
                            "ipv4Address": "192.0.2.200",
                            "remoteAs": "65000",
                            "neighborAdvanced": {"neighborSecret": "bgp-s3cret-1"},
                        }
                    ]
                },
            }
        ]
    ).json()
    data[f"devices/devicerecords/{SP1}/routing/ospfv2routes"] = items(
        [
            {
                "id": "o-1",
                "processId": 1,
                "areas": [{"areaId": "0", "authentication": {"md5Key": "ospf-s3cret"}}],
            }
        ]
    ).json()
    data[f"devices/devicerecords/{SP1}/operational/outofbandchanges"] = items(
        [
            {
                "oobId": "2c0cd497",
                "oobType": "CONFIG_MODE",
                "oobTaskStatus": "SUCCESS",
                "configDiffInfo": "OOB_CHANGES_REQUEST_COMPLETED_DIFF_REPORTED",
                "isOOBAcknowledged": False,
                "configCLIDiffLines": "hostname firepower@<nextline>enable password ****** encrypted"
                "@<nextline>+ snmp-server community oob-s3cret@<nextline>+ neighbor 192.0.2.9 password 0 "
                "oob-bgp-s3cret@<nextline>",
            }
        ]
    ).json()
    data["global:assignment/policyassignments"]["items"].append(
        {
            "type": "PolicyAssignment",
            "policy": {"type": "FTDPlatformSettingsPolicy", "name": "mcp-w6-ps", "id": "ps-1"},
            "targets": [{"id": SP1, "type": "Device", "name": "mcp-sdwan-t1-spoke1"}],
            "id": "ps-1",
        }
    )
    state = t1(fmc, data)
    fmc.get(f"{CFG}/policy/ftdplatformsettingspolicies/ps-1/snmpsettings").mock(
        side_effect=lambda _req: httpx.Response(200, json=state["data"]["snmp"])
    )
    state["data"]["snmp"] = items(
        [
            {
                "type": "FTDSNMPPlatformSettings",
                "id": "s-1",
                "enableSNMPServers": True,
                "readCommunity": "snmp-s3cret",
            }
        ]
    ).json()
    fmc.get(url__regex=rf"{re.escape(CFG)}/policy/ftdplatformsettingspolicies/ps-1/.+").mock(
        return_value=empty()
    )
    out, doc = await export()
    text = out["export"]
    assert "s3cret" not in text
    bgp = doc["routing"]["bgp"]["addressFamilyIPv4"]["neighbors"][0]
    assert bgp["neighborAdvanced"]["neighborSecret"] == MASK and bgp["ipv4Address"] == "192.0.2.200"
    assert doc["routing"]["ospfv2 process 1"]["areas"][0]["authentication"]["md5Key"] == MASK
    assert doc["platform_settings"]["snmp"] == {"enableSNMPServers": True, "readCommunity": MASK}
    assert doc["policies"]["platform_settings"] == {"name": "mcp-w6-ps", "domain": "Global"}
    oob = doc["out_of_band"]["2c0cd497"]
    assert oob["diff"] == [
        "hostname firepower",
        "enable password ****** encrypted",
        f"+ snmp-server community {MASK}",
        f"+ neighbor 192.0.2.9 password 0 {MASK}",
    ]
    state["data"]["snmp"]["items"][0]["readCommunity"] = "another-s3cret"
    again, _ = await export()
    assert again["digest"] == out["digest"]


def test_mask_cli() -> None:
    assert (
        mask_cli("ikev2 local-authentication pre-shared-key 0 abc")
        == f"ikev2 local-authentication pre-shared-key 0 {MASK}"
    )
    assert (
        mask_cli("username admin password xyz privilege 15") == f"username admin password {MASK} privilege 15"
    )
    assert mask_cli("enable password ****** encrypted") == "enable password ****** encrypted"
    assert mask_cli("interface Ethernet0/1") == "interface Ethernet0/1"
    # The value comes after an encryption type, key id, hash, format or EIGRP AS: those stay, it doesn't.
    for line, kept in (
        ("ospf message-digest-key 1 md5 S1", "ospf message-digest-key 1 md5"),
        ("ntp authentication-key 2 md5 S1", "ntp authentication-key 2 md5"),
        ("authentication key eigrp 100 S1 key-id 1", "authentication key eigrp 100"),
        ("failover key hex S1", "failover key hex"),
        ("snmp-server user u g v3 auth sha S1 priv aes 128 S2", "snmp-server user u g v3 auth sha"),
        ("snmp-server user u g v3 encrypted auth sha256 S1 priv aes256 S2", "priv aes256"),
        ("snmp-server community 12345", "snmp-server community"),
        ("aaa-server ISE (inside) host 192.0.2.5 key S1", "host 192.0.2.5 key"),
    ):
        masked = mask_cli(line)
        assert "S1" not in masked and "S2" not in masked and "12345" not in masked, masked
        assert kept in masked and MASK in masked
    assert mask_cli("authentication key eigrp 100 S1 key-id 1").endswith("key-id 1")
    for plain in ("aaa authentication ssh console LOCAL", "ssh key-exchange group dh-group14-sha256"):
        assert mask_cli(plain) == plain


async def test_vpn_nat_and_overrides(fmc: respx.MockRouter) -> None:
    """VPN membership from the topology's endpoints, the assigned (Global) NAT policy's rules in order,
    and an override of an overridable host on this device only."""
    data = recorded()
    data["global:assignment/policyassignments"]["items"].append(
        {
            "type": "PolicyAssignment",
            "policy": {"type": "FTDNatPolicy", "name": "mcp-test-nat", "id": "nat-1"},
            "targets": [{"id": SP1, "type": "Device", "name": "mcp-sdwan-t1-spoke1"}],
            "id": "nat-1",
        }
    )
    t1(fmc, data)
    sdwan = fixture("sdwan_lab")
    topo = sdwan["policy/ftds2svpns"]
    endpoints = copy.deepcopy(sdwan["policy/ftds2svpns/topo-t1/endpoints"])
    for e in endpoints["items"]:
        if e["name"] == "mcp-sdwan-t1-spoke1":
            e["device"]["id"] = SP1
    fmc.get(f"{CFG}/policy/ftds2svpns").mock(return_value=httpx.Response(200, json=topo))
    fmc.get(f"{CFG}/policy/ftds2svpns/topo-t1/endpoints").mock(
        return_value=httpx.Response(200, json=endpoints)
    )
    fmc.get(f"{CFG}/policy/ftdnatpolicies/nat-1/natrules").mock(
        return_value=httpx.Response(200, json=fixture("natrules"))
    )
    host = {
        "id": "h-1",
        "type": "Host",
        "name": "mcp-w6-branch-gw",
        "value": "192.0.2.254",
        "overridable": True,
    }
    fmc.get(f"{CFG}/object/hosts").mock(
        return_value=items([host, {**host, "id": "h-2", "name": "fixed", "overridable": False}])
    )
    fmc.get(f"{CFG}/object/hosts/h-1/overrides").mock(
        return_value=items(
            [
                {"value": "192.0.2.14", "overrides": {"target": {"id": SP1, "type": "Device"}}},
                {"value": "192.0.2.30", "overrides": {"target": {"id": SP2, "type": "Device"}}},
            ]
        )
    )
    out, doc = await export()
    vpn = doc["vpn"]["mcp-sdwan-t1"]
    assert vpn["topology"] == "SD-WAN (hub and spoke)" and vpn["peerType"] == "SPOKE"
    assert vpn["interface"] == {"name": "Ethernet0/0", "type": "PhysicalInterface"}
    assert vpn["backupInterfaces"] == [{"interface": {"name": "Ethernet0/1", "type": "PhysicalInterface"}}]
    assert doc["policies"]["nat"] == {"name": "mcp-test-nat", "domain": "Global"}
    assert doc["nat"]["name"] == "mcp-test-nat"
    assert [r["section"] for r in doc["nat"]["rules"]] == ["before_auto", "auto"]
    assert out["sections"]["nat"] == 2
    assert doc["object_overrides"] == {
        "Host mcp-w6-branch-gw": {"default": "192.0.2.254", "value": "192.0.2.14"}
    }
    # spoke2: no VPN membership, its own override, the NAT policy only on spoke1
    diff = await call("fmc_diff_device_config", {"a": "mcp-sdwan-t1-spoke1", "b": "mcp-sdwan-t1-spoke2"})
    summary = diff["summary"]
    assert summary["vpn"] == {"removed": 1} and summary["object_overrides"] == {"changed": 1}
    assert summary["policies"] == {"removed": 1} and summary["nat"] == {"removed": 1}
    nat = next(c for c in diff["changes"] if c["section"] == "nat")
    assert nat["key"] == "mcp-test-nat"


async def test_diff_with_device_template(fmc: respx.MockRouter) -> None:
    """b = a device template: only what it defines counts; ${variables} take the values applied to
    spoke1; device interfaces the template doesn't name are skipped and counted."""
    t1(fmc)
    tmpl = copy.deepcopy(fixture("devicetemplates"))
    tid = "b02a4b38-c000-11ee-b131-635e66f9d48b"
    base = f"{CFG}/templates/devicetemplates"
    ifaces = tmpl[f"{base}/{tid}/templateinterfaces"]["items"]
    ifaces[0]["name"], ifaces[1]["name"] = "Ethernet0/0", "Ethernet0/3"
    ifaces[0]["ifname"] = "mpls"
    assoc = tmpl[f"{base}/{tid}/associations"]["items"][0]
    assoc["variableValues"] = [
        {"key": "wanIp", "value": "192.0.2.34/28"},
        {"key": "localPassword", "value": "spoke1-s3cret"},
    ]
    vpn = tmpl[f"{base}/{tid}/vpnsettings/0050568C-430C-0ed3-0000-210453397646"]
    vpn["vpnConnections"][0]["vpnInterface"]["name"] = "Ethernet0/0"
    for path, body in tmpl.items():
        if path.startswith("/"):
            fmc.get(path).mock(return_value=httpx.Response(200, json=body))
    out = await call("fmc_diff_device_config", {"a": "mcp-sdwan-t1-spoke1", "b": "mcp-sdwan-spoke-tmpl"})
    assert out["b"] == {
        "device": "mcp-sdwan-spoke-tmpl",
        "kind": "template",
        "domain": "Global/mcp-test-leaf",
        "exported_at": "live",
        "digest": out["b"]["digest"],
    }
    by_key = {(c["section"], c["key"]): c for c in out["changes"]}
    # Ethernet0/0: the template's zone differs; the address is wanIp as applied to spoke1 (equal)
    assert by_key[("interfaces", "Ethernet0/0")]["fields"] == {
        "securityZone": {"from": "mcp-sdwan-wan", "to": "mcp-sdwan-outside"}
    }
    # Ethernet0/3: insideIp's default (10.10.1.1/24) isn't what spoke1 has
    inside = by_key[("interfaces", "Ethernet0/3")]["fields"]
    assert inside["ipv4.static.address"]["to"] == "10.10.1.1" and inside["ipv4.static.netmask"]["to"] == "24"
    assert by_key[("policies", "nat")]["op"] == "added"  # the template assigns a NAT policy spoke1 lacks
    assert by_key[("vpn", "mcp-sdwan-t1")]["value"] == {
        "peerType": "SPOKE",
        "interface": {"name": "Ethernet0/0"},
    }
    assert ("policies", "access") not in by_key  # same access policy
    assert ("device", "device") not in by_key  # ROUTED both
    assert out["not_in_template"] == {"interfaces": 3, "policies": 1}
    assert out["not_compared"]["routing"] == "not in the template"
    assert "s3cret" not in json.dumps(out)
    # A section the template doesn't define is never "identical": refused, with the reason.
    async with Client(server()) as c:
        args = {"a": "mcp-sdwan-t1-spoke1", "b": "mcp-sdwan-spoke-tmpl", "sections": ["routing"]}
        res = await c.call_tool("fmc_diff_device_config", args, raise_on_error=False)
    assert res.is_error and "routing: not in the template" in res.content[0].text  # type: ignore[union-attr]


async def test_export_ha_pair(fmc: respx.MockRouter) -> None:
    """An HA pair: the primary's configuration, the pair's policies and the failover settings."""
    data = recorded()
    ha = fixture("ha_failover")
    pair = copy.deepcopy(ha["pair"])
    pair["primary"]["id"] = SP1
    pair["ftdHABootstrap"]["sharedKey"] = "ha-s3cret"
    data["assignment/policyassignments"]["items"].append(
        {
            "type": "PolicyAssignment",
            "policy": {"type": "AccessPolicy", "name": "mcp-fw-base-acp", "id": "acp-ha"},
            "targets": [{"id": pair["id"], "type": "DeviceHAPair", "name": "mcp-fw-ha"}],
            "id": "acp-ha",
        }
    )
    for a in data["assignment/policyassignments"]["items"]:  # FMC assigns to the pair, not its units
        a["targets"] = [x for x in a["targets"] if x["id"] != SP1]
    t1(fmc, data)
    ha_base = f"{CFG}/devicehapairs/ftddevicehapairs"
    fmc.get(ha_base).mock(return_value=items([pair]))
    fmc.get(f"{ha_base}/{pair['id']}").mock(return_value=httpx.Response(200, json=pair))
    fmc.get(f"{ha_base}/{pair['id']}/monitoredinterfaces").mock(return_value=items(ha["monitoredinterfaces"]))
    fmc.get(f"{ha_base}/{pair['id']}/failoverinterfacemacaddressconfigs").mock(return_value=empty())
    out, doc = await export("mcp-fw-ha")
    assert out["kind"] == "ha_pair" and doc["meta"]["units"] == {
        "primary": "mcp-fw-ha-a",
        "secondary": "mcp-fw-ha-b",
    }
    assert doc["meta"]["id"] == pair["id"] and doc["interfaces"]["Ethernet0/0"]["ifname"] == "mpls"
    assert doc["policies"]["access"] == {"name": "mcp-fw-base-acp"}  # the pair's, not the unit's record
    assert doc["ha"]["failover link"]["logicalName"] == "FAILOVER-LINK"
    assert doc["ha"]["settings"]["sharedKey"] == MASK and "ha-s3cret" not in out["export"]
    assert {"monitored management", "monitored outside", "monitored inside"} <= set(doc["ha"])


# --- registry, parsing, refusals ----------------------------------------------------------------


async def test_state_sections_plug_in(fmc: respx.MockRouter) -> None:
    """F73 adds state sections to the registry; they stay out of the default set."""

    @export_section("test_state", kind="state", default=False, summary="a test")
    async def _state(ctx: ExportContext) -> dict[str, Any]:
        return {"tunnel": {"status": "UP", "peer": ctx.device.get("name")}}

    try:
        assert "test_state" not in select_sections(None)
        state = select_sections(["state"])
        assert state[-1] == "test_state" and all(SECTIONS[n].kind == "state" for n in state)
        assert not set(state) & set(select_sections(None))
        assert select_sections(["test_state", "device"]) == ["device", "test_state"]
        t1(fmc)
        out = await call("fmc_export_device_config", {"device": SP1, "sections": ["device", "test_state"]})
        doc = parse_export(out["export"], None)
        assert doc["meta"]["sections"] == ["device", "test_state"]
        assert doc["test_state"] == {"tunnel": {"status": "UP", "peer": "mcp-sdwan-t1-spoke1"}}
        with pytest.raises(ValueError, match="twice"):
            export_section("test_state")(_state)
    finally:
        SECTIONS.pop("test_state", None)
    with pytest.raises(InvalidRequest, match="Unknown section"):
        select_sections(["routes"])


def test_parse_export_refuses(tmp_path: Path) -> None:
    with pytest.raises(InvalidRequest, match="Not a device configuration export"):
        parse_export(yaml.safe_dump({"schema": 1, "meta": {"policy": "x"}}), None)
    with pytest.raises(InvalidRequest, match="FMC_BUNDLE_DIR isn't set"):
        parse_export("device-x.yaml", None)
    with pytest.raises(InvalidRequest, match="not a device configuration|Not a device"):
        parse_export("../outside.yaml\n", tmp_path)
    with pytest.raises(Exception, match="No export file"):
        parse_export("missing.yaml", tmp_path)
    with pytest.raises(InvalidRequest, match="version"):
        parse_export(yaml.safe_dump({"format": "fmc-device-config", "version": 9}), None)


async def test_diff_refusals(fmc: respx.MockRouter) -> None:
    t1(fmc)
    async with Client(server()) as c:
        res = await c.call_tool("fmc_diff_device_config", {"a": "mcp-sdwan-t1-spoke1"}, raise_on_error=False)
        assert res.is_error and "Pass `b`" in res.content[0].text  # type: ignore[union-attr]
        res = await c.call_tool(
            "fmc_diff_device_config", {"a": "mcp-sdwan-t1-spoke1", "b": "nope"}, raise_on_error=False
        )
        assert res.is_error and "No device, HA pair or device template named 'nope'" in res.content[0].text  # type: ignore[union-attr]
        res = await c.call_tool("fmc_export_device_config", {"device": "nope"}, raise_on_error=False)
        assert res.is_error and "No HA pair of that name either" in res.content[0].text  # type: ignore[union-attr]
        # A stored export of routing only, compared on interfaces: nothing on both sides.
        res = await c.call_tool("fmc_export_device_config", {"device": SP1, "sections": ["routing"]})
        stored = (res.structured_content or {})["export"]
        args = {"a": stored, "sections": ["interfaces"]}
        res = await c.call_tool("fmc_diff_device_config", args, raise_on_error=False)
        assert res.is_error and "nothing to compare" in res.content[0].text  # type: ignore[union-attr]


async def test_vrf_routing_and_ospfv3_interfaces(fmc: respx.MockRouter) -> None:
    """A user VRF exports its own routes and protocols (static, PBR, ECMP, EIGRP, BFD, OSPF interfaces),
    keyed 'vrf <name>: ...'; OSPFv3 interfaces come from the global table. Keys stay masked."""
    data = recorded()
    routing = f"devices/devicerecords/{SP1}/routing"
    inside = {"type": "PhysicalInterface", "id": "if-in", "name": "Ethernet0/3", "ifname": "inside"}
    data[f"{routing}/virtualrouters"]["items"].append(
        {"type": "VirtualRouter", "id": "vr-blue", "name": "blue", "interfaces": [inside]}
    )
    vr = f"{routing}/virtualrouters/vr-blue"
    data[f"{vr}/ipv4staticroutes"] = items(
        [
            {
                "id": "r-b",
                "interfaceName": "inside",
                "selectedNetworks": [{"type": "Network", "name": "blue-net", "id": "n-b"}],
                "gateway": {"literal": {"type": "Host", "value": "192.0.2.14"}},
                "metricValue": 1,
            }
        ]
    ).json()
    data[f"{vr}/policybasedroutes"] = items(
        [
            {
                "id": "p-b",
                "ingressInterfaces": [inside],
                "forwardingActions": [{"forwardingActionType": "SET_EGRESS_INTF_BY_ORDER"}],
            }
        ]
    ).json()
    data[f"{vr}/ecmpzones"] = items([{"id": "e-b", "name": "blue-wan", "interfaces": [inside]}]).json()
    data[f"{vr}/eigrproutes"] = items([{"id": "g-b", "asNumber": 100, "autoSummary": False}]).json()
    data[f"{vr}/bfdpolicies"] = items([{"id": "b-b", "hopType": "SINGLE_HOP", "interface": inside}]).json()
    data[f"{vr}/ospfinterface"] = items(
        [
            {
                "id": "o-b",
                "deviceInterface": inside,
                "authentication": {"md5AuthList": [{"md5KeyId": 1, "md5Key": "vrf-s3cret"}]},
            }
        ]
    ).json()
    data[f"{routing}/ospfv3interfaces"] = items(
        [
            {
                "id": "o3",
                "deviceInterface": inside,
                "processId": 1,
                "areaId": "0",
                "properties": {"packetCost": 5},
            }
        ]
    ).json()
    t1(fmc, data)
    out, doc = await export()
    assert "vrf-s3cret" not in out["export"]
    keys = set(doc["routing"])
    assert {
        "vrf blue",
        "vrf blue: ipv4 route inside -> blue-net",
        "vrf blue: policy-based route Ethernet0/3",
        "vrf blue: ecmp zone blue-wan",
        "vrf blue: eigrp 100",
        "vrf blue: bfd SINGLE_HOP Ethernet0/3",
        "vrf blue: ospf interface Ethernet0/3",
        "ospfv3 interface Ethernet0/3",
    } <= keys
    assert doc["routing"]["vrf blue"] == {"interfaces": ["Ethernet0/3"]}
    assert doc["routing"]["vrf blue: ospf interface Ethernet0/3"]["authentication"]["md5AuthList"] == [
        {"md5Key": MASK, "md5KeyId": MASK}
    ]
    assert doc["routing"]["ospfv3 interface Ethernet0/3"]["properties"] == {"packetCost": 5}
    # Global-only collections are not read per VRF.
    paths = {c.request.url.path for c in fmc.calls}
    assert f"{CFG}/{vr}/bgpgeneralsettings" not in paths and f"{CFG}/{vr}/ospfv3routes" not in paths
    assert f"{CFG}/{vr}/eigrproutes" in paths


async def test_include_text_false_needs_bundle_dir(fmc: respx.MockRouter) -> None:
    """Refused before any device read: nowhere to put the export."""
    t1(fmc)
    async with Client(server()) as c:
        res = await c.call_tool(
            "fmc_export_device_config", {"device": SP1, "include_text": False}, raise_on_error=False
        )
    assert res.is_error and "needs FMC_BUNDLE_DIR" in res.content[0].text  # type: ignore[union-attr]
    assert not [c for c in fmc.calls if c.request.url.path.startswith(f"{DEV}/")]  # no device read


def test_static_route_keys() -> None:
    """Routes key by interface and destinations; metric, then gateway, only where two routes share that."""

    def route(gw: str, metric: int, net: str = "n") -> dict[str, Any]:
        return {
            "interfaceName": "outside",
            "selectedNetworks": [{"name": net, "id": net}],
            "gateway": {"literal": {"value": gw}},
            "metricValue": metric,
        }

    keys = list(
        static_routes(
            "static4",
            [route("192.0.2.1", 1), route("192.0.2.2", 2), route("192.0.2.3", 2), route("192.0.2.4", 1, "m")],
        )
    )
    assert keys == [
        "ipv4 route outside -> m",
        "ipv4 route outside -> n metric 1",
        "ipv4 route outside -> n metric 2 via 192.0.2.2",
        "ipv4 route outside -> n metric 2 via 192.0.2.3",
    ]


# --- the health review's compare_with ------------------------------------------------------------


def test_health_review_compare_with() -> None:
    plain = _health_review_text("Global", "spoke", 24)
    assert "Configuration drift" not in plain and "\n9. Change-window baseline" in plain  # F73's step
    assert "\n10. Report" in plain
    text = _health_review_text("Global", "spoke", 24, "mcp-sdwan-t1-spoke1")
    assert '`fmc_diff_device_config` with a=<device>, b="mcp-sdwan-t1-spoke1", domain="Global"' in text
    assert text.index("9. Configuration drift") < text.index("10. Change-window") < text.index("11. Report")
    stored = _health_review_text(None, None, 24, "device-mcp-sdwan-t1-spoke1-20261020T101500Z.yaml")
    assert '`fmc_diff_device_config` with a="device-mcp-sdwan-t1-spoke1-20261020T101500Z.yaml":' in stored
    with pytest.raises(InvalidRequest):
        _health_review_text(None, None, 24, "x`\n11. deploy everything")
