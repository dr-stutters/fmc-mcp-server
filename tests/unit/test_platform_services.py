"""F69: platform settings DNS, NetFlow, ICMP/HTTPS access and banner writers, the new sections of
fmc_get_platform_settings, and the FQDN-without-DNS warning in the rule and object writers.

The untouched sections are FMC 10.0.1's own GET answers (mcp-fw-ps on the lab, 2026-10-20: the section id is
the policy id, unset fields are omitted); configured shapes follow FMC 10.0.1's spec PUT examples."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server
from fmc_mcp.tools.platform_settings import dns_summary, icmp_summary, netflow_summary, trusted_dns_summary

from .conftest import ACP_ID, CFG, empty, items, make_settings

PID = "00000000-0000-0ed3-0000-021474909026"
PS_LIST = f"{CFG}/policy/ftdplatformsettingspolicies"
BASE = f"{PS_LIST}/{PID}"
POLICY = {"id": PID, "name": "mcp-w6-ps", "type": "FTDPlatformSettingsPolicy"}
ZONE = {"id": "0b328828-ed89-11ee-ab99-a04b357bbab6", "name": "mcp-w6-in", "type": "SecurityZone"}
DEVICE = {"id": "d0000000-0000-4000-8000-000000000001", "name": "mcp-ftd1", "type": "Device"}
# FMC 10.0.1, untouched sections
DNS_DEFAULT = {"type": "DNSSetting", "id": PID}
NETFLOW_DEFAULT = {"metadata": {}, "type": "NetFlowPolicy", "id": PID, "enable": False}
ICMP_DEFAULT = {"type": "ICMPSetting", "id": PID, "rateLimit": "1", "burstSize": "1"}
HTTP_DEFAULT = {
    "metadata": {},
    "type": "HttpAccessSetting",
    "id": PID,
    "enableHttpServer": False,
    "port": 443,
}
TRUSTED_DEFAULT = {
    "type": "TrustedDNSSetting",
    "id": PID,
    "trustAnyDNSServer": False,
    "trustDhcpPool": True,
    "trustDhcpRelay": True,
    "trustDhcpClient": True,
    "trustDNSServerGroup": True,
}
BANNER_DEFAULT = {"type": "BannerSetting", "id": PID}
# spec PUT example (FTD DNS settings), groups renamed
DNS_SET = {
    "type": "DNSSetting",
    "id": PID,
    "dnsServerGroups": [
        {
            "dnsServerGroup": {
                "name": "mcp-w6-dns-2",
                "id": "00505681-5423-0ed3-0000-012884902039",
                "type": "DNSServerGroupObject",
            },
            "isDefault": False,
            "bypassDomains": ["example.com"],
        },
        {
            "dnsServerGroup": {
                "name": "mcp-w6-dns-1",
                "id": "00505681-5423-0ed3-0000-012884902021",
                "type": "DNSServerGroupObject",
            },
            "isDefault": True,
        },
    ],
    "expiryTimerInMins": 500,
    "pollTimerInMins": 501,
    "enableLookupViaMgmt": True,
    "interfaceObjects": [ZONE],
}
GROUP_1 = {
    "id": "00505681-5423-0ed3-0000-012884902021",
    "name": "mcp-w6-dns-1",
    "type": "DNSServerGroupObject",
    "dnsservers": [{"name-server": "192.0.2.53"}],
    "retries": 2,
    "timeout": 2,
}
COLLECTOR = {
    "id": "e276abeb-e0f2-11e3-8169-6d9ed49b625f",
    "type": "Host",
    "name": "mcp-w6-nf",
    "value": "192.0.2.50",
}
NETFLOW_SET = {  # spec PUT example
    "id": PID,
    "type": "NetFlowPolicy",
    "enable": True,
    "refreshInterval": 25,
    "delayFlowCreate": 12,
    "templateExportTime": 30,
    "flowCollectors": [
        {
            "collectorHost": {"id": COLLECTOR["id"], "type": "Host", "name": "mcp-w6-nf"},
            "interfaces": {
                "objects": [
                    {
                        "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
                        "type": "InterfaceGroup",
                        "name": "MGMT_TYPE_IG",
                    }
                ]
            },
            "port": "4566",
        }
    ],
    "trafficClasses": [
        {
            "trafficClassType": "ACCESS_LIST",
            "trafficClassName": "traffic_class_1",
            "extendedAccessList": {
                "id": "d5eefa54-5449-11ed-bce6-c70590de7487",
                "type": "ExtendedAccessList",
                "name": "mcp-w6-acl",
            },
            "exportFlows": [
                {
                    "collectorHost": {"id": COLLECTOR["id"], "type": "Host", "name": "mcp-w6-nf"},
                    "eventType": ["ALL"],
                }
            ],
        }
    ],
}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def preview_confirm(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(server()) as c:
        p = await run(c, name, args)
        assert p["status"] == "preview", p
        done = await run(c, name, {**args, "confirm": p["confirm"]})
    return p, done


def mock_ps(fmc: respx.MockRouter, **sections: dict[str, Any]) -> dict[str, respx.Route]:
    """The policy, its F69 sections (FMC defaults unless given) and a PUT route per section."""
    fmc.get(PS_LIST).mock(return_value=items([POLICY]))
    current = {
        "dnssettings": DNS_DEFAULT,
        "netflowpolicies": NETFLOW_DEFAULT,
        "icmpsettings": ICMP_DEFAULT,
        "httpaccesssettings": HTTP_DEFAULT,
        "trusteddnssettings": TRUSTED_DEFAULT,
        "bannersettings": BANNER_DEFAULT,
        **sections,
    }
    puts = {}
    for sub, obj in current.items():
        fmc.get(f"{BASE}/{sub}").mock(return_value=items([obj]))
        puts[sub] = fmc.put(f"{BASE}/{sub}/{obj['id']}").mock(return_value=httpx.Response(200, json=obj))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items([{"policy": POLICY, "targets": [DEVICE]}])
    )
    fmc.get(f"{CFG}/object/securityzones").mock(return_value=items([ZONE]))
    fmc.get(f"{CFG}/object/interfacegroups").mock(return_value=empty())
    return puts


# --- read ---------------------------------------------------------------------------------------------


def test_summaries_of_recorded_and_spec_shapes() -> None:
    note = dns_summary(DNS_DEFAULT)
    assert note is not None and set(note) == {"note"} and "never resolve" in note["note"]
    dns = dns_summary(DNS_SET)
    assert dns is not None and dns["server_groups"][1] == {
        "group": "mcp-w6-dns-1",
        "default": True,
        "domains": None,
    }
    assert dns["interfaces"] == ["mcp-w6-in"] and dns["poll_minutes"] == 501 and "note" not in dns
    assert netflow_summary(NETFLOW_DEFAULT) == {"enabled": False}
    nf = netflow_summary(NETFLOW_SET)
    assert nf is not None and nf["collectors"] == [
        {"collector": "mcp-w6-nf", "port": "4566", "via": ["MGMT_TYPE_IG"]}
    ]
    assert nf["traffic_classes"] == [
        {"name": "traffic_class_1", "match": "mcp-w6-acl", "exports": ["mcp-w6-nf: ALL"]}
    ]
    assert icmp_summary(ICMP_DEFAULT) == {"rate_limit": "1", "burst_size": "1"}
    assert trusted_dns_summary(TRUSTED_DEFAULT) == {
        "any_dns_server": False,
        "dns_server_group": True,
        "dhcp_pool": True,
        "dhcp_relay": True,
        "dhcp_client": True,
    }


async def test_get_platform_settings_has_the_new_sections(fmc: respx.MockRouter) -> None:
    mock_ps(
        fmc,
        dnssettings=DNS_SET,
        netflowpolicies=NETFLOW_SET,
        bannersettings={**BANNER_DEFAULT, "bannerText": ["Authorised", "use only"]},
    )
    for sub in (
        "syslog/servers",
        "syslog/basicloggingsetups",
        "syslog/syslogsettings",
        "ntpsettings",
        "snmpsettings",
    ):
        fmc.get(f"{BASE}/{sub}").mock(return_value=items([{"type": "X", "id": PID}]))
    for sub in ("syslog/loggingdestinations", "syslog/eventlists", "sshaccesssettings"):
        fmc.get(f"{BASE}/{sub}").mock(return_value=empty())
    async with Client(server()) as c:
        out = await run(c, "fmc_get_platform_settings", {"policy": "mcp-w6-ps"})
    assert out["netflow"]["enabled"] is True and out["netflow"]["collectors"][0]["collector"] == "mcp-w6-nf"
    assert out["icmp_access"] == {"rate_limit": "1", "burst_size": "1"}
    assert out["http_access"] == {"enabled": False, "port": 443}
    assert out["trusted_dns"]["dhcp_pool"] is True
    assert out["dns"]["server_groups"][1]["group"] == "mcp-w6-dns-1"
    assert out["banner"] == "Authorised\nuse only" and out["assigned_to"] == ["mcp-ftd1"]
    fmc.get(f"{BASE}/trusteddnssettings").mock(return_value=httpx.Response(404, json={"error": {}}))
    async with Client(server()) as c:
        out = await run(c, "fmc_get_platform_settings", {"policy": "mcp-w6-ps"})
    assert out["trusted_dns"] is None and out["netflow"]["enabled"] is True  # an FMC without the section


# --- DNS ----------------------------------------------------------------------------------------------


async def test_dns_creates_the_server_group(fmc: respx.MockRouter) -> None:
    puts = mock_ps(fmc)
    fmc.get(f"{CFG}/object/dnsservergroups").mock(return_value=empty())  # FMC 10.0.1: no `items` when none
    post = fmc.post(f"{CFG}/object/dnsservergroups").mock(
        return_value=httpx.Response(
            201,
            json={
                **GROUP_1,
                "name": "mcp-w6-ps-dns",
                "dnsservers": [{"name-server": "192.0.2.53"}, {"name-server": "198.51.100.53"}],
            },
        )
    )
    args = {
        "policy": "mcp-w6-ps",
        "servers": ["192.0.2.53", "198.51.100.53"],
        "domain_name": "example.com",
        "interfaces": ["mcp-w6-in"],
        "domain": "Global",
    }
    p, done = await preview_confirm("fmc_configure_dns", args)
    assert p["preview"]["creates_server_group"] == {
        "name": "mcp-w6-ps-dns",
        "servers": ["192.0.2.53", "198.51.100.53"],
    }
    assert p["preview"]["changes"]["pollTimerInMins"] == {"from": None, "to": 240}
    assert done["result"]["applied"] == ["dns"]
    group = json.loads(post.calls.last.request.content)
    assert group == {
        "name": "mcp-w6-ps-dns",
        "type": "DNSServerGroupObject",
        "dnsservers": [{"name-server": "192.0.2.53"}, {"name-server": "198.51.100.53"}],
        "retries": 2,
        "timeout": 2,
        "defaultdomain": "example.com",
    }
    body = json.loads(puts["dnssettings"].calls.last.request.content)
    assert body["dnsServerGroups"] == [
        {
            "dnsServerGroup": {"id": GROUP_1["id"], "type": "DNSServerGroupObject", "name": "mcp-w6-ps-dns"},
            "isDefault": True,
        }
    ]
    assert (
        body["interfaceObjects"] == [ZONE]
        and body["expiryTimerInMins"] == 1
        and body["pollTimerInMins"] == 240
    )
    assert body["id"] == PID and body["type"] == "DNSSetting"


async def test_dns_existing_group_replaces_the_default(fmc: respx.MockRouter) -> None:
    puts = mock_ps(fmc, dnssettings=DNS_SET)
    other = {**GROUP_1, "id": "00505681-5423-0ed3-0000-0128849020ff", "name": "mcp-w6-dns-3"}
    fmc.get(f"{CFG}/object/dnsservergroups").mock(return_value=items([GROUP_1, other]))
    _, _ = await preview_confirm(
        "fmc_configure_dns",
        {"policy": "mcp-w6-ps", "server_group": "mcp-w6-dns-3", "lookup_via_management": False},
    )
    body = json.loads(puts["dnssettings"].calls.last.request.content)
    groups = [(g["dnsServerGroup"]["name"], g["isDefault"]) for g in body["dnsServerGroups"]]
    assert groups == [("mcp-w6-dns-2", False), ("mcp-w6-dns-3", True)]  # the old default is replaced
    assert body["dnsServerGroups"][0]["bypassDomains"] == ["example.com"]
    assert body["enableLookupViaMgmt"] is False and body["pollTimerInMins"] == 501  # timers kept


async def test_dns_blockers(fmc: respx.MockRouter) -> None:
    mock_ps(fmc)
    fmc.get(f"{CFG}/object/dnsservergroups").mock(return_value=items([GROUP_1]))
    async with Client(server()) as c:
        clash = await run(
            c,
            "fmc_configure_dns",
            {"policy": "mcp-w6-ps", "servers": ["192.0.2.54"], "server_group": "mcp-w6-dns-1"},
        )
        assert clash["status"] == "blocked" and "exists with servers ['192.0.2.53']" in clash["blockers"][0]
        same = await run(
            c,
            "fmc_configure_dns",
            {"policy": "mcp-w6-ps", "servers": ["192.0.2.53"], "server_group": "mcp-w6-dns-1"},
        )
        assert same["status"] == "preview" and same["preview"]["creates_server_group"] is None  # reused
        none = await run(c, "fmc_configure_dns", {"policy": "mcp-w6-ps", "poll_minutes": 30})
        assert none["status"] == "blocked" and "No DNS server group" in none["blockers"][0]
        with pytest.raises(ToolError, match="not an IP address"):
            await run(c, "fmc_configure_dns", {"policy": "mcp-w6-ps", "servers": ["dns.example.com"]})
        with pytest.raises(ToolError, match="not both"):
            await run(
                c, "fmc_configure_dns", {"policy": "mcp-w6-ps", "servers": ["192.0.2.53"], "disable": True}
            )


async def test_dns_disable(fmc: respx.MockRouter) -> None:
    puts = mock_ps(fmc, dnssettings=DNS_SET)
    p, _ = await preview_confirm("fmc_configure_dns", {"policy": "mcp-w6-ps", "disable": True})
    assert "dnsServerGroups" in p["preview"]["changes"]
    assert json.loads(puts["dnssettings"].calls.last.request.content)["dnsServerGroups"] == []


# --- NetFlow ------------------------------------------------------------------------------------------


async def test_netflow_first_collector_creates_host_and_default_class(fmc: respx.MockRouter) -> None:
    puts = mock_ps(fmc)
    fmc.get(f"{CFG}/object/networks").mock(return_value=empty())
    fmc.get(f"{CFG}/object/hosts").mock(return_value=empty())
    host_post = fmc.post(f"{CFG}/object/hosts").mock(
        return_value=httpx.Response(201, json={**COLLECTOR, "name": "mcp-w6-nf"})
    )
    args = {
        "policy": "mcp-w6-ps",
        "collector": "192.0.2.50",
        "interfaces": ["mcp-w6-in"],
        "collector_name": "mcp-w6-nf",
    }
    p, done = await preview_confirm("fmc_configure_netflow", args)
    assert p["preview"]["creates_host_object"] == {"name": "mcp-w6-nf", "type": "Host", "value": "192.0.2.50"}
    assert p["preview"]["after"]["enabled"] is True
    assert p["preview"]["after"]["traffic_classes"] == [
        {"name": "class-default", "match": "all traffic", "exports": ["mcp-w6-nf: ALL"]}
    ]
    assert json.loads(host_post.calls.last.request.content)["value"] == "192.0.2.50"
    body = json.loads(puts["netflowpolicies"].calls.last.request.content)
    ref = {"id": COLLECTOR["id"], "type": "Host", "name": "mcp-w6-nf"}
    assert body["enable"] is True and body["refreshInterval"] == 1 and body["templateExportTime"] == 30
    assert body["flowCollectors"] == [{"collectorHost": ref, "port": 2055, "interfaces": {"objects": [ZONE]}}]
    assert body["trafficClasses"] == [
        {
            "trafficClassName": "class-default",
            "trafficClassType": "DEFAULT",
            "exportFlows": [{"collectorHost": ref, "eventType": ["ALL"]}],
        }
    ]
    assert done["result"]["applied"] == ["netflow"]


async def test_netflow_traffic_classes_and_remove(fmc: respx.MockRouter) -> None:
    puts = mock_ps(fmc, netflowpolicies=NETFLOW_SET)
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([COLLECTOR]))
    fmc.get(f"{CFG}/object/networks").mock(return_value=empty())
    acl = {"id": "d5eefa54-5449-11ed-bce6-c70590de7488", "type": "ExtendedAccessList", "name": "mcp-w6-acl-2"}
    fmc.get(f"{CFG}/object/extendedaccesslists").mock(return_value=items([acl]))
    classes = [
        {"name": "mcp-w6-web", "access_list": "mcp-w6-acl-2", "events": ["CREATED", "TORN_DOWN"]},
        {"name": "class-default"},
    ]
    await preview_confirm("fmc_configure_netflow", {"policy": "mcp-w6-ps", "traffic_classes": classes})
    body = json.loads(puts["netflowpolicies"].calls.last.request.content)
    ref = NETFLOW_SET["flowCollectors"][0]["collectorHost"]
    assert body["trafficClasses"] == [
        {
            "trafficClassName": "mcp-w6-web",
            "trafficClassType": "ACCESS_LIST",
            "exportFlows": [{"collectorHost": ref, "eventType": ["CREATED", "TORN_DOWN"]}],
            "extendedAccessList": acl,
        },
        {
            "trafficClassName": "class-default",
            "trafficClassType": "DEFAULT",
            "exportFlows": [{"collectorHost": ref, "eventType": ["ALL"]}],
        },
    ]
    assert body["refreshInterval"] == 25 and body["flowCollectors"] == NETFLOW_SET["flowCollectors"]  # kept
    p, _ = await preview_confirm(
        "fmc_configure_netflow", {"policy": "mcp-w6-ps", "remove_collector": "192.0.2.50", "enable": False}
    )
    body = json.loads(puts["netflowpolicies"].calls.last.request.content)
    assert body["enable"] is False and body["flowCollectors"] == [] and body["trafficClasses"] == []
    assert p["preview"]["changes"]["enable"] == {"from": True, "to": False}


async def test_netflow_blockers(fmc: respx.MockRouter) -> None:
    mock_ps(fmc)
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([COLLECTOR]))
    fmc.get(f"{CFG}/object/networks").mock(return_value=empty())
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="interfaces"):
            await run(c, "fmc_configure_netflow", {"policy": "mcp-w6-ps", "collector": "192.0.2.50"})
        on = await run(c, "fmc_configure_netflow", {"policy": "mcp-w6-ps", "enable": True})
        assert on["status"] == "blocked" and "needs a collector" in on["blockers"][0]
        new = {"policy": "mcp-w6-ps", "collector": "192.0.2.50", "interfaces": ["mcp-w6-in"]}
        with pytest.raises(ToolError, match="Only one traffic class"):
            await run(c, "fmc_configure_netflow", {**new, "traffic_classes": [{"name": "a"}, {"name": "b"}]})
        named = await run(
            c, "fmc_configure_netflow", {**new, "traffic_classes": [{"name": "all", "events": ["DENIED"]}]}
        )
        assert named["preview"]["after"]["traffic_classes"] == [
            {"name": "class-default", "match": "all traffic", "exports": ["mcp-w6-nf: DENIED"]}
        ]
        gone = await run(
            c, "fmc_configure_netflow", {"policy": "mcp-w6-ps", "remove_collector": "192.0.2.50"}
        )
        assert gone["status"] == "blocked" and "No collector" in gone["blockers"][0]


# --- ICMP / HTTPS access ------------------------------------------------------------------------------


async def test_icmp_allow_and_remove(fmc: respx.MockRouter) -> None:
    echo = {"id": "11111111-0000-4000-8000-0000000000e8", "name": "mcp-w6-echo", "type": "ICMPV4Object"}
    fmc.get(f"{CFG}/object/icmpv4objects").mock(return_value=items([echo]))
    puts = mock_ps(fmc)
    args = {
        "policy": "mcp-w6-ps",
        "kind": "icmp",
        "networks": ["198.51.100.0/24"],
        "interfaces": ["mcp-w6-in"],
        "icmp_service": "mcp-w6-echo",
        "rate_limit": 10,
    }
    p, _ = await preview_confirm("fmc_configure_mgmt_access", args)
    assert p["preview"]["after"]["rules"] == [
        {"action": "Permit", "service": "mcp-w6-echo", "network": "198.51.100.0/24", "via": ["mcp-w6-in"]}
    ]
    body = json.loads(puts["icmpsettings"].calls.last.request.content)
    assert body["icmpConfigs"] == [
        {
            "icmpAction": "Permit",
            "network": {"literal": "198.51.100.0/24"},
            "interfaces": {"objects": [ZONE]},
            "icmpService": {"id": echo["id"], "type": "ICMPV4Object", "name": "mcp-w6-echo"},
        }
    ]
    assert body["rateLimit"] == "10" and body["burstSize"] == "1"
    configured = {**ICMP_DEFAULT, "icmpConfigs": body["icmpConfigs"]}
    puts = mock_ps(fmc, icmpsettings=configured)
    async with Client(server()) as c:
        again = await run(c, "fmc_configure_mgmt_access", args)
        assert again["status"] == "blocked" and "already allowed" in again["blockers"][0]
        rm = {k: v for k, v in args.items() if k not in ("rate_limit", "interfaces")} | {"action": "remove"}
        p = await run(c, "fmc_configure_mgmt_access", rm)
        await run(c, "fmc_configure_mgmt_access", {**rm, "confirm": p["confirm"]})
    assert json.loads(puts["icmpsettings"].calls.last.request.content)["icmpConfigs"] == []


async def test_http_access_needs_a_network_object(fmc: respx.MockRouter) -> None:
    puts = mock_ps(fmc)
    net = {
        "id": "22222222-0000-4000-8000-000000000001",
        "name": "mcp-w6-admin-net",
        "type": "Network",
        "value": "198.51.100.0/24",
    }
    fmc.get(f"{CFG}/object/hosts").mock(return_value=empty())
    networks = fmc.get(f"{CFG}/object/networks").mock(return_value=empty())
    args = {
        "policy": "mcp-w6-ps",
        "kind": "http",
        "networks": ["198.51.100.0/24"],
        "interfaces": ["mcp-w6-in"],
        "http_port": 8443,
    }
    async with Client(server()) as c:
        out = await run(c, "fmc_configure_mgmt_access", args)
    assert (
        out["status"] == "blocked"
        and "No network object with the value 198.51.100.0/24" in out["blockers"][0]
    )
    networks.mock(return_value=items([net]))
    p, _ = await preview_confirm("fmc_configure_mgmt_access", args)
    assert p["preview"]["changes"]["enableHttpServer"] == {"from": False, "to": True}
    body = json.loads(puts["httpaccesssettings"].calls.last.request.content)
    assert body["enableHttpServer"] is True and body["port"] == 8443
    assert body["httpConfiguration"] == [
        {
            "ipAddress": {"id": net["id"], "type": "Network", "name": "mcp-w6-admin-net"},
            "interfaces": {"objects": [ZONE]},
        }
    ]


async def test_mgmt_access_needs_interfaces(fmc: respx.MockRouter) -> None:
    mock_ps(fmc)
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="interfaces"):
            await run(
                c,
                "fmc_configure_mgmt_access",
                {"policy": "mcp-w6-ps", "kind": "icmp", "networks": ["192.0.2.0/24"]},
            )


# --- banner -------------------------------------------------------------------------------------------


async def test_banner_set_and_clear(fmc: respx.MockRouter) -> None:
    puts = mock_ps(fmc)
    p, _ = await preview_confirm(
        "fmc_set_banner", {"policy": "mcp-w6-ps", "text": "Authorised use only\r\n$(hostname)\n\n"}
    )
    assert p["preview"]["before"] is None and p["preview"]["after"] == "Authorised use only\n$(hostname)"
    assert json.loads(puts["bannersettings"].calls.last.request.content) == {
        "type": "BannerSetting",
        "id": PID,
        "bannerText": ["Authorised use only", "$(hostname)"],
    }
    puts = mock_ps(fmc, bannersettings={**BANNER_DEFAULT, "bannerText": ["old"]})
    await preview_confirm("fmc_set_banner", {"policy": "mcp-w6-ps", "text": ""})
    assert json.loads(puts["bannersettings"].calls.last.request.content)["bannerText"] == []
    async with Client(server()) as c:
        same = await run(c, "fmc_set_banner", {"policy": "mcp-w6-ps", "text": "old"})
        assert same["status"] == "blocked"
        with pytest.raises(ToolError, match="longer than 510"):
            await run(c, "fmc_set_banner", {"policy": "mcp-w6-ps", "text": "x" * 511})


# --- the FQDN warning ---------------------------------------------------------------------------------

FQDN = {
    "id": "33333333-0000-4000-8000-000000000001",
    "name": "mcp-w6-fqdn",
    "type": "FQDN",
    "value": "www.example.com",
}
ACP_ASSIGNMENT = {
    "policy": {"id": ACP_ID, "name": "mcp-test-acp", "type": "AccessPolicy"},
    "targets": [DEVICE],
}
PS_ASSIGNMENT = {"policy": POLICY, "targets": [DEVICE]}


def mock_fqdn(fmc: respx.MockRouter, *, dns: dict[str, Any], ps_assigned: bool = True) -> None:
    for kind in ("hosts", "networks", "ranges", "networkgroups"):
        fmc.get(f"{CFG}/object/{kind}").mock(return_value=empty())
    fmc.get(f"{CFG}/object/fqdns").mock(return_value=items([FQDN]))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items([ACP_ASSIGNMENT] + ([PS_ASSIGNMENT] if ps_assigned else []))
    )
    fmc.get(f"{BASE}/dnssettings").mock(return_value=items([dns]))


async def test_access_rule_preview_warns_when_the_device_has_no_dns(lab: respx.MockRouter) -> None:
    mock_fqdn(lab, dns=DNS_DEFAULT)
    args = {
        "policy": "mcp-test-acp",
        "name": "mcp-w6-saas",
        "action": "ALLOW",
        "destination_networks": ["mcp-w6-fqdn"],
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_create_access_rule", args)
    assert p["status"] == "preview"
    (warning,) = p["preview"]["warnings"]
    assert "FQDN mcp-w6-fqdn" in warning and "mcp-ftd1 (platform settings mcp-w6-ps)" in warning
    assert "fmc_configure_dns policy='mcp-w6-ps'" in warning


async def test_no_warning_with_dns_or_without_fqdn(lab: respx.MockRouter) -> None:
    mock_fqdn(lab, dns=DNS_SET)
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_create_access_rule",
            {
                "policy": "mcp-test-acp",
                "name": "mcp-w6-saas",
                "action": "ALLOW",
                "destination_networks": ["mcp-w6-fqdn"],
            },
        )
        assert p["status"] == "preview" and "warnings" not in p["preview"]
        p = await run(
            c,
            "fmc_create_access_rule",
            {
                "policy": "mcp-test-acp",
                "name": "mcp-w6-tcp",
                "action": "ALLOW",
                "destination_ports": ["tcp/8443"],
            },
        )
        assert "warnings" not in p["preview"]


async def test_update_rule_and_group_member_warn(lab: respx.MockRouter) -> None:
    mock_fqdn(lab, dns=DNS_DEFAULT, ps_assigned=False)
    group = {"id": "44444444-0000-4000-8000-000000000001", "name": "mcp-w6-saas-grp", "type": "NetworkGroup"}
    lab.get(f"{CFG}/object/networkgroups").mock(return_value=items([group]))
    lab.get(f"{CFG}/object/networkgroups/{group['id']}").mock(
        return_value=httpx.Response(
            200, json={**group, "objects": [{k: FQDN[k] for k in ("id", "name", "type")}]}
        )
    )
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_update_access_rule",
            {
                "policy": "mcp-test-acp",
                "rule": "mcp-test-ssh-admin",
                "destination_networks": ["mcp-w6-saas-grp"],
            },
        )
    assert p["status"] == "preview"
    (warning,) = p["preview"]["warnings"]
    assert (
        "mcp-w6-fqdn (in group mcp-w6-saas-grp)" in warning
        and "mcp-ftd1 (no platform settings policy)" in warning
    )


async def test_create_fqdn_object_warns_and_a_failed_check_is_silent(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/fqdns").mock(return_value=empty())
    fmc.get(f"{CFG}/object/hosts").mock(return_value=empty())
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([ACP_ASSIGNMENT, PS_ASSIGNMENT]))
    dns = fmc.get(f"{BASE}/dnssettings").mock(return_value=items([DNS_DEFAULT]))
    args = {"type": "fqdn", "name": "mcp-w6-fqdn", "value": "www.example.com"}
    async with Client(server()) as c:
        p = await run(c, "fmc_create_object", args)
        assert "mcp-ftd1 (platform settings mcp-w6-ps)" in p["preview"]["warnings"][0]
        dns.mock(return_value=httpx.Response(500, json={"error": {"messages": [{"description": "boom"}]}}))
        p = await run(c, "fmc_create_object", args)
        assert p["status"] == "preview" and "warnings" not in p["preview"]
        p = await run(c, "fmc_create_object", {"type": "host", "name": "mcp-w6-h", "value": "192.0.2.9"})
    assert "warnings" not in p["preview"]
