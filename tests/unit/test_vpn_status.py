"""F41: fmc_vpn_status (every S2S topology's tunnels, the devices' IKE/IPsec SAs and sessions, routes over
the VTIs, degraded tunnels first). Fixture: tests/fixtures/vpn_status.json (`show` holds the device outputs,
`tunneldetails` the spec's TunnelDetail shape)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools import sdwan_status, show_commands
from fmc_mcp.tools.vpn_status import (
    detail_view,
    overlay_routes,
    parse_ikev2_sa,
    parse_ipsec_sa,
    parse_l2l_sessions,
    parse_routes,
)

from .conftest import CFG, fixture, items, make_settings

LAB = fixture("vpn_status")
SHOW = LAB["show"]


@pytest.fixture(autouse=True)
def _fresh_ike_counters() -> Any:
    sdwan_status._IKE_SEEN.clear()
    yield
    sdwan_status._IKE_SEEN.clear()


def server() -> Any:
    return create_server(make_settings(rate_limit=100000))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def lab(
    fmc: respx.MockRouter,
    *,
    tunnels: list[dict[str, Any]] | None = None,
    outputs: dict[str, dict[str, str]] | None = None,
) -> list[str]:
    """Mount the lab; return the log of show commands run (device id + command)."""
    for key, data in LAB.items():
        if not key.startswith("_") and key not in ("show", "tunneldetails"):
            fmc.get(f"{CFG}/{key}").mock(return_value=httpx.Response(200, json=data))
    if tunnels is not None:
        fmc.get(f"{CFG}/health/tunnelstatuses").mock(return_value=items(tunnels))
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([]))
    fmc.get(url__regex=r".*/health/tunnelstatuses/[^/]+/tunneldetails").mock(
        return_value=httpx.Response(200, json=LAB["tunneldetails"])
    )
    ran: list[str] = []

    def show(req: httpx.Request) -> httpx.Response:
        dev = req.url.path.split("/devicerecords/")[1].split("/")[0]
        cmd = " ".join(x for x in (req.url.params.get("command"), req.url.params.get("parameters")) if x)
        ran.append(f"{dev} {cmd}")
        text = (outputs or {}).get(dev, {}).get(cmd)
        if text is None:
            text = SHOW.get(dev, {}).get(cmd, "")
        return httpx.Response(200, json={"items": [{"commandInput": cmd, "commandOutput": text}]})

    fmc.get(url__regex=r".*/devicerecords/[^/]+/operational/commands.*").mock(side_effect=show)
    return ran


# --- parsers -------------------------------------------------------------------------------------------
def test_parse_ikev2_sa_with_and_without_vrf_column() -> None:
    a = parse_ikev2_sa(SHOW["d-a"]["show crypto ikev2 sa"])
    assert a == [
        {
            "session": 7,
            "session_status": "UP-ACTIVE",
            "child_sas": 1,
            "local": "203.0.113.1",
            "remote": "203.0.113.2",
            "remote_port": 500,
            "state": "READY",
            "role": "initiator",
            "encryption": "AES-GCM-256",
            "dh_group": 21,
            "auth": "PSK",
            "lifetime_s": 86400,
            "age_s": 583,
        }
    ]
    b = parse_ikev2_sa(SHOW["d-b"]["show crypto ikev2 sa"])
    assert b[0]["role"] == "responder" and b[0]["remote"] == "203.0.113.1" and "vrf" not in b[0]
    assert parse_ikev2_sa("There are no IKEv2 SAs\n") == []


def test_parse_ikev2_sa_not_ready_and_vrf() -> None:
    text = (
        "Session-id:2, Status:UP-IDLE, IKE count:1, CHILD count:0\n\n"
        " 1234 192.0.2.1/4500 198.51.100.9/4500 red/red IN-NEG INITIATOR\n"
        "      Encr: AES-CBC, keysize: 256, Hash: SHA256, DH Grp:14, Auth sign: PSK, Auth verify: RSA\n"
    )
    [sa] = parse_ikev2_sa(text)
    assert sa["state"] == "IN-NEG" and sa["vrf"] == "red/red" and sa["remote_port"] == 4500
    assert sa["hash"] == "SHA256" and sa["auth"] == "PSK/RSA" and sa["child_sas"] == 0


def test_parse_ipsec_sa() -> None:
    [sa] = parse_ipsec_sa(SHOW["d-a"]["show crypto ipsec sa"])
    assert sa == {
        "interface": "vti-to-b",
        "crypto_map": "__vti-crypto-map-Tunnel1-0-1",
        "local_network": "any",
        "remote_network": "any",
        "peer": "203.0.113.2",
        "encaps": 120,
        "decaps": 0,
        "send_errors": 0,
        "recv_errors": 0,
        "transform": "esp-aes-gcm-256 esp-null-hmac no compression",
        "rekey_in_s": 28215,
    }
    policy = SHOW["d-a"]["show crypto ipsec sa"].replace(
        "(0.0.0.0/0.0.0.0/0/0)", "(10.1.1.0/255.255.255.0/0/0)", 1
    )
    assert parse_ipsec_sa(policy)[0]["local_network"] == "10.1.1.0/24"
    assert parse_ipsec_sa("There are no ipsec sas\n") == []


def test_parse_l2l_sessions() -> None:
    [s] = parse_l2l_sessions(SHOW["d-a"]["show vpn-sessiondb l2l"])
    assert s == {
        "peer": "203.0.113.2",
        "protocol": "IKEv2 IPsec",
        "encryption": "IKEv2: (1)AES-GCM-256 IPsec: (1)AES-GCM-256",
        "hashing": "IKEv2: (1)none IPsec: (1)none",
        "bytes_tx": 14400,
        "bytes_rx": 0,
        "login_time": "09:41:12 UTC Sun Oct 18 2026",
        "duration": "0h:09m:43s",
        "duration_s": 583,
    }
    assert parse_l2l_sessions("INFO: There are presently no active sessions\n") == []
    two = parse_l2l_sessions(SHOW["d-a"]["show vpn-sessiondb l2l"] + SHOW["d-b"]["show vpn-sessiondb l2l"])
    assert [x["peer"] for x in two] == ["203.0.113.2", "203.0.113.1"]
    assert parse_l2l_sessions("Duration     : 1d 02h:03m:04s")[0:] == []  # no Connection line, no session


def test_parse_routes_and_overlay() -> None:
    routes = parse_routes(SHOW["d-a"]["show route"])
    by = {r["prefix"]: r for r in routes}
    assert by["0.0.0.0/0"]["code"] == "S*" and by["0.0.0.0/0"]["interfaces"] == ["outside"]
    assert by["10.2.3.0/24"] == {
        "code": "B",
        "protocol": "bgp",
        "prefix": "10.2.3.0/24",
        "via": ["169.254.10.2"],
        "interfaces": [],
    }
    over = overlay_routes(routes, {"vti-to-b"})
    assert over == [
        {"protocol": "static", "prefix": "10.2.2.0/24", "via": ["169.254.10.2"], "interfaces": ["vti-to-b"]},
        # recursive (no egress interface): the next hop is in the VTI's subnet
        {"protocol": "bgp", "prefix": "10.2.3.0/24", "via": ["169.254.10.2"]},
    ]
    assert overlay_routes(routes, set()) == []
    assert overlay_routes(parse_routes(SHOW["d-b"]["show route"]), {"vti-to-a"}) == []


def test_overlay_routes_dynamic_vti_and_ecmp() -> None:
    text = (
        "O        10.10.11.0 255.255.255.0 [110/11] via 10.255.9.9, 00:03:12, sdwan-dvti_va1\n"
        "O IA     10.10.12.0 255.255.255.0 [110/11] via 10.255.9.10, 1d02h, sdwan-dvti_va2\n"
        "B        10.20.1.0 255.255.255.0 [200/1] via 10.255.1.1, 00:12:41\n"
        "                                 [200/1] via 10.255.2.1, 00:12:41\n"
        "S        10.255.1.1 255.255.255.255 [1/0] via 10.255.1.1, mpls_static_vti_1\n"
        "S        10.99.0.0 255.255.0.0 [1/0] via 192.0.2.1, inside\n"
    )
    routes = parse_routes(text)
    assert [r["code"] for r in routes] == ["O", "O IA", "B", "S", "S"]
    assert routes[2]["via"] == ["10.255.1.1", "10.255.2.1"]
    over = overlay_routes(routes, {"sdwan-dvti", "mpls_static_vti_1"})
    assert [r["prefix"] for r in over] == ["10.10.11.0/24", "10.10.12.0/24", "10.20.1.0/24", "10.255.1.1/32"]


def test_detail_view_spec_shape() -> None:
    d = detail_view(LAB["tunneldetails"])
    assert d["peerA"]["auth"] == "PRESHARED_KEY" and d["peerA"]["bytes_tx"] == 14400
    assert d["peerA"]["sas"] == [
        {
            "network": "0.0.0.0/0.0.0.0/0/0",
            "encaps": 120,
            "decaps": 0,
            "settings": "L2L, Tunnel, IKEv2",
            "rekey_in_s": 28215,
        }
    ]
    assert "sas" not in d["peerB"]
    assert detail_view({}) == {}


# --- the tool ------------------------------------------------------------------------------------------
async def test_vpn_status_ranks_degraded_tunnels(fmc: respx.MockRouter) -> None:
    ran = lab(fmc)
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {})
    assert [t["topology"] for t in r["topologies"]] == ["mcp-fw-vti", "mcp-fw-pb", "mcp-fw-bc"]
    vti = r["topologies"][0]
    assert vti["route_based"] is True and vti["tunnels_up"] == 1 and vti["ike"] == "IKEv2"
    [tun] = vti["tunnels"]
    assert tun["vti"] == "vti-to-b <-> vti-to-a"
    assert tun["device_says"] == [
        "branch-a: IKE READY initiator, up 583 s; IPsec 120 out / 0 in, rekey in 28215 s",
        "branch-b: IKE READY responder, up 581 s; IPsec 0 out / 120 in, rekey in 28213 s",
    ]
    pb = r["topologies"][1]
    assert pb["route_based"] is False and pb["tunnels_down"] == 1
    assert {e["name"]: e.get("nat_exempt") for e in pb["endpoints"]} == {"branch-a": True, "hq-asa": None}
    # degraded: the down tunnel first (critical, with the IKEv2 counters), then the warnings
    deg = r["degraded"]
    assert deg[0]["severity"] == "critical" and deg[0]["topology"] == "mcp-fw-pb"
    assert "TUNNEL_DOWN" in deg[0]["reasons"][0]
    assert any("no READY IKE SA with hq-asa" in x for x in deg[0]["reasons"])
    assert any("Authentication Failures 8" in x and "fmc_vpn_status again" in x for x in deg[0]["reasons"])
    whats = {(d["device"], d["what"]) for d in deg[1:]}
    assert ("branch-a", "tunnel traffic") in whats and ("branch-b", "tunnel traffic") in whats  # one-way
    assert ("branch-b", "overlay routing") in whats  # B has no route back over its VTI
    assert ("branch-a", "overlay routing") not in whats
    assert ("branch-c", "device") in whats  # disconnected
    unknown = next(d for d in deg if d["topology"] == "mcp-fw-bc" and d["what"] == "tunnel")
    assert unknown["severity"] == "warning" and "UNKNOWN" in unknown["reasons"][0]
    assert all(d["severity"] == "warning" for d in deg[1:])
    assert r["summary"] == {
        "critical": 1,
        "warning": len(deg) - 1,
        "topologies": 3,
        "tunnels_up": 1,
        "tunnels_down": 1,
        "tunnels_unknown": 1,
    }
    devs = {d["device"]: d for d in r["devices"]}
    assert devs["branch-a"]["vtis"] == ["vti-to-b"]
    assert devs["branch-a"]["overlay_routes"][0]["prefix"] == "10.2.2.0/24"
    assert devs["branch-b"]["overlay_routes"] == []
    assert devs["branch-c"] == {"device": "branch-c", "connected": False}
    assert devs["branch-a"]["ikev2"]["authentication_failures"] == 8
    # the worst device first (branch-a has the down tunnel), every command in FMC 10.0.1's list, no show
    # commands on the disconnected device
    assert ran[0].startswith("d-a ")
    assert not any(x.startswith("d-c ") for x in ran)
    assert sorted({x.split(" ", 1)[1] for x in ran}) == [
        "show crypto ikev2 sa",
        "show crypto ikev2 stats",
        "show crypto ipsec sa",
        "show route",
        "show vpn-sessiondb l2l",
    ]
    assert any("tunnel monitor" in n for n in r["notes"])


async def test_vpn_status_fmc10_allowlist_sends_everything(fmc: respx.MockRouter, monkeypatch: Any) -> None:
    """FMC 10.0.1's real list (the built-in fallback) passes all five commands: nothing 'not available'."""
    monkeypatch.setattr(show_commands, "FALLBACK", show_commands.build(None))
    lab(fmc)
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {"topology": "mcp-fw-vti"})
    for d in r["devices"]:
        assert not any(str(v).startswith("not available") for v in d["evidence"].values())


async def test_vpn_status_device_filter(fmc: respx.MockRouter) -> None:
    ran = lab(fmc)
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {"device": "branch-b"})
    assert [t["topology"] for t in r["topologies"]] == ["mcp-fw-vti", "mcp-fw-bc"]
    assert [e["name"] for e in r["topologies"][0]["endpoints"]] == ["branch-a", "branch-b"]
    assert ran[0].startswith("d-b ")  # the asked device first, then its peer
    assert {x.split(" ", 1)[0] for x in ran} == {"d-a", "d-b"}


async def test_vpn_status_device_in_no_topology(fmc: respx.MockRouter) -> None:
    lab(fmc)
    fmc.get(f"{CFG}/policy/ftds2svpns").mock(return_value=items([LAB["policy/ftds2svpns"]["items"][2]]))
    async with Client(server()) as c:
        r = await c.call_tool("fmc_vpn_status", {"device": "branch-a"}, raise_on_error=False)
    assert r.is_error and "in no VPN topology" in r.content[0].text  # type: ignore[union-attr]


async def test_vpn_status_fmc_down_but_device_up_is_lag(fmc: respx.MockRouter) -> None:
    tunnels = json.loads(json.dumps(LAB["health/tunnelstatuses"]["items"]))
    tunnels[0]["state"] = "TUNNEL_DOWN"
    lab(fmc, tunnels=tunnels)
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {"topology": "mcp-fw-vti"})
    lagged = next(d for d in r["degraded"] if d["what"] == "tunnel")
    assert lagged["severity"] == "warning"
    assert any("READY IKE SA with 203.0.113.2" in x and "lags" in x for x in lagged["reasons"])


async def test_vpn_status_fmc_up_but_no_sa(fmc: respx.MockRouter) -> None:
    no_sa = {"show crypto ikev2 sa": "There are no IKEv2 SAs\n", "show crypto ipsec sa": ""}
    lab(fmc, outputs={"d-b": no_sa})
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {"topology": "mcp-fw-vti"})
    warn = [d for d in r["degraded"] if d["what"] == "tunnel"]
    assert len(warn) == 1 and warn[0]["device"] == "branch-b"
    assert "FMC shows TUNNEL_UP but branch-b has no IKE SA" in warn[0]["reasons"][0]
    says = r["topologies"][0]["tunnels"][0]["device_says"]
    assert "branch-b: no IKE SA" in says


async def test_vpn_status_key_mismatch_between_calls(fmc: respx.MockRouter) -> None:
    """Authentication failures growing between two calls name a pre-shared key mismatch."""
    stats = SHOW["d-a"]["show crypto ikev2 stats"]
    outputs: dict[str, dict[str, str]] = {"d-a": {}}
    lab(fmc, outputs=outputs)
    async with Client(server()) as c:
        await run(c, "fmc_vpn_status", {"topology": "mcp-fw-pb"})
        outputs["d-a"]["show crypto ikev2 stats"] = stats.replace(
            "Authentication Failures:                 8", "Authentication Failures:                11"
        )
        r = await run(c, "fmc_vpn_status", {"topology": "mcp-fw-pb"})
    down = r["degraded"][0]
    assert down["severity"] == "critical"
    assert any("authentication failures rose by 3" in x and "pre-shared key" in x for x in down["reasons"])


async def test_vpn_status_without_show_commands(fmc: respx.MockRouter) -> None:
    ran = lab(fmc)
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {"show_commands": False})
    assert ran == []
    assert {d["device"] for d in r["devices"]} == {"branch-a", "branch-b", "branch-c"}
    assert "device_says" not in r["topologies"][0]["tunnels"][0]
    assert r["degraded"][0]["severity"] == "critical"


async def test_vpn_status_max_devices_and_tunnel_details(fmc: respx.MockRouter) -> None:
    ran = lab(fmc)
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {"max_devices": 1, "tunnel_details": True})
    assert {x.split(" ", 1)[0] for x in ran} == {"d-a"}
    assert any("skipped on branch-b" in n for n in r["notes"])
    assert any("worst tunnel(s) only" in n for n in r["notes"])
    with_details = [t for topo in r["topologies"] for t in topo["tunnels"] if "fmc_details" in t]
    assert len(with_details) == 1 and with_details[0]["fmc_details"]["peerA"]["auth"] == "PRESHARED_KEY"
    assert with_details[0]["state"] == "TUNNEL_DOWN"  # worst first


async def test_vpn_status_no_topologies(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/ftds2svpns").mock(return_value=items([]))
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {})
    assert r["topologies"] == [] and "fmc_create_s2s_vpn" in r["note"]


async def test_vpn_status_topology_not_monitored(fmc: respx.MockRouter) -> None:
    lab(fmc, tunnels=[])
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {"topology": "mcp-fw-pb", "show_commands": False})
    [f] = r["degraded"]
    assert f["what"] == "topology" and "not deployed yet" in f["reasons"][0]


async def test_vpn_status_ha_pair_endpoint(fmc: respx.MockRouter) -> None:
    """An HA pair endpoint: show commands on its active unit, VTIs from the primary, standby problems
    reported."""
    ran = lab(fmc, outputs={"d-a2": SHOW["d-a"]})
    devices = LAB["devices/devicerecords"]["items"] + [{"id": "d-a2", "name": "branch-a2", "type": "Device"}]
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items(devices))
    pair = {
        "id": "ha-1",
        "name": "branch-ha",
        "type": "DeviceHAPair",
        "primary": {"id": "d-a", "name": "branch-a", "type": "Device"},
        "secondary": {"id": "d-a2", "name": "branch-a2", "type": "Device"},
        "metadata": {
            "primaryStatus": {"currentStatus": "Standby"},
            "secondaryStatus": {"currentStatus": "Active"},
        },
    }
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([pair]))
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs/ha-1").mock(return_value=httpx.Response(200, json=pair))
    eps = json.loads(json.dumps(LAB["policy/ftds2svpns/topo-vti/endpoints"]))
    eps["items"][0]["device"] = {"id": "ha-1", "name": "branch-ha", "type": "DeviceHAPair"}
    eps["items"][0]["name"] = "branch-ha"
    fmc.get(f"{CFG}/policy/ftds2svpns/topo-vti/endpoints").mock(return_value=httpx.Response(200, json=eps))
    tunnels = json.loads(json.dumps(LAB["health/tunnelstatuses"]["items"][:1]))
    tunnels[0]["peerA"]["device"] = {"id": "ha-1", "name": "branch-ha[branch-a2]", "type": "DeviceHAPair"}
    fmc.get(f"{CFG}/health/tunnelstatuses").mock(return_value=items(tunnels))
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {"topology": "mcp-fw-vti", "device": "branch-a2"})
    devs = {d["device"]: d for d in r["devices"]}
    assert devs["branch-ha"]["ha"][1] == {"role": "secondary", "device": "branch-a2", "state": "Active"}
    assert devs["branch-ha"]["vtis"] == ["vti-to-b"]  # read from the primary's record
    assert ran[0].startswith("d-a2 ")  # the active unit
    assert r["topologies"][0]["tunnels"][0]["device_says"][0].startswith("branch-ha: IKE READY")
