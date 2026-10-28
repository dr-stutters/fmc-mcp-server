"""F40a: RA VPN authoring (address pools, group policies, RA VPN policy, connection profiles). Request bodies
follow FMC 10.0.1's schemas (IPv4AddressPool, IPv6AddressPool, GroupPolicyModel, FTDRAVpnModel,
FTDRAVpnConnectionProfileModel, FTDRAVpnAddressAssignmentSetting); synthetic values only."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, items, make_settings

RAVPN = f"{CFG}/policy/ravpns"
DFLT = {"id": "00000000-0000-0ed3-0000-000000010001", "name": "DfltGrpPolicy", "type": "GroupPolicy"}
POOL4 = {"id": "pool-4", "name": "mcp-test-ra-pool", "type": "IPv4AddressPool"}
POOL6 = {"id": "pool-6", "name": "mcp-test-ra-pool6", "type": "IPv6AddressPool"}
ZONE = {"id": "z-out", "name": "mcp-test-outside", "type": "SecurityZone"}
ENROLL = {"id": "enr-1", "name": "mcp-test-ra-cert", "type": "CertEnrollment", "enrollmentType": "PKCS12"}
PKG = {"id": "pkg-1", "name": "secure-client-win-5.1", "type": "AnyConnectPackage"}
REALM_AD = {"id": "realm-ad", "name": "mcp-test-ad", "type": "Realm", "realmType": "AD"}
REALM_LOCAL = {"id": "realm-local", "name": "mcp-test-local", "type": "Realm", "realmType": "LOCAL"}
RADIUS = {"id": "rad-1", "name": "mcp-test-ise", "type": "RadiusServerGroup"}
POLICY = {"id": "ra-1", "name": "mcp-test-ravpn", "type": "RAVpn", "localRealmServer": {"id": "realm-local"}}
PROFILE = {
    "id": "cp-1",
    "name": "mcp-test-employees",
    "type": "RaVpnConnectionProfile",
    "authenticationMethod": "AAA_ONLY",
    "groupPolicy": DFLT,
    "primaryAuthenticationServer": {"id": "realm-ad", "type": "IdentityRealm", "name": "mcp-test-ad"},
    "ipv4AddressPool": [POOL4],
    "links": {"self": "x"},
}
ASSIGN = {
    "id": "aa-1",
    "type": "RaVpnAddressAssignmentSetting",
    "useAuthorizationServerForIPv4": True,
    "useDHCP": False,
    "useInternalAddressPoolForIPv4": True,
    "ipAddressReuseInterval": 0,
}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, rate_limit=100000))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def echo(status: int = 201) -> Any:
    return lambda req: httpx.Response(status, json=json.loads(req.content) | {"id": "new-1"})


def objects(fmc: respx.MockRouter, *, packages: list[dict[str, Any]] | None = None) -> None:
    fmc.get(f"{CFG}/object/ipv4addresspools").mock(return_value=items([POOL4]))
    fmc.get(f"{CFG}/object/ipv6addresspools").mock(return_value=items([POOL6]))
    fmc.get(f"{CFG}/object/grouppolicies").mock(return_value=items([DFLT]))
    fmc.get(f"{CFG}/object/standardaccesslists").mock(
        return_value=items([{"id": "acl-1", "name": "mcp-test-split", "type": "StandardAccessList"}])
    )
    fmc.get(f"{CFG}/object/anyconnectprofiles").mock(
        return_value=items([{"id": "prof-1", "name": "mcp-test-sc-profile", "type": "AnyConnectProfile"}])
    )
    fmc.get(f"{CFG}/object/anyconnectpackages").mock(
        return_value=items([PKG] if packages is None else packages)
    )
    fmc.get(f"{CFG}/object/hosts").mock(
        return_value=items([{"id": "h-dns", "name": "mcp-test-dns", "type": "Host", "value": "192.0.2.53"}])
    )
    for coll in ("networks", "ranges", "fqdns", "networkgroups"):
        fmc.get(f"{CFG}/object/{coll}").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/securityzones").mock(return_value=items([ZONE]))
    fmc.get(f"{CFG}/object/interfacegroups").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/certenrollments").mock(return_value=items([ENROLL]))
    fmc.get(f"{CFG}/object/certenrollments/enr-1").mock(return_value=httpx.Response(200, json=ENROLL))
    fmc.get(f"{CFG}/object/realms").mock(return_value=items([REALM_AD, REALM_LOCAL]))
    fmc.get(f"{CFG}/object/radiusservergroups").mock(return_value=items([RADIUS]))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items(
            [
                {
                    "id": "ra-1",
                    "policy": {"id": "ra-1", "type": "RAVpn"},
                    "targets": [{"id": "d1", "name": "mcp-ftd1"}],
                }
            ]
        )
    )


# --- address pools ---------------------------------------------------------------------------------


async def test_ipv4_pool_body_and_confirm(fmc: respx.MockRouter) -> None:
    objects(fmc)
    post = fmc.post(f"{CFG}/object/ipv4addresspools").mock(side_effect=echo())
    args = {"name": "mcp-test-ra-pool2", "ipv4_range": "192.0.2.10-192.0.2.200", "mask": "255.255.255.0"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_address_pool", args)
        assert preview["status"] == "preview"
        await run(c, "fmc_create_address_pool", {**args, "confirm": preview["confirm"]})
    assert json.loads(post.calls.last.request.content) == {
        "name": "mcp-test-ra-pool2",
        "type": "IPv4AddressPool",
        "ipAddressRange": "192.0.2.10-192.0.2.200",
        "mask": "255.255.255.0",
    }


async def test_ipv6_pool_body(fmc: respx.MockRouter) -> None:
    objects(fmc)
    post = fmc.post(f"{CFG}/object/ipv6addresspools").mock(side_effect=echo())
    args = {"name": "mcp-test-v6", "ipv6_start": "2001:db8::10/64", "ipv6_count": 250}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_address_pool", args)
        await run(c, "fmc_create_address_pool", {**args, "confirm": preview["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "name": "mcp-test-v6",
        "type": "IPv6AddressPool",
        "ipv6StartAddress": "2001:db8::10/64",
        "numberOfAddresses": 250,
    }


async def test_pool_name_taken_blocks(fmc: respx.MockRouter) -> None:
    objects(fmc)
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_create_address_pool",
            {"name": "mcp-test-ra-pool", "ipv4_range": "192.0.2.10-192.0.2.20", "mask": "255.255.255.0"},
        )
    assert out["status"] == "blocked" and "already exists" in out["blockers"][0]


@pytest.mark.parametrize(
    "bad",
    [
        {"ipv4_range": "192.0.2.10-192.0.2.20"},  # no mask
        {"ipv4_range": "192.0.2.20-192.0.2.10", "mask": "255.255.255.0"},  # backwards
        {"ipv4_range": "192.0.2.10-198.51.100.1", "mask": "255.255.255.0"},  # spans subnets
        {"ipv6_start": "2001:db8::10", "ipv6_count": 5},  # no prefix length
        {"ipv4_range": "192.0.2.1-192.0.2.2", "mask": "255.255.255.0", "ipv6_start": "2001:db8::1/64"},
    ],
)
async def test_pool_validation(fmc: respx.MockRouter, bad: dict[str, Any]) -> None:
    objects(fmc)
    async with Client(server()) as c:
        r = await c.call_tool("fmc_create_address_pool", {"name": "p", **bad}, raise_on_error=False)
    assert r.is_error


# --- group policies --------------------------------------------------------------------------------

GP_ARGS = {
    "name": "mcp-test-gp",
    "split_tunnel": "tunnel_specified",
    "split_tunnel_acl": "mcp-test-split",
    "dns_servers": ["mcp-test-dns"],
    "default_domain": "example.com",
    "split_dns_domains": ["example.com", "corp.example.com"],
    "banner": "Authorised users only",
    "address_pools": ["mcp-test-ra-pool"],
    "secure_client_profile": "mcp-test-sc-profile",
    "idle_timeout": 30,
}


async def test_group_policy_body(fmc: respx.MockRouter) -> None:
    objects(fmc)
    post = fmc.post(f"{CFG}/object/grouppolicies").mock(side_effect=echo())
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_group_policy", GP_ARGS)
        assert preview["status"] == "preview", preview
        await run(c, "fmc_create_group_policy", {**GP_ARGS, "confirm": preview["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["type"] == "GroupPolicy" and body["enableSSLProtocol"] and body["enableIPsecIKEv2Protocol"]
    g = body["generalSettings"]
    assert g["splitTunnelSettings"] == {
        "ipv4SplitTunnelPolicy": "TUNNEL_SPECIFIED",
        "ipv6SplitTunnelPolicy": "TUNNEL_ALL",
        "splitDNSRequestPolicy": "TUNNEL_SPECIFIED_DOMAINS",
        "splitTunnelACL": {"id": "acl-1", "type": "StandardAccessList", "name": "mcp-test-split"},
        "splitDNSDomainList": "example.com,corp.example.com",
    }
    assert g["primaryDNSServer"]["id"] == "h-dns" and "secondaryDNSServer" not in g
    assert g["addressAssignment"] == {"ipv4LocalAddressPool": [POOL4], "defaultDomainName": "example.com"}
    assert g["banner"] == "Authorised users only"
    assert body["anyConnectSettings"] == {
        "vpnClientProfile": {"id": "prof-1", "type": "AnyConnectProfile", "name": "mcp-test-sc-profile"}
    }
    assert body["advancedSettings"] == {"sessionSettings": {"vpnIdleTimeout": 30}}


async def test_group_policy_unknown_refs_block(fmc: respx.MockRouter) -> None:
    objects(fmc)
    async with Client(server()) as c:
        out = await run(
            c, "fmc_create_group_policy", {**GP_ARGS, "split_tunnel_acl": "nope", "address_pools": ["gone"]}
        )
    assert out["status"] == "blocked"
    assert any("standard ACL named 'nope'" in b for b in out["blockers"])
    assert any("address pool named 'gone'" in b for b in out["blockers"])


async def test_split_tunnel_needs_acl(fmc: respx.MockRouter) -> None:
    objects(fmc)
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_create_group_policy",
            {"name": "x", "split_tunnel": "exclude_specified"},
            raise_on_error=False,
        )
    assert r.is_error


# --- RA VPN policy ---------------------------------------------------------------------------------

RA_ARGS = {
    "name": "mcp-test-ravpn2",
    "access_interfaces": ["mcp-test-outside"],
    "certificate": "mcp-test-ra-cert",
}


async def test_create_ravpn_body(fmc: respx.MockRouter) -> None:
    objects(fmc)
    fmc.get(RAVPN).mock(return_value=items([]))
    post = fmc.post(RAVPN).mock(side_effect=echo())
    args = {**RA_ARGS, "ikev2": True, "local_realm": "mcp-test-local"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_ravpn", args)
        assert preview["status"] == "preview", preview
        assert any("identity NAT rule" in s for s in preview["side_effects"])
        assert any("fmc_enroll_certificate" in s for s in preview["side_effects"])
        await run(c, "fmc_create_ravpn", {**args, "confirm": preview["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["type"] == "RAVpn" and body["configureSSL"] and body["configureIpsec"]
    acc = body["accessInterfaceSettings"]
    assert acc["interfaceSettings"] == [
        {
            "accessInterface": ZONE,
            "enableSSL": True,
            "enableDTLS": True,
            "enableIPSecIkev2": True,
            "configureInterfaceIDCertificate": False,
        }
    ]
    cert = {"id": "enr-1", "type": "CertEnrollment", "name": "mcp-test-ra-cert"}
    assert acc["sslIdCertificate"] == cert and acc["ipsecIdCertificate"] == cert
    assert acc["webPort"] == 443 and acc["bypassACPolicyForDecryptTraffic"] is False
    assert body["anyConnectClientImages"] == [
        {
            "operatingSystem": "WINDOWS",
            "anyconnectImage": {"id": "pkg-1", "type": "AnyConnectPackage", "name": PKG["name"]},
        }
    ]
    assert body["groupPolicies"] == [DFLT]
    assert body["localRealmServer"] == {
        "id": "realm-local",
        "type": "IdentityRealm",
        "name": "mcp-test-local",
    }


@pytest.mark.parametrize(
    ("override", "needle"),
    [
        ({"access_interfaces": ["no-such-zone"]}, "security zone or interface group named 'no-such-zone'"),
        ({"certificate": "no-such-cert"}, "certificate enrollment named 'no-such-cert'"),
        ({"local_realm": "no-such-realm"}, "realm named 'no-such-realm'"),
        ({"secure_client_packages": ["no-such-pkg"]}, "Secure Client package named 'no-such-pkg'"),
    ],
)
async def test_create_ravpn_blocks_on_unknown_refs(
    fmc: respx.MockRouter, override: dict[str, Any], needle: str
) -> None:
    objects(fmc)
    fmc.get(RAVPN).mock(return_value=items([]))
    async with Client(server()) as c:
        out = await run(c, "fmc_create_ravpn", {**RA_ARGS, **override})
    assert out["status"] == "blocked" and any(needle in b for b in out["blockers"]), out


async def test_create_ravpn_without_package_blocks(fmc: respx.MockRouter) -> None:
    objects(fmc, packages=[])
    fmc.get(RAVPN).mock(return_value=items([]))
    async with Client(server()) as c:
        out = await run(c, "fmc_create_ravpn", RA_ARGS)
    assert out["status"] == "blocked" and "upload one in the FMC UI" in out["blockers"][0]


# --- connection profiles ---------------------------------------------------------------------------


def policy(fmc: respx.MockRouter, profiles: list[dict[str, Any]]) -> None:
    fmc.get(RAVPN).mock(return_value=items([POLICY]))
    fmc.get(f"{RAVPN}/ra-1/connectionprofiles").mock(return_value=items(profiles))
    fmc.get(f"{RAVPN}/ra-1/addressassignmentsettings").mock(return_value=items([ASSIGN]))


async def test_new_profile_with_ise_radius(fmc: respx.MockRouter) -> None:
    objects(fmc)
    policy(fmc, [])
    # change management off (FMC 10.0.1 answers 400): change_ref is shown and recorded, no ticket
    off = {"error": {"messages": [{"description": "Change management is not enabled"}]}}
    fmc.get(f"{CFG}/changemanagement/tickets").mock(return_value=httpx.Response(400, json=off))
    post = fmc.post(f"{RAVPN}/ra-1/connectionprofiles").mock(side_effect=echo())
    args = {
        "policy": "mcp-test-ravpn",
        "name": "mcp-test-contractors",
        "aaa_server": "mcp-test-ise",
        "accounting_server": "mcp-test-ise",
        "ipv4_pools": ["mcp-test-ra-pool"],
        "aliases": ["Contractors"],
        "change_ref": "CHG0042",
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_set_connection_profile", args)
        assert preview["status"] == "preview", preview
        assert preview["preview"]["change_ref"] == "CHG0042"
        assert preview["preview"]["where_used"] == ["mcp-ftd1"]
        assert any("mcp-ftd1" in s for s in preview["side_effects"])
        done = await run(c, "fmc_set_connection_profile", {**args, "confirm": preview["confirm"]})
    assert done["result"]["change_ref"] == "CHG0042"
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "name": "mcp-test-contractors",
        "type": "RaVpnConnectionProfile",
        "groupPolicy": DFLT,
        "authenticationMethod": "AAA_ONLY",
        "primaryAuthenticationServer": {"id": "rad-1", "type": "RadiusServerGroup", "name": "mcp-test-ise"},
        "useLocalAsPrimaryAuthServer": False,
        "accountingServer": {"id": "rad-1", "type": "RadiusServerGroup", "name": "mcp-test-ise"},
        "ipv4AddressPool": [POOL4],
        "groupAlias": [{"aliasName": "Contractors", "enabled": True}],
    }


async def test_change_profile_shows_diff_and_puts(fmc: respx.MockRouter) -> None:
    objects(fmc)
    policy(fmc, [PROFILE])
    put = fmc.put(f"{RAVPN}/ra-1/connectionprofiles/cp-1").mock(side_effect=echo(200))
    aa = fmc.put(f"{RAVPN}/ra-1/addressassignmentsettings/aa-1").mock(side_effect=echo(200))
    args = {
        "policy": "mcp-test-ravpn",
        "name": "mcp-test-employees",
        "ipv6_pools": ["mcp-test-ra-pool6"],
        "use_aaa_addresses": False,
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_set_connection_profile", args)
        assert preview["status"] == "preview", preview
        assert list(preview["preview"]["changes"]) == ["ipv6AddressPool"]
        assert any("policy-wide" in s for s in preview["side_effects"])
        await run(c, "fmc_set_connection_profile", {**args, "confirm": preview["confirm"]})
    body = json.loads(put.calls.last.request.content)
    assert body["id"] == "cp-1" and "links" not in body and body["ipv6AddressPool"] == [POOL6]
    assert body["primaryAuthenticationServer"]["id"] == "realm-ad"  # kept
    assert json.loads(aa.calls.last.request.content) == {**ASSIGN, "useAuthorizationServerForIPv4": False}


async def test_profile_unknown_server_blocks(fmc: respx.MockRouter) -> None:
    objects(fmc)
    policy(fmc, [])
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_set_connection_profile",
            {"policy": "mcp-test-ravpn", "name": "x", "aaa_server": "no-such-server", "group_policy": "nope"},
        )
    assert out["status"] == "blocked"
    assert any("RADIUS server group or realm named 'no-such-server'" in b for b in out["blockers"])
    assert any("group policy named 'nope'" in b for b in out["blockers"])


async def test_profile_no_change_blocks(fmc: respx.MockRouter) -> None:
    objects(fmc)
    policy(fmc, [PROFILE])
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_set_connection_profile",
            {"policy": "mcp-test-ravpn", "name": "mcp-test-employees", "ipv4_pools": ["mcp-test-ra-pool"]},
        )
    assert out["status"] == "blocked" and "already has these settings" in out["blockers"][0]


async def test_new_aaa_profile_needs_a_server(fmc: respx.MockRouter) -> None:
    objects(fmc)
    policy(fmc, [])
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_set_connection_profile", {"policy": "mcp-test-ravpn", "name": "x"}, raise_on_error=False
        )
    assert r.is_error
