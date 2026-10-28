"""F40a: remote-access VPN (Secure Client) authoring. Address pools (object/ipv4addresspools,
object/ipv6addresspools), group policies (object/grouppolicies: protocols, split tunnel, DNS, banner,
Secure Client profile), the RA VPN policy (policy/ravpns: access interfaces, identity certificate from an
F75 enrollment, Secure Client images, local realm) and its connection profiles
(policy/ravpns/{id}/connectionprofiles: group policy, AAA server, pools, aliases) with the policy's address
assignment settings. Every write is preview-first and names what it touches and what a deploy pushes.

Payload shapes follow FMC 10.0.1's schemas (IPv4AddressPool, IPv6AddressPool, GroupPolicyModel,
FTDRAVpnModel, FTDRAVpnConnectionProfileModel, FTDRAVpnAddressAssignmentSetting). Stays in the FMC UI:
uploading the Secure Client package and profile files (a multipart upload; the tools reference what is
already there), and NAT exemption, which FTDRAVpnModel has no field for: make it an identity NAT rule
(fmc_create_nat_rule: inside networks -> the pool, no-proxy-arp, route-lookup). Assigning the policy to its
FTDs ("Targeted Devices") is a policy assignment of type RAVpn."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import Confirm, InvalidRequest, NotFound, Plan, ToolRegistrar, UpstreamError, get_client
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import NETWORK_TYPES, ZONE_TYPES
from fmc_mcp.tools.common import Domain, pick_by_name, ref_of, resolve_object
from fmc_mcp.tools.enrollment import resolve_enrollment
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.policies import policy_assignments
from fmc_mcp.tools.vpn import RAVPN, _profile_row

POOLS4 = "object/ipv4addresspools"
POOLS6 = "object/ipv6addresspools"
GROUP_POLICIES = "object/grouppolicies"
STANDARD_ACLS = "object/standardaccesslists"
SC_PACKAGES = "object/anyconnectpackages"
SC_PROFILES = "object/anyconnectprofiles"
REALMS = "object/realms"
RADIUS_GROUPS = "object/radiusservergroups"
DEFAULT_GROUP_POLICY = "DfltGrpPolicy"

SPLIT = {
    "tunnel_all": "TUNNEL_ALL",
    "tunnel_specified": "TUNNEL_SPECIFIED",
    "exclude_specified": "EXCLUDE_SPECIFIED_OVER_TUNNEL",
}
SplitTunnel = Literal["tunnel_all", "tunnel_specified", "exclude_specified"]
AUTH = {
    "aaa": "AAA_ONLY",
    "certificate": "CLIENT_CERTIFICATE_ONLY",
    "aaa_and_certificate": "AAA_AND_CLIENT_CERTIFICATE",
}
AuthMethod = Literal["aaa", "certificate", "aaa_and_certificate"]
OS_WORDS = (("win", "WINDOWS"), ("mac", "MAC"), ("darwin", "MAC"), ("linux", "LINUX"))
NAT_NOTE = (
    "NAT exemption is not part of the RA VPN policy in FMC's API: if the FTD NATs inside traffic to the "
    "outside, add an identity NAT rule (fmc_create_nat_rule: inside networks -> the VPN pool, "
    "no-proxy-arp, route-lookup) or the clients' return traffic is translated."
)
DEPLOY_NOTE = "Reaches the FTDs only on the next fmc_deploy of the devices the RA VPN policy targets."

PolicyRef = Annotated[str, Field(description="RA VPN policy name or UUID (fmc_get_ravpn)")]
ChangeName = Annotated[str, Field(min_length=1, max_length=64, description="Object name")]
Description = Annotated[str | None, Field(max_length=1024, description="Optional description")]


async def find(app: FmcApp, path: str, ref: str, domain: str | None) -> dict[str, Any] | None:
    """One item of a collection by UUID or name (case-insensitive), or None. Ambiguous names still raise."""
    ref = ref.strip()
    full = await app.config_path(path, domain)
    if is_uuid(ref):
        try:
            hit: dict[str, Any] = await app.api.get(f"{full}/{ref}")
            return hit
        except NotFound:
            return None
    page = await app.all(full, cap=5000)
    try:
        return pick_by_name(page.items, ref, path, partial=not page.complete)
    except NotFound:
        return None


async def _refs(
    app: FmcApp, path: str, names: list[str] | None, what: str, domain: str | None, blockers: list[str]
) -> list[dict[str, Any]]:
    out = []
    for n in names or []:
        hit = await find(app, path, n, domain)
        if hit is None:
            blockers.append(f"No {what} named {n!r}.")
        else:
            out.append(ref_of(hit))
    return out


async def _network(app: FmcApp, ref: str, domain: str | None, blockers: list[str]) -> dict[str, Any] | None:
    try:
        return ref_of((await resolve_object(app, ref, domain, NETWORK_TYPES))[1])
    except NotFound:
        blockers.append(f"No network/host object named {ref!r} (fmc_create_object first).")
        return None


async def _aaa_server(
    app: FmcApp, ref: str, domain: str | None, blockers: list[str], radius_only: bool = False
) -> dict[str, Any] | None:
    """A RADIUS server group, or (authentication only) an AD/LDAP/local realm, as FMC references it."""
    rad = await find(app, RADIUS_GROUPS, ref, domain)
    if rad is not None:
        return {"id": rad["id"], "type": "RadiusServerGroup", "name": rad.get("name")}
    if not radius_only:
        realm = await find(app, REALMS, ref, domain)
        if realm is not None:
            return {"id": realm["id"], "type": "IdentityRealm", "name": realm.get("name")}
    what = "RADIUS server group" if radius_only else "RADIUS server group or realm"
    blockers.append(f"No {what} named {ref!r} (fmc_get_identity_sources lists them).")
    return None


async def _ravpn(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    hit = await find(app, RAVPN, ref, domain)
    if hit is None:
        raise NotFound(f"No RA VPN policy named {ref!r} (fmc_get_ravpn lists them).", 404)
    return hit


async def _targets(app: FmcApp, policy_id: str, domain: str | None) -> list[str]:
    try:
        for a in await policy_assignments(app, domain):
            if (a.get("policy") or {}).get("id") == policy_id:
                return [str(t.get("name") or t.get("id")) for t in a.get("targets") or []]
    except UpstreamError:
        pass
    return []


def _os_of(pkg: dict[str, Any]) -> str | None:
    if pkg.get("operatingSystem"):
        return str(pkg["operatingSystem"]).upper()
    text = f"{pkg.get('name', '')} {pkg.get('pkgName', '')} {pkg.get('fileName', '')}".lower()
    return next((os for word, os in OS_WORDS if word in text), None)


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create RA VPN address pool")
    async def fmc_create_address_pool(
        ctx: Context,
        name: ChangeName,
        ipv4_range: Annotated[
            str | None, Field(description="IPv4 pool as 'first-last', e.g. 192.0.2.10-192.0.2.200")
        ] = None,
        mask: Annotated[str | None, Field(description="IPv4 pool mask, e.g. 255.255.255.0")] = None,
        ipv6_start: Annotated[
            str | None, Field(description="IPv6 pool start with prefix length, e.g. 2001:db8::10/64")
        ] = None,
        ipv6_count: Annotated[
            int | None, Field(ge=1, le=16384, description="IPv6 addresses in the pool")
        ] = None,
        description: Description = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an address pool for remote-access VPN clients: IPv4 (a range and its mask) or IPv6 (a
        start address/prefix and a count). Nothing reaches a device until a connection profile or group
        policy uses it (fmc_set_connection_profile, fmc_create_group_policy) and the policy is deployed."""
        app: FmcApp = get_client(ctx)
        if (ipv4_range is None) == (ipv6_start is None):
            raise InvalidRequest("Give ipv4_range (with mask) or ipv6_start (with ipv6_count), not both.")
        blockers: list[str] = []
        body: dict[str, Any]
        if ipv4_range is not None:
            if not mask:
                raise InvalidRequest("An IPv4 pool needs its mask, e.g. 255.255.255.0.")
            try:
                a, b = (ipaddress.IPv4Address(x.strip()) for x in ipv4_range.split("-", 1))
                net = ipaddress.IPv4Network(f"{a}/{mask.strip()}", strict=False)
            except ValueError as e:
                raise InvalidRequest(f"IPv4 pool {ipv4_range!r} / {mask!r}: {e}") from None
            if int(a) > int(b):
                raise InvalidRequest("The pool's first address is after its last.")
            if b not in net:
                raise InvalidRequest(f"{a}-{b} does not fit in one subnet with mask {mask} ({net}).")
            path, body = (
                POOLS4,
                {
                    "name": name,
                    "type": "IPv4AddressPool",
                    "ipAddressRange": f"{a}-{b}",
                    "mask": str(net.netmask),
                },
            )
            size = int(b) - int(a) + 1
        else:
            if not ipv6_count:
                raise InvalidRequest("An IPv6 pool needs ipv6_count.")
            try:
                iface = ipaddress.IPv6Interface(str(ipv6_start).strip())
            except ValueError as e:
                raise InvalidRequest(f"IPv6 pool start {ipv6_start!r}: {e}") from None
            if "/" not in str(ipv6_start):
                raise InvalidRequest("Give the IPv6 start with its prefix length, e.g. 2001:db8::10/64.")
            path, body = (
                POOLS6,
                {
                    "name": name,
                    "type": "IPv6AddressPool",
                    "ipv6StartAddress": str(iface),
                    "numberOfAddresses": ipv6_count,
                },
            )
            size = ipv6_count
        if description:
            body["description"] = description
        if await find(app, path, name, domain) is not None:
            blockers.append(f"An address pool named {name!r} already exists.")
        full = await app.config_path(path, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_address_pool",
            args={
                "name": name,
                "ipv4_range": ipv4_range,
                "mask": mask,
                "ipv6_start": ipv6_start,
                "ipv6_count": ipv6_count,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create {'IPv4' if path == POOLS4 else 'IPv6'} address pool {name!r} ({size} addresses)",
                details={"pool": body},
                fingerprint=body,
                blockers=blockers,
                side_effects=[
                    "A new object: nothing uses it yet. Clients get addresses from it once a connection "
                    "profile or group policy names it and the RA VPN policy is deployed."
                ],
            ),
            apply=lambda: applied(app, lambda: app.api.post(full, body)),
        )

    @reg.write(title="Create RA VPN group policy")
    async def fmc_create_group_policy(
        ctx: Context,
        name: ChangeName,
        ssl: Annotated[bool, Field(description="Allow SSL/DTLS (Secure Client) tunnels")] = True,
        ikev2: Annotated[bool, Field(description="Allow IPsec-IKEv2 tunnels")] = True,
        split_tunnel: Annotated[
            SplitTunnel,
            Field(
                description="IPv4 split tunnel: tunnel_all (default), tunnel_specified (only the ACL's "
                "networks through the tunnel) or exclude_specified (all but the ACL's networks)"
            ),
        ] = "tunnel_all",
        split_tunnel_acl: Annotated[
            str | None, Field(description="Standard ACL object (name/UUID) for tunnel_/exclude_specified")
        ] = None,
        dns_servers: Annotated[
            list[str] | None,
            Field(max_length=2, description="Primary (and secondary) DNS server host objects"),
        ] = None,
        default_domain: Annotated[str | None, Field(description="Default domain name for clients")] = None,
        split_dns_domains: Annotated[
            list[str] | None, Field(description="Only these domains resolve through the tunnel's DNS")
        ] = None,
        banner: Annotated[
            str | None, Field(max_length=4000, description="Login banner shown to users")
        ] = None,
        address_pools: Annotated[
            list[str] | None,
            Field(description="IPv4 address pools (fmc_create_address_pool) for this policy"),
        ] = None,
        secure_client_profile: Annotated[
            str | None, Field(description="Secure Client VPN profile object (uploaded in the FMC UI)")
        ] = None,
        idle_timeout: Annotated[
            int | None, Field(ge=1, le=35791394, description="VPN idle timeout, minutes")
        ] = None,
        simultaneous_logins: Annotated[
            int | None, Field(ge=0, le=2147483647, description="Simultaneous logins per user (FMC default 3)")
        ] = None,
        description: Description = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a group policy for RA VPN users: tunnel protocols, split tunnelling (with a standard
        ACL), DNS servers and split DNS, default domain, banner, address pools, the Secure Client VPN
        profile, idle timeout and simultaneous logins. A connection profile names it as its group policy
        (fmc_set_connection_profile); FMC also pushes it once the RA VPN policy lists it."""
        app: FmcApp = get_client(ctx)
        if not (ssl or ikev2):
            raise InvalidRequest("Allow at least one of ssl or ikev2.")
        if split_tunnel != "tunnel_all" and not split_tunnel_acl:
            raise InvalidRequest(f"split_tunnel={split_tunnel!r} needs split_tunnel_acl (a standard ACL).")
        blockers: list[str] = []
        if await find(app, GROUP_POLICIES, name, domain) is not None:
            blockers.append(f"A group policy named {name!r} already exists.")
        split: dict[str, Any] = {
            "ipv4SplitTunnelPolicy": SPLIT[split_tunnel],
            "ipv6SplitTunnelPolicy": "TUNNEL_ALL",
            "splitDNSRequestPolicy": "TUNNEL_SPECIFIED_DOMAINS"
            if split_dns_domains
            else "USE_SPLIT_TUNNEL_SETTING",
        }
        if split_tunnel_acl:
            acl = await _refs(app, STANDARD_ACLS, [split_tunnel_acl], "standard ACL", domain, blockers)
            if acl:
                split["splitTunnelACL"] = acl[0]
        if split_dns_domains:
            split["splitDNSDomainList"] = ",".join(d.strip() for d in split_dns_domains)
        general: dict[str, Any] = {"splitTunnelSettings": split}
        for key, ref in zip(("primaryDNSServer", "secondaryDNSServer"), dns_servers or [], strict=False):
            if (r := await _network(app, ref, domain, blockers)) is not None:
                general[key] = r
        assign: dict[str, Any] = {}
        if address_pools:
            assign["ipv4LocalAddressPool"] = await _refs(
                app, POOLS4, address_pools, "IPv4 address pool", domain, blockers
            )
        if default_domain:
            assign["defaultDomainName"] = default_domain.strip()
        if assign:
            general["addressAssignment"] = assign
        if banner:
            general["banner"] = banner
        body: dict[str, Any] = {
            "name": name,
            "type": "GroupPolicy",
            "enableSSLProtocol": ssl,
            "enableIPsecIKEv2Protocol": ikev2,
            "generalSettings": general,
        }
        if description:
            body["description"] = description
        if secure_client_profile:
            prof = await _refs(
                app, SC_PROFILES, [secure_client_profile], "Secure Client profile", domain, blockers
            )
            if prof:
                body["anyConnectSettings"] = {"vpnClientProfile": prof[0]}
        session = {
            k: v
            for k, v in (("vpnIdleTimeout", idle_timeout), ("simultaneousLoginPerUser", simultaneous_logins))
            if v is not None
        }
        if session:
            body["advancedSettings"] = {"sessionSettings": session}
        full = await app.config_path(GROUP_POLICIES, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_group_policy",
            args={
                "name": name,
                "ssl": ssl,
                "ikev2": ikev2,
                "split_tunnel": split_tunnel,
                "split_tunnel_acl": split_tunnel_acl,
                "dns_servers": dns_servers,
                "default_domain": default_domain,
                "split_dns_domains": split_dns_domains,
                "banner": banner,
                "address_pools": address_pools,
                "secure_client_profile": secure_client_profile,
                "idle_timeout": idle_timeout,
                "simultaneous_logins": simultaneous_logins,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create group policy {name!r} ({split_tunnel.replace('_', ' ')})",
                details={"group_policy": body},
                fingerprint=body,
                blockers=blockers,
                side_effects=[
                    "A new object: users get it once a connection profile names it and the RA VPN "
                    "policy is deployed."
                ],
            ),
            apply=lambda: applied(app, lambda: app.api.post(full, body)),
        )

    @reg.write(title="Create RA VPN policy")
    async def fmc_create_ravpn(
        ctx: Context,
        name: ChangeName,
        access_interfaces: Annotated[
            list[str],
            Field(
                min_length=1, description="Security zones or interface groups clients connect to (outside)"
            ),
        ],
        certificate: Annotated[
            str,
            Field(
                description="Certificate enrollment (fmc_create_cert_enrollment) used as the identity "
                "certificate on the access interfaces"
            ),
        ],
        secure_client_packages: Annotated[
            list[str] | None,
            Field(
                description="Secure Client packages (uploaded once in the FMC UI); default: every one there"
            ),
        ] = None,
        ssl: Annotated[bool, Field(description="SSL/DTLS (Secure Client) tunnels")] = True,
        ikev2: Annotated[bool, Field(description="IPsec-IKEv2 tunnels")] = False,
        group_policies: Annotated[
            list[str] | None,
            Field(description="Extra group policies the policy carries (DfltGrpPolicy is always there)"),
        ] = None,
        local_realm: Annotated[
            str | None, Field(description="Local realm for connection profiles that authenticate locally")
        ] = None,
        web_port: Annotated[
            int, Field(ge=1, le=65535, description="SSL/IKEv2 port clients connect to")
        ] = 443,
        dtls_port: Annotated[int, Field(ge=1, le=65535, description="DTLS (UDP) port")] = 443,
        bypass_access_control: Annotated[
            bool,
            Field(
                description="Let decrypted VPN traffic bypass the access control policy (sysopt permit-vpn). "
                "Off: the ACP inspects VPN traffic, as a validated design does"
            ),
        ] = False,
        description: Description = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a remote-access VPN policy: access interfaces (zones / interface groups), the identity
        certificate (an F75 enrollment, for SSL and IKEv2), Secure Client images, protocols, ports and the
        local realm. FMC creates DefaultWEBVPNGroup with it; add profiles with fmc_set_connection_profile.
        Then assign the policy to its FTDs, enroll the certificate on them (fmc_enroll_certificate) and
        deploy. NAT exemption is an identity NAT rule (the preview says so)."""
        app: FmcApp = get_client(ctx)
        if not (ssl or ikev2):
            raise InvalidRequest("Enable at least one of ssl or ikev2.")
        blockers: list[str] = []
        if await find(app, RAVPN, name, domain) is not None:
            blockers.append(f"An RA VPN policy named {name!r} already exists.")
        zones = []
        for z in access_interfaces:
            try:
                zones.append(ref_of((await resolve_object(app, z, domain, ZONE_TYPES))[1]))
            except NotFound:
                blockers.append(f"No security zone or interface group named {z!r}.")
        try:
            enr = await resolve_enrollment(app, certificate, domain)
            cert: dict[str, Any] | None = {"id": enr["id"], "type": "CertEnrollment", "name": enr.get("name")}
        except NotFound:
            cert = None
            blockers.append(f"No certificate enrollment named {certificate!r} (fmc_create_cert_enrollment).")
        images = []
        pkgs: list[dict[str, Any] | None] = []
        if ssl:
            if secure_client_packages:
                pkgs = [await find(app, SC_PACKAGES, n, domain) for n in secure_client_packages]
                for n, p in zip(secure_client_packages, pkgs, strict=True):
                    if p is None:
                        blockers.append(f"No Secure Client package named {n!r}.")
            else:
                pkgs = list((await app.all(await app.config_path(SC_PACKAGES, domain), cap=200)).items)
            for p in pkgs:
                if p is None:
                    continue
                os_ = _os_of(p)
                if os_ is None:
                    blockers.append(
                        f"Can't tell the operating system of Secure Client package {p.get('name')!r}."
                    )
                    continue
                images.append({"operatingSystem": os_, "anyconnectImage": ref_of(p)})
            if not images and not blockers:
                blockers.append(
                    "No Secure Client package on FMC: upload one in the FMC UI (Objects > Object Management "
                    "> VPN > Secure Client File); SSL clients download it from the FTD."
                )
        dflt = await find(app, GROUP_POLICIES, DEFAULT_GROUP_POLICY, domain)
        gps = [ref_of(dflt)] if dflt else []
        gps += await _refs(app, GROUP_POLICIES, group_policies, "group policy", domain, blockers)
        access: dict[str, Any] = {
            "interfaceSettings": [
                {
                    "accessInterface": z,
                    "enableSSL": ssl,
                    "enableDTLS": ssl,
                    "enableIPSecIkev2": ikev2,
                    "configureInterfaceIDCertificate": False,
                }
                for z in zones
            ],
            "webPort": web_port,
            "dtlsPort": dtls_port,
            "allowConnectionProfileSelection": True,
            "bypassACPolicyForDecryptTraffic": bypass_access_control,
        }
        if cert:
            if ssl:
                access["sslIdCertificate"] = cert
            if ikev2:
                access["ipsecIdCertificate"] = cert
        body: dict[str, Any] = {
            "name": name,
            "type": "RAVpn",
            "configureSSL": ssl,
            "configureIpsec": ikev2,
            "accessInterfaceSettings": access,
            "groupPolicies": gps,
        }
        if images:
            body["anyConnectClientImages"] = images
        if local_realm:
            realm = await find(app, REALMS, local_realm, domain)
            if realm is None:
                blockers.append(f"No realm named {local_realm!r}.")
            else:
                body["localRealmServer"] = {
                    "id": realm["id"],
                    "type": "IdentityRealm",
                    "name": realm.get("name"),
                }
        if description:
            body["description"] = description
        side_effects = [
            "A new policy, targeting no device yet: assign it to the FTDs (Targeted Devices), enroll "
            f"{certificate!r} on each one (fmc_enroll_certificate), then fmc_deploy.",
            NAT_NOTE,
        ]
        if bypass_access_control:
            side_effects.append(
                "Decrypted VPN traffic bypasses the access control policy (sysopt permit-vpn)."
            )
        full = await app.config_path(RAVPN, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_ravpn",
            args={
                "name": name,
                "access_interfaces": access_interfaces,
                "certificate": certificate,
                "secure_client_packages": secure_client_packages,
                "ssl": ssl,
                "ikev2": ikev2,
                "group_policies": group_policies,
                "local_realm": local_realm,
                "web_port": web_port,
                "dtls_port": dtls_port,
                "bypass_access_control": bypass_access_control,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create RA VPN policy {name!r} on {', '.join(access_interfaces)}",
                details={"ravpn": body},
                fingerprint=body,
                blockers=blockers,
                side_effects=side_effects,
            ),
            apply=lambda: applied(app, lambda: app.api.post(full, body)),
        )

    @reg.write(title="Set RA VPN connection profile")
    async def fmc_set_connection_profile(
        ctx: Context,
        policy: PolicyRef,
        name: ChangeName,
        group_policy: Annotated[
            str | None, Field(description=f"Group policy (default {DEFAULT_GROUP_POLICY} for a new profile)")
        ] = None,
        authentication: Annotated[
            AuthMethod | None,
            Field(description="aaa (default for a new profile), certificate or aaa_and_certificate"),
        ] = None,
        aaa_server: Annotated[
            str | None,
            Field(description="Authentication server: a RADIUS server group (ISE) or an AD/LDAP realm"),
        ] = None,
        local_authentication: Annotated[
            bool | None, Field(description="Authenticate against the policy's local realm instead")
        ] = None,
        authorization_server: Annotated[
            str | None, Field(description="RADIUS server group for authorization")
        ] = None,
        accounting_server: Annotated[
            str | None, Field(description="RADIUS server group for accounting")
        ] = None,
        ipv4_pools: Annotated[list[str] | None, Field(description="IPv4 address pools")] = None,
        ipv6_pools: Annotated[list[str] | None, Field(description="IPv6 address pools")] = None,
        aliases: Annotated[
            list[str] | None, Field(description="Group aliases users pick at login (enabled)")
        ] = None,
        strip_realm: Annotated[bool | None, Field(description="Strip the realm from the username")] = None,
        strip_group: Annotated[bool | None, Field(description="Strip the group from the username")] = None,
        use_aaa_addresses: Annotated[
            bool | None, Field(description="Policy-wide: take client IPv4 addresses from the AAA server")
        ] = None,
        use_dhcp: Annotated[
            bool | None, Field(description="Policy-wide: take client addresses from DHCP")
        ] = None,
        use_pools: Annotated[
            bool | None, Field(description="Policy-wide: take client IPv4 addresses from the address pools")
        ] = None,
        address_reuse_minutes: Annotated[
            int | None,
            Field(ge=0, le=480, description="Policy-wide: minutes before a returned address is reused"),
        ] = None,
        description: Description = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create or change a connection profile (tunnel group) of an RA VPN policy: its group policy,
        authentication (AAA via ISE RADIUS or an AD realm, local, or certificate), authorization and
        accounting servers, IPv4/IPv6 pools and group aliases. The address assignment switches
        (use_aaa_addresses, use_dhcp, use_pools, address_reuse_minutes) are the policy's own settings,
        shared by every profile. Changing an existing profile shows what changes and the devices that get
        it on the next deploy."""
        app: FmcApp = get_client(ctx)
        if aaa_server and local_authentication:
            raise InvalidRequest("Give aaa_server or local_authentication=true, not both.")
        pol = await _ravpn(app, policy, domain)
        base = await app.config_path(f"{RAVPN}/{pol['id']}", domain)
        profiles = (await app.all(f"{base}/connectionprofiles", cap=500)).items
        existing = next((c for c in profiles if str(c.get("name", "")).lower() == name.lower()), None)
        blockers: list[str] = []
        body: dict[str, Any] = (
            {k: v for k, v in existing.items() if k not in ("links", "metadata")}
            if existing
            else {"name": name, "type": "RaVpnConnectionProfile"}
        )
        if group_policy or not existing:
            gp = await _refs(
                app, GROUP_POLICIES, [group_policy or DEFAULT_GROUP_POLICY], "group policy", domain, blockers
            )
            if gp:
                body["groupPolicy"] = gp[0]
        if authentication or not existing:
            body["authenticationMethod"] = AUTH[authentication or "aaa"]
        if aaa_server:
            if (srv := await _aaa_server(app, aaa_server, domain, blockers)) is not None:
                body["primaryAuthenticationServer"] = srv
                body["useLocalAsPrimaryAuthServer"] = False
        elif local_authentication:
            if not pol.get("localRealmServer"):
                blockers.append(
                    f"RA VPN policy {pol.get('name')!r} has no local realm: create it with local_realm "
                    "(fmc_create_ravpn) or set one in the FMC UI."
                )
            body["useLocalAsPrimaryAuthServer"] = True
            body.pop("primaryAuthenticationServer", None)
        elif not existing and body["authenticationMethod"] != "CLIENT_CERTIFICATE_ONLY":
            raise InvalidRequest("A new AAA profile needs aaa_server or local_authentication=true.")
        for key, ref in (
            ("authorizationServer", authorization_server),
            ("accountingServer", accounting_server),
        ):
            if ref and (srv := await _aaa_server(app, ref, domain, blockers, radius_only=True)) is not None:
                body[key] = srv
        if ipv4_pools is not None:
            body["ipv4AddressPool"] = await _refs(
                app, POOLS4, ipv4_pools, "IPv4 address pool", domain, blockers
            )
        if ipv6_pools is not None:
            body["ipv6AddressPool"] = await _refs(
                app, POOLS6, ipv6_pools, "IPv6 address pool", domain, blockers
            )
        if aliases is not None:
            body["groupAlias"] = [{"aliasName": a, "enabled": True} for a in aliases]
        for key, val in (
            ("stripRealmFromUsername", strip_realm),
            ("stripGroupFromUsername", strip_group),
            ("description", description),
        ):
            if val is not None:
                body[key] = val
        changes = (
            {k: {"from": existing.get(k), "to": v} for k, v in body.items() if existing.get(k) != v}
            if existing
            else None
        )
        assign_changed = False
        assign_body: dict[str, Any] | None = None
        assign_path = ""
        flags = {
            "useAuthorizationServerForIPv4": use_aaa_addresses,
            "useDHCP": use_dhcp,
            "useInternalAddressPoolForIPv4": use_pools,
            "ipAddressReuseInterval": address_reuse_minutes,
        }
        if any(v is not None for v in flags.values()):
            current = (await app.all(f"{base}/addressassignmentsettings", cap=5)).items
            if not current:
                blockers.append("FMC returned no address assignment settings for this policy.")
            else:
                cur = current[0]
                assign_body = {
                    **{k: v for k, v in cur.items() if k not in ("links", "metadata")},
                    **{k: v for k, v in flags.items() if v is not None},
                }
                assign_path = f"{base}/addressassignmentsettings/{cur['id']}"
                assign_changed = assign_body != {
                    k: v for k, v in cur.items() if k not in ("links", "metadata")
                }
        if existing and not changes and not assign_changed:
            blockers.append(f"Connection profile {name!r} already has these settings.")
        targets = await _targets(app, pol["id"], domain)
        side_effects = [
            f"{DEPLOY_NOTE} Targets now: {', '.join(targets)}."
            if targets
            else "The RA VPN policy targets no device yet: nothing is pushed until it is assigned, deployed."
        ]
        if existing and targets:
            side_effects.append(
                f"Users of {name!r} on {', '.join(targets)} get the change at their next connection after "
                "the deploy; connected sessions keep their old settings."
            )
        if assign_body is not None:
            side_effects.append(
                "The address assignment switches are policy-wide: they apply to every connection profile of "
                f"{pol.get('name')!r}."
            )
        prof_path = f"{base}/connectionprofiles"

        async def apply() -> Any:
            out: dict[str, Any] = {}
            if existing and changes:
                res = await applied(app, lambda: app.api.put(f"{prof_path}/{existing['id']}", body))
                out["connection_profile"] = _profile_row(res if isinstance(res, dict) and res else body)
            elif not existing:
                res = await applied(app, lambda: app.api.post(prof_path, body))
                out["connection_profile"] = _profile_row(res if isinstance(res, dict) and res else body)
            if assign_body is not None and assign_changed:
                await applied(app, lambda: app.api.put(assign_path, assign_body))
                out["address_assignment"] = {k: v for k, v in flags.items() if v is not None}
            out["next"] = "fmc_deploy the targeted FTDs, then fmc_get_ravpn."
            return out

        details: dict[str, Any] = {"policy": pol.get("name"), "where_used": targets or "no device yet"}
        if existing:
            details["changes"] = changes
        else:
            details["connection_profile"] = body
        if assign_body is not None:
            details["address_assignment"] = assign_body
        return await fmc_preview(
            ctx,
            tool="fmc_set_connection_profile",
            owned=[pol],
            args={
                "policy": policy,
                "name": name,
                "group_policy": group_policy,
                "authentication": authentication,
                "aaa_server": aaa_server,
                "local_authentication": local_authentication,
                "authorization_server": authorization_server,
                "accounting_server": accounting_server,
                "ipv4_pools": ipv4_pools,
                "ipv6_pools": ipv6_pools,
                "aliases": aliases,
                "strip_realm": strip_realm,
                "strip_group": strip_group,
                "use_aaa_addresses": use_aaa_addresses,
                "use_dhcp": use_dhcp,
                "use_pools": use_pools,
                "address_reuse_minutes": address_reuse_minutes,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{'Change' if existing else 'Create'} connection profile {name!r} in RA VPN policy "
                f"{pol.get('name')!r}",
                details=details,
                fingerprint={"body": body, "assign": assign_body, "existing": existing},
                blockers=blockers,
                side_effects=side_effects,
            ),
            apply=apply,
        )
