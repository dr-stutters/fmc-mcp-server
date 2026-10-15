"""VPN depth: site-to-site topologies (view, build point-to-point, delete), SD-WAN (AUTO_VPN hub and
spoke) read, and remote-access VPN read (policies, connection profiles, gateways and sessions)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from stutters_mcp_core.http import page_of

from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import NETWORK_TYPES
from fmc_mcp.tools.common import Domain, pick_by_name, ref_label, ref_of, resolve_in, resolve_object, slim
from fmc_mcp.tools.device_config import device_interfaces, pick_interface
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS
from fmc_mcp.tools.troubleshoot import tunnel_row

S2S = "policy/ftds2svpns"
RAVPN = "policy/ravpns"
DEFAULT_IKE_POLICY = "AES-GCM-NULL-SHA-LATEST"
DEFAULT_IPSEC_PROPOSAL = "AES-GCM"
# Without export-controlled (strong crypto) licensing, e.g. FMC evaluation mode, FMC refuses to
# deploy anything stronger than DES ("Strong crypto ... is not supported").
WEAK_IKE_POLICY = "DES-SHA-SHA-LATEST"
WEAK_IPSEC_PROPOSAL = "DES_SHA-1"
MASK = "********"

TopologyRef = Annotated[str, Field(description="VPN topology name or UUID (fmc_list_vpn_topologies)")]
TOPOLOGY_TYPES = {
    "POINT_TO_POINT": "point-to-point",
    "HUB_AND_SPOKE": "hub and spoke",
    "FULL_MESH": "full mesh",
}


def _names(refs: Any) -> list[str]:
    if isinstance(refs, dict):
        refs = (refs.get("networks") or []) + (refs.get("objects") or []) + (refs.get("literals") or [])
    return [ref_label(r) for r in refs or []]


def _kind(t: dict[str, Any]) -> str:
    """point-to-point / hub and spoke / full mesh, with 'SD-WAN' for AUTO_VPN (FMC's SD-WAN wizard)."""
    base = TOPOLOGY_TYPES.get(str(t.get("topologyType")), str(t.get("topologyType") or "?"))
    auto = t.get("autoVpnSettings") or {}
    if auto or str(t.get("topologyType")) == "AUTO_VPN":
        return f"SD-WAN ({base})"
    return base


def topology_row(t: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": t.get("name"),
        "kind": _kind(t),
        "route_based": t.get("routeBased"),
        "ike": "+".join(
            v for v, on in (("IKEv1", t.get("ikeV1Enabled")), ("IKEv2", t.get("ikeV2Enabled"))) if on
        ),
        "id": t.get("id"),
    }


def endpoint_row(e: dict[str, Any]) -> dict[str, Any]:
    extranet = bool(e.get("extranet"))
    info = e.get("extranetInfo") or {}
    row: dict[str, Any] = {
        "name": e.get("name"),
        "role": e.get("peerType"),
        "device": info.get("name") if extranet else ref_label(e.get("device") or {}),
        "extranet": extranet,
        "peer_ip": info.get("ipAddress") if extranet else None,
        "interface": ref_label(e.get("interface") or {}) if e.get("interface") else None,
        "tunnel_source": ref_label(e.get("tunnelSourceInterface") or {})
        if e.get("tunnelSourceInterface")
        else None,
        "protected_networks": _names(e.get("protectedNetworks")),
        "connection": e.get("connectionType"),
        "nat_exempt": e.get("enableNATExempt"),
        "nat_exempt_inside": [ref_label(r) for r in e.get("insideInterface") or []] or None,
        "id": e.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, [], "")}


def _ike_view(ike: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for ver, key in (("ikev1", "ikeV1Settings"), ("ikev2", "ikeV2Settings")):
        s = ike.get(key)
        if not s:
            continue
        out[ver] = {
            "authentication": s.get("authenticationType"),
            "pre_shared_key": MASK if s.get("manualPreSharedKey") else None,
            "policies": _names(s.get("policies")),
            "certificate": ref_label(s["certificateAuth"]) if s.get("certificateAuth") else None,
        }
        out[ver] = {k: v for k, v in out[ver].items() if v not in (None, [])}
    return out


def _ipsec_view(p: dict[str, Any]) -> dict[str, Any]:
    pfs = p.get("perfectForwardSecrecy") or {}
    out = {
        "crypto_map": p.get("cryptoMapType"),
        "ikev2_mode": p.get("ikeV2Mode"),
        "ikev2_proposals": _names(p.get("ikeV2IpsecProposal")),
        "ikev1_proposals": _names(p.get("ikeV1IpsecProposal")),
        "pfs": pfs.get("modulusGroup") if pfs.get("enabled") else False if pfs else None,
        "lifetime_seconds": p.get("lifetimeSeconds"),
        "lifetime_kilobytes": p.get("lifetimeKilobytes"),
        "reverse_route_injection": p.get("enableRRI"),
    }
    return {k: v for k, v in out.items() if v not in (None, [])}


async def _one(app: FmcApp, path: str) -> dict[str, Any]:
    """The single child (ikesettings / ipsecsettings / advancedsettings) of a topology, expanded."""
    page = await app.all(path, cap=10)
    if not page.items:
        raise NotFound(f"FMC returned no item at {path}.", 404)
    item: dict[str, Any] = page.items[0]
    return item


async def strong_crypto_allowed(app: FmcApp) -> bool | None:
    """False when FMC runs in evaluation mode or without export control; None if unknown."""
    try:
        smart = await app.api.get("/api/fmc_platform/v1/license/smartlicenses")
    except UpstreamError:
        return None
    items = (smart or {}).get("items") or []
    if not items:
        return None
    for i in items:
        if str(i.get("regStatus", "")).upper() == "EVALUATION" or i.get("exportControl") is False:
            return False
    return True


def _strong(obj: dict[str, Any]) -> bool:
    return any(str(a).upper() != "DES" for a in obj.get("encryptionAlgorithms") or [])


async def resolve_topology(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, S2S, ref, "VPN topology", domain)


async def _peer_device(app: FmcApp, ref: str, domain: str | None) -> tuple[dict[str, Any], str]:
    """A managed device or HA pair as a VPN endpoint: ({id, type, name}, the device id whose
    interfaces to use)."""
    ref = ref.strip()
    devices = await app.all(await app.config_path(DEVICES, domain), expanded=False)
    pairs = await app.all(await app.config_path(HA_PAIRS, domain))
    for d in devices.items:
        if ref in (d.get("id"), d.get("name")):
            return {"id": d["id"], "type": "Device", "name": d.get("name")}, d["id"]
    for h in pairs.items:
        if ref in (h.get("id"), h.get("name")):
            prim = (h.get("primary") or {}).get("id")
            return {"id": h["id"], "type": "DeviceHAPair", "name": h.get("name")}, str(prim)
    every = [*devices.items, *pairs.items]
    found = pick_by_name(every, ref, "device or HA pair")  # case-insensitive match or a helpful error
    if found in pairs.items:
        return {"id": found["id"], "type": "DeviceHAPair", "name": found.get("name")}, (
            found.get("primary") or {}
        )["id"]
    return {"id": found["id"], "type": "Device", "name": found.get("name")}, found["id"]


async def _named(
    app: FmcApp, path: str, names: list[str], what: str, domain: str | None
) -> list[dict[str, Any]]:
    full = await app.config_path(path, domain)
    page = await app.all(full, cap=2000)
    out = []
    for n in names:
        hit = next((i for i in page.items if n in (i.get("id"), i.get("name"))), None)
        if hit is None:
            hit = pick_by_name(page.items, n, what)
        out.append(
            {"id": hit["id"], "type": hit.get("type"), "name": hit.get("name"), "strong": _strong(hit)}
        )
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List VPN topologies")
    async def fmc_list_vpn_topologies(
        ctx: Context,
        kind: Annotated[
            Literal["all", "site_to_site", "sdwan"] | None,
            Field(description="all (default), site_to_site (classic) or sdwan (AUTO_VPN hub and spoke)"),
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Site-to-site and SD-WAN VPN topologies: kind (point-to-point, hub and spoke, full mesh;
        'SD-WAN' for FMC's AUTO_VPN topologies), route- or policy-based, IKE versions, and per
        topology how many tunnels are up and down. Details: fmc_get_vpn_topology."""
        app: FmcApp = get_client(ctx)
        topos = await app.all(await app.config_path(S2S, domain), cap=2000)
        tunnels = await app.all(await app.config_path("health/tunnelstatuses", domain), cap=5000)
        counts: dict[str, dict[str, int]] = {}
        for t in tunnels.items:
            tid = (t.get("vpnTopology") or {}).get("id")
            st = str(t.get("state") or "UNKNOWN")
            counts.setdefault(str(tid), {})[st] = counts.setdefault(str(tid), {}).get(st, 0) + 1
        rows = []
        for t in topos.items:
            row = topology_row(t)
            sdwan = row["kind"].startswith("SD-WAN")
            if kind == "sdwan" and not sdwan or kind == "site_to_site" and sdwan:
                continue
            c = counts.get(str(t.get("id")), {})
            row["tunnels_up"] = c.get("TUNNEL_UP", 0)
            row["tunnels_down"] = c.get("TUNNEL_DOWN", 0) + c.get("UNKNOWN", 0)
            rows.append(row)
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Get VPN topology")
    async def fmc_get_vpn_topology(ctx: Context, topology: TopologyRef, domain: Domain = None) -> Any:
        """One site-to-site or SD-WAN VPN topology in full: kind, route/policy-based, every endpoint
        (device or extranet peer, interface or VTI, protected networks, NAT exemption, hub/spoke
        role), IKE settings (versions, policies, authentication; the pre-shared key is masked),
        IPsec settings (proposals, PFS, lifetimes) and the live tunnel states FMC monitors."""
        app: FmcApp = get_client(ctx)
        t = await resolve_topology(app, topology, domain)
        base = await app.config_path(f"{S2S}/{t['id']}", domain)
        endpoints = await app.all(f"{base}/endpoints", cap=2000)
        out: dict[str, Any] = {**topology_row(t), "description": t.get("description")}
        out["endpoints"] = [endpoint_row(e) for e in endpoints.items]
        for key, path, view in (("ike", "ikesettings", _ike_view), ("ipsec", "ipsecsettings", _ipsec_view)):
            try:
                out[key] = view(await _one(app, f"{base}/{path}"))
            except (NotFound, UpstreamError) as e:
                out[key] = {"error": str(e)}
        if t.get("autoVpnSettings"):
            out["sdwan"] = slim(t["autoVpnSettings"])
        tunnels = await app.all(
            await app.config_path("health/tunnelstatuses", domain),
            {"filter": f"vpnTopologyId:{t['id']}"},
            cap=2000,
        )
        rows = [
            tunnel_row(x) for x in tunnels.items if (x.get("vpnTopology") or {}).get("id") in (None, t["id"])
        ]
        out["tunnels"] = rows
        return object_result({k: v for k, v in out.items() if v not in (None, "")}, shape=False)

    @reg.write(title="Create site-to-site VPN")
    async def fmc_create_s2s_vpn(
        ctx: Context,
        name: Annotated[str, Field(description="New topology name", min_length=1, max_length=64)],
        device_a: Annotated[str, Field(description="Managed FTD or HA pair (name/UUID) for endpoint A")],
        interface_a: Annotated[
            str, Field(description="Endpoint A's outside interface logical name, or its VTI when route_based")
        ],
        pre_shared_key: Annotated[
            str, Field(description="IKEv2 pre-shared key (never echoed back)", min_length=8, max_length=127)
        ],
        networks_a: Annotated[
            list[str] | None,
            Field(description="Policy-based: network objects/groups behind A (protected networks)"),
        ] = None,
        device_b: Annotated[
            str | None, Field(description="Managed FTD or HA pair for endpoint B (or give extranet_ip)")
        ] = None,
        interface_b: Annotated[
            str | None, Field(description="Endpoint B's interface (or VTI) when device_b is managed")
        ] = None,
        networks_b: Annotated[
            list[str] | None, Field(description="Policy-based: network objects/groups behind B")
        ] = None,
        extranet_ip: Annotated[
            str | None, Field(description="Endpoint B is an unmanaged peer (extranet) with this IP")
        ] = None,
        extranet_name: Annotated[str | None, Field(description="Name for the extranet peer")] = None,
        route_based: Annotated[
            bool, Field(description="Route-based (VTI) instead of policy-based (crypto map)")
        ] = False,
        nat_exempt_zone_a: Annotated[
            str | None,
            Field(
                description="Inside zone/interface group on A to exempt VPN traffic from NAT (policy-based)"
            ),
        ] = None,
        nat_exempt_zone_b: Annotated[
            str | None, Field(description="Inside zone/interface group on B for NAT exemption")
        ] = None,
        ike_policies: Annotated[
            list[str] | None, Field(description=f"IKEv2 policy names (default {DEFAULT_IKE_POLICY})")
        ] = None,
        ipsec_proposals: Annotated[
            list[str] | None,
            Field(description=f"IKEv2 IPsec proposal names (default {DEFAULT_IPSEC_PROPOSAL})"),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Build a point-to-point IKEv2 site-to-site VPN with a pre-shared key between two managed
        FTDs (or HA pairs), or between one FTD and an unmanaged peer (extranet). Policy-based: give
        the protected networks on each side (and an inside zone for NAT exemption when the device
        NATs that traffic). Route-based: give existing VTI interfaces and route over them. Creates
        the topology, sets IKE and IPsec, then adds both endpoints, in that order. Deploy both
        devices afterwards (fmc_deploy); check with fmc_get_vpn_topology / fmc_list_vpn_tunnels."""
        app: FmcApp = get_client(ctx)
        if (device_b is None) == (extranet_ip is None):
            raise InvalidRequest("Give device_b (managed peer) or extranet_ip (unmanaged peer), not both.")
        if device_b and not interface_b:
            raise InvalidRequest("interface_b is required with device_b.")
        if route_based and extranet_ip:
            raise InvalidRequest(
                "Route-based (VTI) VPNs need two managed devices; use policy-based for extranet."
            )
        if route_based and (networks_a or networks_b or nat_exempt_zone_a or nat_exempt_zone_b):
            raise InvalidRequest(
                "Route-based VPNs route over the VTIs: don't give networks or NAT-exempt zones."
            )
        if not route_based and (not networks_a or not networks_b):
            raise InvalidRequest("Policy-based VPNs need networks_a and networks_b (protected networks).")
        if extranet_ip:
            try:
                ipaddress.ip_address(extranet_ip.strip())
            except ValueError:
                raise InvalidRequest(f"extranet_ip {extranet_ip!r} is not an IP address.") from None
        blockers: list[str] = []
        try:
            await resolve_topology(app, name, domain)
            blockers.append(f"A VPN topology named {name!r} already exists.")
        except NotFound:
            pass

        async def endpoint(
            dev_ref: str, iface: str, nets: list[str] | None, zone: str | None
        ) -> dict[str, Any]:
            dev, iface_dev = await _peer_device(app, dev_ref, domain)
            kinds = ["vti"] if route_based else None
            _, i = pick_interface(await device_interfaces(app, iface_dev, domain, kinds), iface, dev["name"])
            ep: dict[str, Any] = {
                "name": dev["name"],
                "type": "EndPoint",
                "peerType": "PEER",
                "extranet": False,
                "device": dev,
                "interface": {"id": i["id"], "type": i.get("type"), "name": i.get("name")},
                "connectionType": "BIDIRECTIONAL",
            }
            if nets:
                ep["protectedNetworks"] = {
                    "networks": [
                        ref_of((await resolve_object(app, n, domain, NETWORK_TYPES))[1]) for n in nets
                    ]
                }
            if zone:
                _, z = await resolve_object(app, zone, domain, ["security_zone", "interface_group"])
                ep["enableNATExempt"] = True
                ep["insideInterface"] = [ref_of(z)]
            return ep

        ep_a = await endpoint(device_a, interface_a, networks_a, nat_exempt_zone_a)
        if device_b:
            ep_b = await endpoint(device_b, interface_b or "", networks_b, nat_exempt_zone_b)
            if ep_b["device"]["id"] == ep_a["device"]["id"]:
                raise InvalidRequest("device_a and device_b must differ.")
        else:
            ep_b = {
                "name": extranet_name or f"extranet-{extranet_ip}",
                "type": "EndPoint",
                "peerType": "PEER",
                "extranet": True,
                "extranetType": "GENERIC",
                "extranetInfo": {
                    "name": extranet_name or f"extranet-{extranet_ip}",
                    "ipAddress": str(extranet_ip).strip(),
                    "isDynamicIP": False,
                },
            }
            if networks_b:
                ep_b["protectedNetworks"] = {
                    "networks": [
                        ref_of((await resolve_object(app, n, domain, NETWORK_TYPES))[1]) for n in networks_b
                    ]
                }
        strong_ok = await strong_crypto_allowed(app)
        side_effects = ["Takes effect after deploying both devices (fmc_deploy)."]
        weak = strong_ok is False
        if weak and not ike_policies and not ipsec_proposals:
            side_effects.append(
                "FMC has no strong-crypto (export-controlled) licence (evaluation mode), so the defaults are "
                f"{WEAK_IKE_POLICY} / {WEAK_IPSEC_PROPOSAL} (DES): fine for a lab, not for production."
            )
        policies = await _named(
            app,
            "object/ikev2policies",
            ike_policies or [WEAK_IKE_POLICY if weak else DEFAULT_IKE_POLICY],
            "IKEv2 policy",
            domain,
        )
        proposals = await _named(
            app,
            "object/ikev2ipsecproposals",
            ipsec_proposals or [WEAK_IPSEC_PROPOSAL if weak else DEFAULT_IPSEC_PROPOSAL],
            "IKEv2 IPsec proposal",
            domain,
        )
        if weak and (strong := [p["name"] for p in [*policies, *proposals] if p["strong"]]):
            blockers.append(
                "FMC has no strong-crypto licence (evaluation mode), so it won't deploy "
                f"{', '.join(strong)}; "
                f"use DES ones such as {WEAK_IKE_POLICY} and {WEAK_IPSEC_PROPOSAL}, or register FMC with a "
                "Smart Account that allows export-controlled features."
            )
        topo_body = {
            "name": name,
            "type": "FTDS2SVpn",
            "topologyType": "POINT_TO_POINT",
            "routeBased": route_based,
            "ikeV1Enabled": False,
            "ikeV2Enabled": True,
        }
        ike_v2 = {
            "authenticationType": "MANUAL_PRE_SHARED_KEY",
            "manualPreSharedKey": pre_shared_key,
            "enforceHexBasedPreSharedKeyOnly": False,
            "policies": [
                {"id": p["id"], "type": p.get("type") or "IKEv2Policy", "name": p["name"]} for p in policies
            ],
        }
        ipsec = {
            "cryptoMapType": "STATIC",
            "ikeV2Mode": "TUNNEL",
            "ikeV2IpsecProposal": [
                {"id": p["id"], "type": p.get("type") or "IKEv2IPsecProposal", "name": p["name"]}
                for p in proposals
            ],
        }
        path = await app.config_path(S2S, domain)
        shown_ike = {**ike_v2, "manualPreSharedKey": MASK}

        async def apply() -> Any:
            topo = await app.api.post(path, topo_body)
            app.invalidate_cache()
            base = f"{path}/{topo['id']}"
            done = [f"topology {name!r} ({topo['id']})"]
            try:
                ike = await _one(app, f"{base}/ikesettings")
                await app.api.put(
                    f"{base}/ikesettings/{ike['id']}",
                    {"id": ike["id"], "type": ike.get("type") or "IkeSettings", "ikeV2Settings": ike_v2},
                )
                done.append("IKE settings")
                ips = await _one(app, f"{base}/ipsecsettings")
                await app.api.put(
                    f"{base}/ipsecsettings/{ips['id']}",
                    {**{k: v for k, v in ips.items() if k not in ("links", "metadata")}, **ipsec},
                )
                done.append("IPsec settings")
                made = []
                for ep in (ep_a, ep_b):
                    made.append(await app.api.post(f"{base}/endpoints", ep))
                    done.append(f"endpoint {ep['name']}")
            except Exception as e:  # roll back the half-built topology, whatever failed
                try:
                    await app.api.delete(base)
                    cleanup = "The partial topology was deleted again; fix the cause and retry."
                except Exception:
                    cleanup = (
                        f"Removing the partial topology failed: delete {name!r} with fmc_delete_s2s_vpn."
                    )
                app.invalidate_cache()
                msg = str(e).replace(pre_shared_key, MASK)
                raise UpstreamError(
                    f"Building VPN {name!r} failed after {', '.join(done)}: {msg}. {cleanup}",
                    getattr(e, "status_code", None),
                ) from None
            return {
                "topology": topology_row(topo),
                "endpoints": [endpoint_row(m) for m in made],
                "next": "Deploy both devices (fmc_deploy), then check fmc_get_vpn_topology / "
                "fmc_list_vpn_tunnels and fmc_run_show_command('show crypto ipsec sa').",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_create_s2s_vpn",
            args={
                "name": name,
                "device_a": device_a,
                "interface_a": interface_a,
                "pre_shared_key": pre_shared_key,
                "networks_a": networks_a,
                "device_b": device_b,
                "interface_b": interface_b,
                "networks_b": networks_b,
                "extranet_ip": extranet_ip,
                "extranet_name": extranet_name,
                "route_based": route_based,
                "nat_exempt_zone_a": nat_exempt_zone_a,
                "nat_exempt_zone_b": nat_exempt_zone_b,
                "ike_policies": ike_policies,
                "ipsec_proposals": ipsec_proposals,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create {'route' if route_based else 'policy'}-based point-to-point VPN {name!r}: "
                f"{ep_a['name']} <-> {ep_b['name']}",
                details={
                    "topology": topo_body,
                    "ike_v2": shown_ike,
                    "ipsec": ipsec,
                    "endpoints": [endpoint_row(ep_a), endpoint_row(ep_b)],
                },
                fingerprint={
                    "a": ep_a,
                    "b": ep_b,
                    "ike": [p["id"] for p in policies],
                    "ipsec": [p["id"] for p in proposals],
                },
                blockers=blockers,
                side_effects=side_effects,
            ),
            apply=apply,
        )

    @reg.write(title="Delete site-to-site VPN", destructive=True)
    async def fmc_delete_s2s_vpn(
        ctx: Context, topology: TopologyRef, domain: Domain = None, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Delete a site-to-site VPN topology with its endpoints and settings. The tunnels go down on
        the next deployment of the devices (fmc_deploy)."""
        app: FmcApp = get_client(ctx)
        t = await resolve_topology(app, topology, domain)
        base = await app.config_path(f"{S2S}/{t['id']}", domain)
        endpoints = await app.all(f"{base}/endpoints", cap=2000)
        rows = [endpoint_row(e) for e in endpoints.items]
        return await fmc_preview(
            ctx,
            tool="fmc_delete_s2s_vpn",
            args={"topology": topology, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete VPN topology {t.get('name')!r} ({len(rows)} endpoint(s))",
                details={"topology": topology_row(t), "endpoints": rows},
                fingerprint={"topology": topology_row(t), "endpoints": rows},
                side_effects=["The tunnels go down when the devices are next deployed."],
            ),
            apply=lambda: _delete(app, base, t),
        )

    @reg.read(title="Get remote-access VPN")
    async def fmc_get_ravpn(
        ctx: Context,
        policy: Annotated[str | None, Field(description="Only this RA VPN policy (name/UUID)")] = None,
        sessions: Annotated[
            bool, Field(description="Also list the RA VPN gateways and their sessions")
        ] = True,
        domain: Domain = None,
    ) -> Any:
        """Remote-access VPN (Secure Client) configuration and state, read-only: each RA VPN policy
        with its connection profiles (group policy, address pools, authentication/authorization/
        accounting servers), access interfaces and assigned devices, plus the RA VPN gateways FMC
        monitors with their current session counts (health/ravpngateways). Building RA VPN needs
        Secure Client packages and certificates, which stay in the FMC UI."""
        app: FmcApp = get_client(ctx)
        everything = await app.all(await app.config_path(RAVPN, domain), cap=500)
        pols = everything.items
        if policy:
            pols = [p for p in pols if policy in (p.get("id"), p.get("name"))] or [
                pick_by_name(everything.items, policy, "RA VPN policy")
            ]
        out_pols = []
        for p in pols:
            base = await app.config_path(f"{RAVPN}/{p['id']}", domain)
            try:
                profiles = (await app.all(f"{base}/connectionprofiles", cap=500)).items
            except UpstreamError:
                profiles = []
            out_pols.append(
                {
                    "name": p.get("name"),
                    "id": p.get("id"),
                    "description": p.get("description"),
                    "protocols": [
                        x for x in ("SSL", "IPSEC_IKEV2") if (p.get("protocol") or {}).get(x.lower())
                    ]
                    or None,
                    "connection_profiles": [_profile_row(c) for c in profiles],
                }
            )
        result: dict[str, Any] = {"policies": out_pols}
        if sessions:
            try:
                gws = await app.all(await app.config_path("health/ravpngateways", domain), cap=1000)
                result["gateways"] = [_gateway_row(g) for g in gws.items]
            except UpstreamError as e:
                result["gateways"] = {"error": str(e)}
        return object_result(result, shape=False)


async def _delete(app: FmcApp, path: str, t: dict[str, Any]) -> dict[str, Any]:
    await app.api.delete(path)  # the response echoes the whole topology, keys included: don't return it
    app.invalidate_cache()
    return {"deleted": t.get("name"), "id": t.get("id")}


def _profile_row(c: dict[str, Any]) -> dict[str, Any]:
    def server(key: str) -> str | None:
        s = c.get(key) or {}
        ref = s.get("authenticationServer") or s.get("authorizationServer") or s.get("accountingServer") or s
        return ref_label(ref) if isinstance(ref, dict) and (ref.get("name") or ref.get("id")) else None

    row = {
        "name": c.get("name"),
        "group_policy": ref_label(c["groupPolicy"]) if c.get("groupPolicy") else None,
        "ipv4_pools": _names(c.get("ipv4AddressPool")),
        "ipv6_pools": _names(c.get("ipv6AddressPool")),
        "authentication": (c.get("authenticationMethod") or c.get("authenticationSettings") or {}).get(
            "authenticationMethod"
        )
        if isinstance(c.get("authenticationMethod") or c.get("authenticationSettings"), dict)
        else c.get("authenticationMethod"),
        "aaa_server": server("authenticationSettings") or server("authenticationServer"),
        "aliases": _names(c.get("groupAliases")) or None,
        "id": c.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, [], "")}


def _gateway_row(g: dict[str, Any]) -> dict[str, Any]:
    row = {
        "device": ref_label(g.get("device") or {}) if g.get("device") else g.get("name"),
        "active_sessions": g.get("activeSessions", g.get("currentSessions")),
        "max_sessions": g.get("maxSessions"),
        "status": g.get("status") or g.get("state"),
    }
    return {k: v for k, v in row.items() if v is not None}
