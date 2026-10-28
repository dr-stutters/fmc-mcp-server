"""BFD on FTDs (F95): a BFD template object plus the per-device BFD policy that applies it (single-hop on an
interface, multi-hop between two addresses), and the checks fmc_configure_bgp uses for `bfd` (fall-over BFD
on a neighbour).

Shapes, FMC 10.0.1 OpenAPI (request/response examples; no BFD object existed in the lab when this was
written, so tests/fixtures/bfd_fmc10.json is spec-shaped):
- object/bfdtemplates: {type BFDTemplate, name, hopType SINGLE_HOP|MULTI_HOP, txRxInterval MILLISECONDS|
  MICROSECONDS|NONE, minTransmit, minReceive, txRxMultiplier, echo ENABLED|DISABLED (single-hop),
  authentication{authType MD5|METICULOUSMD5|SHA1|METICULOUSSHA1|NONE, pwdEncryption, authKey, authKeyId}}
  (the spec calls authentication mandatory for a multi-hop template; FMC returns authKey masked).
- devicerecords/{id}/routing/bfdpolicies (and routing/virtualrouters/{id}/bfdpolicies): {type BFDPolicy,
  hopType, template{ref}, interface{ref} (single-hop) or sourceAddress/destinationAddress{ref} (multi-hop)}.
- A BGP neighbour's neighborGeneral.fallOverBFD: SINGLE_HOP|MULTI_HOP|AUTO_DETECT_HOP|NONE.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import Confirm, InvalidRequest, NotFound, Plan, ToolRegistrar, UpstreamError, get_client
from fmc_mcp._core.formatting import MASK
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.app_routing import collection
from fmc_mcp.tools.common import Domain, ref_label, ref_of, resolve_object
from fmc_mcp.tools.device_config import (
    device_interfaces,
    iref,
    network_by_value,
    pick_interface,
    resolve_device,
    routing_base,
    static_network,
)
from fmc_mcp.tools.devices import DeviceRef
from fmc_mcp.tools.object_writes import editable

TEMPLATES = "object/bfdtemplates"
HOP = {"single_hop": "SINGLE_HOP", "multi_hop": "MULTI_HOP"}
HOP_LABEL = {v: k for k, v in HOP.items()} | {"AUTO_DETECT_HOP": "auto"}
AUTH_TYPES = {
    "md5": "MD5",
    "meticulous_md5": "METICULOUSMD5",
    "sha1": "SHA1",
    "meticulous_sha1": "METICULOUSSHA1",
}
# Timers for a new template when the call gives none: 300 ms x 3 (detection in under a second), the value
# Cisco's BFD guidance uses for software and virtual platforms (FTDv) rather than the 50 ms floor.
DEFAULT_INTERVAL_MS = 300
DEFAULT_MULTIPLIER = 3
NEW_TEMPLATE = "<id of the new BFD template>"
# fallOverBFD values in the order fmc_configure_bgp's `bfd` names them
FALL_OVER = {"single_hop": "SINGLE_HOP", "multi_hop": "MULTI_HOP", "auto": "AUTO_DETECT_HOP", "none": "NONE"}
BfdMode = Literal["single_hop", "multi_hop", "auto", "none"]


# --- helpers (also used by fmc_configure_bgp) -----------------------------------------------------


def masked(v: Any) -> Any:
    """A body as a preview shows it: a template's authKey masked."""
    if isinstance(v, dict):
        return {k: (MASK if k == "authKey" and x else masked(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [masked(x) for x in v]
    return v


def is_masked(secret: Any) -> bool:
    return bool(secret) and set(str(secret)) == {"*"}


def template_row(t: dict[str, Any]) -> dict[str, Any]:
    auth = t.get("authentication") or {}
    unit = {"MICROSECONDS": "us"}.get(str(t.get("txRxInterval")), "ms")
    return {
        "name": t.get("name"),
        "hop": HOP_LABEL.get(str(t.get("hopType")), t.get("hopType")),
        "min_tx": f"{t['minTransmit']} {unit}" if t.get("minTransmit") is not None else None,
        "min_rx": f"{t['minReceive']} {unit}" if t.get("minReceive") is not None else None,
        "multiplier": t.get("txRxMultiplier"),
        "echo": {"ENABLED": True, "DISABLED": False}.get(str(t.get("echo"))),
        "authentication": None if auth.get("authType") in (None, "NONE") else str(auth["authType"]).lower(),
    }


def policy_row(p: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "hop": HOP_LABEL.get(str(p.get("hopType")), p.get("hopType")),
        "template": ref_label(p.get("template") or {}),
    }
    if p.get("interface"):
        out["interface"] = ref_label(p["interface"])
    if p.get("sourceAddress"):
        out["source"] = ref_label(p["sourceAddress"])
    if p.get("destinationAddress"):
        out["destination"] = ref_label(p["destinationAddress"])
    return out


def connected(items: list[tuple[str, dict[str, Any]]], addr: ipaddress.IPv4Address) -> dict[str, Any] | None:
    """The interface whose IPv4 subnet holds `addr` (a directly connected peer), or None."""
    for _kind, i in items:
        net = static_network(i)
        if net is not None and net.network.prefixlen < 32 and addr in net.network:
            return i
    return None


def bgp_neighbors(bgp: dict[str, Any] | None) -> list[dict[str, Any]]:
    return list(((bgp or {}).get("addressFamilyIPv4") or {}).get("neighbors") or [])


def fall_over(n: dict[str, Any]) -> str:
    return str((n.get("neighborGeneral") or {}).get("fallOverBFD") or "NONE")


async def object_network(app: FmcApp, value: str, domain: str | None) -> dict[str, Any]:
    """A Host/Network object by name, UUID or the CIDR/address it holds (multi-hop source/destination)."""
    text = value.strip()
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        _t, obj = await resolve_object(app, text, domain, ["host", "network"])
        return obj
    found = await network_by_value(app, text, domain)
    if found is None:
        raise InvalidRequest(
            f"No host or network object with value {text}; create one with fmc_create_object."
        )
    return found


def object_net(obj: dict[str, Any]) -> ipaddress.IPv4Network | None:
    try:
        net = ipaddress.ip_network(str(obj.get("value", "")), strict=False)
    except ValueError:
        return None
    return net if isinstance(net, ipaddress.IPv4Network) else None


async def neighbor_bfd_warnings(
    app: FmcApp,
    dev: dict[str, Any],
    base: str,
    address: str,
    mode: str,
    domain: str | None,
) -> list[str]:
    """What fmc_configure_bgp's preview says about bfd=<mode> on neighbour `address`: a multi-hop peer that
    is directly connected, a single-hop peer that isn't, and a peer with no matching BFD policy on this
    device (FMC accepts fall-over BFD without one, but no BFD session comes up and BGP keeps relying on the
    hold timer)."""
    if mode not in ("single_hop", "multi_hop"):
        return []
    addr = ipaddress.IPv4Address(address)
    items = await device_interfaces(app, dev["id"], domain)
    iface = connected(items, addr)
    policies = await collection(app, f"{base}/bfdpolicies", domain)
    out: list[str] = []
    if mode == "multi_hop" and iface is not None:
        out.append(
            f"{address} is directly connected (on {iface.get('ifname') or iface.get('name')}): multi-hop BFD "
            "is for peers several hops away (loopback peering); use bfd='single_hop' with a single-hop BFD "
            "policy on that interface."
        )
    if mode == "single_hop":
        if iface is None:
            out.append(
                f"{address} isn't in a subnet of any interface of {dev.get('name')}: single-hop BFD needs a "
                "directly connected peer; use bfd='multi_hop' with a multi-hop BFD policy."
            )
        elif not any(
            p.get("hopType") == "SINGLE_HOP" and (p.get("interface") or {}).get("id") == iface.get("id")
            for p in policies
        ):
            out.append(
                f"No single-hop BFD policy on {iface.get('ifname') or iface.get('name')} (the interface "
                f"toward {address}): the BFD session stays down and BGP keeps failing over on the hold "
                "timer. Add one with fmc_configure_bfd(interface=...)."
            )
    if mode == "multi_hop":
        multi = [p for p in policies if p.get("hopType") == "MULTI_HOP"]
        covered = False
        for p in multi:
            dst = p.get("destinationAddress") or {}
            try:
                _t, obj = await resolve_object(
                    app, str(dst.get("id") or dst.get("name")), domain, ["host", "network"]
                )
            except (NotFound, InvalidRequest, UpstreamError):
                continue
            net = object_net(obj)
            if net is not None and addr in net:
                covered = True
                break
        if not covered:
            out.append(
                f"No multi-hop BFD policy whose destination holds {address}: the BFD session stays down. Add "
                "one with fmc_configure_bfd(hop='multi_hop', source=..., destination=...)."
            )
    out.append(
        f"The peer must run BFD too ('bfd interval' or a BFD template, and "
        f"'neighbor {address} fall-over bfd'), or the session stays down."
    )
    return out


# --- tool ----------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Configure BFD")
    async def fmc_configure_bfd(
        ctx: Context,
        device: DeviceRef,
        template: Annotated[
            str,
            Field(
                description="BFD template object (name/UUID): reused when it exists (changed when timers are "
                "given), created otherwise with the timers below",
                min_length=1,
                max_length=64,
            ),
        ],
        hop: Annotated[
            Literal["single_hop", "multi_hop"],
            Field(
                description="single_hop: on an interface toward a directly connected peer; multi_hop: "
                "between two addresses (loopback peering)"
            ),
        ] = "single_hop",
        interface: Annotated[
            str | None, Field(description="Single-hop: the interface (hardware/logical name or UUID)")
        ] = None,
        source: Annotated[
            str | None,
            Field(description="Multi-hop: this device's address (host/network object name, UUID or value)"),
        ] = None,
        destination: Annotated[
            str | None,
            Field(description="Multi-hop: the peer's address (host/network object name, UUID or value)"),
        ] = None,
        min_tx_ms: Annotated[
            int | None,
            Field(
                ge=50,
                le=999,
                description=f"Minimum transmit interval, ms (new template: {DEFAULT_INTERVAL_MS})",
            ),
        ] = None,
        min_rx_ms: Annotated[
            int | None,
            Field(
                ge=50,
                le=999,
                description=f"Minimum receive interval, ms (new template: {DEFAULT_INTERVAL_MS})",
            ),
        ] = None,
        multiplier: Annotated[
            int | None,
            Field(
                ge=3,
                le=50,
                description="Missed packets before the peer is declared down (new template: "
                f"{DEFAULT_MULTIPLIER})",
            ),
        ] = None,
        echo: Annotated[
            bool | None,
            Field(description="Single-hop: BFD echo mode on the template (FMC default when unset)"),
        ] = None,
        auth_type: Annotated[
            Literal["md5", "meticulous_md5", "sha1", "meticulous_sha1"] | None,
            Field(description="Template authentication (with auth_key); default md5 when auth_key is given"),
        ] = None,
        auth_key: Annotated[
            str | None,
            Field(
                description="Template authentication key (FMC never returns it: required again to change a "
                "template that has one)",
                max_length=29,
            ),
        ] = None,
        auth_key_id: Annotated[int, Field(ge=0, le=255, description="Authentication key id")] = 1,
        remove: Annotated[
            bool,
            Field(
                description="Delete the BFD policy on `interface` (or source/destination); the template stays"
            ),
        ] = False,
        virtual_router: Annotated[
            str | None, Field(description="Virtual router (VRF) name/UUID; default the global table")
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Turn on BFD (bidirectional forwarding detection) on an FTD so BGP notices a dead neighbour in
        under a second instead of after the hold timer: applies a BFD template (timers, echo,
        authentication; created or reused in object/bfdtemplates) as a BFD policy, single-hop on the
        interface toward a directly connected peer or multi-hop between two addresses, in the global table
        or a VRF. remove deletes the policy (the template stays). Then fmc_configure_bgp(neighbor=...,
        bfd='single_hop'|'multi_hop') sets fall-over BFD on the neighbour, and the peer needs BFD too. The
        preview shows the template and policy before and after, each request (`requests`, keys masked),
        and warns about BGP neighbours on that interface without fall-over BFD and multi-hop policies
        toward directly connected peers. Deploy to apply; verify with fmc_run_show_command('show bfd
        neighbors') and 'show bgp summary'."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        where = f"{dev.get('name')} ({vr_name or 'global table'})"
        hop_type = HOP[hop]
        if hop == "single_hop":
            if not interface or source or destination:
                raise InvalidRequest("A single-hop BFD policy takes `interface` (not source/destination).")
        elif not (source and destination) or interface:
            raise InvalidRequest("A multi-hop BFD policy takes `source` and `destination` (not interface).")
        if echo is not None and hop == "multi_hop":
            raise InvalidRequest("Echo mode is single-hop only.")
        if auth_type and not auth_key:
            raise InvalidRequest("auth_type needs auth_key.")
        timers = any(x is not None for x in (min_tx_ms, min_rx_ms, multiplier, echo, auth_key))
        if remove and timers:
            raise InvalidRequest("remove can't be combined with template settings.")

        blockers: list[str] = []
        warnings: list[str] = []
        steps: list[tuple[str, str, str, dict[str, Any] | None]] = []
        policies_path = await app.config_path(f"{base}/bfdpolicies", domain)
        policies = await collection(app, f"{base}/bfdpolicies", domain)
        items = await device_interfaces(app, dev["id"], domain)

        # where the policy goes: one interface, or a source/destination pair
        target: dict[str, Any] = {}
        iface: dict[str, Any] | None = None
        src_obj: dict[str, Any] | None = None
        dst_obj: dict[str, Any] | None = None
        if hop == "single_hop":
            _kind, iface = pick_interface(items, str(interface), str(dev.get("name")))
            if not iface.get("ifname"):
                blockers.append(
                    f"{iface.get('name')} has no logical name; name it first (fmc_update_interface)."
                )
            target["interface"] = iref(iface)
            existing = next(
                (p for p in policies if (p.get("interface") or {}).get("id") == iface["id"]), None
            )
            label = str(iface.get("ifname") or iface.get("name"))
        else:
            src_obj = await object_network(app, str(source), domain)
            dst_obj = await object_network(app, str(destination), domain)
            target["sourceAddress"] = ref_of(src_obj)
            target["destinationAddress"] = ref_of(dst_obj)
            existing = next(
                (
                    p
                    for p in policies
                    if (p.get("sourceAddress") or {}).get("id") == src_obj["id"]
                    and (p.get("destinationAddress") or {}).get("id") == dst_obj["id"]
                ),
                None,
            )
            label = f"{src_obj.get('name')} -> {dst_obj.get('name')}"

        # the template: reuse, change or create (not needed to remove a policy)
        tpl: dict[str, Any] | None = None
        tpl_after: dict[str, Any] | None = None
        tpl_ref: dict[str, Any] | None = None
        if not remove:
            page = await app.all(await app.config_path(TEMPLATES, domain), cap=2000)
            want = template.strip().lower()
            tpl = next(
                (
                    t
                    for t in page.items
                    if want in (str(t.get("name", "")).lower(), str(t.get("id", "")).lower())
                ),
                None,
            )
            tpl_path = await app.config_path(TEMPLATES, domain)
            if tpl is not None and tpl.get("hopType") != hop_type:
                blockers.append(
                    f"BFD template {tpl.get('name')!r} is {HOP_LABEL.get(str(tpl.get('hopType')))}; "
                    f"this policy is {hop}: name another template."
                )
            body: dict[str, Any] = (
                editable(tpl)
                if tpl
                else {
                    "type": "BFDTemplate",
                    "name": template.strip(),
                    "hopType": hop_type,
                    "txRxInterval": "MILLISECONDS",
                    "minTransmit": DEFAULT_INTERVAL_MS,
                    "minReceive": DEFAULT_INTERVAL_MS,
                    "txRxMultiplier": DEFAULT_MULTIPLIER,
                }
            )
            if tpl is not None and timers and str(body.get("txRxInterval")) == "MICROSECONDS":
                body["txRxInterval"] = "MILLISECONDS"  # the *_ms values below are milliseconds
            if min_tx_ms is not None:
                body["minTransmit"] = min_tx_ms
            if min_rx_ms is not None:
                body["minReceive"] = min_rx_ms
            if multiplier is not None:
                body["txRxMultiplier"] = multiplier
            if echo is not None:
                body["echo"] = "ENABLED" if echo else "DISABLED"
            if auth_key:
                body["authentication"] = {
                    "authType": AUTH_TYPES[auth_type or "md5"],
                    "pwdEncryption": "UN_ENCRYPTED",
                    "authKey": auth_key,
                    "authKeyId": auth_key_id,
                }
            elif tpl is None and hop == "multi_hop":
                # the spec calls authentication mandatory on a multi-hop template
                body["authentication"] = {"authType": "NONE"}
            tpl_after = template_row(body)
            if tpl is None:
                steps.append(("create bfd template", "POST", tpl_path, body))
                tpl_ref = {"id": NEW_TEMPLATE, "type": "BFDTemplate", "name": body["name"]}
            else:
                tpl_ref = {"id": tpl["id"], "type": "BFDTemplate", "name": tpl.get("name")}
                if body != editable(tpl):
                    if is_masked((body.get("authentication") or {}).get("authKey")):
                        blockers.append(
                            f"BFD template {tpl.get('name')!r} has an authentication key FMC only returns "
                            "masked; changing it would replace the key. Pass auth_key, or change it in "
                            "the FMC UI."
                        )
                    steps.append(("update bfd template", "PUT", f"{tpl_path}/{tpl['id']}", body))
                    warnings.append(
                        f"BFD template {tpl.get('name')!r} is a shared object: every BFD policy using it, on "
                        "any device, gets the new timers at its next deployment."
                    )

        # the policy
        before = policy_row(existing) if existing else None
        after: dict[str, Any] | None
        if remove:
            if existing is None:
                raise NotFound(f"No BFD policy on {label} ({where}).", 404)
            steps.append(("delete bfd policy", "DELETE", f"{policies_path}/{existing['id']}", None))
            after = None
        else:
            assert tpl_ref is not None
            pol = {
                **(editable(existing) if existing else {"type": "BFDPolicy"}),
                "hopType": hop_type,
                **target,
            }
            pol["template"] = tpl_ref
            after = policy_row(pol)
            if existing is None:
                steps.append(("create bfd policy", "POST", policies_path, pol))
            elif (existing.get("template") or {}).get("id") != tpl_ref["id"]:
                steps.append(("update bfd policy", "PUT", f"{policies_path}/{existing['id']}", pol))
            if not steps:
                blockers.append(f"{label} already uses BFD template {tpl_ref.get('name')!r} that way.")

        # BGP neighbours this BFD serves (or no longer serves)
        bgp = next(iter(await collection(app, f"{base}/bgp", domain)), None)
        neighbors = bgp_neighbors(bgp)
        if hop == "single_hop" and iface is not None:
            net = static_network(iface)
            here = [
                n
                for n in neighbors
                if net is not None and ipaddress.ip_address(str(n.get("ipv4Address"))) in net.network
            ]
            if remove:
                users = [
                    str(n.get("ipv4Address"))
                    for n in here
                    if fall_over(n) in ("SINGLE_HOP", "AUTO_DETECT_HOP")
                ]
                if users:
                    warnings.append(
                        f"BGP neighbor {', '.join(users)} keeps fall-over BFD but loses its BFD session: set "
                        "fmc_configure_bgp(neighbor=..., bfd='none') too."
                    )
            elif not here:
                warnings.append(
                    f"No BGP neighbor in {label}'s subnet: nothing uses this BFD session until a neighbor "
                    "there has fall-over BFD (fmc_configure_bgp(neighbor=..., bfd='single_hop'))."
                )
            else:
                for n in here:
                    fo = fall_over(n)
                    if fo == "NONE":
                        warnings.append(
                            f"BGP neighbor {n.get('ipv4Address')} has no fall-over BFD: set it with "
                            f"fmc_configure_bgp(neighbor='{n.get('ipv4Address')}', bfd='single_hop')."
                        )
                    elif fo == "MULTI_HOP":
                        warnings.append(
                            f"BGP neighbor {n.get('ipv4Address')} uses multi-hop fall-over BFD but is "
                            "directly connected: set bfd='single_hop' on it."
                        )
        elif hop == "multi_hop" and dst_obj is not None and not remove:
            dnet = object_net(dst_obj)
            if dnet is not None:
                direct_warned = False
                for n in neighbors:
                    a = ipaddress.IPv4Address(str(n.get("ipv4Address")))
                    if a not in dnet:
                        continue
                    direct = connected(items, a)
                    if direct is not None:
                        direct_warned = True
                        warnings.append(
                            f"BGP neighbor {a} is directly connected (on "
                            f"{direct.get('ifname') or direct.get('name')}): a multi-hop template on a "
                            "directly connected peer; use a single-hop policy on that interface instead."
                        )
                    elif fall_over(n) != "MULTI_HOP":
                        warnings.append(
                            f"BGP neighbor {a} has no multi-hop fall-over BFD: set it with "
                            f"fmc_configure_bgp(neighbor='{a}', bfd='multi_hop')."
                        )
                direct = connected(items, dnet.network_address) if dnet.num_addresses == 1 else None
                if direct is not None and not direct_warned:
                    warnings.append(
                        f"{dst_obj.get('name')} is directly connected (on "
                        f"{direct.get('ifname') or direct.get('name')}): multi-hop BFD is for peers several "
                        "hops away; use a single-hop policy on that interface."
                    )
        if not remove:
            warnings.append(
                "The peer must run BFD too (a matching interval/template and 'neighbor <this device> "
                "fall-over bfd'), or the session stays down."
            )

        async def apply() -> Any:
            done: list[str] = []
            new_id: str | None = None
            try:
                for name, method, path, body in steps:
                    sent = body
                    if body is not None and new_id and (body.get("template") or {}).get("id") == NEW_TEMPLATE:
                        sent = {**body, "template": {**body["template"], "id": new_id}}
                    try:
                        if method == "DELETE":
                            await app.api.delete(path)
                        elif method == "POST":
                            answer = await app.api.post(path, sent)
                            if name == "create bfd template":
                                new_id = answer.get("id") if isinstance(answer, dict) else None
                                if not new_id:
                                    raise UpstreamError("FMC answered the template create without an id.")
                        else:
                            await app.api.put(path, sent)
                    except Exception as e:
                        raise UpstreamError(
                            f"{name} failed ({e}); already applied: {done or 'nothing'}.",
                            getattr(e, "status_code", None),
                        ) from e
                    done.append(name)
            finally:
                app.invalidate_cache()
            return {
                "applied": done,
                "next": "fmc_deploy, then fmc_run_show_command('show bfd neighbors') and 'show bgp summary'",
            }

        shown = [
            {"step": n, "method": m, "path": p, **({"body": masked(b)} if b is not None else {})}
            for n, m, p, b in steps
        ]
        verb = "Remove" if remove else ("Change" if existing else "Add")
        return await fmc_preview(
            ctx,
            tool="fmc_configure_bfd",
            args={
                "device": device,
                "template": template,
                "hop": hop,
                "interface": interface,
                "source": source,
                "destination": destination,
                "min_tx_ms": min_tx_ms,
                "min_rx_ms": min_rx_ms,
                "multiplier": multiplier,
                "echo": echo,
                "auth_type": auth_type,
                "auth_key": auth_key,
                "auth_key_id": auth_key_id,
                "remove": remove,
                "virtual_router": virtual_router,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{verb} {hop.replace('_', '-')} BFD on {label} ({where})",
                details={
                    "steps": [s[0] for s in steps],
                    "policy": {"before": before, "after": after},
                    **(
                        {"template": {"before": tpl and template_row(tpl), "after": tpl_after}}
                        if not remove
                        else {}
                    ),
                    **({"warnings": warnings} if warnings else {}),
                }
                | ({} if blockers else {"requests": shown}),
                fingerprint={
                    "policies": [editable(p) for p in policies],
                    "template": tpl and editable(tpl),
                },
                blockers=blockers,
                side_effects=["Takes effect on the device after the next deployment."]
                + (["BGP neighbors using this BFD session fall back to the hold timer."] if remove else []),
            ),
            apply=apply,
        )
