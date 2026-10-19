"""Device templates (F51d): list and view templates, create one from a device or from parameters,
delete one, and apply one to a device (dangerous tier) so a new branch FTD gets its interfaces,
routing, policies and SD-WAN/VPN membership from one call. FMC 7.6+."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import ipaddress
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    TaskFailed,
    ToolRegistrar,
    UpstreamError,
    UpstreamTimeout,
    get_client,
    get_settings,
    list_result,
    object_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.rails import check_deploy_window, deploy_window_blockers
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, slim
from fmc_mcp.tools.dangerous import Wait, finish, task_id_of, wait_task
from fmc_mcp.tools.devices import CLUSTERS, DEVICES, HA_PAIRS, DeviceRef
from fmc_mcp.tools.policies import POLICY_KINDS

TEMPLATES = "templates/devicetemplates"
MASK = "********"
OVERRIDE_KINDS = {"Host": "hosts", "Network": "networks", "Range": "ranges", "FQDN": "fqdns"}
OBJECT_PATHS = {
    "Host": "object/hosts",
    "Network": "object/networks",
    "Range": "object/ranges",
    "FQDN": "object/fqdns",
}
FQDN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$")

TemplateRef = Annotated[str, Field(description="Device template name or UUID (fmc_list_device_templates)")]


def template_row(t: dict[str, Any]) -> dict[str, Any]:
    meta = t.get("metadata") or {}
    assoc = meta.get("templateAssociationInfo") or {}
    row = {
        "name": t.get("name"),
        "firewall_mode": t.get("firewallMode"),
        "access_policy": ref_label(t["accessPolicy"]) if t.get("accessPolicy") else None,
        "remote_branch": (t.get("initialConfig") or {}).get("isRemoteBranch"),
        "devices": assoc.get("associatedDevicesCount", assoc.get("count"))
        if isinstance(assoc, dict)
        else None,
        "locked": meta.get("isLocked"),
        "description": t.get("description"),
        "id": t.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def variable_row(v: dict[str, Any]) -> dict[str, Any]:
    secret = str(v.get("variableType")) == "PASSWORD"
    row = {
        "name": v.get("name"),
        "type": v.get("variableType"),
        "default": (MASK if v.get("value") else None) if secret else v.get("value"),
        "description": v.get("description"),
        "id": v.get("id"),
    }
    return {k: val for k, val in row.items() if val not in (None, "")}


def association_row(a: dict[str, Any], secret: set[str] | None = None) -> dict[str, Any]:
    """A device the template was applied to. Values of the PASSWORD variables named in `secret` are
    masked; with secret=None (variable types unknown) every value is."""
    values = {kv.get("key"): kv.get("value") for kv in a.get("variableValues") or []}
    row = {
        "device": ref_label(a.get("device") or {}),
        "last_applied": a.get("lastAppliedStatus"),
        "sync": a.get("syncStatus"),
        "last_applied_at": a.get("lastAppliedTimestamp"),
        "variables": {k: MASK if v and (secret is None or k in secret) else v for k, v in values.items()}
        or None,
        "device_id": (a.get("device") or {}).get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "", {})}


def _var_ref(v: Any) -> Any:
    """A VPN-setting field that holds a literal or {"variable": {...}}: show the variable by name."""
    if isinstance(v, dict) and isinstance(v.get("variable"), dict):
        return "${" + str(v["variable"].get("name")) + "}"
    if isinstance(v, dict) and v.get("name"):
        return v["name"]
    return v


def vpn_row(s: dict[str, Any]) -> dict[str, Any]:
    s2s = s.get("s2sVpnSettings") or {}
    conns = []
    for c in s.get("vpnConnections") or []:
        ident = c.get("localTunnelIdentity") or {}
        conns.append(
            {
                k: v
                for k, v in {
                    "interface": ref_label(c.get("vpnInterface") or {}) if c.get("vpnInterface") else None,
                    "ipv4": _var_ref(c.get("ipv4Address")),
                    "ipv6": _var_ref(c.get("ipv6Address")),
                    "local_identity": _var_ref(ident.get("localIdentityVariable"))
                    if ident.get("isLocalTunnelIdEnabled")
                    else None,
                }.items()
                if v not in (None, "")
            }
        )
    row = {
        "topology": ref_label(s2s["s2sVpn"]) if s2s.get("s2sVpn") else None,
        "topology_id": (s2s.get("s2sVpn") or {}).get("id"),
        "topology_type": s2s.get("topologyType"),
        "role": s2s.get("peerRole"),
        "connections": conns or None,
        "protected_networks": [ref_label(n) for n in s.get("protectedNetworks") or []] or None,
        "id": s.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "", [])}


_HINTS = {
    "AS_NUMBER": "an AS number (1-4294967295, or asdot like 65000.1)",
    "IPV4_HOST": "an IPv4 address (or address/prefix for an interface)",
    "ROUTER_ID": "an IPv4 address",
    "IPV6_HOST": "an IPv6 address (or address/prefix for an interface)",
    "IPV4_NETWORK": "an IPv4 network, e.g. 10.10.1.0/24",
    "IPV6_NETWORK": "an IPv6 network, e.g. 2001:db8:10::/64",
    "IPV4_RANGE": "a range low-high, e.g. 10.0.0.10-10.0.0.20",
    "HOST": "an IP address",
    "NETWORK": "a network, e.g. 10.10.1.0/24",
    "RANGE": "a range low-high, e.g. 10.0.0.10-10.0.0.20",
    "FQDN": "a host name such as branch1.example.com",
}
# Override object type -> the value check to use.
OVERRIDE_CHECK = {"Host": "HOST", "Network": "NETWORK", "Range": "RANGE", "FQDN": "FQDN"}


def _range(v: str) -> bool:
    lo, sep, hi = v.partition("-")
    if not sep:
        return False
    a, b = ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip())
    return a.version == b.version and int(a) <= int(b)


def _asn(v: str) -> bool:
    if re.fullmatch(r"\d+", v):
        return 1 <= int(v) <= 4294967295
    if re.fullmatch(r"\d+\.\d+", v):
        return all(0 <= int(p) <= 65535 for p in v.split("."))
    return False


_CHECKS: dict[str, Any] = {
    "AS_NUMBER": _asn,
    "IPV4_HOST": lambda v: bool(ipaddress.IPv4Interface(v)),
    "ROUTER_ID": lambda v: bool(ipaddress.IPv4Address(v)),
    "IPV6_HOST": lambda v: bool(ipaddress.IPv6Interface(v)),
    "IPV4_NETWORK": lambda v: bool(ipaddress.IPv4Network(v, strict=False)),
    "IPV6_NETWORK": lambda v: bool(ipaddress.IPv6Network(v, strict=False)),
    "IPV4_RANGE": _range,
    "HOST": lambda v: bool(ipaddress.ip_address(v)),
    "NETWORK": lambda v: bool(ipaddress.ip_network(v, strict=False)),
    "RANGE": _range,
    "FQDN": lambda v: bool(FQDN_RE.match(v)),
}


def check_value(kind: str, value: str) -> str | None:
    """Why `value` is not valid for a template variable (or override object) of `kind`, or None.
    STRING and PASSWORD only need to be non-empty."""
    v = value.strip()
    if not v:
        return "a non-empty value"
    check = _CHECKS.get(kind.upper())
    if check is None:
        return None
    try:
        ok = check(v)
    except ValueError:
        ok = False
    return None if ok else _HINTS[kind.upper()]


async def resolve_template(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, TEMPLATES, ref, "device template", domain)


async def template_with_metadata(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    """The template with FMC's add-on metadata (validation messages, other policies, device count)."""
    t = await resolve_template(app, ref, domain)
    full: dict[str, Any] = await app.api.get(
        await app.config_path(f"{TEMPLATES}/{t['id']}", domain), {"addOnMetadata": "true"}
    )
    return {**t, **(full or {})}


async def _items(app: FmcApp, path: str) -> list[dict[str, Any]]:
    return list((await app.all(path, cap=2000)).items)


async def vpn_settings(app: FmcApp, base: str) -> list[dict[str, Any]]:
    """The template's VPN settings; the list may hold bare references, so fetch those one by one."""
    rows = []
    for r in await _items(app, f"{base}/vpnsettings"):
        full = r if r.get("s2sVpnSettings") else await app.api.get(f"{base}/vpnsettings/{r['id']}")
        rows.append(vpn_row(full))
    return rows


async def declared_overrides(app: FmcApp, base: str, tid: str) -> list[dict[str, Any]]:
    data = await app.api.get(f"{base}/objectoverrides/{tid}")
    return list((data or {}).get("declaredObjectOverrides") or [])


async def template_detail(app: FmcApp, t: dict[str, Any], domain: str | None) -> dict[str, Any]:
    base = await app.config_path(f"{TEMPLATES}/{t['id']}", domain)
    out: dict[str, Any] = {**template_row(t)}
    msgs = (t.get("metadata") or {}).get("templateValidationMessages") or []
    if msgs:
        out["validation"] = slim(msgs)
    others = (t.get("metadata") or {}).get("otherAssociatedPolicies") or []
    if others:
        out["other_policies"] = [f"{ref_label(p)} ({p.get('type')})" for p in others]

    async def section(key: str, fetch: Any) -> None:
        try:
            out[key] = await fetch()
        except (NotFound, UpstreamError) as e:
            out[key] = {"error": str(e)}

    async def interfaces() -> list[dict[str, Any]]:
        rows = await _items(app, f"{base}/templateinterfaces")
        return [
            {
                k: v
                for k, v in {
                    "name": i.get("name"),
                    "logical_name": i.get("ifname"),
                    "enabled": i.get("enabled"),
                    "mode": i.get("mode"),
                    "zone": ref_label(i["securityZone"]) if i.get("securityZone") else None,
                    "ipv4": _var_ref((i.get("ipv4") or {}).get("static")) if i.get("ipv4") else None,
                    "state": (i.get("metadata") or {}).get("state"),
                    "id": i.get("id"),
                }.items()
                if v not in (None, "")
            }
            for i in rows
        ]

    async def variables() -> list[dict[str, Any]]:
        rows = await _items(app, f"{base}/variables")
        secret.update(str(v.get("name")) for v in rows if str(v.get("variableType")) == "PASSWORD")
        return [variable_row(v) for v in rows]

    async def models() -> list[dict[str, Any]]:
        rows = await _items(app, f"{base}/modelmappings")
        return [
            {
                "name": m.get("name"),
                "model": (m.get("metadata") or {}).get("modelName"),
                "valid": (m.get("metadata") or {}).get("validationState"),
                "interfaces": {
                    x.get("templateInterface"): x.get("modelInterface")
                    for x in m.get("interfaceMappings") or []
                },
                "id": m.get("id"),
            }
            for m in rows
        ]

    async def overrides() -> list[dict[str, Any]]:
        return [
            {"name": o.get("name"), "type": o.get("type"), "id": o.get("id")}
            for o in await declared_overrides(app, base, t["id"])
        ]

    secret: set[str] = set()

    async def devices() -> list[dict[str, Any]]:
        known = isinstance(out.get("variables"), list)  # else the variable types are unknown: mask all
        rows = await _items(app, f"{base}/associations")
        return [association_row(a, secret if known else None) for a in rows]

    await section("interfaces", interfaces)
    await section("variables", variables)
    await section("model_mappings", models)
    await section("vpn_settings", lambda: vpn_settings(app, base))
    await section("object_overrides", overrides)
    await section("devices", devices)
    return out


async def _standalone(app: FmcApp, dev: dict[str, Any], domain: str | None) -> str | None:
    """Why the device can't take a template (an HA or cluster member), or None."""
    pairs = await app.all(await app.config_path(HA_PAIRS, domain))
    for h in pairs.items:
        if dev["id"] in {(h.get("primary") or {}).get("id"), (h.get("secondary") or {}).get("id")}:
            return f"{dev.get('name')!r} is a member of HA pair {h.get('name')!r}"
    try:
        clusters = await app.all(await app.config_path(CLUSTERS, domain))
    except UpstreamError:
        return None
    for c in clusters.items:
        members = [c.get("controlDevice") or {}, *(c.get("dataDevices") or [])]
        ids = {(m.get("deviceDetails") or m).get("id") for m in members}
        if dev["id"] in ids:
            return f"{dev.get('name')!r} is a member of cluster {c.get('name')!r}"
    return None


async def _find_by_name(app: FmcApp, name: str, domain: str | None) -> dict[str, Any] | None:
    page = await app.all(await app.config_path(TEMPLATES, domain), cap=2000)
    return next((t for t in page.items if str(t.get("name", "")).lower() == name.lower()), None)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List device templates")
    async def fmc_list_device_templates(
        ctx: Context,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Device templates (FMC 7.6+): name, firewall mode, access policy, how many devices use each,
        and whether it is locked. A template carries a branch's interfaces, routing, policies and
        SD-WAN/VPN membership with variables per branch. Details: fmc_get_device_template; onboard a
        branch with fmc_apply_device_template."""
        app: FmcApp = get_client(ctx)
        page = await app.all(await app.config_path(TEMPLATES, domain), {"addOnMetadata": "true"}, cap=2000)
        rows = [template_row(t) for t in page.items]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Get device template")
    async def fmc_get_device_template(ctx: Context, template: TemplateRef, domain: Domain = None) -> Any:
        """One device template in full: firewall mode, access policy and the other policies it
        assigns (NAT, platform settings, health, S2S VPN...), validation messages, template
        interfaces (logical names, zones, addresses or ${variables}), variables (type and default;
        passwords masked), model mappings (template interface -> model interface per FTD model), VPN
        settings (SD-WAN/S2S topology, hub or spoke role, tunnel interfaces and addresses),
        overridable objects, and the devices it was applied to with the last apply and sync status.
        Use it before fmc_apply_device_template to see which variables a branch needs. About 7 FMC
        requests."""
        app: FmcApp = get_client(ctx)
        t = await template_with_metadata(app, template, domain)
        return object_result(await template_detail(app, t, domain), shape=False)

    @reg.write(title="Create device template")
    async def fmc_create_device_template(
        ctx: Context,
        name: Annotated[str, Field(description="New template name", min_length=1, max_length=64)],
        source_device: Annotated[
            str | None,
            Field(
                description="Generate the template from this standalone FTD (name/UUID): its interfaces, "
                "routing, policies and VPN membership, FMC's 'generatetemplate'. Omit to create an empty "
                "template from the parameters"
            ),
        ] = None,
        access_policy: Annotated[
            str | None,
            Field(
                description="Access control policy (name/UUID). Required without source_device; with one, "
                "replaces the device's access policy in the generated template"
            ),
        ] = None,
        firewall_mode: Annotated[
            Literal["ROUTED", "TRANSPARENT"], Field(description="Firewall mode (parameters only)")
        ] = "ROUTED",
        description: Annotated[str | None, Field(description="Template description", max_length=255)] = None,
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a device template. From a device (source_device): FMC copies a working branch's
        configuration into a template (a background task; with wait, polls it), the usual way to
        roll out more branches like it. From parameters: an empty template with the firewall mode and
        access policy, to fill in FMC's template editor or with fmc_api_call. Doesn't change any
        device. Then fmc_get_device_template (check variables and interfaces) and
        fmc_apply_device_template."""
        app: FmcApp = get_client(ctx)
        if not source_device and not access_policy:
            raise InvalidRequest(
                "Give source_device (generate from a device) or access_policy (from parameters)."
            )
        blockers: list[str] = []
        if await _find_by_name(app, name, domain):
            blockers.append(f"A device template named {name!r} already exists.")
        acp = None
        if access_policy:
            acp = await resolve_in(app, POLICY_KINDS["access"], access_policy, "access policy", domain)
        details: dict[str, Any] = {"name": name}
        fingerprint: dict[str, Any] = {"acp": acp and acp.get("id")}
        side_effects: list[str] = ["No device changes: a template only takes effect when applied."]
        if source_device:
            dev = await resolve_in(app, DEVICES, source_device, "device", domain)
            why = await _standalone(app, dev, domain)
            if why:
                blockers.append(f"{why}: FMC generates templates from standalone devices only.")
            body: dict[str, Any] = {"name": name, "source": {"id": dev["id"], "type": "Device"}}
            if description:
                body["description"] = description
            if acp:
                body["accessPolicy"] = {"id": acp["id"], "type": "AccessPolicy"}
            path = await app.config_path(f"{TEMPLATES}/operational/generatetemplate", domain)
            details.update(
                {
                    "from_device": {k: dev.get(k) for k in ("name", "model", "sw_version", "ftdMode", "id")},
                    "access_policy": acp.get("name") if acp else ref_label(dev.get("accessPolicy") or {}),
                    "body": body,
                }
            )
            fingerprint["device"] = dev["id"]
            side_effects.append(
                "FMC turns the device's interface addresses and similar per-device values into template "
                "variables; review them with fmc_get_device_template before applying."
            )
            summary = f"Generate device template {name!r} from {dev.get('name')!r}"
        else:
            assert acp is not None
            body = {
                "name": name,
                "type": "DeviceTemplate",
                "firewallMode": firewall_mode,
                "accessPolicy": {"id": acp["id"], "type": "AccessPolicy"},
            }
            if description:
                body["description"] = description
            path = await app.config_path(TEMPLATES, domain)
            details.update({"access_policy": acp.get("name"), "body": body})
            summary = f"Create device template {name!r} ({firewall_mode}, access policy {acp.get('name')!r})"

        async def apply() -> Any:
            resp = await app.api.post(path, body)
            app.invalidate_cache()
            if not source_device:
                return {
                    "template": template_row(resp),
                    "next": "fmc_get_device_template, fmc_apply_device_template",
                }
            tid = task_id_of(resp)
            if tid is None or not wait:
                return {
                    "task_id": tid,
                    "note": "Generation started; check it with fmc_get_task, then fmc_get_device_template.",
                }
            try:
                task = await wait_task(ctx, app, tid, domain, "device template generation")
            except (UpstreamTimeout, TaskFailed) as e:
                raise type(e)(
                    f"{e} The request was submitted as task {tid}; check it with fmc_get_task."
                ) from e
            app.invalidate_cache()
            made = await _find_by_name(app, name, domain)
            return {
                "task_id": tid,
                "task": task,
                "template": template_row(made) if made else None,
                "next": "Check the variables FMC created with fmc_get_device_template, then "
                "fmc_apply_device_template on the new branch.",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_create_device_template",
            args={
                "name": name,
                "source_device": source_device,
                "access_policy": access_policy,
                "firewall_mode": firewall_mode,
                "description": description,
                "wait": wait,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                summary,
                details=details,
                fingerprint=fingerprint,
                blockers=blockers,
                side_effects=side_effects,
            ),
            apply=apply,
        )

    @reg.write(title="Delete device template", destructive=True)
    async def fmc_delete_device_template(
        ctx: Context, template: TemplateRef, domain: Domain = None, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Delete a device template. Devices it was applied to keep their configuration; they only
        lose the link to the template (fmc_get_device_template lists them first)."""
        app: FmcApp = get_client(ctx)
        t = await resolve_template(app, template, domain)
        base = await app.config_path(f"{TEMPLATES}/{t['id']}", domain)
        try:
            devices = [association_row(a) for a in await _items(app, f"{base}/associations")]
        except UpstreamError:
            devices = []
        side = ["Devices keep the configuration the template gave them."]
        if devices:
            side.append(
                f"{len(devices)} device(s) lose their template link: "
                + ", ".join(d["device"] for d in devices)
            )

        async def apply() -> Any:
            await app.api.delete(base)
            app.invalidate_cache()
            return {"deleted": t.get("name"), "id": t.get("id")}

        return await fmc_preview(
            ctx,
            tool="fmc_delete_device_template",
            owned=[t],
            args={"template": template, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete device template {t.get('name')!r}",
                details={"template": template_row(t), "devices": devices},
                fingerprint={"id": t.get("id"), "devices": [d.get("device_id") for d in devices]},
                side_effects=side,
            ),
            apply=apply,
        )

    @reg.dangerous(title="Apply device template")
    async def fmc_apply_device_template(
        ctx: Context,
        template: TemplateRef,
        device: DeviceRef,
        variables: Annotated[
            dict[str, str] | None,
            Field(
                description="Template variable values for this device, by variable name "
                "(fmc_get_device_template lists them), e.g. {'insideIp': '10.10.1.1/24', 'bgpAs': '65001'}. "
                "Variables left out keep the template's default"
            ),
        ] = None,
        overrides: Annotated[
            dict[str, str] | None,
            Field(
                description="Per-device values for the template's overridable host/network/range/FQDN "
                "objects, by object name, e.g. {'branch-lan': '10.10.1.0/24'}"
            ),
        ] = None,
        deploy: Annotated[
            bool, Field(description="Deploy the device right after the template is applied")
        ] = False,
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Apply a device template to one standalone FTD: FMC REPLACES the device's interfaces,
        routing, policy assignments and VPN/SD-WAN membership with the template's, filled in with
        this device's variable values and object overrides. This is how a freshly registered branch
        joins an SD-WAN topology in one call. The preview lists every variable (value given or
        template default, passwords masked) and every overridable object, the device's current
        template, and model-mapping and firewall-mode checks; unknown, missing or malformed values
        block it. With deploy, FMC deploys afterwards; otherwise fmc_pending_changes then fmc_deploy.
        With wait, polls the apply task."""
        app: FmcApp = get_client(ctx)
        t = await template_with_metadata(app, template, domain)
        base = await app.config_path(f"{TEMPLATES}/{t['id']}", domain)
        dev = await resolve_in(app, DEVICES, device, "device", domain)
        given = {str(k).strip(): str(v) for k, v in (variables or {}).items()}
        wanted = {str(k).strip(): str(v) for k, v in (overrides or {}).items()}
        blockers: list[str] = []
        side_effects = [
            f"Replaces {dev.get('name')!r}'s interface, routing, policy and VPN configuration in FMC with "
            "the template's; settings the template doesn't carry are kept.",
        ]

        why = await _standalone(app, dev, domain)
        if why:
            blockers.append(f"{why}: FMC applies templates to standalone devices only.")
        if t.get("firewallMode") and dev.get("ftdMode") and t["firewallMode"] != dev["ftdMode"]:
            blockers.append(
                f"Template {t.get('name')!r} is {t['firewallMode']} but {dev.get('name')!r} runs "
                f"{dev['ftdMode']}: FMC can't change the firewall mode by template."
            )
        for m in (t.get("metadata") or {}).get("templateValidationMessages") or []:
            sev = str(m.get("severity") or m.get("type") or "").upper()
            if sev in ("ERROR", "CRITICAL"):
                blockers.append(f"Template validation error: {m.get('message') or m.get('description') or m}")

        tvars = await _items(app, f"{base}/variables")
        by_name = {str(v.get("name")): v for v in tvars}
        secret_names = {n for n, v in by_name.items() if str(v.get("variableType")) == "PASSWORD"}
        unknown = sorted(set(given) - set(by_name))
        if unknown:
            blockers.append(
                f"Template {t.get('name')!r} has no variable(s) {', '.join(unknown)}; it has: "
                + (", ".join(sorted(by_name)) or "none")
            )
        var_rows = []
        for n, v in sorted(by_name.items()):
            kind = str(v.get("variableType") or "STRING")
            secret = n in secret_names
            if n in given:
                problem = check_value(kind, given[n])
                if problem:
                    shown = MASK if secret else given[n]
                    blockers.append(f"Variable {n} ({kind}) = {shown!r} is not {problem}.")
                value, source = given[n], "given"
            elif v.get("value") not in (None, ""):
                value, source = str(v["value"]), "template default"
            else:
                value, source = None, "missing"
                blockers.append(f"Variable {n} ({kind}) has no template default: give it in variables.")
            var_rows.append(
                {
                    "name": n,
                    "type": kind,
                    "value": MASK if secret and value else value,
                    "source": source,
                    **(
                        {"default": MASK if secret else v.get("value")}
                        if source == "given" and v.get("value")
                        else {}
                    ),
                }
            )

        declared = await declared_overrides(app, base, t["id"])
        decl_by_name = {str(o.get("name")): o for o in declared}
        unknown_o = sorted(set(wanted) - set(decl_by_name))
        if unknown_o:
            blockers.append(
                f"Template {t.get('name')!r} has no overridable object(s) {', '.join(unknown_o)}; it has: "
                + (", ".join(sorted(decl_by_name)) or "none")
            )
        override_rows = []
        overridden: dict[str, list[dict[str, Any]]] = {}
        for n, o in sorted(decl_by_name.items()):
            kind = str(o.get("type") or "")
            current = o.get("value")
            if current is None and kind in OBJECT_PATHS and o.get("id"):
                try:
                    obj = await app.api.get(await app.config_path(f"{OBJECT_PATHS[kind]}/{o['id']}", domain))
                    current = (obj or {}).get("value")
                except UpstreamError:
                    current = None
            row: dict[str, Any] = {"name": n, "type": kind, "current": current}
            if n in wanted:
                problem = check_value(OVERRIDE_CHECK.get(kind, "STRING"), wanted[n])
                if kind not in OVERRIDE_KINDS:
                    blockers.append(
                        f"Object {n} is a {kind}; only host, network, range and FQDN objects can be "
                        "overridden."
                    )
                elif problem:
                    blockers.append(f"Override {n} ({kind}) = {wanted[n]!r} is not {problem}.")
                else:
                    overridden.setdefault(OVERRIDE_KINDS[kind], []).append(
                        {"name": n, "id": o.get("id"), "type": kind, "value": wanted[n].strip()}
                    )
                row["value"] = wanted[n]
            else:
                row["value"] = "keep (template object's value)"
            override_rows.append(row)

        try:
            models = await _items(app, f"{base}/modelmappings")
        except UpstreamError:
            models = []
        model_names = [str((m.get("metadata") or {}).get("modelName") or m.get("name")) for m in models]
        if models and dev.get("model") and dev["model"] not in model_names:
            side_effects.append(
                f"No model mapping for {dev['model']!r} (the template maps {', '.join(model_names)}); FMC "
                "uses its default mapping for this model: check the interfaces with fmc_pending_changes."
            )
        try:
            current = [
                association_row(a, secret_names)
                for a in await _items(app, f"{base}/associations")
                if (a.get("device") or {}).get("id") == dev["id"]
            ]
        except UpstreamError:
            current = []
        try:
            vpns = await vpn_settings(app, base)
        except UpstreamError:
            vpns = []
        for s in vpns:
            if s.get("topology"):
                side_effects.append(
                    f"Adds {dev.get('name')!r} to VPN topology {s['topology']!r}"
                    + (f" as {s['role']}" if s.get("role") else "")
                    + "; the hub(s) need a deploy too."
                )
        if deploy:
            side_effects.append(
                f"FMC deploys {dev.get('name')!r} right after applying (postApplyAction=DEPLOY)."
            )
        else:
            side_effects.append(
                "Nothing reaches the device until it is deployed (fmc_pending_changes, fmc_deploy)."
            )
        window, window_blockers = deploy_window_blockers(get_settings(ctx), "fmc_apply_device_template")
        blockers += window_blockers

        entry: dict[str, Any] = {
            "device": {"id": dev["id"], "type": "Device"},
            "variableValues": [{"key": k, "value": given[k].strip()} for k in sorted(given)],
            "postApplyAction": "DEPLOY" if deploy else "NOACTION",
        }
        if overridden:
            entry["overriddenValues"] = overridden
        body = {"applyToDevices": [entry]}
        shown_body = {
            "applyToDevices": [
                {
                    **entry,
                    "variableValues": [
                        {"key": kv["key"], "value": MASK if kv["key"] in secret_names else kv["value"]}
                        for kv in entry["variableValues"]
                    ],
                }
            ]
        }
        secrets = [given[n] for n in secret_names if given.get(n)]

        def scrub(text: str) -> str:
            for s in secrets:
                text = text.replace(s, MASK)
            return text

        async def apply() -> Any:
            check_deploy_window(get_settings(ctx), "fmc_apply_device_template")
            try:
                resp = await app.api.post(f"{base}/operational/apply", body)
                result = await finish(ctx, app, resp, wait, domain, "device template apply")
            except (UpstreamError, UpstreamTimeout, TaskFailed) as e:
                raise type(e)(scrub(str(e))) from None
            if isinstance(result, dict) and wait:
                with contextlib.suppress(UpstreamError):
                    result["association"] = [
                        association_row(a, secret_names)
                        for a in await _items(app, f"{base}/associations")
                        if (a.get("device") or {}).get("id") == dev["id"]
                    ]
                result["next"] = (
                    "fmc_get_device (connected), fmc_list_device_interfaces, then "
                    + ("fmc_list_deployments" if deploy else "fmc_pending_changes and fmc_deploy")
                    + "; for SD-WAN, fmc_get_vpn_topology and fmc_list_vpn_tunnels."
                )
            return result

        return await fmc_preview(
            ctx,
            tool="fmc_apply_device_template",
            owned=[t],
            args={
                "template": template,
                "device": device,
                "variables": variables,
                "overrides": overrides,
                "deploy": deploy,
                "wait": wait,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Apply device template {t.get('name')!r} to {dev.get('name')!r}"
                + (" and deploy" if deploy else ""),
                details={
                    "template": template_row(t),
                    "device": {k: dev.get(k) for k in ("name", "model", "sw_version", "ftdMode", "id")},
                    "current_template": current or None,
                    "variables": var_rows,
                    "object_overrides": override_rows,
                    "vpn_settings": vpns or None,
                    "body": shown_body,
                    **({"deploy_window": window} if window else {}),
                },
                fingerprint={
                    "template": t.get("id"),
                    "stamp": (t.get("metadata") or {}).get("timestamp"),
                    "device": dev["id"],
                    "vars": sorted(
                        (n, None if n in secret_names else str(v.get("value"))) for n, v in by_name.items()
                    ),
                    "overrides": sorted(decl_by_name),
                },
                blockers=blockers,
                blast_radius=1,
                side_effects=side_effects,
            ),
            apply=apply,
        )
