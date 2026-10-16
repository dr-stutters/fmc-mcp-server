"""Policy tools: access control (flattened rules), NAT, prefilter, other policy lists, assignments."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from collections import Counter
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import InvalidRequest, ResponseFormat, ToolRegistrar, get_client, list_result
from fmc_mcp._core.http import Page, page_of
from fmc_mcp.catalog import Catalog, ip_contains
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.rules import flatten_access_rule, flatten_nat_rule, flatten_prefilter_rule
from fmc_mcp.tools.common import Domain, pick_by_name, ref_label, resolve_in, slim

ACCESS = "policy/accesspolicies"
NAT = "policy/ftdnatpolicies"
PREFILTER = "policy/prefilterpolicies"
RULE_CAP = 10_000

POLICY_KINDS: dict[str, str] = {
    "access": ACCESS,
    "nat": NAT,
    "prefilter": PREFILTER,
    "intrusion": "policy/intrusionpolicies",
    "network_analysis": "policy/networkanalysispolicies",
    "file": "policy/filepolicies",
    "dns": "policy/dnspolicies",
    "identity": "policy/identitypolicies",
    "decryption": "policy/decryptionpolicies",
    "platform_settings": "policy/ftdplatformsettingspolicies",
    "health": "policy/healthpolicies",
    "flexconfig": "policy/flexconfigpolicies",
    "remote_access_vpn": "policy/ravpns",
    "site_to_site_vpn": "policy/ftds2svpns",
}
PolicyKind = Literal[
    "access",
    "nat",
    "prefilter",
    "intrusion",
    "network_analysis",
    "file",
    "dns",
    "identity",
    "decryption",
    "platform_settings",
    "health",
    "flexconfig",
    "remote_access_vpn",
    "site_to_site_vpn",
]

# Access-rule table columns in display order; empty ones are left out (see rule_columns).
RULE_COLUMNS = [
    "index",
    "section",
    "category",
    "name",
    "action",
    "enabled",
    "src_zones",
    "dst_zones",
    "src_networks",
    "dst_networks",
    "src_dynamic",
    "dst_dynamic",
    "src_ports",
    "dst_ports",
    "applications",
    "urls",
    "users",
    "vlan_tags",
    "src_sgts",
    "dst_sgts",
    "time_ranges",
    "intrusion_policy",
    "file_policy",
]
_ALWAYS = ("index", "name", "action", "enabled")


def rule_columns(rows: list[dict[str, Any]], order: list[str] = RULE_COLUMNS) -> list[str]:
    """The columns that carry a value in at least one row (a missing condition means 'any')."""
    return [c for c in order if c in _ALWAYS or any(r.get(c) not in (None, "", []) for r in rows)]


NAT_COLUMNS = [
    "section",
    "index",
    "kind",
    "nat_type",
    "enabled",
    "src_interface",
    "dst_interface",
    "original_source",
    "translated_source",
    "original_destination",
    "translated_destination",
    "service",
    "description",
]

PolicyRef = Annotated[str, Field(description="Policy name or UUID (from the matching list tool)")]
# NAT rule address fields (auto and manual) -> flattened row key.
NAT_ADDRESS_FIELDS = {
    "originalNetwork": "original_source",
    "translatedNetwork": "translated_source",
    "originalSource": "original_source",
    "translatedSource": "translated_source",
    "originalDestination": "original_destination",
    "translatedDestination": "translated_destination",
}


async def nat_policy_of(app: FmcApp, device_id: str, domain: str | None) -> str | None:
    """Id of the NAT policy assigned to a device (policy assignments)."""
    page = await app.all(await app.config_path("assignment/policyassignments", domain), cap=2000)
    for a in page.items:
        pol = a.get("policy") or {}
        if pol.get("type") != "FTDNatPolicy":
            continue
        if any(t.get("id") == device_id for t in a.get("targets") or []):
            return str(pol.get("id"))
    return None


def policy_row(p: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {"name": p.get("name"), "type": p.get("type")}
    if p.get("description"):
        row["description"] = p["description"]
    da = p.get("defaultAction")
    if isinstance(da, dict) and da.get("action"):
        row["default_action"] = da["action"]
    if p.get("inspectionMode"):
        row["inspection_mode"] = p["inspectionMode"]
    if p.get("isSystemDefined") is not None:
        row["system_defined"] = p["isSystemDefined"]
    if p.get("topologyType"):
        row["topology"] = p["topologyType"]
    usage = (p.get("metadata") or {}).get("usage")
    if isinstance(usage, dict):
        row["usage"] = usage
    row["id"] = p.get("id")
    return row


async def all_rules(app: FmcApp, path: str) -> Page:
    return await app.all(path, cap=RULE_CAP)


def acp_settings_body(acp: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """An access policy as FMC accepts it back in a settings PUT: every setting it has (default action,
    prefilter / decryption / identity links, logging, EVE, ...) but not the rule or category collections
    or link-only blocks, which make FMC treat the PUT as a bulk rule update (422)."""
    body: dict[str, Any] = {}
    for key, value in acp.items():
        if key in ("metadata", "links", "rules", "categories"):
            continue
        if isinstance(value, dict) and ("refType" in value or set(value) <= {"links"}):
            continue
        if isinstance(value, dict):
            value = {k: v for k, v in value.items() if k != "links"}
        body[key] = value
    body.update(overrides)
    return body


async def resolve_policy(app: FmcApp, kind: str, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, POLICY_KINDS[kind], ref, f"{kind} policy", domain)


def _rule_filter(
    rows: list[dict[str, Any]],
    *,
    text: str | None,
    action: str | None,
    enabled: bool | None,
    section: str | None = None,
) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        if action and str(r.get("action", "")).upper() != action.upper():
            continue
        if enabled is not None and bool(r.get("enabled", True)) is not enabled:
            continue
        if section and str(r.get("section", "")).lower() != section.lower():
            continue
        if text and text.lower() not in str({k: v for k, v in r.items() if k != "id"}).lower():
            continue
        out.append(r)
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List policies")
    async def fmc_list_policies(
        ctx: Context,
        kind: Annotated[PolicyKind, Field(description="Which policy type to list")] = "access",
        name: Annotated[str | None, Field(description="Filter: name contains (case-insensitive)")] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List FMC policies of one kind: access control, NAT, prefilter, intrusion, network
        analysis, file, DNS, identity, decryption, platform settings, health, FlexConfig, RA VPN or
        site-to-site VPN. Shows name, default action / inspection mode where relevant, and id.
        Drill into access policies with fmc_get_access_policy and fmc_list_access_rules."""
        app: FmcApp = get_client(ctx)
        path = await app.config_path(POLICY_KINDS[kind], domain)
        if name:
            page = await app.all(path, cap=5000)
            rows = [policy_row(p) for p in page.items if name.lower() in str(p.get("name", "")).lower()]
            return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)
        page = await app.page(path, limit=limit, offset=offset)
        page.items = [policy_row(p) for p in page.items]
        return list_result(page, fmt=response_format)

    @reg.read(title="Get access control policy")
    async def fmc_get_access_policy(
        ctx: Context,
        policy: PolicyRef,
        include_rules: Annotated[
            bool,
            Field(description="Also return the flattened rules (up to 200; page with fmc_list_access_rules)"),
        ] = False,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Summarise an access control policy: default action (and its intrusion policy), parent
        (inheritance), prefilter policy, the devices it is assigned to, and rule counts by section and
        action. With include_rules, also returns rules flattened to one row each with zones, networks,
        ports, applications and URLs shown by name."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        rules = await all_rules(app, await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain))
        flat = [flatten_access_rule(r) for r in rules.items]
        da = p.get("defaultAction") or {}
        out: dict[str, Any] = {
            "name": p.get("name"),
            "id": p.get("id"),
            "description": p.get("description"),
            "default_action": da.get("action"),
            "default_intrusion_policy": ref_label(da["intrusionPolicy"])
            if da.get("intrusionPolicy")
            else None,
            "parent_policy": ref_label((p.get("metadata") or {}).get("parentPolicy"))
            if (p.get("metadata") or {}).get("parentPolicy")
            else None,
            "prefilter_policy": ref_label(p["prefilterPolicySetting"])
            if p.get("prefilterPolicySetting")
            else None,
            "decryption_policy": ref_label(p["decryptionPolicySetting"])
            if p.get("decryptionPolicySetting")
            else None,
            "identity_policy": ref_label(p["identityPolicySetting"])
            if p.get("identityPolicySetting")
            else None,
            "rules": {
                "total": len(flat),
                "enabled": sum(1 for r in flat if r.get("enabled") is not False),
                "by_section": dict(Counter(str(r.get("section")) for r in flat)),
                "by_action": dict(Counter(str(r.get("action")) for r in flat)),
            },
            "assigned_to": await _assigned_devices(app, p["id"], domain),
        }
        if not rules.complete:
            out["rules"]["note"] = (
                f"Policy has more than {RULE_CAP} rules; counts cover the first {RULE_CAP}."
            )
        if include_rules:
            out["rule_list"] = flat[:200]
            if len(flat) > 200:
                out["rule_list_note"] = "First 200 rules; use fmc_list_access_rules with offset for more."
        return {k: v for k, v in out.items() if v is not None}

    @reg.read(title="List access rules")
    async def fmc_list_access_rules(
        ctx: Context,
        policy: PolicyRef,
        text: Annotated[
            str | None,
            Field(description="Filter: any field contains this text (rule name, object name, zone, app...)"),
        ] = None,
        action: Annotated[
            str | None, Field(description="Filter by action: ALLOW, TRUST, BLOCK, BLOCK_RESET, MONITOR, ...")
        ] = None,
        enabled: Annotated[
            bool | None, Field(description="Filter: only enabled (true) or disabled (false)")
        ] = None,
        section: Annotated[
            Literal["mandatory", "default"] | None, Field(description="Filter by rule section")
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List an access control policy's rules in evaluation order, one row per rule: index,
        section, category, name, action, enabled, source/destination zones, networks, dynamic objects
        and ports, applications, URLs, users, intrusion/file policy, with objects shown by name. An
        empty condition means 'any'; columns no rule uses are left out. Full detail for one rule:
        fmc_get_access_rule."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        path = await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain)
        extra = {"policy": p.get("name")}
        if not any((text, action, enabled is not None, section)):
            page = await app.page(path, limit=limit, offset=offset)
            page.items = [flatten_access_rule(r) for r in page.items]
            return list_result(page, fmt=response_format, extra=extra, columns=rule_columns(page.items))
        rules = await all_rules(app, path)
        rows = _rule_filter(
            [flatten_access_rule(r) for r in rules.items],
            text=text,
            action=action,
            enabled=enabled,
            section=section,
        )
        if not rules.complete:
            extra["note"] = f"Searched only the first {RULE_CAP} rules."
        shown = page_of(rows, limit=limit, offset=offset)
        return list_result(shown, fmt=response_format, extra=extra, columns=rule_columns(shown.items))

    @reg.read(title="Get access rule")
    async def fmc_get_access_rule(
        ctx: Context,
        policy: PolicyRef,
        rule: Annotated[str, Field(description="Rule name, UUID, or 1-based rule index")],
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Get one access rule in full (all conditions with object names and ids, logging, comments,
        intrusion/file policy, variable set) plus its flattened summary."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        r = await find_access_rule(app, p, rule, domain)
        return {"summary": flatten_access_rule(r), "rule": slim(r)}

    @reg.read(title="List NAT rules")
    async def fmc_list_nat_rules(
        ctx: Context,
        policy: Annotated[
            str | None, Field(description="NAT policy name or UUID; default: the one assigned to `device`")
        ] = None,
        device: Annotated[str | None, Field(description="Device name or UUID: list its NAT policy")] = None,
        address: Annotated[
            str | None,
            Field(
                description="Only rules whose original or translated source/destination contains this IP "
                "(objects and groups are resolved), e.g. 10.99.1.10"
            ),
        ] = None,
        text: Annotated[str | None, Field(description="Filter: any field contains this text")] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List a Threat Defense NAT policy's rules in order (manual 'before auto', auto NAT, manual
        'after auto'): kind, static/dynamic, interfaces, original and translated source, destination
        and ports, options. 'What NAT applies to 10.99.1.10?': device=<ftd>, address=10.99.1.10
        (a rule for a subnet or group containing the host matches; values are shown next to object
        names). NAT policies come from fmc_list_policies(kind='nat')."""
        app: FmcApp = get_client(ctx)
        if not policy:
            if not device:
                raise InvalidRequest("Give the NAT policy (policy=...) or the device (device=...).")
            dev = await resolve_in(app, "devices/devicerecords", device, "device", domain)
            assigned = await nat_policy_of(app, str(dev["id"]), domain)
            if assigned is None:
                raise InvalidRequest(f"{dev.get('name')} has no NAT policy assigned.")
            policy = assigned
        p = await resolve_policy(app, "nat", policy, domain)
        page = await all_rules(app, await app.config_path(f"{NAT}/{p['id']}/natrules", domain))
        order = {"BEFORE_AUTO": 0, "AUTO": 1, "AFTER_AUTO": 2}
        raw = list(page.items)
        if address:
            try:
                ip = ipaddress.ip_address(address.strip())
            except ValueError:
                raise InvalidRequest(f"address must be one IP address, got {address!r}") from None
            cat = Catalog(app, domain)
            await cat.load_networks()
            want: list[tuple[int, int, int]] = [(ip.version, int(ip), int(ip))]
            kept = []
            for r in raw:
                for f in NAT_ADDRESS_FIELDS:
                    nets = cat.networks(r[f]) if r.get(f) else None
                    if nets and ip_contains(nets, want):
                        kept.append(r)
                        break
            raw = kept
        rows = [flatten_nat_rule(r) for r in raw]
        if address:
            for r, row in zip(raw, rows, strict=True):
                for f, key in NAT_ADDRESS_FIELDS.items():
                    if r.get(f) and row.get(key) and row[key] != "interface":
                        value = (cat.objects.get(str(r[f].get("id"))) or r[f]).get("value")
                        if value:
                            row[key] = f"{row[key]} ({value})"
        rows.sort(key=lambda r: (order.get(str(r.get("section", "")).upper(), 1), r.get("index") or 0))
        if text:
            rows = [r for r in rows if text.lower() in str(r).lower()]
        extra: dict[str, Any] = {"policy": p.get("name")}
        if address:
            extra["address"] = address
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra, columns=NAT_COLUMNS
        )

    @reg.read(title="List prefilter rules")
    async def fmc_list_prefilter_rules(
        ctx: Context,
        policy: Annotated[
            str | None, Field(description="Prefilter policy name or UUID (default: Default Prefilter Policy)")
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List a prefilter policy's rules (evaluated before access control): type (PREFILTER or
        TUNNEL), action (FASTPATH, ANALYZE, BLOCK), interfaces, networks, ports, VLANs. Also shows the
        policy's default action."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "prefilter", policy or "Default Prefilter Policy", domain)
        path = await app.config_path(f"{PREFILTER}/{p['id']}/prefilterrules", domain)
        page = await app.page(path, limit=limit, offset=offset)
        page.items = [flatten_prefilter_rule(r) for r in page.items]
        extra = {"policy": p.get("name"), "default_action": (p.get("defaultAction") or {}).get("action")}
        return list_result(page, fmt=response_format, extra=extra)

    @reg.read(title="List policy assignments")
    async def fmc_list_policy_assignments(
        ctx: Context,
        policy: Annotated[str | None, Field(description="Filter: policy name contains")] = None,
        device: Annotated[
            str | None, Field(description="Filter: target device/HA/cluster name contains")
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List which policies (access, NAT, platform settings, ...) are assigned to which devices,
        HA pairs and clusters. Empty when nothing is assigned."""
        app: FmcApp = get_client(ctx)
        page = await app.all(await app.config_path("assignment/policyassignments", domain), cap=5000)
        rows = []
        for a in page.items:
            pol = a.get("policy") or {}
            targets = [ref_label(t) for t in a.get("targets") or []]
            if policy and policy.lower() not in str(pol.get("name", "")).lower():
                continue
            if device and not any(device.lower() in t.lower() for t in targets):
                continue
            rows.append(
                {
                    "policy": pol.get("name"),
                    "policy_type": pol.get("type"),
                    "targets": targets,
                    "id": a.get("id"),
                }
            )
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)


async def _assigned_devices(app: FmcApp, policy_id: str, domain: str | None) -> list[str]:
    page = await app.all(await app.config_path("assignment/policyassignments", domain), cap=5000)
    for a in page.items:
        if (a.get("policy") or {}).get("id") == policy_id or a.get("id") == policy_id:
            return [ref_label(t) for t in a.get("targets") or []]
    return []


async def find_access_rule(
    app: FmcApp, policy: dict[str, Any], rule: str, domain: str | None
) -> dict[str, Any]:
    """An access rule by UUID, 1-based index or name (expanded)."""
    rule = rule.strip()
    base = await app.config_path(f"{ACCESS}/{policy['id']}/accessrules", domain)
    if is_uuid(rule):
        data: dict[str, Any] = await app.api.get(f"{base}/{rule}")
        return data
    rules = await all_rules(app, base)
    if rule.isdigit():
        idx = int(rule)
        for r in rules.items:
            if (r.get("metadata") or {}).get("ruleIndex") == idx:
                found: dict[str, Any] = r
                return found
        raise InvalidRequest(
            f"Policy {policy.get('name')!r} has no rule with index {idx} ({len(rules.items)} rules)."
        )
    return pick_by_name(rules.items, rule, f"rule in {policy.get('name')!r}")
