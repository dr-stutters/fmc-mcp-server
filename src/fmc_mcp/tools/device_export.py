"""Device configuration export and compare (F72): one FTD's (or HA pair's) configuration as FMC holds it,
as a versioned YAML document keyed by name, and a field-level diff of two of them (another device, a
stored export, a device template, or the live device against its own earlier export).

Export layout (format fmc-device-config, version 1); ids, links and FMC metadata are stripped:

    format: fmc-device-config
    version: 1
    meta: {device, kind, id, host, serial, units, domain, fmc_version, server, sections, errors,
           exported_at, digest}
    device: {model, version, mode, licenses, performance_tier, snort_engine, ...}    # one object
    interfaces: {<hardware name>: {kind, ifname, securityZone, ipv4, MTU, ...}}
    routing: {<route or protocol key>: {...}}       # static routes, BGP, OSPF, EIGRP, PBR, ECMP, BFD, VRFs
    policies: {<access|nat|platform_settings|health|...>: {name, domain?}}
    nat: {name, rules: [...]}                       # the assigned NAT policy, rules in order
    platform_settings: {<setting>: {...}}           # the assigned platform settings policy
    vpn: {<topology>: {topology, route_based, peerType, interface, ...}}
    object_overrides: {<Type name>: {value, default}}
    out_of_band: {<oob id>: {type, status, result, acknowledged, diff: [...]}}
    ha: {settings | failover link | state link | monitored <if> | mac <if>: {...}}  # HA pairs only

Sections come from a registry (SECTIONS, filled by `export_section`): each has a collector, a kind
(`config`; F73's snapshots add `state` sections the same way), a shape that picks how it is diffed
(`keyed`: item by item; `single`: field by field; `policy`: settings + ordered rules, the policy
bundle's planner) and whether it is in the default set. A section that is empty is left out of the
document but still listed in meta.sections, so a diff knows it was read. Mappings are sorted by key,
set-like lists sorted, and secret values masked (core's key patterns, FMC's registration keys and
pre-shared keys, and secrets on the CLI lines of out-of-band diffs), so re-exporting an unchanged device
gives the same meta.digest.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import copy
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import InvalidRequest, NotFound, ToolRegistrar, UpstreamError, get_client
from fmc_mcp._core.formatting import mask_secrets, max_chars
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.bundle import (
    clean,
    diff_policy,
    field_delta,
    finish,
    generic_rule,
    ordered,
    server_version,
    summarise,
    write_file,
)
from fmc_mcp.tools.common import SECRET_FIELDS, Domain, ref_label, resolve_in
from fmc_mcp.tools.device_config import route_row
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS, INTERFACE_KINDS, interface_row
from fmc_mcp.tools.platform_settings import LISTS, PS, SINGLE
from fmc_mcp.tools.policies import NAT, RULE_CAP, policy_assignments
from fmc_mcp.tools.templates import TEMPLATES, template_with_metadata
from fmc_mcp.tools.vpn import S2S, topology_row

FORMAT = "fmc-device-config"
VERSION = 1
MASK = "********"
OBJECT_CAP = 20_000
MAX_OVERRIDABLE = 100  # overridable objects whose overrides are read (one request each)
MAX_TOPOLOGIES = 200
# Overridable value objects: FMC type -> collection.
OVERRIDE_TYPES = {
    "Host": "object/hosts",
    "Network": "object/networks",
    "Range": "object/ranges",
    "FQDN": "object/fqdns",
}
# Policy assignment types -> key in the policies section.
POLICY_LABELS = {
    "AccessPolicy": "access",
    "FTDNatPolicy": "nat",
    "FTDPlatformSettingsPolicy": "platform_settings",
    "HealthPolicy": "health",
    "QosPolicy": "qos",
    "QoSPolicy": "qos",
    "FlexConfigPolicy": "flexconfig",
    "RAVpn": "remote_access_vpn",
    "FTDRAVpn": "remote_access_vpn",
}
# Lists FMC treats as sets: sorted in the export so FMC's ordering never shows as a change.
UNORDERED = frozenset(
    {
        "neighbors",
        "networks",
        "areaNetworks",
        "areas",
        "redistributeProtocols",
        "selectedInterfaces",
        "selectedNetworks",
        "protectedNetworks",
        "interfaces",
        "ingressInterfaces",
        "objects",
        "literals",
        "ntpServerInfos",
        "insideInterface",
        "entries",
    }
)
# Secrets on device CLI lines (out-of-band diffs): the value after the keyword is masked, past the
# qualifiers that may sit between them: an encryption type or key id (`password 0 x`,
# `message-digest-key 1 md5 x`), a hash or format (`failover key hex x`, `auth sha x`, `priv aes 128 x`)
# and EIGRP's AS (`authentication key eigrp 100 x`). Values the device already masked (`*****`) stay.
_CLI_SECRET = re.compile(
    r"(?i)\b(password|passwd|secret|key-string|pre-shared-key|authentication-key|message-digest-key"
    r"|community|key|auth|priv)"
    r"((?:\s+(?:\d+|md5|sha\d*|hex|ascii|aes\d*(?:\s+\d+)?|3des|des|eigrp\s+\d+))*)"
    r"\s+(?!\*+(?:\s|$))(\S+)"
)
_VARIABLE = re.compile(r"^\$\{[^}]+\}$")
_FILE_NAME = re.compile(r"[\w.@+-]+\.ya?ml")
_EMPTY: tuple[Any, ...] = (None, "", [], {})

SectionShape = Literal["keyed", "single", "policy"]
SectionKind = Literal["config", "state"]


# --- the section registry (F73 adds state sections with export_section(kind="state")) -----------


@dataclass(frozen=True)
class Section:
    name: str
    collect: Callable[["ExportContext"], Awaitable[Any]]
    kind: SectionKind = "config"
    shape: SectionShape = "keyed"
    default: bool = True
    summary: str = ""


SECTIONS: dict[str, Section] = {}


def export_section(
    name: str,
    *,
    kind: SectionKind = "config",
    shape: SectionShape = "keyed",
    default: bool = True,
    summary: str = "",
) -> Callable[[Callable[["ExportContext"], Awaitable[Any]]], Callable[["ExportContext"], Awaitable[Any]]]:
    """Register a section collector. Sections export (and diff) in registration order; a `keyed`
    collector returns {item key: item}, a `single` one one object, a `policy` one {name, ..., rules}."""

    def deco(fn: Callable[["ExportContext"], Awaitable[Any]]) -> Callable[["ExportContext"], Awaitable[Any]]:
        if name in SECTIONS:
            raise ValueError(f"export section {name!r} is registered twice")
        SECTIONS[name] = Section(name, fn, kind, shape, default, summary)
        return fn

    return deco


def select_sections(wanted: list[str] | None) -> list[str]:
    """Section names in registry order: the default set, or the named ones; 'config', 'state' and 'all'
    stand for every section of that kind."""
    if not wanted:
        return [n for n, s in SECTIONS.items() if s.default]
    out: set[str] = set()
    for w in wanted:
        key = w.strip().lower()
        if key == "all":
            out |= set(SECTIONS)
        elif key in ("config", "state"):
            out |= {n for n, s in SECTIONS.items() if s.kind == key}
        elif key in SECTIONS:
            out.add(key)
        else:
            raise InvalidRequest(
                f"Unknown section {w!r}. Sections: {', '.join(SECTIONS)}; or 'config', 'state', 'all'."
            )
    return [n for n in SECTIONS if n in out]


# --- collecting ----------------------------------------------------------------------------------


@dataclass
class ExportContext:
    """What a section collector works with: the device (the primary unit for an HA pair), the pair,
    and `shared`, a per-call cache so a two-device diff reads zones, assignments, VPN topologies,
    objects and shared policies once."""

    app: FmcApp
    domain: str | None
    device: dict[str, Any]
    ha: dict[str, Any] | None = None
    shared: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def target_ids(self) -> set[str]:
        """The ids policies, VPN endpoints and overrides may name this device by."""
        ids = {str(self.device.get("id"))}
        if self.ha:
            ids.add(str(self.ha.get("id")))
            ids |= {str((self.ha.get(s) or {}).get("id")) for s in ("primary", "secondary")}
        return ids - {"None"}

    @property
    def base(self) -> str:
        return f"{DEVICES}/{self.device['id']}"

    async def items(
        self,
        suffix: str,
        params: dict[str, Any] | None = None,
        *,
        cap: int = 2000,
        optional: bool = True,
        expanded: bool = True,
    ) -> list[dict[str, Any]]:
        """Every item of a collection; 404/405 (a kind this model or version doesn't have) is empty.
        Never the analysis tools' 60 s catalog cache: an export must show FMC as it is now."""
        try:
            path = await self.app.config_path(suffix, self.domain)
            page = await self.app.all(path, params, cap=cap, expanded=expanded)
        except UpstreamError as e:
            if optional and e.status_code in (404, 405):
                return []
            raise
        if not page.complete:
            self.warnings.append(f"{suffix}: FMC returned only the first {len(page.items)} items.")
        return list(page.items)

    async def one_page(self, suffix: str) -> list[dict[str, Any]]:
        """One large page, de-duplicated by id: FMC 10.0.1 reports `count: 2` for a single OSPFv2
        process and returns it again at offset 1, so paging the routing collections never ends."""
        try:
            page = await self.app.page(await self.app.config_path(suffix, self.domain), limit=1000)
        except UpstreamError as e:
            if e.status_code in (404, 405):
                return []
            raise
        seen: dict[str, dict[str, Any]] = {}
        for item in page.items:
            seen.setdefault(str(item.get("id") or len(seen)), item)
        if len(page.items) >= 1000:
            self.warnings.append(f"{suffix}: only the first 1000 items were read.")
        return list(seen.values())

    async def memo(self, key: str, fetch: Callable[[], Awaitable[Any]]) -> Any:
        if key not in self.shared:
            self.shared[key] = await fetch()
        return copy.deepcopy(self.shared[key])


# --- normalising ---------------------------------------------------------------------------------


def _sort_key(item: Any) -> str:
    return json.dumps(item, sort_keys=True, default=str)


def _sort_sets(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {k: _sort_sets(v, k) for k, v in value.items()}
    if isinstance(value, list):
        items = [_sort_sets(v) for v in value]
        return sorted(items, key=_sort_key) if key in UNORDERED else items
    return value


def norm(value: Any) -> Any:
    """The bundle's clean() (ids, links, metadata and empty values dropped, keys sorted, nested
    references reduced to name and type) with set-like lists sorted."""
    return _sort_sets(clean(value))


def _body(item: dict[str, Any], *drop: str) -> dict[str, Any]:
    skip = {"id", "links", "metadata", "type", *drop}
    return {k: v for k, v in item.items() if k not in skip}


def mask_cli(line: str) -> str:
    return _CLI_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)} {MASK}", line)


def mask(value: Any) -> Any:
    """Core's secret masking (passwords, keys, communities, PSKs by key name) plus FMC's own secret
    fields (registration key, NAT id, manual pre-shared keys)."""

    def walk(v: Any) -> Any:
        if isinstance(v, dict):
            return {
                k: (MASK if k.lower() in SECRET_FIELDS and x not in _EMPTY else walk(x)) for k, x in v.items()
            }
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return walk(mask_secrets(value))


def _sorted(d: dict[str, Any]) -> dict[str, Any]:
    return {k: d[k] for k in sorted(d, key=str)}


def _put(out: dict[str, Any], key: str, value: Any) -> None:
    """Add an item; a key already taken gets ' #2', ' #3', ..."""
    k, n = key, 1
    while k in out:
        n += 1
        k = f"{key} #{n}"
    out[k] = value


def _named(refs: Any) -> list[str]:
    return sorted(ref_label(r) for r in refs or [] if isinstance(r, dict))


# --- sections ------------------------------------------------------------------------------------


@export_section(
    "device",
    shape="single",
    summary="model, software and content versions, firewall mode, licences, performance tier, Snort",
)
async def _device(ctx: ExportContext) -> dict[str, Any]:
    d = ctx.device
    meta = d.get("metadata") or {}
    desc = d.get("description")
    out = {
        "model": d.get("model"),
        "version": d.get("sw_version"),
        "mode": d.get("ftdMode"),
        "licenses": sorted(d.get("license_caps") or []),
        "performance_tier": d.get("performanceTier"),
        "snort_engine": d.get("snortEngine"),
        "snort_version": meta.get("snortVersion"),
        "vdb_version": meta.get("vdbVersion"),
        "lsp_version": meta.get("lspVersion"),
        "device_group": ref_label(d["deviceGroup"]) if d.get("deviceGroup") else None,
        "description": desc if desc != "NOT SUPPORTED" else None,
        "keep_local_events": d.get("keepLocalEvents"),
        "prohibit_packet_transfer": d.get("prohibitPacketTransfer"),
        "analytics_only": d.get("analyticsOnly"),
        "advanced": norm(d.get("advanced")),
    }
    return {k: v for k, v in out.items() if v not in _EMPTY}


def interface_entry(kind: str, i: dict[str, Any], zones: dict[str, str]) -> dict[str, Any]:
    """One interface: its kind, then every setting (cleaned); the zone by name, a VRF other than the
    global table as `virtualRouter`."""
    body = _body(i, "name")
    zone = i.get("securityZone")
    if isinstance(zone, dict):
        body["securityZone"] = zones.get(str(zone.get("id")), zone.get("name") or zone.get("id"))
    vr = ((i.get("metadata") or {}).get("virtualRouter") or {}).get("name")
    if vr and str(vr).lower() != "global":
        body["virtualRouter"] = vr
    return {"kind": kind, **norm(body)}


@export_section(
    "interfaces",
    summary="every interface kind by hardware name: logical name, zone, addresses, MTU, VRF, path monitoring",
)
async def _interfaces(ctx: ExportContext) -> dict[str, Any]:
    rows = await ctx.memo("zones", partial(ctx.items, "object/securityzones", expanded=False))
    zones = {str(z.get("id")): str(z.get("name")) for z in rows}
    out: dict[str, Any] = {}
    for kind, sub in INTERFACE_KINDS.items():
        for i in await ctx.items(f"{ctx.base}/{sub}"):
            _put(out, str(interface_row(kind, i)["name"]), interface_entry(kind, i, zones))
    return _sorted(out)


def static_routes(kind: str, routes: list[dict[str, Any]], prefix: str = "") -> dict[str, Any]:
    """Static routes keyed by family, egress interface and destinations (metric, then gateway, added
    only where two routes share that), so a gateway change shows as a changed field, not a new route."""
    fam = "ipv4" if kind == "static4" else "ipv6"
    rows = []
    for r in routes:
        row = {k: v for k, v in route_row(kind, r).items() if k not in ("id", "kind") and v not in _EMPTY}
        row["networks"] = sorted(row.get("networks") or [])
        rows.append(row)

    def base(row: dict[str, Any]) -> str:
        return f"{prefix}{fam} route {row.get('interface')} -> {', '.join(row['networks']) or '?'}"

    keys = [base(r) for r in rows]
    for extra in ("metric", "gateway"):
        dup = {k for k in keys if keys.count(k) > 1}
        keys = [
            f"{k} {'metric' if extra == 'metric' else 'via'} {r.get(extra)}" if k in dup else k
            for k, r in zip(keys, rows, strict=True)
        ]
    out: dict[str, Any] = {}
    for k, r in sorted(zip(keys, rows, strict=True), key=lambda kr: (kr[0], _sort_key(kr[1]))):
        _put(out, k, r)
    return out


async def _protocols(ctx: ExportContext, base: str, prefix: str, *, global_table: bool) -> dict[str, Any]:
    """One routing table: the global one (base = the device's routing/) or a user VRF's (base = its
    virtualrouters/<id>, keys prefixed 'vrf <name>: '). FMC keeps BGP general settings and OSPFv3 in the
    global table only; everything else exists per VRF too."""
    out: dict[str, Any] = {}
    out.update(static_routes("static4", await ctx.one_page(f"{base}/ipv4staticroutes"), prefix))
    out.update(static_routes("static6", await ctx.one_page(f"{base}/ipv6staticroutes"), prefix))
    for b in await ctx.one_page(f"{base}/bgp"):
        _put(out, f"{prefix}bgp", norm(_body(b, "name")))
    for p in await ctx.one_page(f"{base}/ospfv2routes"):
        _put(out, f"{prefix}ospfv2 process {p.get('processId')}", norm(_body(p, "name")))
    for i in await ctx.one_page(f"{base}/ospfinterface"):
        _put(
            out, f"{prefix}ospf interface {ref_label(i.get('deviceInterface') or {})}", norm(_body(i, "name"))
        )
    for e in await ctx.one_page(f"{base}/eigrproutes"):
        _put(out, f"{prefix}eigrp {e.get('asNumber') or e.get('name') or ''}".strip(), norm(_body(e, "name")))
    for p in await ctx.one_page(f"{base}/policybasedroutes"):
        ingress = ", ".join(_named(p.get("ingressInterfaces"))) or str(p.get("name") or "?")
        _put(out, f"{prefix}policy-based route {ingress}", norm(_body(p, "name")))
    for z in await ctx.one_page(f"{base}/ecmpzones"):
        _put(out, f"{prefix}ecmp zone {z.get('name')}", norm(_body(z, "name")))
    for b in await ctx.one_page(f"{base}/bfdpolicies"):
        where = ref_label(b["interface"]) if isinstance(b.get("interface"), dict) else b.get("name")
        _put(
            out,
            f"{prefix}bfd {b.get('hopType') or ''} {where or ''}".replace("  ", " ").strip(),
            norm(_body(b, "name")),
        )
    if not global_table:
        return out
    for g in await ctx.one_page(f"{base}/bgpgeneralsettings"):
        _put(out, "bgp general settings", norm(_body(g, "name")))
    for p in await ctx.one_page(f"{base}/ospfv3routes"):
        _put(out, f"ospfv3 process {p.get('processId')}", norm(_body(p, "name")))
    for i in await ctx.one_page(f"{base}/ospfv3interfaces"):
        _put(out, f"ospfv3 interface {ref_label(i.get('deviceInterface') or {})}", norm(_body(i, "name")))
    return out


@export_section(
    "routing",
    summary="static routes (IPv4/IPv6), BGP, OSPFv2/v3 and their interfaces, EIGRP, policy-based routes, "
    "ECMP zones, BFD, and user VRFs with their own routes and protocols",
)
async def _routing(ctx: ExportContext) -> dict[str, Any]:
    base = f"{ctx.base}/routing"
    out = await _protocols(ctx, base, "", global_table=True)
    for v in await ctx.one_page(f"{base}/virtualrouters"):
        name = str(v.get("name"))
        if name.lower() == "global":
            continue
        _put(out, f"vrf {name}", norm({**_body(v, "name"), "interfaces": _named(v.get("interfaces"))}))
        out.update(
            await _protocols(ctx, f"{base}/virtualrouters/{v['id']}", f"vrf {name}: ", global_table=False)
        )
    return _sorted(out)


async def assigned(ctx: ExportContext) -> dict[str, dict[str, Any]]:
    """{label: {id, name, domain?}} of the policies assigned to this device (or its HA pair), ancestor
    domains included."""
    rows = await ctx.memo("assignments", lambda: policy_assignments(ctx.app, ctx.domain))
    out: dict[str, dict[str, Any]] = {}
    for a in rows:
        pol = a.get("policy") or {}
        if not ctx.target_ids & {str(t.get("id")) for t in a.get("targets") or []}:
            continue
        label = POLICY_LABELS.get(str(pol.get("type")), str(pol.get("type") or "policy").lower())
        item = {"id": pol.get("id") or a.get("id"), "name": pol.get("name") or a.get("name")}
        if a.get("_domain"):
            item["domain"] = a["_domain"]
        _put(out, label, item)
    for fld, label in (("accessPolicy", "access"), ("healthPolicy", "health")):
        ref = ctx.device.get(fld)
        if isinstance(ref, dict) and ref.get("name") and label not in out:
            out[label] = {"id": ref.get("id"), "name": ref["name"]}
    return out


@export_section(
    "policies", summary="assigned policies by kind (access, NAT, platform settings, health, QoS, ...)"
)
async def _policies(ctx: ExportContext) -> dict[str, Any]:
    return _sorted(
        {k: {f: v[f] for f in ("name", "domain") if v.get(f)} for k, v in (await assigned(ctx)).items()}
    )


@export_section("nat", shape="policy", summary="the assigned NAT policy's rules in order")
async def _nat(ctx: ExportContext) -> dict[str, Any]:
    pol = (await assigned(ctx)).get("nat")
    if not pol or not pol.get("id"):
        return {}

    async def load() -> dict[str, Any]:
        rules = await ctx.items(f"{NAT}/{pol['id']}/natrules", cap=RULE_CAP, optional=False)
        return {"name": pol["name"], "rules": [generic_rule(r) for r in ordered(rules)]}

    result: dict[str, Any] = await ctx.memo(f"nat:{pol['id']}", load)
    return result


@export_section(
    "platform_settings",
    summary="the assigned platform settings policy: syslog, NTP, SNMP, SSH/HTTP access, banner, DNS",
)
async def _platform_settings(ctx: ExportContext) -> dict[str, Any]:
    pol = (await assigned(ctx)).get("platform_settings")
    if not pol or not pol.get("id"):
        return {}

    async def load() -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, sub in SINGLE.items():
            rows = await ctx.items(f"{PS}/{pol['id']}/{sub}", cap=500)
            if rows:
                out[key] = norm(_body(rows[0], "name"))
        for key, sub in LISTS.items():
            rows = await ctx.items(f"{PS}/{pol['id']}/{sub}", cap=500)
            if rows:
                out[key] = norm({"entries": [_body(r) for r in rows]})
        return {k: v for k, v in sorted(out.items()) if v not in _EMPTY}

    result: dict[str, Any] = await ctx.memo(f"ps:{pol['id']}", load)
    return result


@export_section(
    "vpn",
    summary="site-to-site and SD-WAN topologies the device is an endpoint of: role, interface, networks",
)
async def _vpn(ctx: ExportContext) -> dict[str, Any]:
    topologies = await ctx.memo("s2s", lambda: ctx.items(S2S, cap=MAX_TOPOLOGIES))
    out: dict[str, Any] = {}
    for t in topologies:
        if not t.get("id"):
            continue
        endpoints = await ctx.memo(f"s2s:{t['id']}", partial(ctx.items, f"{S2S}/{t['id']}/endpoints"))
        for e in endpoints:
            if str((e.get("device") or {}).get("id")) not in ctx.target_ids:
                continue
            row = topology_row(t)
            item = {
                "topology": row["kind"],
                "route_based": row["route_based"],
                "ike": row["ike"],
                **norm(_body(e, "name", "device")),
            }
            _put(out, str(t.get("name")), {k: v for k, v in item.items() if v not in _EMPTY})
    return _sorted(out)


@export_section(
    "object_overrides",
    summary="host, network, range and FQDN objects with a value of their own on this device (and the "
    "default)",
)
async def _object_overrides(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    budget = MAX_OVERRIDABLE
    for otype, path in OVERRIDE_TYPES.items():
        objs = await ctx.memo(f"objects:{path}", partial(ctx.items, path, cap=OBJECT_CAP))
        for o in sorted(
            (o for o in objs if o.get("overridable") and o.get("id")), key=lambda o: str(o.get("name"))
        ):
            if budget <= 0:
                if "overrides-capped" not in ctx.shared:
                    ctx.shared["overrides-capped"] = True
                    ctx.warnings.append(
                        f"object_overrides: only the first {MAX_OVERRIDABLE} overridable objects were read."
                    )
                break
            budget -= 1
            overrides = await ctx.memo(
                f"overrides:{o['id']}", partial(ctx.items, f"{path}/{o['id']}/overrides")
            )
            for ov in overrides:
                target = (ov.get("overrides") or {}).get("target") or {}
                if str(target.get("id")) in ctx.target_ids:
                    value = ov.get("value") or ov.get("literals") or ov.get("objects")
                    _put(out, f"{otype} {o.get('name')}", norm({"value": value, "default": o.get("value")}))
    return _sorted(out)


@export_section(
    "out_of_band",
    summary="out-of-band changes FMC detected on the device (CLI diff lines, secrets masked)",
)
async def _out_of_band(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for r in await ctx.items(f"{ctx.base}/operational/outofbandchanges"):
        lines = [
            mask_cli(x) for x in str(r.get("configCLIDiffLines") or "").split("@<nextline>") if x.strip()
        ]
        item = {
            "type": r.get("oobType"),
            "status": r.get("oobTaskStatus"),
            "result": r.get("configDiffInfo"),
            "acknowledged": r.get("isOOBAcknowledged"),
            "message": r.get("message"),
            "diff": lines,
        }
        _put(
            out,
            str(r.get("oobId") or r.get("id") or "change"),
            {k: v for k, v in item.items() if v not in _EMPTY},
        )
    return _sorted(out)


@export_section(
    "ha", summary="HA pairs only: failover and state links, encryption, monitored interfaces, virtual MACs"
)
async def _ha(ctx: ExportContext) -> dict[str, Any]:
    if not ctx.ha:
        return {}
    base = f"{HA_PAIRS}/{ctx.ha['id']}"
    boot = ctx.ha.get("ftdHABootstrap") or {}
    out: dict[str, Any] = {"settings": norm(_body(boot, "lanFailover", "statefulFailover"))}
    if boot.get("lanFailover"):
        out["failover link"] = norm(boot["lanFailover"])
    if boot.get("statefulFailover"):
        out["state link"] = norm(boot["statefulFailover"])
    for m in await ctx.items(f"{base}/monitoredinterfaces"):
        _put(out, f"monitored {m.get('name')}", norm(_body(m, "name")))
    for m in await ctx.items(f"{base}/failoverinterfacemacaddressconfigs"):
        _put(out, f"mac {ref_label(m.get('physicalInterface') or {})}", norm(_body(m, "physicalInterface")))
    return _sorted({k: v for k, v in out.items() if v not in _EMPTY})


# --- export --------------------------------------------------------------------------------------


async def resolve_target(
    app: FmcApp, ref: str, domain: str | None
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """(device record, HA pair or None) for a device or HA pair name/UUID. An HA pair exports its primary
    unit's configuration (FMC keeps the pair's interfaces and routes there) plus the `ha` section."""
    try:
        dev = await resolve_in(app, DEVICES, ref, "device", domain)
    except NotFound as dev_err:
        try:
            ha = await resolve_in(app, HA_PAIRS, ref, "HA pair", domain)
        except NotFound:
            raise NotFound(f"{dev_err} No HA pair of that name either.", 404) from None
        return await _ha_target(app, ha, domain)
    if not dev.get("model") and dev.get("id"):
        dev = await app.api.get(await app.config_path(f"{DEVICES}/{dev['id']}", domain))
    return dict(dev), None


async def _ha_target(
    app: FmcApp, ha: dict[str, Any], domain: str | None
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if not ha.get("ftdHABootstrap") and ha.get("id"):
        ha = await app.api.get(await app.config_path(f"{HA_PAIRS}/{ha['id']}", domain))
    primary = (ha.get("primary") or {}).get("id")
    if not primary:
        raise UpstreamError(f"HA pair {ha.get('name')!r} names no primary unit.")
    dev = await app.api.get(await app.config_path(f"{DEVICES}/{primary}", domain))
    return dict(dev or {}), dict(ha)


async def build_export(
    app: FmcApp,
    ref: str,
    domain: str | None,
    sections: list[str],
    shared: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """The export document (without exported_at/digest: finish() stamps those) and warnings."""
    device, ha = await resolve_target(app, ref, domain)
    ctx = ExportContext(app, domain, device, ha, shared if shared is not None else {})
    domain_name = await app.domain_name(await app.domain_uuid(domain))
    meta: dict[str, Any] = {
        "device": (ha or device).get("name"),
        "kind": "ha_pair" if ha else "device",
        "id": (ha or device).get("id"),
        "host": device.get("hostName"),
        "serial": (device.get("metadata") or {}).get("deviceSerialNumber"),
    }
    if ha:
        meta["units"] = {s: ref_label(ha.get(s) or {}) for s in ("primary", "secondary")}
    meta.update(
        {"domain": domain_name, "fmc_version": await app.server_version(), "server": server_version()}
    )
    doc: dict[str, Any] = {"format": FORMAT, "version": VERSION, "meta": {}}
    errors: dict[str, str] = {}
    for name in sections:
        try:
            value = await SECTIONS[name].collect(ctx)
        except UpstreamError as e:
            errors[name] = str(e)
            continue
        value = mask(value)
        if value not in _EMPTY:
            doc[name] = value
    meta["sections"] = [n for n in sections if n not in errors]
    if errors:
        meta["errors"] = errors
    doc["meta"] = {k: v for k, v in meta.items() if v not in _EMPTY}
    return doc, ctx.warnings


def parse_export(text: str, bundle_dir: Path | None) -> dict[str, Any]:
    """An export from YAML text, or from a file name inside FMC_BUNDLE_DIR (never a path outside it)."""
    name = text.strip()
    if "\n" not in name and _FILE_NAME.fullmatch(name):
        if bundle_dir is None:
            raise InvalidRequest(
                f"{name!r} looks like a file name, but FMC_BUNDLE_DIR isn't set: pass the YAML."
            )
        path = (bundle_dir / name).resolve()
        if path.parent != bundle_dir.resolve() or not path.is_file():
            raise NotFound(f"No export file {name!r} in FMC_BUNDLE_DIR.", 404)
        text = path.read_text()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise InvalidRequest(f"Not a device configuration export: the YAML doesn't parse ({e}).") from None
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise InvalidRequest(
            f"Not a device configuration export (format: {FORMAT}): pass the YAML from "
            "fmc_export_device_config, or the name of an export file in FMC_BUNDLE_DIR."
        )
    if data.get("version") != VERSION:
        raise InvalidRequest(
            f"Export version {data.get('version')!r} isn't supported (this server reads {VERSION})."
        )
    return data


def looks_like_export(text: str) -> bool:
    t = text.strip()
    return "\n" in t or t.startswith("format:") or bool(_FILE_NAME.fullmatch(t))


def counts(doc: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for name in (doc.get("meta") or {}).get("sections") or []:
        value = doc.get(name) or {}
        shape = SECTIONS[name].shape if name in SECTIONS else "keyed"
        if shape == "policy":
            out[name] = len(value.get("rules") or [])
        elif shape == "single":
            out[name] = 1 if value else 0
        else:
            out[name] = len(value)
    return out


def _flat(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, dict) and value:
        out: list[tuple[str, Any]] = []
        for k, v in value.items():
            out += _flat(v, f"{prefix}{k}.")
        return out
    return [(prefix.rstrip("."), value)]


def _line(value: Any, width: int = 400) -> str:
    text = ", ".join(
        f"{k}={json.dumps(v, default=str) if not isinstance(v, str) else v}" for k, v in _flat(value) if k
    )
    return text if len(text) <= width else text[: width - 3] + "..."


def render_markdown(doc: dict[str, Any]) -> str:
    meta = doc.get("meta") or {}
    head = f"# {meta.get('device')} ({meta.get('kind')}, {meta.get('domain')})"
    lines = [
        head,
        "",
        f"FMC {meta.get('fmc_version')}; exported {meta.get('exported_at')}; {meta.get('digest')}",
    ]
    for name in meta.get("sections") or []:
        value = doc.get(name) or {}
        shape = SECTIONS[name].shape if name in SECTIONS else "keyed"
        lines += ["", f"## {name}"]
        if not value:
            lines.append("(none)")
        elif shape == "single":
            lines += [f"- {k}: {_line(v) if isinstance(v, dict) else v}" for k, v in value.items()]
        elif shape == "policy":
            lines.append(f"Policy {value.get('name')}, {len(value.get('rules') or [])} rules:")
            lines += [f"{i}. {_line(r)}" for i, r in enumerate(value.get("rules") or [], 1)]
        else:
            lines += [f"- **{k}**: {_line(v)}" for k, v in value.items()]
    if meta.get("errors"):
        lines += ["", "## not read"] + [f"- {k}: {v}" for k, v in meta["errors"].items()]
    return "\n".join(lines) + "\n"


# --- device templates as the `b` side ------------------------------------------------------------


async def template_export(
    app: FmcApp, ref: str, domain: str | None, a: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """A device template as an export of the sections it defines (device mode, policies, interfaces,
    VPN membership). ${variables} take the value the template's association with device `a` holds,
    else the variable's default; the rest stay `${name}` and match anything in the diff."""
    t = await template_with_metadata(app, ref, domain)
    base = await app.config_path(f"{TEMPLATES}/{t['id']}", domain)

    async def items(sub: str) -> list[dict[str, Any]]:
        try:
            return list((await app.all(f"{base}/{sub}", cap=2000)).items)
        except UpstreamError as e:
            if e.status_code in (404, 405):
                return []
            raise

    variables = {str(v.get("name")): v for v in await items("variables")}
    a_meta = a.get("meta") or {}
    values: dict[str, Any] = {}
    for assoc in await items("associations"):
        dev = assoc.get("device") or {}
        if dev.get("id") == a_meta.get("id") or dev.get("name") == a_meta.get("device"):
            values = {str(v.get("key")): v.get("value") for v in assoc.get("variableValues") or []}
    unresolved: set[str] = set()

    def resolve(v: Any) -> Any:
        if isinstance(v, dict) and isinstance(v.get("variable"), dict):
            name = str(v["variable"].get("name"))
            var = variables.get(name) or {}
            if str(var.get("variableType")) == "PASSWORD":
                return MASK
            value = values.get(name) or var.get("value")
            if value in (None, ""):
                unresolved.add(name)
                return f"${{{name}}}"
            return value
        if isinstance(v, dict):
            return {k: resolve(x) for k, x in v.items()}
        if isinstance(v, list):
            return [resolve(x) for x in v]
        return v

    model = (a.get("device") or {}).get("model")
    mapping: dict[str, str] = {}
    for m in await items("modelmappings"):
        if (m.get("metadata") or {}).get("modelName") == model:
            mapping = {
                str(x.get("templateInterface")): str(x.get("modelInterface"))
                for x in m.get("interfaceMappings") or []
            }
    interfaces: dict[str, Any] = {}
    for i in await items("templateinterfaces"):
        body = _body(i, "name", "slot", "port")
        if isinstance(i.get("securityZone"), dict):
            body["securityZone"] = i["securityZone"].get("name") or i["securityZone"].get("id")
        static = ((i.get("ipv4") or {}).get("static")) or None
        if static is not None:
            value = resolve(static)
            if isinstance(value, str) and "/" in value:
                addr, _, plen = value.partition("/")
                value = {"address": addr, "netmask": plen}
            elif isinstance(value, str):
                value = {"address": value, "netmask": value}
            body["ipv4"] = {**(i.get("ipv4") or {}), "static": value}
        name = str(i.get("name"))
        _put(interfaces, mapping.get(name, name), norm(resolve(body)))
    meta = t.get("metadata") or {}
    policies: dict[str, Any] = {}
    if (t.get("accessPolicy") or {}).get("name"):
        policies["access"] = {"name": t["accessPolicy"]["name"]}
    for p in meta.get("otherAssociatedPolicies") or []:
        label = POLICY_LABELS.get(str(p.get("type")))
        if label:
            policies[label] = {"name": p.get("name")}
    vpn: dict[str, Any] = {}
    for s in await items("vpnsettings"):
        full = s if s.get("s2sVpnSettings") else await app.api.get(f"{base}/vpnsettings/{s['id']}")
        settings = (full or {}).get("s2sVpnSettings") or {}
        topo = (settings.get("s2sVpn") or {}).get("name")
        if not topo:
            continue
        item: dict[str, Any] = {"peerType": settings.get("peerRole")}
        conn: dict[str, Any] = next(iter((full or {}).get("vpnConnections") or []), {})
        iface = (conn.get("vpnInterface") or {}).get("name")
        if iface:
            item["interface"] = {"name": mapping.get(str(iface), iface)}
        _put(vpn, str(topo), {k: v for k, v in item.items() if v not in _EMPTY})
    doc: dict[str, Any] = {
        "format": FORMAT,
        "version": VERSION,
        "meta": {
            "device": t.get("name"),
            "kind": "template",
            "id": t.get("id"),
            "domain": await app.domain_name(await app.domain_uuid(domain)),
            "sections": ["device", "interfaces", "policies", "vpn"],
        },
        "device": {"mode": t.get("firewallMode")} if t.get("firewallMode") else {},
        "interfaces": _sorted(interfaces),
        "policies": _sorted(policies),
        "vpn": _sorted(vpn),
    }
    doc["meta"]["unresolved_variables"] = sorted(unresolved)
    return mask(doc), []


# --- diff ----------------------------------------------------------------------------------------


def _fields(a: Any, b: Any) -> dict[str, dict[str, Any]]:
    out = field_delta(a, b)
    if "" in out:  # two scalars or lists: name the value
        out["value"] = out.pop("")
    return out


def subset_delta(a: Any, b: Any, prefix: str = "") -> dict[str, dict[str, Any]]:
    """The fields `b` (a template) sets that `a` differs on; b's unresolved ${variables} match anything."""
    if isinstance(b, dict):
        out: dict[str, dict[str, Any]] = {}
        for k in sorted(b, key=str):
            out.update(subset_delta(a.get(k) if isinstance(a, dict) else None, b[k], f"{prefix}{k}."))
        return out
    if isinstance(b, str) and _VARIABLE.match(b):
        return {}
    if isinstance(a, str) and isinstance(b, str | int) and a == str(b):
        return {}
    return {} if a == b else {prefix.rstrip(".") or "value": {"from": a, "to": b}}


def diff_keyed(
    section: str, a: dict[str, Any], b: dict[str, Any], *, subset: bool
) -> tuple[list[dict[str, Any]], int]:
    """Item by item. With subset (b is a template) only b's items and fields count; items only in `a`
    are skipped and counted."""
    out: list[dict[str, Any]] = []
    skipped = 0
    for key in sorted(set(a) | set(b), key=str):
        if key not in b:
            if subset:
                skipped += 1
                continue
            out.append({"section": section, "op": "removed", "key": key, "value": a[key]})
        elif key not in a:
            out.append({"section": section, "op": "added", "key": key, "value": b[key]})
        else:
            fields = subset_delta(a[key], b[key]) if subset else _fields(a[key], b[key])
            if fields:
                out.append({"section": section, "op": "changed", "key": key, "fields": fields})
    return out, skipped


def diff_exports(a: dict[str, Any], b: dict[str, Any], sections: list[str] | None = None) -> dict[str, Any]:
    """Every change that turns export `a` into `b` (meta ignored), section by section in registry order;
    sections only one side read are listed under not_compared."""
    subset = (b.get("meta") or {}).get("kind") == "template"
    sa = set((a.get("meta") or {}).get("sections") or [])
    sb = set((b.get("meta") or {}).get("sections") or [])
    names = [n for n in SECTIONS if n in sa | sb] + sorted((sa | sb) - set(SECTIONS))
    if sections is not None:
        names = [n for n in names if n in sections]
    changes: list[dict[str, Any]] = []
    not_compared: dict[str, str] = {}
    skipped: dict[str, int] = {}
    for name in names:
        if name not in sa or name not in sb:
            side = "b" if name in sa else "a"
            not_compared[name] = "not in the template" if subset and side == "b" else f"not read in {side}"
            continue
        va, vb = a.get(name) or {}, b.get(name) or {}
        shape = SECTIONS[name].shape if name in SECTIONS else "keyed"
        if shape == "single":
            fields = subset_delta(va, vb) if subset else _fields(va, vb)
            if fields:
                changes.append({"section": name, "op": "changed", "key": name, "fields": fields})
        elif shape == "policy":
            changes += diff_policy(name, va or None, vb or None)
        else:
            more, n = diff_keyed(name, va, vb, subset=subset)
            changes += more
            if n:
                skipped[name] = n
    out: dict[str, Any] = {"changes": changes, "compared": [n for n in names if n not in not_compared]}
    if not_compared:
        out["not_compared"] = not_compared
    if skipped:
        out["not_in_template"] = skipped
    return out


def _meta(doc: dict[str, Any]) -> dict[str, Any]:
    m = doc.get("meta") or {}
    keys = ("device", "kind", "domain", "fmc_version", "exported_at", "digest", "unresolved_variables")
    return {k: m[k] for k in keys if m.get(k) not in _EMPTY}


def _result(data: dict[str, Any], text: str | None = None) -> ToolResult:
    return ToolResult(
        content=text if text is not None else json.dumps(data, default=str), structured_content=data
    )


DeviceOrHa = Annotated[
    str, Field(description="Device or HA pair name or UUID (fmc_list_devices, fmc_list_ha_pairs)")
]
SectionsArg = Annotated[
    list[str] | None,
    Field(
        description="Sections (default: every config section): device, interfaces, routing, policies, nat, "
        "platform_settings, vpn, object_overrides, out_of_band, ha; or 'config', 'state', 'all'"
    ),
]


async def _side(
    app: FmcApp,
    ref: str,
    kind: str,
    domain: str | None,
    sections: list[str],
    shared: dict[str, Any],
    a: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """One side of a diff: a stored export, a live device / HA pair, or (b only) a device template.
    Live sides are stamped exported_at 'live' (their digest compares with a stored export's)."""
    bundle_dir = app.settings.bundle_dir
    if kind == "export" or (kind == "auto" and looks_like_export(ref)):
        return await asyncio.to_thread(parse_export, ref, bundle_dir), []
    if kind == "template" and a is None:
        raise InvalidRequest("A device template can only be `b` (compare a device or export with it).")
    try:
        if kind == "template" and a is not None:
            doc, warnings = await template_export(app, ref, domain, a)
        else:
            doc, warnings = await build_export(app, ref, domain, sections, shared)
    except NotFound:
        if kind != "auto" or a is None:
            raise
        try:
            doc, warnings = await template_export(app, ref, domain, a)
        except NotFound:
            raise NotFound(f"No device, HA pair or device template named {ref!r}.", 404) from None
    finish(doc)
    doc["meta"]["exported_at"] = "live"
    return doc, warnings


# --- tools ---------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Export a device configuration")
    async def fmc_export_device_config(
        ctx: Context,
        device: DeviceOrHa,
        sections: SectionsArg = None,
        format: Annotated[
            Literal["yaml", "markdown"],
            Field(
                description="yaml: the export document (re-readable by fmc_diff_device_config); "
                "markdown: a readable summary"
            ),
        ] = "yaml",
        domain: Domain = None,
        include_text: Annotated[
            bool,
            Field(description="Return the export in the result (false: only write the FMC_BUNDLE_DIR file)"),
        ] = True,
        offset: Annotated[
            int,
            Field(ge=0, description="Character offset into an export too big for one result (next_offset)"),
        ] = 0,
    ) -> ToolResult:
        """Export one FTD's (or HA pair's) configuration as FMC holds it, as one versioned YAML document by
        section: device (model, version, mode, licences, tier, Snort/VDB/LSP), interfaces of every kind
        by hardware name (logical name, zone, addresses, MTU, VRF, path monitoring), routing (static
        routes, BGP, OSPF, EIGRP, PBR, ECMP, BFD, VRFs), assigned policies, the NAT policy's rules, the
        platform settings, VPN topology memberships, per-device object overrides, out-of-band changes,
        and for an HA pair the failover settings. Ids and links stripped, items keyed by name in a stable
        order, secrets masked (SNMP communities, BGP/OSPF keys, PSKs, CLI secrets): re-exporting an
        unchanged device gives the same `digest`. Compare with fmc_diff_device_config. Written to
        FMC_BUNDLE_DIR too when set. Reads only FMC (works for disconnected devices); about 30
        requests for one device."""
        app: FmcApp = get_client(ctx)
        bundle_dir = app.settings.bundle_dir
        if not include_text and bundle_dir is None:
            raise InvalidRequest("include_text=false needs FMC_BUNDLE_DIR (nowhere else to put the export).")
        doc, warnings = await build_export(app, device, domain, select_sections(sections))
        text = finish(doc)
        meta = doc["meta"]
        out: dict[str, Any] = {
            "device": meta.get("device"),
            "kind": meta.get("kind"),
            "domain": meta.get("domain"),
            "digest": meta["digest"],
            "exported_at": meta["exported_at"],
            "sections": counts(doc),
        }
        if meta.get("errors"):
            out["errors"] = meta["errors"]
        if bundle_dir is not None and offset == 0:
            out["file"] = str(
                await asyncio.to_thread(
                    write_file, bundle_dir, f"device-{meta.get('device')}", text, meta["exported_at"]
                )
            )
        if warnings:
            out["warnings"] = warnings[:20]
        if not include_text:
            return _result(out)
        body = text if format == "yaml" else render_markdown(doc)
        out["size"] = len(body)
        budget = max(4000, int(max_chars() * 0.8) - 4000)
        chunk = body[offset : offset + budget]
        out["export" if format == "yaml" else "markdown"] = chunk
        if offset + budget < len(body):
            out["next_offset"] = offset + budget
            out["note"] = (
                "The export is larger than one result: call again with offset=next_offset and join the "
                "parts (the digest changes if FMC changed meanwhile), or set FMC_BUNDLE_DIR."
            )
        return _result(out)

    @reg.read(title="Compare device configurations")
    async def fmc_diff_device_config(
        ctx: Context,
        a: Annotated[
            str,
            Field(
                description="Device or HA pair name/UUID (read live), or a stored export: YAML from "
                "fmc_export_device_config or the file name of one in FMC_BUNDLE_DIR"
            ),
        ],
        b: Annotated[
            str | None,
            Field(
                description="Another device or HA pair, a stored export, or a device template. Omit (or "
                "'live') when `a` is a stored export to compare it with the same device now."
            ),
        ] = None,
        b_kind: Annotated[
            Literal["auto", "device", "export", "template"],
            Field(
                description="What `b` is; auto: an export if it looks like one, else a device or HA "
                "pair, else a template"
            ),
        ] = "auto",
        sections: SectionsArg = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> ToolResult:
        """Compare two device configurations section by section and field by field: is branch B
        configured like branch A, what changed on this FTD since its export yesterday (a stored export
        vs live), or does it still match its device template. `a` and `b` are devices or HA pairs (read
        live), exports from fmc_export_device_config (YAML or an FMC_BUNDLE_DIR file name), or for `b` a
        device template (only the interfaces, policies, mode and VPN roles it defines count; its
        ${variables} take the values applied to `a`, unresolved ones match anything). Changes turn `a`
        into `b`: added, removed (with the value), changed (`fields` {path: {from, to}}) per section key
        (interface name, route, protocol, topology, policy kind), NAT rules by name or position. Device
        names, hosts and serials are not compared. Secrets are masked on both sides, so a changed
        password shows no difference. Reads only FMC."""
        app: FmcApp = get_client(ctx)
        names = select_sections(sections)
        shared: dict[str, Any] = {}
        da, warnings = await _side(app, a, "auto", domain, names, shared)
        if b is None or b.strip().lower() == "live":
            if da.get("meta", {}).get("exported_at") == "live":
                raise InvalidRequest(
                    "Pass `b` (another device, an export or a template), or a stored export as `a` to "
                    "compare it with the live device."
                )
            meta_a = da.get("meta") or {}
            target = str(meta_a.get("id") or meta_a.get("device") or "")
            if not target or meta_a.get("kind") == "template":
                raise InvalidRequest("Export `a` names no device to read live; pass `b`.")
            live_sections = [
                n for n in meta_a.get("sections") or [] if n in SECTIONS and (sections is None or n in names)
            ]
            db, more = await _side(
                app, target, "device", domain or meta_a.get("domain"), live_sections, shared
            )
        else:
            db, more = await _side(app, b, b_kind, domain, names, shared, a=da)
        warnings += more
        result = diff_exports(da, db, None if sections is None else names)
        if not result["compared"]:  # never 'identical' on nothing
            why = "; ".join(f"{k}: {v}" for k, v in (result.get("not_compared") or {}).items())
            raise InvalidRequest(
                "No section was read on both sides, so there is nothing to compare"
                + (f" ({why})." if why else ".")
                + " Pick sections both sides have (a stored export keeps the ones it was exported with)."
            )
        changes = result.pop("changes")
        out: dict[str, Any] = {
            "a": _meta(da),
            "b": _meta(db),
            "identical": not changes,
            "summary": summarise(changes),
            "total": len(changes),
            **result,
            "changes": changes[offset : offset + limit],
        }
        if offset + limit < len(changes):
            out["next_offset"] = offset + limit
        if warnings:
            out["warnings"] = warnings[:20]
        text = json.dumps(out, default=str)
        while len(out["changes"]) > 1 and len(text) > max_chars():
            out["changes"] = out["changes"][: len(out["changes"]) // 2]
            out["next_offset"] = offset + len(out["changes"])
            out["truncated"] = True
            text = json.dumps(out, default=str)
        return _result(out, text)
