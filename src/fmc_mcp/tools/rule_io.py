"""Access rule export and import (F23): every rule of a policy as rows that fmc_import_access_rules accepts
back, and bulk creation of reviewed rows (validated and resolved in the preview, posted in chunks)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import csv
import io
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import BaseModel, Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
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
from fmc_mcp.refs import RefResolver
from fmc_mcp.tools.common import Domain, proto_name, ref_label, resolve_in
from fmc_mcp.tools.policies import ACCESS, all_rules, resolve_policy
from fmc_mcp.tools.policy_writes import BLOCKING, LogMode, RuleAction, _conditions, _log_fields

CHUNK = 100  # rules per bulk POST (FMC accepts up to 1000; smaller chunks fail smaller)
MAX_IMPORT = 500

# exported column -> (import parameter of _conditions, FMC field)
CONDITIONS = {
    "src_zones": ("source_zones", "sourceZones"),
    "dst_zones": ("destination_zones", "destinationZones"),
    "src_networks": ("source_networks", "sourceNetworks"),
    "dst_networks": ("destination_networks", "destinationNetworks"),
    "src_ports": ("source_ports", "sourcePorts"),
    "dst_ports": ("destination_ports", "destinationPorts"),
    "urls": ("urls", "urls"),
    "src_dynamic": ("source_dynamic_objects", "sourceDynamicObjects"),
    "dst_dynamic": ("destination_dynamic_objects", "destinationDynamicObjects"),
}
# conditions the importer can't rebuild (exported so a reviewer sees them; such rows are refused on import)
UNSUPPORTED = {
    "applications": "applications",
    "users": "users",
    "vlan_tags": "vlanTags",
    "src_sgts": "sourceSecurityGroupTags",
    "dst_sgts": "destinationSecurityGroupTags",
}
COLUMNS = [
    "index",
    "section",
    "name",
    "action",
    "enabled",
    *CONDITIONS,
    "intrusion_policy",
    "log",
    *UNSUPPORTED,
]


def literal_label(ref: dict[str, Any]) -> str:
    """Labels the importer parses back: tcp/443, udp/1000-2000, icmp, icmp/8, 10.1.1.0/24, URLs."""
    if ref.get("name"):
        return str(ref["name"])
    if "value" in ref:
        return str(ref["value"])
    if ref.get("url"):
        return str(ref["url"])
    if "protocol" in ref:
        proto = proto_name(ref.get("protocol")).lower()
        if ref.get("icmpType") not in (None, "Any"):
            return f"{proto}/{ref['icmpType']}"
        return f"{proto}/{ref['port']}" if ref.get("port") else proto
    return ref_label(ref)


def labels(block: Any) -> list[str]:
    if isinstance(block, list):
        return [literal_label(r) for r in block]
    if not isinstance(block, dict):
        return []
    return [literal_label(r) for r in (block.get("objects") or []) + (block.get("literals") or [])]


def export_row(r: dict[str, Any]) -> dict[str, Any]:
    meta = r.get("metadata") or {}
    log = (
        "begin_and_end"
        if r.get("logBegin") and r.get("logEnd")
        else "end"
        if r.get("logEnd")
        else ("begin" if r.get("logBegin") else "none")
    )
    row: dict[str, Any] = {
        "index": meta.get("ruleIndex"),
        "section": str(meta.get("section") or "").lower() or None,
        "name": r.get("name"),
        "action": r.get("action"),
        "enabled": r.get("enabled"),
    }
    for col, (_, field) in CONDITIONS.items():
        row[col] = labels(r.get(field)) or None
    row["intrusion_policy"] = (r.get("ipsPolicy") or {}).get("name")
    row["log"] = log
    for col, field in UNSUPPORTED.items():
        row[col] = (
            labels(r.get(field))
            or [ref_label(a) for a in (r.get(field) or {}).get("applications") or []]
            or None
        )
    return {k: v for k, v in row.items() if v not in (None, [])}


def to_csv(rows: list[dict[str, Any]]) -> str:
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=COLUMNS, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({k: ";".join(map(str, v)) if isinstance(v, list) else v for k, v in r.items()})
    return out.getvalue()


class RuleRow(BaseModel):
    """One rule to import (the export's row format)."""

    name: str = Field(min_length=1, max_length=50)
    action: RuleAction
    enabled: bool = True
    section: Literal["mandatory", "default"] | None = None
    src_zones: list[str] | None = None
    dst_zones: list[str] | None = None
    src_networks: list[str] | None = None
    dst_networks: list[str] | None = None
    src_ports: list[str] | None = None
    dst_ports: list[str] | None = None
    urls: list[str] | None = None
    src_dynamic: list[str] | None = None
    dst_dynamic: list[str] | None = None
    intrusion_policy: str | None = None
    log: Literal["none", "begin", "end", "begin_and_end"] = "end"
    applications: list[str] | None = None
    users: list[str] | None = None
    vlan_tags: list[str] | None = None
    src_sgts: list[str] | None = None
    dst_sgts: list[str] | None = None
    index: int | None = None


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Export access rules")
    async def fmc_export_access_rules(
        ctx: Context,
        policy: Annotated[str, Field(description="Access control policy name or UUID")],
        format: Annotated[Literal["rows", "csv"], Field(description="rows (JSON) or one CSV text")] = "rows",
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 1000,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """Every rule of an access policy in order, as flat rows with object names and literals (tcp/443,
        icmp/8, 10.1.0.0/16) that fmc_import_access_rules accepts back: for reviews, audits, diffs and
        migrations. CSV joins list values with ';'. Applications, users, VLAN tags and SGTs are exported
        but can't be imported."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        page = await all_rules(app, await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain))
        rows = [export_row(r) for r in page.items]
        if format == "csv":
            return object_result(
                {"policy": p.get("name"), "rules": len(rows), "csv": to_csv(rows), "complete": page.complete},
                fmt=response_format,
            )
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, extra={"policy": p.get("name")}
        )

    @reg.write(title="Import access rules")
    async def fmc_import_access_rules(
        ctx: Context,
        policy: Annotated[str, Field(description="Access control policy to add the rules to (name or UUID)")],
        rules: Annotated[
            list[RuleRow],
            Field(
                min_length=1, max_length=MAX_IMPORT, description="Rules in order, in the export's row format"
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Append many access rules at once, in order, to the end of their section (Default unless a row
        says mandatory). The preview resolves every object and literal and lists each row's problems
        (unknown objects, duplicate names, unsupported conditions); nothing is created while any row has
        one. Rules are posted with FMC's bulk API in chunks of 100. Deploy to take effect."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        base = await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain)
        existing = await all_rules(app, base)
        taken = {str(r.get("name", "")).lower() for r in existing.items}
        resolver = RefResolver(app, domain)
        problems: list[str] = []
        bodies: dict[str, list[dict[str, Any]]] = {"mandatory": [], "default": []}
        seen: set[str] = set()
        ips_cache: dict[str, dict[str, Any]] = {}
        for n, row in enumerate(rules, 1):
            where = f"row {n} ({row.name!r})"
            unsupported = [c for c in UNSUPPORTED if getattr(row, c)]
            if unsupported:
                problems.append(f"{where}: can't import {', '.join(unsupported)}; create it with the FMC UI.")
                continue
            if row.name.lower() in taken or row.name.lower() in seen:
                problems.append(f"{where}: a rule with that name already exists.")
            seen.add(row.name.lower())
            body: dict[str, Any] = {
                "name": row.name,
                "type": "AccessRule",
                "action": row.action,
                "enabled": row.enabled,
            }
            try:
                conds = await _conditions(
                    resolver, {param: getattr(row, col) for col, (param, _) in CONDITIONS.items()}
                )
            except (InvalidRequest, UpstreamError) as e:
                problems.append(f"{where}: {e}")
                continue
            body.update({k: v for k, v in conds.items() if v})
            # begin-only logging: block rules log at the start anyway; others log begin and end
            log: LogMode = (
                ("end" if row.action in BLOCKING else "begin_and_end") if row.log == "begin" else row.log
            )
            body.update(_log_fields(log, row.action))
            if row.intrusion_policy:
                if row.action != "ALLOW":
                    problems.append(f"{where}: an intrusion policy needs action ALLOW.")
                    continue
                key = row.intrusion_policy.lower()
                if key not in ips_cache:
                    try:
                        ips_cache[key] = await resolve_in(
                            app, "policy/intrusionpolicies", row.intrusion_policy, "intrusion policy", domain
                        )
                    except UpstreamError as e:
                        problems.append(f"{where}: {e}")
                        continue
                ips = ips_cache[key]
                body["ipsPolicy"] = {"id": ips["id"], "type": "IntrusionPolicy", "name": ips.get("name")}
            bodies[row.section or "default"].append(body)

        async def apply() -> Any:
            created: list[str] = []
            for section, items in bodies.items():
                for i in range(0, len(items), CHUNK):
                    chunk = items[i : i + CHUNK]
                    try:
                        await app.api.post(base, chunk, params={"bulk": "true", "section": section})
                    except UpstreamError as e:
                        raise UpstreamError(
                            f"Import stopped: {len(created)} rules created "
                            f"(last: {', '.join(created[-5:]) or 'none'}); "
                            f"chunk starting at {chunk[0]['name']!r} failed: {e}",
                            e.status_code,
                        ) from e
                    created += [b["name"] for b in chunk]
            app.invalidate_cache()
            return {"policy": p.get("name"), "created": len(created), "next": "fmc_deploy to take effect"}

        total = sum(len(v) for v in bodies.values())
        return await fmc_preview(
            ctx,
            tool="fmc_import_access_rules",
            args={
                "policy": policy,
                "rules": [r.model_dump(exclude_none=True) for r in rules],
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Import {total} access rules into {p.get('name')!r}",
                details={
                    "rules_now": len(existing.items),
                    "by_section": {k: len(v) for k, v in bodies.items() if v},
                    "first": [b["name"] for b in (bodies["mandatory"] + bodies["default"])[:10]],
                    "problems": problems or None,
                },
                fingerprint={"policy": p["id"], "rules": [r.get("id") for r in existing.items]},
                blockers=problems[:20] + (["...and more problems"] if len(problems) > 20 else []),
                blast_radius=total,
                side_effects=["Rules are appended to the end of their section; takes effect after a deploy."],
            ),
            apply=apply,
        )
