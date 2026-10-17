"""Policy hygiene (F42): one ranked audit of an access control policy with a proposed fix per finding."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import ToolRegistrar, UpstreamError, get_client
from fmc_mcp.catalog import Catalog, parse_ip_value, parse_port_value
from fmc_mcp.client import FmcApp
from fmc_mcp.rules import OPAQUE_CONDITIONS, flatten_access_rule, has_value
from fmc_mcp.tools.analysis import shadow_findings
from fmc_mcp.tools.common import Domain, is_system, ref_label
from fmc_mcp.tools.policies import ACCESS, all_rules, resolve_policy
from fmc_mcp.tools.troubleshoot import _parse_local, rule_hits

Check = Literal[
    "shadowed",
    "permissive",
    "no_intrusion",
    "no_logging",
    "disabled",
    "unused",
    "duplicate_objects",
    "expired_time_ranges",
    "consolidation",
]
ALL_CHECKS: tuple[str, ...] = Check.__args__  # type: ignore[attr-defined]
SEVERITY = {"high": 0, "medium": 1, "low": 2, "info": 3}
ALLOWING = {"ALLOW", "TRUST"}
CONDITION_FIELDS = (
    "sourceZones",
    "destinationZones",
    "sourceNetworks",
    "destinationNetworks",
    "sourcePorts",
    "destinationPorts",
    *OPAQUE_CONDITIONS,
)
# Flattened-row keys two adjacent rules may differ in and still be merged into one rule.
MERGEABLE = ("src_zones", "dst_zones", "src_networks", "dst_networks", "src_ports", "dst_ports")
IGNORED_IN_COMPARE = {"index", "name", "id", "comments"}
MAX_DUPLICATE_SETS = 50

LIMITS = (
    "Offline review of this access policy's own rules: inherited rules, prefilter and NAT are not "
    "considered. Shadowing uses zones, networks and ports only (rules with layer-7 or identity "
    "conditions are skipped). Hit counts are summed across the devices and HA members the policy is "
    "assigned to; counters reset when a device reloads and packet-tracer runs count as hits. Time "
    "ranges are compared with FMC's values as UTC. Duplicate objects are checked across the domain."
)


def _idx(r: dict[str, Any]) -> int:
    i = (r.get("metadata") or {}).get("ruleIndex")
    return i if isinstance(i, int) else 1_000_000


def _ref(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "index": (r.get("metadata") or {}).get("ruleIndex"),
        "name": r.get("name"),
        "action": r.get("action"),
    }


def _call(tool: str, **kw: Any) -> str:
    args = ", ".join(f"{k}={v!r}" for k, v in kw.items())
    return f"{tool}({args})"


def _finding(check: str, severity: str, detail: str, fix: str, **extra: Any) -> dict[str, Any]:
    return {"check": check, "severity": severity, **extra, "detail": detail, "fix": fix}


# --- rule checks ----------------------------------------------------------------------------


def permissive(policy: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in rules:
        if not r.get("enabled", True) or str(r.get("action", "")).upper() not in ALLOWING:
            continue
        if any(has_value(r.get(f)) for f in CONDITION_FIELDS):
            continue
        out.append(
            _finding(
                "permissive",
                "high",
                f"{r.get('action')} with no conditions: any zone, network, port, application and user.",
                "Narrow it to the zones, networks and ports it is meant for: "
                + _call(
                    "fmc_update_access_rule", policy=policy, rule=r.get("name"), destination_networks=["..."]
                ),
                rule=_ref(r),
            )
        )
    return out


def no_intrusion(policy: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in rules:
        if not r.get("enabled", True) or str(r.get("action", "")).upper() != "ALLOW" or r.get("ipsPolicy"):
            continue
        out.append(
            _finding(
                "no_intrusion",
                "medium",
                "Allowed traffic is not inspected by an intrusion policy.",
                _call(
                    "fmc_update_access_rule",
                    policy=policy,
                    rule=r.get("name"),
                    intrusion_policy="Balanced Security and Connectivity",
                ),
                rule=_ref(r),
            )
        )
    return out


def no_logging(policy: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in rules:
        action = str(r.get("action", "")).upper()
        if not r.get("enabled", True) or action == "MONITOR" or r.get("logBegin") or r.get("logEnd"):
            continue
        out.append(
            _finding(
                "no_logging",
                "low",
                "No connection events are logged for this rule.",
                _call("fmc_update_access_rule", policy=policy, rule=r.get("name"), log="end"),
                rule=_ref(r),
            )
        )
    return out


def disabled(policy: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _finding(
            "disabled",
            "info",
            "Disabled rule: it is kept in the policy but never evaluated.",
            "Delete it if it is no longer needed: "
            + _call("fmc_delete_access_rule", policy=policy, rule=r.get("name")),
            rule=_ref(r),
        )
        for r in rules
        if not r.get("enabled", True)
    ]


def shadowed(policy: str, cat: Catalog, rules: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    found, _, skipped = shadow_findings(cat, rules)
    out = []
    for f in found:
        rule, by = f["rule"], f["covered_by"]
        brief = {"index": rule["index"], "name": rule["name"], "action": rule["action"]}
        if f["kind"] == "shadowed":
            out.append(
                _finding(
                    "shadowed",
                    "high",
                    f"Never matches: rule {by['index']} {by['name']!r} ({by['action']}) takes all of its "
                    f"traffic with a different action.",
                    "Move it above the covering rule if its action is intended, otherwise delete it: "
                    + _call("fmc_update_access_rule", policy=policy, rule=rule["name"], move_to=by["index"]),
                    rule=brief,
                    covered_by=by["name"],
                )
            )
        else:
            out.append(
                _finding(
                    "shadowed",
                    "medium",
                    f"Redundant: rule {by['index']} {by['name']!r} already allows all of its "
                    "traffic with the same action.",
                    _call("fmc_delete_access_rule", policy=policy, rule=rule["name"]),
                    rule=brief,
                    covered_by=by["name"],
                )
            )
    return out, skipped


def consolidation(policy: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Adjacent enabled rules that are identical except for one mergeable condition."""
    enabled = [r for r in sorted(rules, key=_idx) if r.get("enabled", True)]
    out = []
    for a, b in zip(enabled, enabled[1:], strict=False):
        ma, mb = a.get("metadata") or {}, b.get("metadata") or {}
        if (ma.get("section"), ma.get("category")) != (mb.get("section"), mb.get("category")):
            continue
        fa = {k: v for k, v in flatten_access_rule(a).items() if k not in IGNORED_IN_COMPARE}
        fb = {k: v for k, v in flatten_access_rule(b).items() if k not in IGNORED_IN_COMPARE}
        diff = [k for k in fa.keys() | fb.keys() if _norm(fa.get(k)) != _norm(fb.get(k))]
        if len(diff) != 1 or diff[0] not in MERGEABLE or fa.get(diff[0]) is None or fb.get(diff[0]) is None:
            continue  # one side 'any' means the other is covered: the shadowed check reports that
        key = diff[0]
        merged = sorted({*fa[key], *fb[key]})
        param = _PARAM[key]
        out.append(
            _finding(
                "consolidation",
                "info",
                f"Rules {ma.get('ruleIndex')} and {mb.get('ruleIndex')} differ only in {key}: "
                f"{fa[key]} vs {fb[key]}.",
                "Merge into one rule, then delete the second: "
                + _call("fmc_update_access_rule", policy=policy, rule=a.get("name"), **{param: merged})
                + "; "
                + _call("fmc_delete_access_rule", policy=policy, rule=b.get("name")),
                rule=_ref(a),
                merge_with=b.get("name"),
            )
        )
    return out


_PARAM = {
    "src_zones": "source_zones",
    "dst_zones": "destination_zones",
    "src_networks": "source_networks",
    "dst_networks": "destination_networks",
    "src_ports": "source_ports",
    "dst_ports": "destination_ports",
}


def _norm(v: Any) -> Any:
    return sorted(map(str, v)) if isinstance(v, list) else v


# --- objects --------------------------------------------------------------------------------


def _object_key(cat: Catalog, o: dict[str, Any]) -> tuple[Any, ...] | None:
    """A comparable value for an object; None when it can't be compared (FQDN, unknown)."""
    typ = str(o.get("type", "")).lower()
    if typ == "networkgroup":
        nets = cat.networks(o)
        return ("network_group", *sorted(set(nets))) if nets else None
    if typ == "portobjectgroup":
        ports = cat.ports(o)
        return ("port_group", *sorted(set(ports))) if ports else None
    if typ in ("host", "network", "range"):
        nets = parse_ip_value(str(o.get("value") or ""))
        return ("network", *sorted(set(nets))) if nets else None
    if typ == "protocolportobject":
        try:
            return ("port", parse_port_value(o.get("protocol"), o.get("port")))
        except ValueError:
            return None
    if "icmp" in typ:
        return ("icmp", typ, str(o.get("icmpType")), str(o.get("code")))
    return None


def _used_ids(rules: list[dict[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for r in rules:
        for f in CONDITION_FIELDS:
            block = r.get(f)
            if isinstance(block, dict):
                ids |= {str(o["id"]) for o in block.get("objects") or [] if o.get("id")}
    return ids


def duplicate_objects(cat: Catalog, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for o in cat.objects.values():
        if is_system(o):
            continue
        key = _object_key(cat, o)
        if key is not None:
            groups.setdefault(key, []).append(o)
    used = _used_ids(rules)
    out = []
    for key, objs in groups.items():
        if len(objs) < 2:
            continue
        objs.sort(key=lambda o: (o.get("id") not in used, str(o.get("name"))))
        keep, rest = objs[0], objs[1:]
        names = [str(o.get("name")) for o in objs]
        out.append(
            _finding(
                "duplicate_objects",
                "low",
                f"{len(objs)} {key[0].replace('_', ' ')} objects with the same value: {', '.join(names)}.",
                f"Keep {keep.get('name')!r}; check each other with fmc_where_used, repoint its "
                "references, then "
                + "; ".join(_call("fmc_delete_object", object=o.get("name")) for o in rest),
                objects=names,
                used_in_policy=[str(o.get("name")) for o in objs if o.get("id") in used],
            )
        )
    out.sort(key=lambda f: (not f["used_in_policy"], f["objects"][0]))
    return out[:MAX_DUPLICATE_SETS]


def _end_time(o: dict[str, Any]) -> datetime | None:
    v = str(o.get("effectiveEndDateTime") or "").strip()
    if not v:
        return None
    try:
        t = datetime.fromisoformat(v.rstrip("Z"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _time_ranges_of(r: dict[str, Any]) -> list[dict[str, Any]]:
    """A rule's time range references: FMC sends a plain list (older exports used {objects: [...]})."""
    block = r.get("timeRangeObjects")
    refs = block.get("objects") if isinstance(block, dict) else block
    return [ref for ref in refs or [] if isinstance(ref, dict)]


def expired_time_ranges(
    policy: str, time_ranges: list[dict[str, Any]], rules: list[dict[str, Any]], now: datetime
) -> list[dict[str, Any]]:
    expired = {}
    for o in time_ranges:
        end = _end_time(o)
        if end is not None and end < now:
            expired[str(o.get("id"))] = (o, end)
    out = []
    referenced: set[str] = set()
    for r in rules:
        if not r.get("enabled", True):
            continue
        for ref in _time_ranges_of(r):
            hit = expired.get(str(ref.get("id")))
            if not hit:
                continue
            referenced.add(str(ref.get("id")))
            out.append(
                _finding(
                    "expired_time_ranges",
                    "medium",
                    f"Uses time range {hit[0].get('name')!r}, which ended {hit[1]:%Y-%m-%d %H:%M}: the "
                    "rule no longer matches anything.",
                    "Delete the rule if the window is over, or extend the time range in FMC: "
                    + _call("fmc_delete_access_rule", policy=policy, rule=r.get("name")),
                    rule=_ref(r),
                    time_range=hit[0].get("name"),
                )
            )
    for oid, (o, end) in expired.items():
        if oid in referenced:
            continue
        out.append(
            _finding(
                "expired_time_ranges",
                "low",
                f"Time range {o.get('name')!r} ended {end:%Y-%m-%d %H:%M}.",
                "Delete it if nothing else uses it (fmc_where_used), or extend it in FMC.",
                time_range=o.get("name"),
            )
        )
    return out


# --- hit counts -----------------------------------------------------------------------------


async def assigned_devices(
    app: FmcApp, policy_id: str, domain: str | None
) -> tuple[list[tuple[str, str]], list[str]]:
    """(device id, label) for every device the policy is deployed to, HA pairs expanded to both
    members; plus notes for targets that can't be read (clusters)."""
    page = await app.all(await app.config_path("assignment/policyassignments", domain), cap=5000)
    devices: list[tuple[str, str]] = []
    notes: list[str] = []
    for a in page.items:
        if (a.get("policy") or {}).get("id") != policy_id:
            continue
        for t in a.get("targets") or []:
            typ = str(t.get("type", ""))
            if typ == "Device":
                devices.append((str(t["id"]), ref_label(t)))
            elif typ == "DeviceHAPair":
                ha = await app.api.get(
                    await app.config_path(f"devicehapairs/ftddevicehapairs/{t['id']}", domain)
                )
                for role in ("primary", "secondary"):
                    m = (ha or {}).get(role) or {}
                    if m.get("id"):
                        devices.append((str(m["id"]), f"{ref_label(t)}/{ref_label(m)}"))
            else:
                notes.append(f"Hit counts of {typ} {ref_label(t)!r} were not read.")
    return devices, notes


async def unused(
    ctx: Context,
    app: FmcApp,
    policy: dict[str, Any],
    rules: list[dict[str, Any]],
    days: int,
    refresh: bool,
    domain: str | None,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Enabled rules with no hits on any assigned device (ever, or in the last `days`)."""
    devices, notes = await assigned_devices(app, policy["id"], domain)
    if not devices:
        return [], [], notes + ["The policy is not assigned to a device: unused rules can't be judged."]
    enabled = [r for r in rules if r.get("enabled", True)]
    if not enabled:  # FMC answers 500 to a hit-count query without rule ids
        return [], [label for _, label in devices], notes
    hc_path = await app.config_path(f"{ACCESS}/{policy['id']}/operational/hitcounts", domain)
    total: dict[str, int] = {}
    latest: dict[str, datetime] = {}
    for dev_id, label in devices:
        try:
            hits, _, dev_notes = await rule_hits(
                ctx,
                app,
                hc_path,
                [r["id"] for r in enabled],
                dev_id,
                domain,
                refresh=refresh,
                include_default=False,
            )
        except UpstreamError as e:
            notes.append(f"Hit counts of {label} could not be read ({e}).")
            continue
        notes += [f"{label}: {n}" for n in dev_notes]
        for rid, h in hits.items():
            total[rid] = total.get(rid, 0) + int(h.get("hitCount") or 0)
            t = _parse_local(h.get("lastHitTimeStamp"))
            if t is not None:
                if app.local_offset is not None:
                    t = datetime.fromtimestamp(t.timestamp() - app.local_offset, UTC)
                if rid not in latest or t > latest[rid]:
                    latest[rid] = t
    cutoff = time.time() - days * 86400
    out = []
    for r in enabled:
        rid = str(r["id"])
        if rid not in total:
            continue
        name = r.get("name")
        if total[rid] == 0:
            detail = f"Never hit on {len(devices)} device(s)."
        elif rid in latest and latest[rid].timestamp() < cutoff:
            detail = f"No hits in {days} days (last {latest[rid]:%Y-%m-%d})."
        else:
            continue
        out.append(
            _finding(
                "unused",
                "low",
                detail,
                "Confirm it isn't needed for rare traffic (backups, DR, quarterly jobs), then disable it "
                "for a cycle before deleting: "
                + _call("fmc_update_access_rule", policy=policy.get("name"), rule=name, enabled=False),
                rule=_ref(r),
                hits=total[rid],
            )
        )
    return out, [label for _, label in devices], notes


# --- tool -----------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Audit an access policy")
    async def fmc_policy_audit(
        ctx: Context,
        policy: Annotated[str, Field(description="Access control policy name or UUID")],
        checks: Annotated[
            list[Check] | None,
            Field(description="Checks to run (default: all). 'unused' reads hit counts from the devices."),
        ] = None,
        unused_days: Annotated[
            int, Field(ge=1, le=3650, description="'unused': rules with no hits in this many days")
        ] = 90,
        refresh_hits: Annotated[
            bool,
            Field(
                description="'unused': pull fresh hit counters from each device first (a few seconds each)"
            ),
        ] = True,
        max_findings: Annotated[
            int, Field(ge=1, le=500, description="Findings to return, highest severity first")
        ] = 200,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Review an access control policy the way a firewall audit does and rank what to fix:
        shadowed (never matches, high) and redundant rules, any-any allow rules, allow rules without an
        intrusion policy, rules that log nothing, disabled rules, rules with no hits in N days on the
        devices the policy is deployed to, rules on expired time ranges, duplicate objects (same value,
        different names) and adjacent rules that could be merged. Each finding carries a proposed fix as
        a tool call to preview; nothing is changed. Use fmc_shadowed_rules for just the shadowing check."""
        app: FmcApp = get_client(ctx)
        wanted = set(checks or ALL_CHECKS)
        p = await resolve_policy(app, "access", policy, domain)
        name = str(p.get("name"))
        page = await all_rules(app, await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain))
        rules = page.items
        findings: list[dict[str, Any]] = []
        notes: list[str] = []
        complete = page.complete
        out: dict[str, Any] = {"policy": name, "rules": len(rules)}

        if wanted & {"shadowed", "duplicate_objects"}:
            cat = Catalog(app, domain)
            await cat.load_networks()
            await cat.load_ports()
            complete = complete and cat.complete
            if "shadowed" in wanted:
                found, skipped = shadowed(name, cat, rules)
                findings += found
                if skipped:
                    notes.append(
                        f"{skipped} rule(s) skipped by the shadowing check (FQDN or unresolvable objects)."
                    )
            if "duplicate_objects" in wanted:
                findings += duplicate_objects(cat, rules)
        if "permissive" in wanted:
            findings += permissive(name, rules)
        if "no_intrusion" in wanted:
            findings += no_intrusion(name, rules)
        if "no_logging" in wanted:
            findings += no_logging(name, rules)
        if "disabled" in wanted:
            findings += disabled(name, rules)
        if "consolidation" in wanted:
            findings += consolidation(name, rules)
        if "expired_time_ranges" in wanted and any(has_value(r.get("timeRangeObjects")) for r in rules):
            tr = await app.all(await app.config_path("object/timeranges", domain), cap=5000)
            findings += expired_time_ranges(name, tr.items, rules, datetime.now(UTC))
        if "unused" in wanted:
            found, devices, hit_notes = await unused(ctx, app, p, rules, unused_days, refresh_hits, domain)
            findings += found
            notes += hit_notes
            out["hit_counts_from"] = devices

        findings.sort(key=lambda f: (SEVERITY[f["severity"]], (f.get("rule") or {}).get("index") or 10**6))
        counts: dict[str, int] = {}
        for f in findings:
            counts[f["check"]] = counts.get(f["check"], 0) + 1
        out["summary"] = {
            "findings": len(findings),
            "by_severity": {s: n for s in SEVERITY if (n := sum(f["severity"] == s for f in findings))},
            "by_check": counts,
            "checks_run": [c for c in ALL_CHECKS if c in wanted],
        }
        out["findings"] = findings[:max_findings]
        if len(findings) > max_findings:
            notes.append(
                f"Showing the first {max_findings} of {len(findings)} findings (highest severity first)."
            )
        if not findings:
            out["summary"]["verdict"] = "No findings."
        if not complete:
            out["warning"] = (
                "Policy or object collections were larger than the scan cap; results are partial."
            )
        if notes:
            out["notes"] = notes
        out["limits"] = LIMITS
        return out
