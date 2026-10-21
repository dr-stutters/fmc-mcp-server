"""Pre/post-change device snapshots (F73): what each FTD runs right now, as F72's device export with state
sections, captured for several devices at once, and compared with fmc_diff_device_config.

State sections (kind "state" in device_export's registry, so `sections=['state']` on the export and diff
tools reads them too):

    route_table:     {<prefix>: {protocol, code, via, interfaces}}       show route (IPv4, global table)
    interface_state: {<interface>: {ip, status, protocol, method}}       show interface ip brief
    failover:        {<unit>: {role, state, mate_state, ...}}            show failover state (HA units)
    vpn_sas:         {total: {ike_sas, ipsec_sas}, ike <local> -> <remote>: {state, ...}}
                                                                          show crypto ikev2 sa
    tunnels:         {<topology>: <peer a> <-> <peer b>: {state, message}}  FMC's tunnel monitor
    hit_counts:      {<rule>: {hits, last_hit}}                           access policy hit counts
    health_alerts:   {<module>: {status, details}}                        FMC health alerts, not green
    deployment:      {status, deployed_version, last_job, ..., pending}   job history + deployable list
    running_config:  {<section>: [lines]}                                 show running-config <section>

An HA pair's per-unit sections key each item by unit ('mcp-fw-ha-a: 198.51.100.0/24'). Show commands go
through F68's fleet runner: `fmc_device_snapshot` runs each command once for every device (FMC's
bulkcommands where FMC enables it, else one request per device, eight at a time) before the per-device
FMC reads. Volatile values are left out (route ages, SA lifetimes and SPIs, alert timestamps, tunnel
change times), so two snapshots of an unchanged device compare identical; hit-count changes, and a
health message whose only change is a reading (a CPU or memory percentage, a disk size), are reported
as deltas, never as a difference (traffic and load move them all the time).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import difflib
import json
import re
from functools import partial
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import InvalidRequest, ToolRegistrar, UpstreamError, get_client
from fmc_mcp._core.formatting import max_chars
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.bundle import field_delta, finish, write_file
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.deploy import DEPLOYABLE, JOBS, deployable_row
from fmc_mcp.tools.device_export import (
    ExportContext,
    _put,
    _sorted,
    assigned,
    counts,
    export_section,
    export_target,
    mask_cli,
    resolve_target,
    select_sections,
)
from fmc_mcp.tools.device_groups import expand_devices
from fmc_mcp.tools.devices import DEVICES, membership_of
from fmc_mcp.tools.fleet import MAX_FLEET, run_fleet
from fmc_mcp.tools.ha import parse_failover_state
from fmc_mcp.tools.policies import ACCESS, all_rules
from fmc_mcp.tools.show_commands import check_command
from fmc_mcp.tools.system import iso
from fmc_mcp.tools.troubleshoot import redact, rule_hits, to_utc, tunnel_row
from fmc_mcp.tools.vpn_status import parse_ikev2_sa, parse_routes

ROUTES = "show route"
INTERFACES = "show interface ip brief"
IKE_SAS = "show crypto ikev2 sa"
FAILOVER = "show failover state"
RUNNING = "show running-config"
TUNNELS = "health/tunnelstatuses"
ALERTS = "health/alerts"
SHOW = "show"  # ExportContext.shared key: {(unit id lower case, command): (ok, output or error)}
JOB_ROWS = 5  # deployment jobs read per device (newest first) to find the last successful one
MAX_LABEL = 60
# Per-unit show commands of each section; failover runs on HA units only.
SECTION_COMMANDS = {"route_table": ROUTES, "interface_state": INTERFACES, "vpn_sas": IKE_SAS}
SNAPSHOT_DEFAULT = ("device", "policies")  # the cheap config sections a snapshot adds to the state ones
# Readings in a health module's message: a percentage, a size, a time of day ('Data Path average is
# 0.12%', '/ngfw using 4%: 2.2G (55G Avail) of 61G', '35.86%'). Interface names (Ethernet0/2), addresses,
# versions with more than one dot and plain counts are not readings, so a change in them still counts.
_READING = re.compile(
    r"(?<![\w/.:])(?:\d+:\d{2}(?::\d{2})?|\d+(?:\.\d+)?\s?(?:%|[KMGT]i?B?\b)|\d+\.\d+)(?![\w/.:]*\d)"
)


# --- show output, per unit ------------------------------------------------------------------------


def command_text(command: str) -> str:
    return " ".join(command.split())


def unit_records(device: dict[str, Any], ha: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The devices a state section reads: both units of an HA pair (the primary's full record, the
    secondary as {id, name}; named as the pair names them), else the device."""
    if not ha:
        return [device]
    out = []
    for side in ("primary", "secondary"):
        u = ha.get(side) or {}
        if not u.get("id"):
            continue
        if str(u["id"]).lower() == str(device.get("id")).lower():
            out.append({**device, "name": u.get("name") or device.get("name")})
        else:
            out.append({"id": u["id"], "name": u.get("name") or u["id"]})
    return out or [device]


def units(ctx: ExportContext) -> list[dict[str, Any]]:
    return unit_records(ctx.device, ctx.ha)


def prefix(ctx: ExportContext, unit: dict[str, Any]) -> str:
    """'unit: ' before an HA pair's per-unit keys; nothing for a device."""
    return f"{unit.get('name')}: " if ctx.ha else ""


def in_ha(device: dict[str, Any], ha: dict[str, Any] | None) -> bool:
    """An HA pair, or one unit of one named directly (FMC's containerDetails on the record)."""
    if ha:
        return True
    member = membership_of(device)
    return member is not None and member.kind == "ha"


def remember(shared: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    cache: dict[tuple[str, str], tuple[bool, str]] = shared.setdefault(SHOW, {})
    for row in rows:
        cache[(str(row["id"]).lower(), command_text(row["command"]))] = (
            bool(row["ok"]),
            str(row.get("text") if row["ok"] else row.get("error") or ""),
        )


async def outputs(
    ctx: ExportContext, command: str, targets: list[dict[str, Any]] | None = None
) -> list[tuple[dict[str, Any], str]]:
    """(unit, output) of one show command on each unit: from the snapshot's prefetch, else run now
    through the fleet runner. A unit that failed fails the section (UpstreamError naming it), so a diff
    reports the section as not compared rather than every item as lost."""
    text = command_text(command)
    todo = targets if targets is not None else units(ctx)
    cache: dict[tuple[str, str], tuple[bool, str]] = ctx.shared.setdefault(SHOW, {})
    missing = [u for u in todo if (str(u["id"]).lower(), text) not in cache]
    if missing:
        if ctx.mcp is None:
            raise UpstreamError(f"'{text}' needs a tool call's context to run on the device.")
        run = await run_fleet(ctx.mcp, ctx.app, missing, [text], ctx.domain)
        remember(ctx.shared, run.rows)
        ctx.warnings += [n for n in run.notes if n not in ctx.warnings]
    got, failed = [], []
    for u in todo:
        ok, out = cache[(str(u["id"]).lower(), text)]
        if ok:
            got.append((u, out))
        else:
            failed.append(f"{u.get('name')}: {out}")
    if failed:
        raise UpstreamError(f"'{text}' failed on " + "; ".join(failed))
    return got


# --- parsing --------------------------------------------------------------------------------------

_IP_BRIEF = re.compile(
    r"^(?P<name>\S+)\s+(?P<ip>\S+)\s+(?P<ok>YES|NO)\s+(?P<method>\S+)\s+"
    r"(?P<status>administratively down|up|down|deleted)\s+(?P<protocol>up|down)\s*$"
)


def parse_ip_brief(text: str) -> list[dict[str, Any]]:
    """`show interface ip brief` rows, FTD's internal interfaces (Internal-Control/-Data) left out."""
    rows = []
    for line in text.splitlines():
        m = _IP_BRIEF.match(line.strip())
        if not m or m["name"].lower().startswith("internal-"):
            continue
        rows.append(
            {
                "interface": m["name"],
                "ip": m["ip"],
                "method": m["method"],
                "status": m["status"],
                "protocol": m["protocol"],
            }
        )
    return rows


def running_lines(text: str) -> list[str]:
    """`show running-config <section>` as lines, secrets masked (F72's CLI masking, which skips key ids,
    hashes and formats, then the show-command redaction), blank and '!' lines dropped."""
    out = []
    for line in text.replace("\r", "").splitlines():
        s = line.rstrip()
        if s.strip() and s.strip() != "!":
            out.append(redact(mask_cli(s))[0])
    return out


# --- explaining changes ---------------------------------------------------------------------------


def _v(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(map(str, value)) or "none"
    return "none" if value in (None, "") else str(value)


def _fields(change: dict[str, Any]) -> str:
    return "; ".join(f"{p} {_v(f.get('from'))} -> {_v(f.get('to'))}" for p, f in change["fields"].items())


def _route(v: dict[str, Any]) -> str:
    via = f" via {_v(v['via'])}" if v.get("via") else ""
    on = f" on {_v(v['interfaces'])}" if v.get("interfaces") else ""
    return f"{v.get('protocol')}{via}{on}"


def explain_route(c: dict[str, Any]) -> str | None:
    if c["op"] == "removed":
        return f"route lost: {c['key']} ({_route(c['value'])})"
    if c["op"] == "added":
        return f"route added: {c['key']} ({_route(c['value'])})"
    return f"route changed: {c['key']}: {_fields(c)}"


def explain_interface(c: dict[str, Any]) -> str | None:
    if c["op"] == "removed":
        return f"interface {c['key']} is no longer listed (was {c['value'].get('status')})"
    if c["op"] == "added":
        return f"interface {c['key']} appeared ({c['value'].get('status')}/{c['value'].get('protocol')})"
    return f"interface {c['key']}: {_fields(c)}"


def explain_failover(c: dict[str, Any]) -> str | None:
    if c["op"] == "changed":
        return f"failover {c['key']}: {_fields(c)}"
    return f"failover {c['key']}: {'appeared' if c['op'] == 'added' else 'no longer reported'}"


def explain_sas(c: dict[str, Any]) -> str | None:
    if c["key"] == "total" and c["op"] == "changed":
        return f"VPN SA counts: {_fields(c)}"
    if c["op"] == "removed":
        return f"IKEv2 SA lost: {c['key']} (was {c['value'].get('state')})"
    if c["op"] == "added":
        return f"IKEv2 SA up: {c['key']} ({c['value'].get('state')})"
    return f"IKEv2 SA {c['key']}: {_fields(c)}"


def explain_tunnel(c: dict[str, Any]) -> str | None:
    if c["op"] == "changed":
        return f"tunnel {c['key']}: {_fields(c)}"
    if c["op"] == "added":
        return f"tunnel {c['key']} appeared ({c['value'].get('state')})"
    return f"tunnel {c['key']} is no longer monitored (was {c['value'].get('state')})"


def explain_alert(c: dict[str, Any]) -> str | None:
    if c["op"] == "delta":
        return f"health alert {c['key']} reading: {c['from']} -> {c['to']}"
    if c["op"] == "added":
        return f"new health alert {c['key']} ({c['value'].get('status')}): {c['value'].get('details')}"
    if c["op"] == "removed":
        return f"health alert cleared: {c['key']} (was {c['value'].get('status')})"
    return f"health alert {c['key']}: {_fields(c)}"


def explain_deployment(c: dict[str, Any]) -> str | None:
    return f"deployment: {_fields(c)}" if c["op"] == "changed" else None


def explain_hits(c: dict[str, Any]) -> str | None:
    if c["op"] == "delta":
        note = " (counters reset, or read from the other HA unit)" if c["delta"] < 0 else ""
        return f"hit count {c['key']}: {c['from']} -> {c['to']} ({c['delta']:+d}){note}"
    if c["op"] == "added":
        return f"rule {c['key']} appeared in the hit counts"
    if c["op"] == "removed":
        return f"rule {c['key']} is gone from the hit counts"
    return f"hit counts {c['key']}: {_fields(c)}"


def explain_running(c: dict[str, Any]) -> str | None:
    sign = "+" if c["op"] == "added" else "-"
    return f"running-config {sign} {c['key']}"


# --- diffs of their own ---------------------------------------------------------------------------


def diff_hits(section: str, a: dict[str, Any], b: dict[str, Any]) -> list[dict[str, Any]]:
    """Rules added or removed are changes; a count that moved is a delta (op 'delta': from, to, delta);
    a last-hit time alone is neither."""
    out: list[dict[str, Any]] = []
    for key in sorted(set(a) | set(b), key=str):
        if key not in b:
            out.append({"section": section, "op": "removed", "key": key, "value": a[key]})
        elif key not in a:
            out.append({"section": section, "op": "added", "key": key, "value": b[key]})
        elif isinstance(a[key], dict) and "hits" in a[key] and isinstance(b[key], dict) and "hits" in b[key]:
            before, after = int(a[key]["hits"] or 0), int(b[key]["hits"] or 0)
            if before != after:
                out.append(
                    {
                        "section": section,
                        "op": "delta",
                        "key": key,
                        "from": before,
                        "to": after,
                        "delta": after - before,
                    }
                )
        elif a[key] != b[key]:
            fields = {"value": {"from": a[key], "to": b[key]}}
            out.append({"section": section, "op": "changed", "key": key, "fields": fields})
    return out


def without_readings(text: Any) -> str:
    """A health message with its readings (percentages, sizes, times) replaced by '#'."""
    return _READING.sub("#", str(text or ""))


def diff_alerts(section: str, a: dict[str, Any], b: dict[str, Any]) -> list[dict[str, Any]]:
    """Modules that turned non-green or green again and status changes are changes, and so is a message
    that says something else (another interface); a message whose only change is a reading (CPU 85.1% ->
    86.4% while YELLOW) is a delta (op 'delta': from, to), never a difference."""
    out: list[dict[str, Any]] = []
    for key in sorted(set(a) | set(b), key=str):
        if key not in b:
            out.append({"section": section, "op": "removed", "key": key, "value": a[key]})
        elif key not in a:
            out.append({"section": section, "op": "added", "key": key, "value": b[key]})
        elif a[key] != b[key]:
            va, vb = a[key], b[key]
            if (
                isinstance(va, dict)
                and isinstance(vb, dict)
                and va.get("status") == vb.get("status")
                and without_readings(va.get("details")) == without_readings(vb.get("details"))
            ):
                change = {"from": va.get("details"), "to": vb.get("details")}
                out.append({"section": section, "op": "delta", "key": key, **change})
            else:
                out.append({"section": section, "op": "changed", "key": key, "fields": field_delta(va, vb)})
    return out


def diff_lines(section: str, a: dict[str, Any], b: dict[str, Any]) -> list[dict[str, Any]]:
    """Per running-config section, the lines removed and added (in order; a moved line is both)."""
    out: list[dict[str, Any]] = []
    for key in sorted(set(a) | set(b), key=str):
        la, lb = list(a.get(key) or []), list(b.get(key) or [])
        for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=la, b=lb, autojunk=False).get_opcodes():
            if tag in ("replace", "delete"):
                out += [
                    {"section": section, "op": "removed", "key": f"{key}: {x}", "value": x} for x in la[i1:i2]
                ]
            if tag in ("replace", "insert"):
                out += [
                    {"section": section, "op": "added", "key": f"{key}: {x}", "value": x} for x in lb[j1:j2]
                ]
    return out


# --- the state sections ---------------------------------------------------------------------------


@export_section(
    "route_table",
    kind="state",
    default=False,
    summary="the device's IPv4 routing table (show route): prefix, protocol, next hops, egress interface",
    explain=explain_route,
)
async def _route_table(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for unit, text in await outputs(ctx, ROUTES):
        for r in parse_routes(text):
            row = {
                "protocol": r["protocol"],
                "code": r["code"],
                "via": sorted(r["via"]),
                "interfaces": sorted(r["interfaces"]),
            }
            _put(out, f"{prefix(ctx, unit)}{r['prefix']}", {k: v for k, v in row.items() if v})
    return _sorted(out)


@export_section(
    "interface_state",
    kind="state",
    default=False,
    summary="each interface's address, status and line protocol (show interface ip brief)",
    explain=explain_interface,
)
async def _interface_state(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for unit, text in await outputs(ctx, INTERFACES):
        for r in parse_ip_brief(text):
            _put(out, f"{prefix(ctx, unit)}{r.pop('interface')}", r)
    return _sorted(out)


@export_section(
    "failover",
    kind="state",
    default=False,
    summary="HA units: each unit's role and failover state and its mate's (show failover state)",
    explain=explain_failover,
)
async def _failover(ctx: ExportContext) -> dict[str, Any]:
    if not in_ha(ctx.device, ctx.ha):
        return {str(ctx.device.get("name")): {"state": "standalone (not in an HA pair)"}}
    out: dict[str, Any] = {}
    for unit, text in await outputs(ctx, FAILOVER):
        parsed = parse_failover_state(text).get("units") or {}
        me, mate = parsed.get("this") or {}, parsed.get("other") or {}
        row = {
            "role": me.get("role"),
            "state": me.get("state"),
            "last_failure_reason": me.get("last_failure_reason"),
            "last_failure_at": me.get("last_failure_at"),
            "mate_role": mate.get("role"),
            "mate_state": mate.get("state"),
        }
        out[str(unit.get("name"))] = {k: v for k, v in row.items() if v}
    return _sorted(out)


@export_section(
    "vpn_sas",
    kind="state",
    default=False,
    summary="IKEv2 SAs per peer and the IKE and IPsec (child) SA counts (show crypto ikev2 sa)",
    explain=explain_sas,
)
async def _vpn_sas(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for unit, text in await outputs(ctx, IKE_SAS):
        rows = parse_ikev2_sa(text)
        sessions = {r.get("session"): r.get("child_sas") or 0 for r in rows}
        out[f"{prefix(ctx, unit)}total"] = {"ike_sas": len(rows), "ipsec_sas": sum(sessions.values())}
        for r in rows:
            vrf = f" vrf {r['vrf']}" if r.get("vrf") else ""
            row = {
                k: r.get(k)
                for k in ("state", "session_status", "child_sas", "encryption", "dh_group", "auth")
            }
            _put(
                out,
                f"{prefix(ctx, unit)}ike {r['local']} -> {r['remote']}{vrf}",
                {k: v for k, v in row.items() if v is not None},
            )
    return _sorted(out)


@export_section(
    "tunnels",
    kind="state",
    default=False,
    summary="site-to-site and SD-WAN tunnels FMC monitors for the device: state and message",
    explain=explain_tunnel,
)
async def _tunnels(ctx: ExportContext) -> dict[str, Any]:
    rows = await ctx.memo("tunnels", partial(ctx.items, TUNNELS, cap=5000))
    out: dict[str, Any] = {}
    for t in rows:
        ends = {str(((t.get(side) or {}).get("device") or {}).get("id")) for side in ("peerA", "peerB")}
        if not ends & ctx.target_ids:
            continue
        row = tunnel_row(t)
        key = f"{row['topology']}: {row['peer_a']} <-> {row['peer_b']}"
        _put(out, key, {k: row[k] for k in ("state", "message") if row.get(k)})
    return _sorted(out)


async def _policy(ctx: ExportContext, policy_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The access policy (for its default action) and its rules, read once per snapshot run."""

    async def load() -> tuple[dict[str, Any], list[dict[str, Any]]]:
        base = await ctx.app.config_path(f"{ACCESS}/{policy_id}", ctx.domain)
        pol = await ctx.app.api.get(base)
        rules = (await all_rules(ctx.app, f"{base}/accessrules")).items
        return dict(pol or {}), list(rules)

    result: tuple[dict[str, Any], list[dict[str, Any]]] = await ctx.memo(f"acp:{policy_id}", load)
    return result


def counting_unit(ctx: ExportContext) -> dict[str, Any]:
    """The unit whose hit counts count: an HA pair's active unit (FMC's view), else the device."""
    if not ctx.ha:
        return ctx.device
    meta = ctx.ha.get("metadata") or {}
    state = str((meta.get("secondaryStatus") or {}).get("currentStatus") or "").lower()
    side = "secondary" if "active" in state else "primary"
    unit = ctx.ha.get(side) or {}
    return next((u for u in units(ctx) if str(u.get("id")) == str(unit.get("id"))), ctx.device)


@export_section(
    "hit_counts",
    kind="state",
    default=False,
    summary="hits and last hit of every rule of the assigned access policy, and of its default action",
    diff=diff_hits,
    explain=explain_hits,
)
async def _hit_counts(ctx: ExportContext) -> dict[str, Any]:
    access = (await assigned(ctx)).get("access")
    if not access or not access.get("id"):
        return {}
    if ctx.mcp is None:
        raise UpstreamError("Hit counts need a tool call's context (FMC refreshes them in a task).")
    pol, rules = await _policy(ctx, str(access["id"]))
    unit = counting_unit(ctx)
    path = await ctx.app.config_path(f"{ACCESS}/{access['id']}/operational/hitcounts", ctx.domain)
    hits, _, notes = await rule_hits(
        ctx.mcp,
        ctx.app,
        path,
        [str(r["id"]) for r in rules if r.get("id")],
        str(unit["id"]),
        ctx.domain,
        refresh=bool(ctx.shared.get("setting:hit_count_refresh", True)),
        include_default=True,
        default_action_id=(pol.get("defaultAction") or {}).get("id"),
    )
    ctx.warnings += [f"hit_counts: {n}" for n in notes]
    out: dict[str, Any] = {}
    for h in hits.values():
        name = str((h.get("rule") or {}).get("name") or "?")
        row = {
            "hits": int(h.get("hitCount") or 0),
            "last_hit": to_utc(h.get("lastHitTimeStamp"), ctx.app.local_offset),
        }
        _put(out, name, {k: v for k, v in row.items() if v is not None})
    if ctx.ha:
        out["(counters from)"] = {"unit": unit.get("name")}
    return _sorted(out)


@export_section(
    "health_alerts",
    kind="state",
    default=False,
    summary="health modules that are not green on the device: status and FMC's message",
    diff=diff_alerts,
    explain=explain_alert,
)
async def _health_alerts(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for unit in units(ctx):
        rows = await ctx.items(ALERTS, {"filter": f"deviceUUIDs:{unit['id']}"}, cap=2000)
        bad = [
            (str(a.get("moduleID") or "?"), str(a.get("status") or "UNKNOWN").upper(), a.get("details"))
            for a in rows
            if str(a.get("status") or "").upper() != "GREEN"
        ]
        # a module's several rows ('CPU', 'CPU #2') in an order its readings can't change
        order = sorted(bad, key=lambda x: (x[0], without_readings(x[2]), x[1], str(x[2])))
        for module, status, details in order:
            _put(
                out,
                f"{prefix(ctx, unit)}{module}",
                {k: v for k, v in (("status", status), ("details", details)) if v},
            )
    return _sorted(out)


@export_section(
    "deployment",
    kind="state",
    shape="single",
    default=False,
    summary="deployment status, the deployed configuration version and its job, and the policies FMC "
    "would deploy next",
    explain=explain_deployment,
)
async def _deployment(ctx: ExportContext) -> dict[str, Any]:
    dev_id = str(ctx.device.get("id")).lower()
    path = await ctx.app.config_path(JOBS, ctx.domain)
    try:
        jobs = (await ctx.app.page(path, {"filter": f"deviceUUID:{ctx.device['id']}"}, limit=JOB_ROWS)).items
    except UpstreamError as e:
        if e.status_code not in (404, 405):
            raise
        jobs = []
    out: dict[str, Any] = {"status": ctx.device.get("deploymentStatus")}
    mine = [
        (j, x) for j in jobs for x in j.get("deviceList") or [] if str(x.get("deviceUUID")).lower() == dev_id
    ]
    if mine:
        job, row = mine[0]
        out.update(
            {
                "last_job": job.get("jobName"),
                "last_job_status": row.get("deploymentStatus") or job.get("jobStatus"),
                "last_job_ended": iso(job.get("endTime")),
            }
        )
    done = next((x for _, x in mine if str(x.get("deploymentStatus")).upper() == "SUCCEEDED"), None)
    if done is not None and done.get("deployedVersion") is not None:
        out["deployed_version"] = done["deployedVersion"]
    pending = await ctx.memo("deployable", partial(ctx.items, DEPLOYABLE, cap=5000))
    ids = ctx.target_ids
    for p in pending:
        members = [
            (p.get("device") or {}).get("id"),
            *((m or {}).get("id") for m in p.get("deviceMembers") or []),
        ]
        if ids & {str(i) for i in members if i}:
            out["pending"] = deployable_row(p).get("out_of_date_policies") or ["(FMC lists it as deployable)"]
            break
    else:
        out["pending"] = []
    return {k: v for k, v in out.items() if v is not None}


@export_section(
    "running_config",
    kind="state",
    default=False,
    summary="the device's own `show running-config <section>` lines for the sections asked (secrets masked)",
    diff=diff_lines,
    explain=explain_running,
)
async def _running_config(ctx: ExportContext) -> dict[str, Any]:
    wanted = [str(s) for s in ctx.shared.get("setting:running_config") or []]
    if not wanted:
        msg = "running_config: no sections named (fmc_device_snapshot running_config=[...])."
        if msg not in ctx.warnings:
            ctx.warnings.append(msg)
        return {}
    out: dict[str, Any] = {}
    for section in wanted:
        for unit, text in await outputs(ctx, f"{RUNNING} {section}"):
            out[f"{prefix(ctx, unit)}{section}"] = running_lines(text)
    return _sorted(out)


# --- the snapshot tool ----------------------------------------------------------------------------


def snapshot_sections(sections: list[str] | None, running_config: list[str] | None) -> list[str]:
    """The sections a snapshot reads: by default the device record, the assigned policies and every state
    section; running_config only with sections of it to capture (named alone without them: refused), and
    always when it names some (also with a `sections` list that leaves running_config out)."""
    names = select_sections(sections or [*SNAPSHOT_DEFAULT, "state"])
    if "running_config" in names and not running_config:
        if any(str(s).strip().lower() == "running_config" for s in sections or []):
            raise InvalidRequest(
                "Name the running-config sections to capture: running_config=['route', 'nat', ...]."
            )
        names.remove("running_config")
    if running_config and "running_config" not in names:
        names = select_sections([*names, "running_config"])
    return names


def running_sections(running_config: list[str] | None) -> list[str]:
    """Running-config sections, each checked against FMC's command allowlist before any call."""
    out: list[str] = []
    for s in running_config or []:
        section = " ".join(str(s).split())
        if not section:
            raise InvalidRequest("An empty running-config section; name one, e.g. 'route' or 'nat'.")
        check_command(f"{RUNNING} {section}")
        if section not in out:
            out.append(section)
    return out


async def resolve_targets(
    app: FmcApp, refs: list[str], domain: str | None
) -> tuple[list[tuple[dict[str, Any], dict[str, Any] | None]], dict[str, list[str]]]:
    """(device record, HA pair or None) per device, HA pair or device group member, duplicates dropped;
    and the groups expanded. One device listing, the cached group list, one record read per device."""
    records = (await app.all(await app.config_path(DEVICES, domain), cap=2000)).items
    fleet = await expand_devices(app, refs, domain, records=records)
    if len(fleet.refs) > MAX_FLEET:  # before one record read per device
        raise InvalidRequest(
            f"{len(fleet.refs)} devices; one snapshot covers at most {MAX_FLEET}. Split the list."
        )
    by_id = {str(d.get("id", "")).lower(): d for d in records}
    out: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    seen: set[str] = set()
    for ref in fleet.refs:
        low = ref.lower()
        hit = by_id.get(low)
        if hit is None:
            named = [d for d in records if d.get("name") == ref] or [
                d for d in records if str(d.get("name", "")).lower() == low
            ]
            hit = named[0] if len(named) == 1 else None
        device, ha = await resolve_target(app, str(hit["id"]) if hit else ref, domain)
        key = str((ha or device).get("id")).lower()
        if key not in seen:
            seen.add(key)
            out.append((device, ha))
    return out, fleet.groups


def _safe_label(label: str | None) -> str | None:
    if label is None:
        return None
    text = " ".join(label.split())
    if not text:
        return None
    if len(text) > MAX_LABEL:
        raise InvalidRequest(f"label is longer than {MAX_LABEL} characters.")
    return text


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Snapshot device state")
    async def fmc_device_snapshot(
        ctx: Context,
        devices: Annotated[
            list[str],
            Field(
                min_length=1,
                description="Devices or HA pairs (names or UUIDs), or device groups as 'group:<name>' "
                "(fmc_list_device_groups); at most 25 devices (HA units count one each)",
            ),
        ],
        label: Annotated[
            str | None,
            Field(
                description="A short label for the change record, e.g. 'before CHG0042' (kept in meta "
                "and in the file name)"
            ),
        ] = None,
        sections: Annotated[
            list[str] | None,
            Field(
                description="Default: device, policies and every state section (route_table, "
                "interface_state, failover, vpn_sas, tunnels, hit_counts, health_alerts, deployment; "
                "running_config when running_config names sections). Any export section, or 'state', "
                "'config' (about 30 more requests per device), 'all'"
            ),
        ] = None,
        running_config: Annotated[
            list[str] | None,
            Field(
                description="`show running-config` sections to capture, masked: e.g. ['route', 'nat', "
                "'access-group'] (one request per section and device)"
            ),
        ] = None,
        refresh_hit_counts: Annotated[
            bool,
            Field(
                description="Ask FMC to pull fresh hit counters from each device first (an operational "
                "task, a few seconds; no configuration change)"
            ),
        ] = True,
        include_text: Annotated[
            bool,
            Field(
                description="Return the snapshots' YAML in the result (false: only write the "
                "FMC_BUNDLE_DIR files)"
            ),
        ] = True,
        domain: Domain = None,
    ) -> ToolResult:
        """Snapshot what one or more FTDs run right now, for a change window's before/after evidence:
        routing table, interface status, failover state, IKEv2 SAs with the IKE/IPsec SA counts,
        FMC's tunnel rows, every access rule's hit count, health alerts that aren't green, the
        deployed configuration version and what is pending, optionally masked `show running-config
        <section>` lines; plus the device record and assigned policies (any export section can be
        added). One fmc-device-config YAML document per device (or HA pair: both
        units' state), like fmc_export_device_config, written to FMC_BUNDLE_DIR when set. Take one
        before the change and one after, then fmc_diff_device_config(a=<before>, b=<after>): routes
        lost, tunnels and SAs down, interface changes, new alerts, deployed version, hit-count deltas;
        or a=<before> alone compares it with the device now. Show commands run once for all devices
        (FMC's bulkcommands where enabled, else per device). Cost: about ten FMC requests per device
        (nine with the defaults: the record, three show commands, the hit-count refresh and read,
        alerts, deployment jobs; +1 per running-config section, +1 per HA unit for failover, -2
        without the refresh, about +30 with sections='config') plus about ten for the whole call
        (device list, policy assignments, the access policy and its rules, tunnels, pending
        deployments). Disconnected devices keep the FMC-side sections and list the device reads
        under errors.
        Read-only (the hit-count refresh is an operational task)."""
        app: FmcApp = get_client(ctx)
        bundle_dir = app.settings.bundle_dir
        if not include_text and bundle_dir is None:
            raise InvalidRequest(
                "include_text=false needs FMC_BUNDLE_DIR (nowhere else to put the snapshots)."
            )
        tag = _safe_label(label)
        run_cfg = running_sections(running_config)
        names = snapshot_sections(sections, run_cfg)
        targets, groups = await resolve_targets(app, devices, domain)
        all_units = [u for d, h in targets for u in unit_records(d, h)]
        if len(all_units) > MAX_FLEET:
            raise InvalidRequest(
                f"{len(all_units)} devices (HA units count one each); one snapshot covers at most "
                f"{MAX_FLEET}. Split the list."
            )
        shared: dict[str, Any] = {
            "setting:running_config": run_cfg,
            "setting:hit_count_refresh": refresh_hit_counts,
        }
        # every show command once for every device (bulkcommands where FMC enables it), before the
        # per-device FMC reads
        commands = [SECTION_COMMANDS[n] for n in names if n in SECTION_COMMANDS]
        if "running_config" in names:
            commands += [f"{RUNNING} {s}" for s in run_cfg]
        notes: list[str] = []
        paths: list[str] = []
        if commands:
            run = await run_fleet(ctx, app, all_units, commands, domain)
            remember(shared, run.rows)
            paths.append(run.path)
            notes += run.notes
        ha_units = [u for d, h in targets if in_ha(d, h) for u in unit_records(d, h)]
        if "failover" in names and ha_units:
            run = await run_fleet(ctx, app, ha_units, [FAILOVER], domain)
            remember(shared, run.rows)
            notes += [n for n in run.notes if n not in notes]
        rows: list[dict[str, Any]] = []
        texts: dict[str, str] = {}
        warnings: list[str] = []
        for device, ha in targets:
            doc, more = await export_target(app, device, ha, domain, names, shared, ctx)
            warnings += [w for w in more if w not in warnings and w not in notes]
            if tag:
                doc["meta"]["label"] = tag
            if "running_config" in names:
                doc["meta"]["running_config"] = run_cfg
            if "hit_counts" in names:
                doc["meta"]["hit_count_refresh"] = refresh_hit_counts
            text = finish(doc)
            meta = doc["meta"]
            row: dict[str, Any] = {
                "device": meta.get("device"),
                "kind": meta.get("kind"),
                "digest": meta["digest"],
                "sections": counts(doc),
            }
            if meta.get("errors"):
                row["errors"] = meta["errors"]
            if bundle_dir is not None:
                stem = f"snapshot-{meta.get('device')}" + (f"-{tag}" if tag else "")
                row["file"] = str(
                    await asyncio.to_thread(write_file, bundle_dir, stem, text, meta["exported_at"])
                )
            rows.append(row)
            texts[str(meta.get("device"))] = text
        out: dict[str, Any] = {"label": tag, "captured_at": _stamp(texts), "sections": names}
        if paths:
            out["show_path"] = paths[0]
        if groups:
            out["groups"] = groups
        if notes:
            out["notes"] = notes
        if warnings:
            out["warnings"] = warnings[:20]
        out["next"] = (
            "After the change: fmc_device_snapshot again (same devices and sections), then "
            "fmc_diff_device_config(a=<before>, b=<after>) per device; or a=<before> alone to compare "
            "with the device now."
        )
        if include_text:
            budget = max(4000, int(max_chars() * 0.8) - 4000) - len(json.dumps(out, default=str))
            kept: dict[str, str] = {}
            for name, text in texts.items():
                if len(text) > budget:
                    break
                kept[name] = text
                budget -= len(text)
            out["snapshots"] = kept
            left = [n for n in texts if n not in kept]
            if left:
                out["not_returned"] = left
                out["note"] = (
                    "Not every snapshot fits in one result"
                    + (" (all are in FMC_BUNDLE_DIR)" if bundle_dir is not None else "")
                    + ": snapshot those devices on their own or with fewer sections, or set FMC_BUNDLE_DIR."
                )
        out = {k: v for k, v in out.items() if v not in (None, [])}
        out["devices"] = rows
        return ToolResult(content=json.dumps(out, default=str), structured_content=out)


def _stamp(texts: dict[str, str]) -> str | None:
    """The first snapshot's exported_at (each document carries its own)."""
    for text in texts.values():
        m = re.search(r"^\s*exported_at:\s*'?([^'\n]+)'?\s*$", text, re.M)
        if m:
            return m.group(1).strip()
    return None
