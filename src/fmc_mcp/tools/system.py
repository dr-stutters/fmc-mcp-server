"""System tools: domains, audit log, background tasks, licensing."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import time
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.audit import (
    NOISE_SUBSYSTEMS,
    compact_message,
    coverage_note,
    fetch_audit,
    fetch_changes,
    fetch_subsystem,
    is_read,
)
from fmc_mcp.client import FmcApp
from fmc_mcp.licensing import licence_needs, licences
from fmc_mcp.tools.common import Domain, ref_label, slim, smart_license_row
from fmc_mcp.tools.devices import DEVICES
from fmc_mcp.tools.policies import ACCESS, all_rules

LICENCE_POLICY_CAP = 10  # access policies whose rules are read for the licences they need


def iso(ts: Any) -> str | None:
    """FMC timestamps are epoch seconds or milliseconds."""
    if isinstance(ts, str) and "T" in ts:
        return ts  # already ISO 8601
    try:
        n = float(ts)
    except (TypeError, ValueError):
        return None
    if n > 10**11:
        n /= 1000
    return datetime.fromtimestamp(n, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List FMC domains")
    async def fmc_list_domains(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Filter: domain name contains (case-insensitive)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the FMC domains this API account can see as a tree (name like 'Global/Child', UUID,
        parent, leaf or not, and the devices each one holds), marking the default one. Devices live only
        in leaf domains; objects and policies defined in a domain are inherited (read-only) by the domains
        below it. Pass a name or UUID from here as `domain` to other tools on multi-domain FMCs."""
        app: FmcApp = get_client(ctx)
        default = await app.domain_uuid(None)
        data = await app.api.get("/api/fmc_platform/v1/info/domain", {"limit": 1000, "expanded": "true"})
        items = [d for d in (data or {}).get("items", []) if d.get("uuid")]
        parents = {d["uuid"]: d.get("parentUUID") for d in items if d.get("parentUUID") != d["uuid"]}
        # Devices with their owning domain, read once from the top-most visible domain (ancestors
        # see their descendants' devices).
        top = min(items, key=lambda d: str(d.get("name", "")).count("/"), default=None)
        per_domain: dict[str, list[str]] = {}
        if top is not None:
            try:
                devs = await app.all(await app.config_path("devices/devicerecords", top["uuid"]))
                for dev in devs.items:
                    dom = ((dev.get("metadata") or {}).get("domain") or {}).get("id") or top["uuid"]
                    per_domain.setdefault(str(dom), []).append(str(dev.get("name")))
            except UpstreamError:
                per_domain = {}
        rows = [
            {
                "name": d.get("name"),
                "uuid": d.get("uuid"),
                "default": d.get("uuid") == default,
                "parent_uuid": parents.get(d["uuid"]),
                "leaf": d["uuid"] not in parents.values(),
                "devices": sorted(per_domain.get(d["uuid"], [])) or None,
            }
            for d in sorted(items, key=lambda d: str(d.get("name", "")).lower())
        ]
        if name:
            rows = [r for r in rows if name.lower() in str(r["name"]).lower()]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="FMC audit records")
    async def fmc_list_audit_records(
        ctx: Context,
        since_minutes: Annotated[
            int, Field(ge=1, le=525_600, description="Look back this many minutes (default 24 hours)")
        ] = 1440,
        user: Annotated[str | None, Field(description="Filter: username contains")] = None,
        subsystem: Annotated[
            str | None,
            Field(
                description="Filter: subsystem contains (FMC filters it), e.g. 'Access Control', 'Object "
                "Management', 'NAT', 'Task Queue', 'Login'"
            ),
        ] = None,
        text: Annotated[
            str | None,
            Field(description="Filter: message contains (case-insensitive), e.g. a rule or object name"),
        ] = None,
        changes_only: Annotated[
            bool | None,
            Field(
                description="Skip reads: API GETs, page views, logins, logouts, session expiry. Default: on, "
                "unless `subsystem` asks for them (e.g. 'Login')"
            ),
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List FMC audit-log records, newest first: who changed what and when (policy and object edits,
        API writes, deployments; logins and reads with changes_only=false). Use it to answer 'who changed
        this object?' (text=<object name>) or 'what changed today?'. FMC logs a change in words under the
        UI path it was made in, also for API changes ('Save Policy <policy>:<revision>' under 'Policies >
        Security policies > Access Control > Policy Editor', 'create <object>:<revision>' under 'Objects >
        Object Management > NetworkObject'); an access or NAT rule edit is a 'Save Policy' without the rule
        name, so search rules by their policy name (fmc_pending_changes names the rules not yet deployed).
        FMC returns only 100 records per request and logs every API read, so: `subsystem` is filtered by
        FMC itself over the whole window; changes (the default) are read in full for the newest 500
        records, and for the rest of the window only through FMC's UI-path and Task Queue subsystems
        (policy, object and device changes, deployments), which leaves out changes FMC logs only under
        another subsystem or as an API request (the note says when; use a shorter window or `subsystem`);
        with changes_only=false every record is read in slices (up to 2500). A note says how far back the
        read got and how many records were reads. `user` and `text` are matched here (FMC ignores a
        username filter). API URLs are shortened ('PUT fmc_config/policy/...')."""
        app: FmcApp = get_client(ctx)
        start = int(time.time()) - since_minutes * 60
        if changes_only is None:
            want = (subsystem or "").strip().lower()
            changes_only = not (want and any(want in n for n in NOISE_SUBSYSTEMS))
        if subsystem and subsystem.strip():
            scan = await fetch_subsystem(app, start, domain, subsystem)
        elif changes_only:
            scan = await fetch_changes(app, start, domain)
        else:
            scan = await fetch_audit(app, start, domain)
        rows = []
        reads = 0
        for r in scan.items:
            if changes_only and is_read(r):
                reads += 1
                continue
            if user and user.lower() not in str(r.get("username", "")).lower():
                continue
            if subsystem and subsystem.lower() not in str(r.get("subSystem", "")).lower():
                continue
            msg = str(r.get("message", ""))
            if text and text.lower() not in f"{msg} {compact_message(msg)}".lower():
                continue
            rows.append(_audit_row(r))
        extra: dict[str, Any] = {"records_read": len(scan.items)}
        if reads:
            extra["reads_skipped"] = reads
        note = coverage_note(scan, reads)
        if note:
            extra["note"] = note
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.read(title="Get FMC task status")
    async def fmc_get_task(
        ctx: Context,
        task_id: Annotated[str, Field(description="Task id returned by a deploy/registration/other job")],
        domain: Domain = None,
    ) -> ToolResult:
        """Get the status of an FMC background task (deployment, device registration, pending-changes
        report, backup): status, message and per-device sub-tasks. Use it to follow up on a tool that
        returned a task id instead of waiting."""
        app: FmcApp = get_client(ctx)
        path = await app.config_path(f"job/taskstatuses/{task_id.strip()}", domain)
        data = await app.api.get(path, {"showDetailedDeviceStatus": "true"})
        return object_result(slim(data))

    @reg.read(title="FMC licensing status")
    async def fmc_license_status(
        ctx: Context,
        check_policies: Annotated[
            bool,
            Field(
                description="Also read each assigned access policy's rules (up to "
                f"{LICENCE_POLICY_CAP} policies) for the licences it needs and list what each device lacks"
            ),
        ] = True,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Smart Licensing status of the FMC (regStatus registered/unregistered/evaluation, authStatus
        such as AUTHORIZED or OUT_OF_COMPLIANCE, virtual account, export control, evaluation used and
        days left, last sync/renewal) and the licences of every device: name, HA pair or cluster and
        role, licences (FMC's *_HA entitlements of HA units shown as the plain licence), performance
        tier and access policy; with check_policies, what that policy needs (IPS for intrusion
        inspection, MALWARE_DEFENSE for file policies, URL for URL categories/reputation, as
        fmc_threat_posture checks it) and what the device is missing, or `not_checked` and why (not in
        the domain's device list, no access policy, policy unreadable or past the first 10 policies).
        `summary` gives the all-clear only when every device was checked. 'Are we licensed
        properly?' in one call; fix with fmc_set_device_licenses."""
        app: FmcApp = get_client(ctx)
        smart = await app.api.get("/api/fmc_platform/v1/license/smartlicenses")
        held = await app.all("/api/fmc_platform/v1/license/devicelicenses", expanded=False, cap=1000)
        out: dict[str, Any] = {
            "smart_license": [smart_license_row(i) for i in (smart or {}).get("items") or []]
        }
        notes: list[str] = []
        absent = "not in this domain's device list (pass `domain`)"
        try:
            records = (await app.all(await app.config_path(DEVICES, domain), cap=1000)).items
        except UpstreamError as e:
            records = []
            absent = "device records not readable"
            notes.append(f"Device records not readable ({e}): licences are listed by device id only.")
        by_id = {str(d.get("id")).lower(): d for d in records}
        needs: dict[str, dict[str, str]] = {}  # access policy id -> licence -> why
        unread: dict[str, str] = {}  # access policy id -> why its needs are unknown
        if check_policies:
            needs, unread, more = await _policy_needs(app, records, domain)
            notes += more
        rows = []
        for i in held.items:
            dev = by_id.get(str(i.get("id")).lower())
            row = _licence_row(i, dev, needs)
            if check_policies and "needs" not in row:
                acp = str(((dev or {}).get("accessPolicy") or {}).get("id") or "")
                if dev is None:
                    row["not_checked"] = absent
                else:
                    row["not_checked"] = (
                        unread.get(acp, "no access policy assigned") if acp else "no access policy assigned"
                    )
            rows.append(row)
        out["device_licenses"] = rows
        unnamed = sum(1 for r in rows if r.get("name") is None)
        if unnamed and records:
            notes.append(f"{unnamed} licensed device(s) are not in this domain's device list: pass `domain`.")
        if check_policies:
            lacking = [f"{_name(r)} ({', '.join(r['missing'])})" for r in rows if r.get("missing")]
            unchecked = [f"{_name(r)} ({r['not_checked']})" for r in rows if r.get("not_checked")]
            out["summary"] = _licence_summary(len(rows), len(lacking), len(unchecked))
            out["missing"] = lacking
            if unchecked:
                out["not_checked"] = unchecked
        if notes:
            out["notes"] = notes
        return out


def _audit_row(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "time": iso(r.get("time")),
        "user": r.get("username"),
        "subsystem": r.get("subSystem"),
        "source": r.get("source"),
        "message": compact_message(r.get("message")),
    }


def _name(row: dict[str, Any]) -> str:
    return str(row.get("name") or row.get("id"))


def _licence_summary(total: int, lacking: int, unchecked: int) -> str:
    """The headline: the all-clear only when every device's needs were checked."""
    if lacking:
        out = f"{lacking} of {total} device(s) lack a licence their access policy needs (see missing)"
        return out + (f"; {unchecked} not checked (see not_checked)" if unchecked else "")
    if unchecked:
        return (
            f"No checked device lacks a licence, but {unchecked} of {total} were not checked "
            "(see not_checked)"
        )
    return f"Every device ({total}) holds the licences its access policy needs"


async def _policy_needs(
    app: FmcApp, records: list[dict[str, Any]], domain: str | None
) -> tuple[dict[str, dict[str, str]], dict[str, str], list[str]]:
    """licence_needs() of each access policy the devices use (up to LICENCE_POLICY_CAP); why the others
    were not read (policy id -> reason); notes."""
    policies: dict[str, str] = {}
    for d in records:
        acp = d.get("accessPolicy") or {}
        if acp.get("id"):
            policies.setdefault(str(acp["id"]), str(acp.get("name") or acp["id"]))
    out: dict[str, dict[str, str]] = {}
    unread: dict[str, str] = {}
    notes: list[str] = []
    for n, (pid, name) in enumerate(policies.items()):
        if n >= LICENCE_POLICY_CAP:
            unread[pid] = f"access policy {name!r} past the first {LICENCE_POLICY_CAP} read"
            continue
        try:
            acp = await app.api.get(await app.config_path(f"{ACCESS}/{pid}", domain))
            rules = (await all_rules(app, await app.config_path(f"{ACCESS}/{pid}/accessrules", domain))).items
        except UpstreamError as e:
            unread[pid] = f"access policy {name!r} not readable"
            notes.append(f"Access policy {name!r} not readable ({e}).")
            continue
        out[pid] = licence_needs(acp or {}, rules)
    return out, unread, notes


def container_role(d: dict[str, Any] | None) -> str | None:
    """'mcp-fw-ha (primary, active)' / 'mcp-sdwan-t3-cluster (control)' from FMC's
    metadata.containerDetails of an expanded device record; None for a standalone device."""
    c = ((d or {}).get("metadata") or {}).get("containerDetails") or {}
    if not isinstance(c, dict) or not c.get("name"):
        return None
    parts = [str(v).lower() for v in (c.get("role"), c.get("status")) if v]
    return f"{c['name']} ({', '.join(parts)})" if parts else str(c["name"])


def _licence_row(
    lic: dict[str, Any], dev: dict[str, Any] | None, needs: dict[str, dict[str, str]]
) -> dict[str, Any]:
    """One device's licences, named, with what its access policy needs and what it lacks."""
    held = sorted(licences(lic.get("licenseTypes")))
    acp = (dev or {}).get("accessPolicy") or {}
    row: dict[str, Any] = {
        "name": (dev or {}).get("name"),
        "ha_or_cluster": container_role(dev),
        "licences": held,
        "performance_tier": lic.get("performanceTier"),
        "access_policy": ref_label(acp) if acp else None,
    }
    need = needs.get(str(acp.get("id"))) if acp.get("id") else None
    if need is not None:
        row["needs"] = sorted(need)
        row["missing"] = [n for n in sorted(need) if n not in held]
        if row["missing"]:
            row["why"] = "; ".join(f"{n}: {need[n]}" for n in row["missing"])
    if dev is not None and dev.get("isConnected") is False:
        row["connected"] = False
    row["id"] = lic.get("id")
    return {k: v for k, v in row.items() if v is not None}
