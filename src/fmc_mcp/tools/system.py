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
from fmc_mcp.audit import NOISE_SUBSYSTEMS, compact_message, coverage_note, fetch_audit, is_read
from fmc_mcp.client import FmcApp
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
                description="Filter: subsystem contains, e.g. 'Access Control', 'Object Management', 'Login'"
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
        this object?' (text=<object name>) or 'what changed today?'. FMC logs an access or NAT rule edit
        as 'Save Policy <policy>:<revision>' without the rule name, so search rules by their policy
        name (fmc_pending_changes names the rules not yet deployed). FMC returns only 100 records per
        request and logs every API read, so the window is read in slices (up to 2500 records); a note
        says how far back it got when the window holds more. API URLs are shortened
        ('PUT fmc_config/policy/...')."""
        app: FmcApp = get_client(ctx)
        start = int(time.time()) - since_minutes * 60
        if changes_only is None:
            want = (subsystem or "").strip().lower()
            changes_only = not (want and any(want in n for n in NOISE_SUBSYSTEMS))
        scan = await fetch_audit(app, start, domain)
        rows = []
        for r in scan.items:
            if changes_only and is_read(r):
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
        note = coverage_note(scan)
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
        fmc_threat_posture checks it) and what the device is missing. 'Are we licensed properly?' in
        one call; fix with fmc_set_device_licenses."""
        app: FmcApp = get_client(ctx)
        smart = await app.api.get("/api/fmc_platform/v1/license/smartlicenses")
        licences = await app.all("/api/fmc_platform/v1/license/devicelicenses", expanded=False, cap=1000)
        out: dict[str, Any] = {
            "smart_license": [smart_license_row(i) for i in (smart or {}).get("items") or []]
        }
        notes: list[str] = []
        try:
            records = (await app.all(await app.config_path(DEVICES, domain), cap=1000)).items
        except UpstreamError as e:
            records = []
            notes.append(f"Device records not readable ({e}): licences are listed by device id only.")
        by_id = {str(d.get("id")).lower(): d for d in records}
        needs: dict[str, dict[str, str]] = {}  # access policy id -> licence -> why
        if check_policies:
            needs, more = await _policy_needs(app, records, domain)
            notes += more
        rows = [_licence_row(i, by_id.get(str(i.get("id")).lower()), needs) for i in licences.items]
        unnamed = sum(1 for r in rows if r.get("name") is None)
        if unnamed and records:
            notes.append(f"{unnamed} licensed device(s) are not in this domain's device list: pass `domain`.")
        out["device_licenses"] = rows
        lacking = [
            f"{r.get('name') or r['id']} ({', '.join(r['missing'])})" for r in rows if r.get("missing")
        ]
        if check_policies:
            out["missing"] = lacking or "none: every device holds the licences its access policy needs"
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


def licence_needs(acp: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, str]:
    """The feature licences an access policy needs, with why (fmc_threat_posture's check): IPS for an
    intrusion policy on the default action or an enabled ALLOW rule, MALWARE_DEFENSE for a file policy on
    an enabled ALLOW rule, URL for URL categories/reputation on an enabled rule."""
    enabled = [r for r in rules if r.get("enabled", True)]
    allow = [r for r in enabled if str(r.get("action", "")).upper() == "ALLOW"]
    out: dict[str, str] = {}
    ips = next((r for r in allow if (r.get("ipsPolicy") or {}).get("id")), None)
    if ((acp.get("defaultAction") or {}).get("intrusionPolicy") or {}).get("id"):
        out["IPS"] = "intrusion policy on the default action"
    elif ips:
        out["IPS"] = f"intrusion policy on rule {ips.get('name')!r}"
    files = next((r for r in allow if r.get("filePolicy")), None)
    if files:
        out["MALWARE_DEFENSE"] = f"file policy on rule {files.get('name')!r}"
    urls = next((r for r in enabled if (r.get("urls") or {}).get("urlCategoriesWithReputation")), None)
    if urls:
        out["URL"] = f"URL categories on rule {urls.get('name')!r}"
    return out


async def _policy_needs(
    app: FmcApp, records: list[dict[str, Any]], domain: str | None
) -> tuple[dict[str, dict[str, str]], list[str]]:
    """licence_needs() of each access policy the devices use (up to LICENCE_POLICY_CAP), and notes."""
    policies: dict[str, str] = {}
    for d in records:
        acp = d.get("accessPolicy") or {}
        if acp.get("id"):
            policies.setdefault(str(acp["id"]), str(acp.get("name") or acp["id"]))
    out: dict[str, dict[str, str]] = {}
    notes: list[str] = []
    for pid, name in list(policies.items())[:LICENCE_POLICY_CAP]:
        try:
            acp = await app.api.get(await app.config_path(f"{ACCESS}/{pid}", domain))
            rules = (await all_rules(app, await app.config_path(f"{ACCESS}/{pid}/accessrules", domain))).items
        except UpstreamError as e:
            notes.append(f"Access policy {name!r} not readable ({e}): its devices' needs are unknown.")
            continue
        out[pid] = licence_needs(acp or {}, rules)
    if len(policies) > LICENCE_POLICY_CAP:
        rest = ", ".join(list(policies.values())[LICENCE_POLICY_CAP:])
        notes.append(f"Needs not checked for access policies past the first {LICENCE_POLICY_CAP}: {rest}.")
    return out, notes


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
    # fmc_threat_posture's licence names; imported here: threat_posture's imports lead back to this module.
    from fmc_mcp.tools.threat_posture import _licences

    # HA units hold IPS_HA, URL_HA, MALWARE_DEFENSE_HA in /license/devicelicenses (FMC 10.0.1).
    held = sorted(_licences([str(t).upper().removesuffix("_HA") for t in lic.get("licenseTypes") or []]))
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
