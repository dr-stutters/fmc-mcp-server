"""Per-rule audit evidence for fmc_export_access_rules(evidence=true) (F80).

Auditors ask what is right as much as what is wrong: the rule exists, traffic hits it, it logs, it is
inspected, who changed it last and when, which deployment put that on the devices, and the ticket it was
approved under. Each answer here comes from one FMC collection read once per call, not per rule:

- hit counts: every rule (and the default action) on each device the policy is assigned to (HA pairs by
  unit), refreshed first like fmc_get_hit_counts;
- the last change: rules carry `metadata.timestamp` but no user; FMC logs every save of an access policy
  as 'Save Policy <policy>:<revision>' (with the user) under 'Policies > Security policies > Access Control >
  Policy Editor' a second or two later (FMC 10.0.1, read 2026-10-21), read with FMC's own subsystem filter.
  Inserting or moving one rule re-stamps the others, so the record is the save that last touched the rule,
  not necessarily one that edited it;
- the deployment: the first successful job per device after that change (deployment/jobhistories), and
  `out_of_date_on` from FMC's deployable list when the device doesn't run the policy as saved;
- the ticket: only when change management answers (FMC 7.6+ with the feature on and a role that may read
  tickets); matched best-effort by the change's user and the ticket's history window. The ticket list
  has no history (FMC spec): each ticket updated in the window is read with ?history=true. With change
  management off, or tickets unreadable, the column is left out and `change_management` says why.
"""

import time
from datetime import UTC, datetime
from typing import Any

from fastmcp import Context

from fmc_mcp._core import AuthError, UpstreamError, ValidationFailed
from fmc_mcp.audit import AUDIT_PAGE, contains, fetch_audit
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import ref_label
from fmc_mcp.tools.deploy import JOBS, deployable
from fmc_mcp.tools.hygiene import assigned_devices
from fmc_mcp.tools.policies import ACCESS
from fmc_mcp.tools.security_intel import si_summary
from fmc_mcp.tools.system import iso
from fmc_mcp.tools.tickets import TICKETS
from fmc_mcp.tools.troubleshoot import is_default_action, rule_hits, to_utc

EDITOR = "Access Control > Policy Editor"  # the access policy editor's audit subsystem (FMC 10.0.1)
AUDIT_PAGES = 10  # 1000 policy-editor records per call
SAVE_SLACK = 120  # seconds from a rule's timestamp to FMC's 'Save Policy' record
DEVICE_CAP = 10
JOB_CAP = 500
COMMENTS = 3
TICKET_CAP = 25  # tickets whose history is read (one GET each)
CLOSING = ("PENDING_APPROVAL", "APPROVED", "REJECTED", "DISCARD")
EVIDENCE_COLUMNS = [
    "hits",
    "last_hit",
    "hits_by_device",
    "to_fmc",
    "syslog",
    "file_policy",
    "last_change",
    "changed_by",
    "change_record",
    "deployed",
    "comment",
    "ticket",
]


def epoch(value: Any) -> float | None:
    """ISO 8601 (with or without seconds, 'Z' or an offset; no zone = UTC) or epoch seconds/ms."""
    if value in (None, ""):
        return None
    if isinstance(value, str) and "T" in value:
        try:
            when = datetime.fromisoformat(value.strip())
        except ValueError:
            return None
        return (when if when.tzinfo else when.replace(tzinfo=UTC)).timestamp()
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return n / 1000 if n > 10**11 else n


def is_save(message: str, policy: str) -> bool:
    """'Save Policy <policy>:<rev>' or 'Save Policy <policy>;Assigned to device(s) - ...:<rev>'."""
    head = f"Save Policy {policy}"
    return message.startswith(head) and message[len(head) : len(head) + 1] in (":", ";")


def revision(message: str) -> str | None:
    tail = message.rsplit(":", 1)
    return tail[1].strip() if len(tail) == 2 and tail[1].strip().isdigit() else None


def log_mode(r: dict[str, Any]) -> str:
    if r.get("logBegin") and r.get("logEnd"):
        return "begin_and_end"
    if r.get("logEnd"):
        return "end"
    return "begin" if r.get("logBegin") else "none"


def logging_of(r: dict[str, Any]) -> dict[str, Any]:
    syslog: Any = bool(r.get("enableSyslog"))
    if r.get("syslogConfig"):
        syslog = ref_label(r["syslogConfig"])
    out = {
        "log": log_mode(r),
        "to_fmc": bool(r.get("sendEventsToFMC")),
        "syslog": syslog,
        "files": bool(r.get("logFiles")) or None,
    }
    return {k: v for k, v in out.items() if v is not None}


def inspection_of(r: dict[str, Any]) -> dict[str, Any] | None:
    out = {
        "intrusion_policy": (r.get("ipsPolicy") or {}).get("name"),
        "variable_set": (r.get("variableSet") or {}).get("name") if r.get("ipsPolicy") else None,
        "file_policy": (r.get("filePolicy") or {}).get("name"),
    }
    return {k: v for k, v in out.items() if v} or None


def comments_of(r: dict[str, Any]) -> list[dict[str, Any]] | None:
    rows = []
    for c in (r.get("commentHistoryList") or [])[-COMMENTS:]:
        rows.append(
            {
                "at": c.get("date"),
                "by": (c.get("user") or {}).get("name"),
                "comment": str(c.get("comment") or "")[:200],
            }
        )
    return rows or None


def last_change(
    r: dict[str, Any], saves: list[dict[str, Any]], start: float, *, audited: bool = True
) -> dict[str, Any] | None:
    """The rule's timestamp and the 'Save Policy' record that wrote it (closest within SAVE_SLACK).
    audited=False: the audit log could not be read, so only the time is known."""
    ts = epoch((r.get("metadata") or {}).get("timestamp"))
    if ts is None:
        return None
    if not audited:
        return {"at": iso(ts), "_ts": ts, "note": "audit records not read: no change record"}
    best: dict[str, Any] | None = None
    for rec in saves:
        t = epoch(rec.get("time"))
        if t is None or not (ts - 5 <= t <= ts + SAVE_SLACK):
            continue
        if best is None or abs(t - ts) < abs((epoch(best.get("time")) or 0) - ts):
            best = rec
    out: dict[str, Any] = {"at": iso(ts), "_ts": ts}
    if best is not None:
        msg = str(best.get("message") or "")
        out.update(by=best.get("username"), audit=msg, revision=revision(msg), audit_at=iso(best.get("time")))
    elif ts < start:
        out["note"] = "before the evidence window"
    else:
        out["note"] = f"no 'Save Policy' audit record within {SAVE_SLACK} s of it"
    return out


def _device_entry(job: dict[str, Any], dev_id: str) -> dict[str, Any] | None:
    return next(
        (x for x in job.get("deviceList") or [] if str(x.get("deviceUUID") or "").lower() == dev_id.lower()),
        None,
    )


def _succeeded(job: dict[str, Any], entry: dict[str, Any]) -> bool:
    status = str(entry.get("deploymentStatus") or "").upper()
    if status:
        return status == "SUCCEEDED"
    return str(job.get("jobStatus") or "").upper() in ("DEPLOYED", "SUCCEEDED")


def deployed_on(
    change: dict[str, Any] | None,
    devices: list[tuple[str, str]],
    jobs: list[dict[str, Any]] | None,
    stale: set[str] | None,
    start: float,
) -> list[dict[str, Any]] | None:
    """Per device: the first successful deployment after the change, or pending. `jobs` / `stale` are None
    when the job history / deployable list could not be read (then nothing is claimed from them). A job is
    named only for a change inside the window: for an older change (or a rule without a change time) the
    first job in the window need not be the one that pushed it."""
    if not devices:
        return None
    ts = (change or {}).get("_ts")
    ordered = sorted(jobs or [], key=lambda j: epoch(j.get("startTime")) or 0)
    out = []
    for dev_id, label in devices:
        if stale is not None and dev_id.lower() in stale:
            out.append({"device": label, "pending": True})
            continue
        if ts is None or ts < start:
            why = (
                "the rule has no change time to match a deployment"
                if ts is None
                else f"the change predates the evidence window ({iso(start)})"
            )
            state = "unknown" if stale is None else "yes (FMC lists it up to date)"
            out.append({"device": label, "deployed": f"{state}; {why}"})
            continue
        job = next(
            (
                j
                for j in ordered
                if (e := _device_entry(j, dev_id)) is not None
                and _succeeded(j, e)
                and (epoch(j.get("startTime")) or 0) >= ts
            ),
            None,
        )
        if job is not None:
            row = {
                "device": label,
                "job": job.get("jobName"),
                "at": iso(job.get("endTime") or job.get("startTime")),
                "by": job.get("user"),
                "note": job.get("deploymentNote"),
            }
            out.append({k: v for k, v in row.items() if v is not None})
        elif stale is None or jobs is None:
            out.append(
                {"device": label, "deployed": "unknown (deployment history or deployable list not read)"}
            )
        else:
            out.append(
                {"device": label, "deployed": "yes (FMC lists it up to date; no job in the window names it)"}
            )
    return out


def ticket_window(t: dict[str, Any], now: float) -> tuple[float, float] | None:
    hist = sorted(
        ((epoch(h.get("time")), str(h.get("state") or "")) for h in t.get("ticketHistory") or []),
        key=lambda x: x[0] or 0,
    )
    hist = [(when, state) for when, state in hist if when is not None]
    if not hist:
        return None
    begin = hist[0][0]
    end = next((when for when, state in hist if state in CLOSING), None)
    if end is None:
        end = (
            now
            if str(t.get("status") or "") not in CLOSING
            else (epoch((t.get("metadata") or {}).get("lastUpdateTime")) or now)
        )
    return float(begin or 0), float(end)


def match_ticket(change: dict[str, Any] | None, tickets: list[dict[str, Any]], now: float) -> dict[str, Any]:
    """The ticket whose history window holds the change, of the change's user (best effort)."""
    if not change or change.get("_ts") is None or not change.get("by"):
        return {"ticket": None, "note": "no audited change to match"}
    ts, user = float(change["_ts"]), str(change["by"]).lower()
    best: tuple[float, dict[str, Any]] | None = None
    for t in tickets:
        users = {
            str(t.get("assignedTo") or "").lower(),
            str((t.get("metadata") or {}).get("creator") or "").lower(),
        }
        users |= {str(h.get("user") or "").lower() for h in t.get("ticketHistory") or []}
        if user not in users:
            continue
        win = ticket_window(t, now)
        if win is None or not (win[0] - 60 <= ts <= win[1] + 60):
            continue
        if best is None or win[1] - win[0] < best[0]:
            best = (win[1] - win[0], t)
    if best is None:
        return {"ticket": None, "note": f"no ticket of {change['by']} spans the change"}
    t = best[1]
    approved: dict[str, Any] = next(
        (h for h in t.get("ticketHistory") or [] if h.get("state") == "APPROVED"), {}
    )
    row = {
        "ticket": t.get("name"),
        "status": t.get("status"),
        "approved_by": approved.get("user"),
        "approved_at": approved.get("time"),
        "id": t.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


async def read_tickets(
    app: FmcApp, domain: str | None, start: float, notes: list[str]
) -> tuple[str, list[dict[str, Any]]]:
    """('on', tickets with their history) or ('off' / 'not readable ...', []): the ticket column only
    when 'on'. FMC lists only the caller's tickets unless allUsers=true (needs the 'review tickets'
    permission), and the list carries no history: GET tickets/{id}?history=true does (FMC spec), read
    for the tickets updated since the window began (up to TICKET_CAP)."""
    path = await app.config_path(TICKETS, domain)
    own_only = False
    try:
        try:
            page = await app.all(path, {"allUsers": "true"})
        except (AuthError, ValidationFailed):  # no 'review tickets' permission: the caller's own
            own_only = True
            page = await app.all(path)
    except AuthError as e:
        return f"not readable by this account ({e.status_code or 403}): no ticket column", []
    except UpstreamError as e:
        if "not enabled" in str(e).lower():
            return "off: no ticket column", []
        return f"not readable ({str(e)[:120]}): no ticket column", []
    if own_only:
        notes.append("Tickets: only this account's own (allUsers needs the 'review tickets' permission).")
    tickets: list[dict[str, Any]] = []
    reads = 0
    for t in page.items:
        updated = epoch((t.get("metadata") or {}).get("lastUpdateTime"))
        if updated is not None and updated < start - SAVE_SLACK:
            continue  # closed before the window: it can't span a change in it
        if t.get("ticketHistory") is None and t.get("id"):
            if reads >= TICKET_CAP:
                notes.append(f"Tickets: history read for the first {TICKET_CAP} changed in the window only.")
                break
            reads += 1
            try:
                t = {**t, **((await app.api.get(f"{path}/{t['id']}", {"history": "true"})) or {})}
            except UpstreamError as e:
                notes.append(f"Ticket {t.get('name')!r}: history not read ({str(e)[:120]}).")
                continue
        tickets.append(t)
    return "on", tickets


async def collect(
    ctx: Context,
    app: FmcApp,
    policy: dict[str, Any],
    rules: list[dict[str, Any]],
    since_days: int,
    domain: str | None,
    *,
    refresh: bool = True,
    now: float | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """(evidence by rule id, the policy's evidence block)."""
    now = time.time() if now is None else now
    start = float(int(now) - since_days * 86400)
    name = str(policy.get("name"))
    notes: list[str] = []

    devices, more = await assigned_devices(app, str(policy["id"]), domain)
    notes += more
    if len(devices) > DEVICE_CAP:
        notes.append(f"{len(devices)} devices run the policy: evidence from the first {DEVICE_CAP}.")
        devices = devices[:DEVICE_CAP]
    if not devices:
        notes.append("The policy is assigned to no device: no hit counts or deployments.")

    hits: dict[str, list[dict[str, Any]]] = {}
    default_hits: list[dict[str, Any]] = []
    hc_path = await app.config_path(f"{ACCESS}/{policy['id']}/operational/hitcounts", domain)
    ids = [str(r["id"]) for r in rules if r.get("id")]
    default_id = (policy.get("defaultAction") or {}).get("id")
    for dev_id, label in devices:
        if not ids and not default_id:
            break  # FMC answers 500 to a hit-count query without ids
        try:
            got, _, dev_notes = await rule_hits(
                ctx,
                app,
                hc_path,
                ids,
                dev_id,
                domain,
                refresh=refresh,
                include_default=True,
                default_action_id=default_id,
            )
        except UpstreamError as e:
            notes.append(f"{label}: hit counts not read ({e}).")
            continue
        notes += [f"{label}: {n}" for n in dev_notes]
        for rid, h in got.items():
            row = {
                "device": label,
                "hits": int(h.get("hitCount") or 0),
                "first_hit": to_utc(h.get("firstHitTimeStamp"), app.local_offset),
                "last_hit": to_utc(h.get("lastHitTimeStamp"), app.local_offset),
            }
            row = {k: v for k, v in row.items() if v is not None}
            if is_default_action(h):
                default_hits.append(row)
            else:
                hits.setdefault(rid, []).append(row)

    si = None
    try:
        page = await app.all(
            await app.config_path(f"{ACCESS}/{policy['id']}/securityintelligencepolicies", domain)
        )
        if page.items:
            si = await si_summary(app, page.items[0], domain)
    except UpstreamError as e:
        notes.append(f"Security Intelligence not read ({e}).")

    saves: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    audit_ok = True
    try:
        scan = await fetch_audit(app, int(start), domain, subsystem=contains(EDITOR), max_pages=AUDIT_PAGES)
        for rec in scan.items:
            msg = str(rec.get("message") or "")
            if is_save(msg, name):
                saves.append(rec)
            elif msg == f"Create Policy {name}" or msg.startswith(f"Policy {name} Assigned to Device"):
                events.append({"at": iso(rec.get("time")), "by": rec.get("username"), "audit": msg})
        if not scan.complete:
            notes.append(
                f"Policy-editor audit records read back to {iso(scan.reached)} only "
                f"({AUDIT_PAGES * AUDIT_PAGE} records): older changes show without their record."
            )
    except UpstreamError as e:
        audit_ok = False
        notes.append(f"Audit records not read ({e}): no change records.")

    jobs: list[dict[str, Any]] | None = None
    try:
        flt = {"filter": f"startTime:{int(start)};endTime:{int(now) + 60}"}
        jobs = list((await app.all(await app.config_path(JOBS, domain), flt, cap=JOB_CAP)).items)
    except UpstreamError as e:
        notes.append(f"Deployment history not read ({e}).")

    stale: set[str] | None = set()
    stale_names: list[str] = []
    if devices:
        found: set[str] = set()
        try:
            for p in await deployable(app, domain):
                if any(
                    (st.get("policy") or {}).get("id") == policy["id"] and st.get("upToDate") is False
                    for st in p.get("policyStatusList") or []
                ):
                    members = [p.get("device") or {}, *(p.get("deviceMembers") or [])]
                    found.update(str(m.get("id") or "").lower() for m in members if m.get("id"))
                    stale_names.append(str(p.get("name") or (p.get("device") or {}).get("name")))
            stale = found
        except UpstreamError as e:
            stale = None
            notes.append(f"Deployable devices not read ({e}).")

    cm, tickets = await read_tickets(app, domain, start, notes)

    per_rule: dict[str, dict[str, Any]] = {}
    for r in rules:
        rid = str(r.get("id"))
        change = last_change(r, saves, start, audited=audit_ok)
        ev: dict[str, Any] = {
            "hits": hits.get(rid) or None,
            "logging": logging_of(r),
            "inspection": inspection_of(r),
            "last_change": {k: v for k, v in change.items() if k != "_ts"} if change else None,
            "deployed": deployed_on(change, devices, jobs, stale, start),
            "comments": comments_of(r),
        }
        if cm == "on":
            ev["ticket"] = match_ticket(change, tickets, now)
        per_rule[rid] = {k: v for k, v in ev.items() if v is not None}

    block: dict[str, Any] = {
        "window": {"days": since_days, "from": iso(start)},
        "devices": [label for _, label in devices] or None,
        "default_action": {
            "action": (policy.get("defaultAction") or {}).get("action"),
            "hits": default_hits or None,
        },
        "security_intelligence": si,
        "out_of_date_on": stale_names or None,
        "saves_in_window": len(saves) if audit_ok else None,
        "policy_events": events[:10] or None,
        "change_management": cm,
        "notes": notes or None,
    }
    return per_rule, {k: v for k, v in block.items() if v is not None}


def flat(ev: dict[str, Any] | None) -> dict[str, Any]:
    """The evidence of one rule as CSV columns (EVIDENCE_COLUMNS)."""
    if not ev:
        return {}
    hits = ev.get("hits") or []
    change = ev.get("last_change") or {}
    lasts = [h["last_hit"] for h in hits if h.get("last_hit")]
    deployed = []
    for d in ev.get("deployed") or []:
        if d.get("pending"):
            deployed.append(f"{d['device']}: pending")
        elif d.get("job"):
            deployed.append(f"{d['device']}: {d['job']} {d.get('at') or ''} by {d.get('by') or '?'}".strip())
        else:
            deployed.append(f"{d['device']}: {d.get('deployed')}")
    comments = ev.get("comments") or []
    ticket = ev.get("ticket") or {}
    row = {
        "hits": sum(int(h.get("hits") or 0) for h in hits) if hits else None,
        "last_hit": max(lasts) if lasts else None,
        "hits_by_device": [
            f"{h['device']}={h.get('hits', 0)}"
            + (f" ({h.get('first_hit')} .. {h.get('last_hit')})" if h.get("last_hit") else "")
            for h in hits
        ]
        or None,
        "to_fmc": (ev.get("logging") or {}).get("to_fmc"),
        "syslog": (ev.get("logging") or {}).get("syslog"),
        "file_policy": (ev.get("inspection") or {}).get("file_policy"),
        "last_change": change.get("at"),
        "changed_by": change.get("by"),
        "change_record": change.get("audit") or change.get("note"),
        "deployed": deployed or None,
        "comment": f"{comments[-1].get('at')} {comments[-1].get('by')}: {comments[-1].get('comment')}"
        if comments
        else None,
        "ticket": ticket.get("ticket") or ticket.get("note") if "ticket" in ev else None,
    }
    return {k: v for k, v in row.items() if v is not None}
