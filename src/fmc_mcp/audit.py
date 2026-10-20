"""Reading FMC's audit log over a whole time window.

FMC 10.0.1 answers `audit/auditrecords` with at most the newest 100 records per query (paging.count
caps at 100 and offset 100 is empty), and every API call - ours included - writes a record. So a
plain query only reaches back a few minutes on a busy FMC. A past `endtime` is accepted (a future
one is rejected), so the window is read newest first in slices: each query asks for the newest 100
records up to the oldest time seen so far.

FMC's own filters (FMC 10.0.1, read-only probes 2026-10-20): `subsystem` is a case-insensitive SQL LIKE
on the whole subsystem name ('task queue' matches 'Task Queue', 'Task' matches nothing, 'Policies%' and
'%>%' are wildcards). `username` and `source` are ignored: every record comes back. So user filters run
here, and a subsystem filter goes to FMC as '%<text>%'.

Changes have their own subsystems. FMC logs a configuration change in words under the UI path it belongs
to, also when it came through the API: 'Save Policy mcp-acp:12' under 'Policies > Security policies >
Access Control > Policy Editor', 'create host1:34' under 'Objects > Object Management > NetworkObject',
'Save Policy ftd1:56' under 'Devices > Device Management > Secure Firewall Interfaces'. Deployments are
'Task Queue' records. The API request of the same change is an 'API' record among every API read, and
those reads are the bulk of the log. fetch_changes therefore reads every record only for the newest few
slices, and the rest of the window through those subsystems (CHANGE_SUBSYSTEMS), filtered by FMC.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from fmc_mcp.client import FmcApp

AUDIT_PATH = "audit/auditrecords"
AUDIT_PAGE = 100  # FMC's per-query maximum
AUDIT_MAX_PAGES = 25  # 2500 records, ~25 requests (FMC allows ~120/min)
# Changes over a long window: every record for the newest CHANGE_SCAN_PAGES slices, then only these
# subsystems (FMC filters them: SQL LIKE), each up to CHANGE_SUBSYSTEM_PAGES slices. '%>%' is every
# subsystem named by a UI path ('Policies > ...', 'Objects > ...', 'Devices > ...': FMC's worded change
# records, plus page views and troubleshooting runs, dropped as reads); 'Task Queue' holds deployments.
CHANGE_SUBSYSTEMS = ("%>%", "Task Queue")
CHANGE_SCAN_PAGES = 5
CHANGE_SUBSYSTEM_PAGES = 10

# Reads and session housekeeping: not changes. A page view is logged under the page's UI path
# ('Policies > Security policies > Access Control > Policy Editor', message 'Page View'), and some UI
# reads in words ('View url filtering settings', subsystem 'Cloud Services').
_READ_MESSAGE = re.compile(r"^(GET\b|Page View$|View )")
NOISE_SUBSYSTEMS = ("page view", "login", "logout", "session expiration")
_API_URL = re.compile(r"https?://[^/\s]+/api/(fmc_\w+)/v\d+/domain/[0-9a-fA-F-]+/")
_API_URL_NODOMAIN = re.compile(r"https?://[^/\s]+/api/")
_STATUS_TAIL = re.compile(r"(\(\d{3}\))\s+-\s.*$")
# Operational requests that change no configuration (hit-count refresh, packet tracer, show commands).
_OPERATIONAL = re.compile(r"^(PUT|POST) \S*/(operational/hitcounts|packettracer|commands)\b", re.I)
# FMC's own records of troubleshooting runs: 'Devices > Troubleshoot > Packet Tracer' ("Trace: packet-tracer
# input inside TCP ... (device: ftd1)"), packet capture, the threat defense CLI, and hit-count refreshes from
# the UI: no configuration changes either (matched anywhere in the subsystem).
OPERATIONAL_SUBSYSTEMS = ("troubleshoot", "hit count", "threat defense cli")
_DEVICE_IN_MESSAGE = re.compile(r"\(device: ([^()]+)\)\s*$")


@dataclass
class AuditScan:
    items: list[dict[str, Any]] = field(default_factory=list)  # newest first, deduplicated
    complete: bool = True
    pages: int = 0
    reached: int | None = None  # oldest record time read when incomplete
    skipped_same_second: bool = False
    # fetch_changes: every record was read back to `all_to`; older ones only through `subsystems`
    all_to: int | None = None
    subsystems: tuple[str, ...] = ()


def is_read(rec: dict[str, Any]) -> bool:
    """A read-only API call, page view, login/logout, session expiry or an operational request
    (hit-count refresh, packet tracer, show command, FMC's Devices > Troubleshoot records)."""
    msg = str(rec.get("message") or "")
    sub = str(rec.get("subSystem") or "").strip().lower()
    return bool(
        _READ_MESSAGE.match(msg)
        or sub in NOISE_SUBSYSTEMS
        or _OPERATIONAL.match(msg)
        or any(o in sub for o in OPERATIONAL_SUBSYSTEMS)
    )


def contains(text: str) -> str:
    """FMC's `subsystem` filter (SQL LIKE) for 'subsystem contains <text>'."""
    return f"%{text.strip()}%"


def device_in(rec: dict[str, Any]) -> str | None:
    """The device a record names at its end, as FMC writes troubleshooting runs: '... (device: ftd1)'."""
    m = _DEVICE_IN_MESSAGE.search(str(rec.get("message") or ""))
    return m.group(1).strip() if m else None


def compact_message(msg: Any) -> str:
    """'PUT https://fmc/api/fmc_config/v1/domain/<uuid>/policy/x OK (200) - The request has succeeded'
    -> 'PUT fmc_config/policy/x OK (200)'."""
    m = _API_URL.sub(r"\1/", str(msg or ""))
    m = _API_URL_NODOMAIN.sub("", m)
    return _STATUS_TAIL.sub(r"\1", m).strip()


def audit_time(rec: dict[str, Any]) -> int:
    try:
        t = int(float(rec.get("time") or 0))
    except (TypeError, ValueError):
        return 0
    return t // 1000 if t > 10**11 else t


def _key(rec: dict[str, Any]) -> str:
    return str(rec.get("auditId") or rec.get("id") or (rec.get("time"), rec.get("message")))


async def fetch_audit(
    app: FmcApp,
    start: int,
    domain: str | None,
    *,
    max_pages: int | None = None,
    subsystem: str | None = None,
    end: int | None = None,
) -> AuditScan:
    """Every audit record from `start` to now (or to `end`), up to max_pages slices, newest first.
    `subsystem` is FMC's own filter (SQL LIKE on the whole name, case-insensitive; see contains)."""
    path = await app.platform_path(AUDIT_PATH, domain)
    max_pages = max_pages or AUDIT_MAX_PAGES
    scan = AuditScan()
    seen: set[str] = set()
    if end is not None and end < start:
        return scan
    while True:
        if scan.pages >= max_pages:
            scan.complete = False
            scan.reached = end
            break
        params: dict[str, Any] = {"starttime": start, "limit": AUDIT_PAGE, "expanded": "true"}
        if end is not None:
            params["endtime"] = end
        if subsystem:
            params["subsystem"] = subsystem
        data = await app.api.get(path, params)
        scan.pages += 1
        items = list((data or {}).get("items") or [])
        new = []
        for rec in items:
            key = _key(rec)
            if key not in seen:
                seen.add(key)
                new.append(rec)
        scan.items.extend(new)
        if len(items) < AUDIT_PAGE:
            break  # FMC had fewer than a full slice left: the window is read
        times = [audit_time(r) for r in items]
        oldest = min(times)
        if not new or oldest == max(times):
            # A full slice within one second (or nothing new): step past that second.
            scan.skipped_same_second = scan.skipped_same_second or oldest == max(times)
            oldest -= 1
        end = oldest
        if end < start:
            break
    scan.items.sort(key=audit_time, reverse=True)
    return scan


async def fetch_changes(
    app: FmcApp,
    start: int,
    domain: str | None,
    *,
    scan_pages: int | None = None,
    subsystem_pages: int | None = None,
) -> AuditScan:
    """The audit records that can be changes, from `start` to now, newest first: every record of the
    newest `scan_pages` slices, and, when the window holds more, only FMC's change subsystems
    (CHANGE_SUBSYSTEMS, filtered by FMC) for the older part. On a busy FMC this reaches a day back in a
    few requests where reading every API GET could not (#203). The result still holds reads (page views,
    packet-tracer runs): callers drop them with is_read."""
    scan = await fetch_audit(app, start, domain, max_pages=scan_pages or CHANGE_SCAN_PAGES)
    if scan.complete:
        return scan
    out = AuditScan(
        items=list(scan.items),
        pages=scan.pages,
        skipped_same_second=scan.skipped_same_second,
        all_to=scan.reached,
        subsystems=CHANGE_SUBSYSTEMS,
    )
    seen = {_key(r) for r in out.items}

    def merge(part: AuditScan) -> None:
        out.pages += part.pages
        out.skipped_same_second = out.skipped_same_second or part.skipped_same_second
        for rec in part.items:
            if _key(rec) not in seen:
                seen.add(_key(rec))
                out.items.append(rec)

    found = 0
    for sub in CHANGE_SUBSYSTEMS:
        part = await fetch_audit(
            app,
            start,
            domain,
            max_pages=subsystem_pages or CHANGE_SUBSYSTEM_PAGES,
            subsystem=sub,
            end=scan.reached,
        )
        merge(part)
        found += len(part.items)
        if not part.complete:
            out.complete = False
            out.reached = max(out.reached or 0, part.reached or 0)
    if not found:
        # Nothing under any UI path or the task queue (an FMC whose filter matches whole names only, or
        # a stretch with no change and no page view): read on through every record, as before.
        rest = await fetch_audit(
            app, start, domain, max_pages=max(1, AUDIT_MAX_PAGES - out.pages), end=scan.reached
        )
        merge(rest)
        out.all_to, out.subsystems = None, ()
        out.complete, out.reached = rest.complete, rest.reached
    out.items.sort(key=audit_time, reverse=True)
    return out


async def fetch_subsystem(app: FmcApp, start: int, domain: str | None, text: str) -> AuditScan:
    """Every audit record whose subsystem contains `text`, from `start` to now: FMC filters them (SQL
    LIKE), so the window is read in a request or two. If FMC finds nothing (also what an FMC matching
    whole names only answers), every record is read so the caller can filter them itself, as before."""
    scan = await fetch_audit(app, start, domain, subsystem=contains(text))
    if scan.items:
        return scan
    return await fetch_audit(app, start, domain)


def coverage_note(scan: AuditScan, reads: int | None = None) -> str | None:
    """Plain-language note when the scan did not read every record of the window: how far back it got,
    and how many of the records it read were reads (`reads`)."""
    from fmc_mcp.tools.system import iso

    counted = f"{len(scan.items)} records in {scan.pages} requests"
    if reads:
        counted += f", {reads} of them reads (API GETs, page views, logins, packet tracer)"
    notes = []
    if scan.all_to is not None:
        notes.append(
            f"Every audit record was read back to {iso(scan.all_to)} ({counted}); before that only FMC's "
            "configuration and deployment records, which FMC filters itself (subsystems with a UI path "
            "such as 'Policies > ... > Policy Editor' or 'Objects > Object Management > ...', and 'Task "
            "Queue'). API requests FMC logs only as 'API' (failed writes, for example) are not in that "
            "older part."
        )
        if not scan.complete:
            notes.append(
                f"Those were read back to {iso(scan.reached)} only: older changes in the window were not "
                "read; use a shorter window."
            )
    elif not scan.complete:
        notes.append(
            f"Audit log read back to {iso(scan.reached)} only ({counted}; FMC returns 100 per request). "
            "Older records in the window were not read: use a shorter window."
        )
    if scan.skipped_same_second:
        notes.append("More than 100 audit records shared one second; some of them may be missing.")
    return " ".join(notes) or None
