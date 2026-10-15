"""Reading FMC's audit log over a whole time window.

FMC 10.0.1 answers `audit/auditrecords` with at most the newest 100 records per query (paging.count
caps at 100 and offset 100 is empty), and every API call - ours included - writes a record. So a
plain query only reaches back a few minutes on a busy FMC. A past `endtime` is accepted (a future
one is rejected), so the window is read newest first in slices: each query asks for the newest 100
records up to the oldest time seen so far.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from fmc_mcp.client import FmcApp

AUDIT_PATH = "audit/auditrecords"
AUDIT_PAGE = 100  # FMC's per-query maximum
AUDIT_MAX_PAGES = 25  # 2500 records, ~25 requests (FMC allows ~120/min)

# Reads and session housekeeping: not changes.
_READ_MESSAGE = re.compile(r"^GET\b")
NOISE_SUBSYSTEMS = ("page view", "login", "logout", "session expiration")
_API_URL = re.compile(r"https?://[^/\s]+/api/(fmc_\w+)/v\d+/domain/[0-9a-fA-F-]+/")
_API_URL_NODOMAIN = re.compile(r"https?://[^/\s]+/api/")
_STATUS_TAIL = re.compile(r"(\(\d{3}\))\s+-\s.*$")
# Operational requests that change no configuration (hit-count refresh, packet tracer, show commands).
_OPERATIONAL = re.compile(r"^(PUT|POST) \S*/(operational/hitcounts|packettracer|commands)\b", re.I)


@dataclass
class AuditScan:
    items: list[dict[str, Any]] = field(default_factory=list)  # newest first, deduplicated
    complete: bool = True
    pages: int = 0
    reached: int | None = None  # oldest record time read when incomplete
    skipped_same_second: bool = False


def is_read(rec: dict[str, Any]) -> bool:
    """A read-only API call, page view, login/logout, session expiry or an operational request
    (hit-count refresh, packet tracer, show command)."""
    msg = str(rec.get("message") or "")
    sub = str(rec.get("subSystem") or "")
    return bool(
        _READ_MESSAGE.match(msg) or sub.strip().lower() in NOISE_SUBSYSTEMS or _OPERATIONAL.match(msg)
    )


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


async def fetch_audit(
    app: FmcApp,
    start: int,
    domain: str | None,
    *,
    max_pages: int | None = None,
    subsystem: str | None = None,
) -> AuditScan:
    """Every audit record from `start` to now (up to max_pages slices), newest first.
    `subsystem` is FMC's own exact-match filter."""
    path = await app.platform_path(AUDIT_PATH, domain)
    max_pages = max_pages or AUDIT_MAX_PAGES
    scan = AuditScan()
    seen: set[str] = set()
    end: int | None = None
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
            key = str(rec.get("auditId") or rec.get("id") or (rec.get("time"), rec.get("message")))
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


def coverage_note(scan: AuditScan) -> str | None:
    """Plain-language note when the scan did not cover the whole window."""
    from fmc_mcp.tools.system import iso

    if not scan.complete:
        return (
            f"Audit log read back to {iso(scan.reached)} only ({len(scan.items)} records in "
            f"{scan.pages} requests; FMC returns 100 per request). Older records in the window were not "
            "read: use a shorter window."
        )
    if scan.skipped_same_second:
        return "More than 100 audit records shared one second; some of them may be missing."
    return None
