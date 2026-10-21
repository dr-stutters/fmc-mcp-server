"""Time-range and source-SGT conditions in fmc_rule_lookup (W6 live fix, F66).

Recorded live on FMC 10.0.1 / FTD 10.0.0 (2026-10-21):
- A rule whose time range had ended (absolute window, no recurrence) got no hits from matching traffic,
  while the lookup listed it as 'conditional'. FMC stores a range created without a start with
  effectiveStartDateTime "Started" (a literal, not a date).
- The device decided bob's flow by an SGT rule (source SGT Contractors) while the lookup, which had his user
  and groups, called that rule conditional and gave the verdict to a later user rule. FMC carries the SGT
  of an ISE session in its user activity (analysis/useractivity `securityGroupTag`, the login event), not
  in analysis/activesessions.

Time-range times have no zone: the device reads them in its own time zone (platform settings). A window
counts as ended (or not started) only when it is so in every zone from UTC-12 to UTC+14, and as in effect
only when it is so in every zone and has no recurring windows; anything else stays conditional.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from fmc_mcp._core import UpstreamError
from fmc_mcp.client import FmcApp
from fmc_mcp.rule_conditions import TIME_RANGES
from fmc_mcp.tools.live import activity_items, history_error, sessions_domain
from fmc_mcp.tools.system import iso

BEHIND = timedelta(hours=12)  # the furthest a device clock can be behind UTC (UTC-12)
AHEAD = timedelta(hours=14)  # and ahead (UTC+14)
ACTIVITY_HOURS = 24 * 30  # how far back the source IP's ISE login (with its SGT) is looked for


def now() -> datetime:
    """The current time in UTC (a function so tests can fix the clock)."""
    return datetime.now(UTC)


# --- time ranges ------------------------------------------------------------------------------------


def _local(value: Any) -> tuple[bool, datetime | None]:
    """(readable, a time range bound as a naive local time): None when there is none ('' or FMC's
    'Started'); readable False when it can't be parsed."""
    s = str(value or "").strip()
    if not s or s.lower() == "started":
        return True, None
    try:
        return True, datetime.fromisoformat(s.rstrip("Z")).replace(tzinfo=None)
    except ValueError:
        return False, None


def window_state(tr: dict[str, Any], at: datetime) -> tuple[bool | None, str | None]:
    """(True: in effect in every time zone, False: ended or not started in every zone, None: it depends on
    the device's zone or a recurring window) and the reason for False."""
    utc = at.astimezone(UTC).replace(tzinfo=None)
    ok_start, start = _local(tr.get("effectiveStartDateTime"))
    ok_end, end = _local(tr.get("effectiveEndDateTime"))
    if not (ok_start and ok_end):
        return None, None
    if end is not None and end < utc - BEHIND:
        return False, f"ended {end:%Y-%m-%dT%H:%M}"
    if start is not None and start > utc + AHEAD:
        return False, f"starts {start:%Y-%m-%dT%H:%M}"
    started = start is None or start <= utc - BEHIND
    running = end is None or end >= utc + AHEAD
    if started and running and not tr.get("recurrenceList"):
        return True, None
    return None, None


def _time_refs(rule: dict[str, Any]) -> list[dict[str, Any]]:
    """A rule's time range refs: FMC sends a plain list (older exports used {objects: [...]})."""
    block = rule.get("timeRangeObjects")
    refs = block.get("objects") if isinstance(block, dict) else block
    return [r for r in refs or [] if isinstance(r, dict)]


def uses_time_ranges(rules: list[dict[str, Any]]) -> bool:
    return any(_time_refs(r) for r in rules)


async def time_range_catalog(app: FmcApp, domain: str | None) -> dict[str, dict[str, Any]] | None:
    """Time range objects by id (lower case), or None when FMC doesn't answer the list."""
    try:
        page = await app.all(await app.config_path(TIME_RANGES, domain))
    except UpstreamError:
        return None
    return {str(t["id"]).lower(): t for t in page.items if t.get("id")}


def time_range_check(
    rule: dict[str, Any], ranges: dict[str, dict[str, Any]] | None, at: datetime
) -> tuple[bool | None, dict[str, Any] | None]:
    """Whether the rule's time range lets it match at `at`: True (none, or in effect everywhere), False
    with {time_range, reason} (ended or not started everywhere), None (unknown: conditional)."""
    refs = _time_refs(rule)
    if not refs:
        return True, None
    if ranges is None:
        return None, None
    states: list[tuple[bool | None, str | None, str]] = []
    for ref in refs:
        tr = ranges.get(str(ref.get("id", "")).lower())
        if tr is None:
            return None, None
        state, why = window_state(tr, at)
        states.append((state, why, str(tr.get("name") or ref.get("name"))))
    if any(s is True for s, _, _ in states):
        return True, None
    if all(s is False for s, _, _ in states):
        return False, {
            "time_range": ", ".join(n for _, _, n in states),
            "reason": "; ".join(str(w) for _, w, _ in states),
        }
    return None, None


# --- the flow's source SGT ----------------------------------------------------------------------------


@dataclass
class FlowSgt:
    """The SGT the device sees on the flow's source: given, or from the source IP's ISE login."""

    name: str | None = None
    tag: int | None = None
    origin: str | None = None
    note: str | None = None

    @property
    def known(self) -> bool:
        return self.name is not None or self.tag is not None

    def label(self) -> str | None:
        if self.name and self.tag is not None:
            return f"{self.name} (SGT {self.tag})"
        if self.name:
            return self.name
        return f"SGT {self.tag}" if self.tag is not None else None

    def as_dict(self) -> dict[str, Any]:
        out = {"sgt": self.label(), "from": self.origin, "note": self.note}
        return {k: v for k, v in out.items() if v is not None}


def with_catalog(sgt: FlowSgt, catalog: list[dict[str, Any]]) -> FlowSgt:
    """Fill in the tag number for a name, or the name for a tag number, from the SGT catalogue."""
    for s in catalog:
        if sgt.name and sgt.tag is None and str(s.get("name", "")).lower() == sgt.name.lower():
            sgt.name, sgt.tag = str(s.get("name")), _int(s.get("tag"))
            break
        if sgt.tag is not None and sgt.name is None and _int(s.get("tag")) == sgt.tag:
            sgt.name = str(s.get("name"))
            break
    return sgt


def given_sgt(text: str) -> FlowSgt:
    t = text.strip()
    if t.isdigit():
        return FlowSgt(tag=int(t), origin="source_sgt (given)")
    return FlowSgt(name=t, origin="source_sgt (given)")


def _int(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _is_login(event: dict[str, Any]) -> bool:
    return "login" in str(event.get("event", "")).lower()


async def session_sgt(app: FmcApp, ip: str, user: str | None, domain: str | None) -> FlowSgt:
    """The SGT of the source IP's ISE session: the newest login event FMC's user activity has for the IP
    (for `user` when the identity sessions named one) carries it. Unknown (rules stay conditional) when
    the activity can't be read, the newest event is a logoff, or the login carries no SGT."""
    try:
        events = await activity_items(app, domain, ip=ip, hours=ACTIVITY_HOURS)
    except UpstreamError as e:
        return FlowSgt(note=f"Source SGT not resolved: {history_error(e)}")
    events = [a for a in events if str(a.get("ipAddress", "")) == ip] or events
    if not events:
        return FlowSgt(
            note=f"No ISE login for {ip} in FMC's user activity (30 days): SGT rules stay conditional."
        )
    newest = events[0]
    if user:
        mine = [a for a in events if str(a.get("username", "")).lower() == user.lower()]
        newest = mine[0] if mine else newest
    who, when = newest.get("username"), iso(newest.get("time"))
    where = f" (domain {sessions_domain(events)})" if sessions_domain(events) else ""
    if not _is_login(newest):
        return FlowSgt(
            note=f"The newest user activity for {ip} is '{newest.get('event')}' by {who} at {when}: no ISE "
            "session there, so SGT rules stay conditional (an SXP or inline tag may still apply)."
        )
    tag = str(newest.get("securityGroupTag") or "").strip()
    origin = f"FMC user activity{where}: {newest.get('event')} {who} at {when}"
    if not tag:
        return FlowSgt(origin=origin, note="That login carries no SGT: SGT rules stay conditional.")
    return FlowSgt(
        name=None if tag.isdigit() else tag, tag=int(tag) if tag.isdigit() else None, origin=origin
    )


def sgt_check(block: Any, sgt: FlowSgt | None, tags: dict[str, Any] | None) -> bool | None:
    """A rule's source SGT condition against the flow's SGT: True/False, None when the rule has SGTs and
    the flow's SGT is unknown."""
    refs = [] if not isinstance(block, dict) else (block.get("objects") or []) + (block.get("literals") or [])
    refs = [r for r in refs if isinstance(r, dict)]
    if not refs:
        return True
    if sgt is None or not sgt.known:
        return None
    for r in refs:
        tag = _int(r.get("tag"))
        if tag is None and tags:
            tag = _int((tags.get(str(r.get("id"))) or (None, None))[0])
        if sgt.name and str(r.get("name", "")).lower() == sgt.name.lower():
            return True
        if sgt.tag is not None and tag == sgt.tag:
            return True
    return False
