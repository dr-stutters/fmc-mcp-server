"""Objects behind access-rule conditions (F66): find applications and application filters, create an
application filter, create a time range. The rule writers take them as `applications=`,
`application_filters=` and `time_range=` (fmc_create_access_rule / fmc_update_access_rule)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, Field

from fmc_mcp._core import Confirm, InvalidRequest, NotFound, Plan, ToolRegistrar, get_client
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.rule_conditions import (
    APP_CATEGORIES,
    APP_FILTERS,
    APP_TAGS,
    APP_TYPES,
    LEVELS,
    TIME_NOTE,
    TIME_RANGES,
    UNLISTED_FILTERS,
    app_condition,
    app_filter_catalog,
    app_index,
    app_row,
    condition_text,
    facet,
    filter_row,
    filters_used_by,
    get_application,
    name_matches,
    remember_filter,
    remembered_filters,
    resolve_applications,
    time_range_row,
)
from fmc_mcp.tools.common import Domain, pick_by_name
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.policies import ACCESS, all_rules

DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")
DETAIL_CAP = 3  # exact-name matches read in full (one GET each)
USE = (
    "Use in rules: fmc_create_access_rule / fmc_update_access_rule applications=[name or id] or "
    "application_filters=[filter]; a new filter from attributes: fmc_create_application_filter."
)
INDEX_NOTE = (
    "FMC 10.0.1 can't filter its application list, so names are matched against an id+name index read "
    "once (about 9 requests of 1000) and reused for an hour; only matches are returned."
)
FILTER_LIST_NOTE = (
    f"FMC lists no application filters in this domain. {UNLISTED_FILTERS} The ones this server created "
    "since it started are listed with listed_by_fmc false; kind='filter' also lists the ones the access "
    "policies' rules use (with used_by). For others use the id from fmc_create_application_filter's result "
    "(application_filters=[id]), or inline_app_filter on the rule. Remove them in the FMC UI (Objects > "
    "Object Management > Application Filters)."
)
FILTER_SCAN_POLICIES = 25  # access policies whose rules kind='filter' reads when FMC lists no filters
CREATED_FILTER_NOTE = (
    f"{UNLISTED_FILTERS} Keep this filter's id: rules take application_filters=[id] (this server also "
    "finds it by name until it restarts). Delete it in the FMC UI (Objects > Object Management > "
    "Application Filters), after the rules that use it."
)


def _day(text: str) -> str:
    d = text.strip().upper()[:3]
    if d not in DAYS:
        raise InvalidRequest(f"Unknown day {text!r}; use MON, TUE, WED, THU, FRI, SAT or SUN.")
    return d


def _hhmm(text: str, what: str) -> str:
    m = re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*", text or "")
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise InvalidRequest(f"{what} must be HH:MM (24-hour), got {text!r}.")
    return f"{int(m.group(1)):02d}:{m.group(2)}"


def _when(text: str | None, what: str) -> str | None:
    """'2026-10-20', '2026-10-20T08:00', '2026-10-20 08:00:00' -> '2026-10-20T08:00' (FMC's form, no zone)."""
    if text is None or not text.strip():
        return None
    t = text.strip().replace(" ", "T").rstrip("Z")
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        raise InvalidRequest(
            f"{what} must be a date or date and time, e.g. 2026-10-20T08:00; got {text!r}."
        ) from None
    if dt.tzinfo is not None:
        raise InvalidRequest(f"{what}: leave out the time zone; devices use their own (platform settings).")
    return dt.strftime("%Y-%m-%dT%H:%M")


class TimeRecurrence(BaseModel):
    """A recurring window of a time range: daily on some days, or one weekly span."""

    days: list[str] | None = Field(
        None,
        description="Daily window: the days it applies, e.g. ['MON','TUE','WED','THU','FRI'] (with "
        "start_time and end_time)",
    )
    start_day: str | None = Field(
        None, description="Weekly span: the day it starts, e.g. 'FRI' (with end_day)"
    )
    end_day: str | None = Field(None, description="Weekly span: the day it ends, e.g. 'MON'")
    start_time: str = Field(description="Start time, HH:MM (24-hour)")
    end_time: str = Field(description="End time, HH:MM (24-hour)")


def recurrence_body(r: TimeRecurrence) -> dict[str, Any]:
    start, end = _hhmm(r.start_time, "start_time"), _hhmm(r.end_time, "end_time")
    if r.start_day or r.end_day:
        if not (r.start_day and r.end_day) or r.days:
            raise InvalidRequest("A weekly span needs start_day and end_day (and no days).")
        return {
            "recurrenceType": "RANGE",
            "rangeStartDay": _day(r.start_day),
            "rangeStartTime": start,
            "rangeEndDay": _day(r.end_day),
            "rangeEndTime": end,
        }
    if not r.days:
        raise InvalidRequest("Give days (a daily window) or start_day + end_day (a weekly span).")
    if start == end:
        raise InvalidRequest("A daily window needs different start_time and end_time.")
    days = []
    for d in r.days:
        if _day(d) not in days:
            days.append(_day(d))
    return {
        "recurrenceType": "DAILY_INTERVAL",
        "days": sorted(days, key=DAYS.index),
        "dailyStartTime": start,
        "dailyEndTime": end,
    }


def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def _recurrence_on(r: dict[str, Any], now: datetime) -> bool:
    minute = now.hour * 60 + now.minute
    if r.get("recurrenceType") == "RANGE":
        week = now.weekday() * 1440 + minute
        lo = DAYS.index(r["rangeStartDay"]) * 1440 + _minutes(r["rangeStartTime"])
        hi = DAYS.index(r["rangeEndDay"]) * 1440 + _minutes(r["rangeEndTime"])
        return lo <= week <= hi if lo <= hi else (week >= lo or week <= hi)
    if DAYS[now.weekday()] not in (r.get("days") or []):
        return False
    lo, hi = _minutes(r["dailyStartTime"]), _minutes(r["dailyEndTime"])
    return lo <= minute < hi if lo < hi else (minute >= lo or minute < hi)


def in_effect(tr: dict[str, Any], now: datetime) -> bool:
    """Whether a time range is in effect at `now`, read as the device's local time."""
    local = now.replace(tzinfo=None)
    start, end = tr.get("effectiveStartDateTime"), tr.get("effectiveEndDateTime")
    if start and local < datetime.fromisoformat(start):
        return False
    if end and local > datetime.fromisoformat(end):
        return False
    recs = tr.get("recurrenceList") or []
    return not recs or any(_recurrence_on(r, local) for r in recs)


def _contains(rows: list[dict[str, Any]] | tuple[tuple[str, str], ...], text: str) -> list[str]:
    t = text.lower()
    names = [r[1] for r in rows] if isinstance(rows, tuple) else [str(r["name"]) for r in rows]
    return [n for n in names if t in n.lower()]


async def _filters_in_rules(
    app: FmcApp, text: str, known: set[str], domain: str | None
) -> tuple[list[dict[str, Any]], str]:
    """The named application filters the domain's access policies' rules use, matching `text` (name part or
    id), each with the rules that use it: FMC 10.0.1 lists none it created over the API, and after a restart
    this server remembers none, so the rules are where their names and ids are left. One list of the
    policies plus one rule list per policy, at most FILTER_SCAN_POLICIES policies."""
    policies = await app.all(await app.config_path(ACCESS, domain), expanded=False)
    read = policies.items[:FILTER_SCAN_POLICIES]
    found: dict[str, dict[str, Any]] = {}
    for pol in read:
        rules = await all_rules(app, await app.config_path(f"{ACCESS}/{pol['id']}/accessrules", domain))
        for fid, hit in filters_used_by(rules.items, str(pol.get("name"))).items():
            if fid in known:
                continue
            row = found.setdefault(fid, {**hit["ref"], "listed_by_fmc": False, "used_by": []})
            row["used_by"] += hit["used_by"]
    t = text.lower()
    rows = [
        {k: v for k, v in r.items() if k != "type"}
        for r in found.values()
        if t in str(r.get("name", "")).lower() or t == str(r["id"]).lower()
    ]
    total = len(policies.items) if policies.complete else f"{len(policies.items)}+"
    note = (
        f"FMC lists no application filters, so the rules of {len(read)} of {total} access policies were read"
    )
    if len(read) < len(policies.items) or not policies.complete:
        note += f" (the first {FILTER_SCAN_POLICIES}; a filter only later policies use isn't listed)"
    return rows, note + "."


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Find applications and application filters")
    async def fmc_find_application(
        ctx: Context,
        text: Annotated[
            str,
            Field(
                min_length=1,
                description="An application name or numeric app id ('HTTP', 'Facebook', '676'), part of a "
                "name, an application filter name, or an attribute value ('High' risk, 'social networking' "
                "category)",
            ),
        ],
        kind: Annotated[
            Literal["any", "application", "filter", "attribute"],
            Field(
                description="What to search: applications, application filters, attribute values (risk, "
                "business relevance, category, tag, type), or all of them"
            ),
        ] = "any",
        limit: Annotated[int, Field(ge=1, le=50, description="Most names to list per kind")] = 10,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Look up applications for access rules. An exact name or numeric app id gives the application
        with its risk, business relevance, categories, tags and types; part of a name lists up to `limit`
        matching names (never the whole catalogue). Also finds application filters (named filters a rule
        can use) and the attribute values fmc_create_application_filter takes. The rule writers take the
        names: fmc_create_access_rule(applications=[...], application_filters=[...]). FMC 10.0.1 doesn't
        list application filters created over its API: the ones this server created since it started are
        remembered (per server process) and listed with listed_by_fmc false, and kind='filter' also reads
        the access policies' rules for the filters they use (used_by: policy / rule); inline_app_filter on
        the rule writers needs no filter object at all."""
        app: FmcApp = get_client(ctx)
        t = text.strip()
        out: dict[str, Any] = {"query": t}
        found = 0
        if kind in ("any", "application"):
            if t.isdigit():
                try:
                    out["applications"] = [app_row(await get_application(app, t, domain))]
                except NotFound:
                    out["applications"] = []
            else:
                index = await app_index(app, domain)
                exact, similar = name_matches(index, t)
                out["applications"] = [
                    app_row(await get_application(app, a["id"], domain)) for a in exact[:DETAIL_CAP]
                ]
                if similar:
                    out["similar_applications"] = [f"{a['name']} ({a['id']})" for a in similar[:limit]]
                    out["similar_total"] = len(similar)
                    found += len(similar)
                out["catalogue_size"] = len(index)
                out["index_note"] = INDEX_NOTE
            found += len(out["applications"])
        if kind in ("any", "filter"):
            filters = await app_filter_catalog(app, domain, expanded=True)
            hits = [f for f in filters if t.lower() in str(f.get("name", "")).lower()]
            listed = {str(f["id"]).lower() for f in filters}
            mine = [
                r["row"]
                for r in remembered_filters(app, await app.config_path(APP_FILTERS, domain))
                if r["id"].lower() not in listed
                and (t.lower() in r["name"].lower() or t.lower() == r["id"].lower())
            ]
            used: list[dict[str, Any]] = []
            if not filters and kind == "filter":
                known = listed | {str(r["id"]).lower() for r in mine}
                used, scan_note = await _filters_in_rules(app, t, known, domain)
                out["rules_scan"] = scan_note
            out["application_filters"] = ([filter_row(f) for f in hits] + mine + used)[:limit]
            found += len(hits) + len(mine) + len(used)
            if not filters:
                out["filter_note"] = FILTER_LIST_NOTE
        if kind in ("any", "attribute"):
            attrs = {
                "risks": _contains(LEVELS, t),
                "business_relevance": _contains(LEVELS, t),
                "types": _contains(APP_TYPES, t),
                "categories": _contains(await facet(app, APP_CATEGORIES, domain), t)[:limit],
                "tags": _contains(await facet(app, APP_TAGS, domain), t)[:limit],
            }
            attrs = {k: v for k, v in attrs.items() if v}
            if attrs:
                out["attributes"] = attrs
                found += sum(len(v) for v in attrs.values())
        out["summary"] = f"{found} match(es) for {t!r}." if found else f"Nothing matches {t!r}."
        out["use"] = USE
        return out

    @reg.write(title="Create application filter")
    async def fmc_create_application_filter(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New application filter name")],
        applications: Annotated[
            list[str] | None,
            Field(description="Applications by exact name or app id, always included (fmc_find_application)"),
        ] = None,
        risks: Annotated[
            list[str] | None,
            Field(description="Risk levels: 'Very Low', 'Low', 'Medium', 'High', 'Very High'"),
        ] = None,
        business_relevance: Annotated[
            list[str] | None,
            Field(description="Business relevance (FMC 'productivity'): 'Very Low' ... 'Very High'"),
        ] = None,
        categories: Annotated[
            list[str] | None,
            Field(description="Application categories, e.g. 'file sharing', 'social networking'"),
        ] = None,
        tags: Annotated[
            list[str] | None, Field(description="Application tags, e.g. 'sends mail', 'opens port'")
        ] = None,
        types: Annotated[
            list[str] | None, Field(description="Application types: 'Server', 'Client', 'Webapp'")
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a named application filter for access rules (application_filters=[...] on
        fmc_create_access_rule / fmc_update_access_rule). It matches the listed applications plus every
        application that has all the given attributes, any value within one attribute: risks=['High',
        'Very High'] and categories=['file sharing'] = high- and very-high-risk file sharing. Attribute
        values: fmc_find_application kind=attribute. Which applications match changes with VDB updates.
        FMC 10.0.1 doesn't list (or delete over REST) a filter created over its API: this server remembers
        the new filter's name and id for the rule writers and fmc_find_application while it runs (per
        process, lost on restart); keep the id from the result for later (application_filters=[id])."""
        app: FmcApp = get_client(ctx)
        cond = await app_condition(
            app,
            domain,
            risks=risks,
            business_relevance=business_relevance,
            categories=categories,
            tags=tags,
            types=types,
        )
        apps = await resolve_applications(app, applications, domain) if applications else []
        if not cond and not apps:
            raise InvalidRequest("Give applications or at least one attribute (risks, categories, ...).")
        body: dict[str, Any] = {"name": name, "type": "ApplicationFilter"}
        if apps:
            body["applications"] = apps
        if cond:
            body["appConditions"] = [cond]
        blockers: list[str] = []
        path = await app.config_path(APP_FILTERS, domain)
        existing = await app_filter_catalog(app, domain)
        try:
            pick_by_name(existing + remembered_filters(app, path), name, "application filter")
            blockers.append(f"An application filter named {name!r} already exists.")
        except NotFound:
            pass
        matches = " or ".join(
            ([f"applications {', '.join(str(a['name']) for a in apps)}"] if apps else [])
            + ([f"every application with {condition_text(cond)}"] if cond else [])
        )

        async def create() -> Any:
            answer = await applied(app, lambda: app.api.post(path, body))
            ref = remember_filter(app, path, answer)
            if ref is None:
                return answer
            return {
                **answer,
                "use": f"fmc_create_access_rule(application_filters=[{ref['id']!r}]) or by name "
                f"{ref['name']!r} while this server runs",
                "note": CREATED_FILTER_NOTE,
            }

        return await fmc_preview(
            ctx,
            tool="fmc_create_application_filter",
            args={
                "name": name,
                "applications": applications,
                "risks": risks,
                "business_relevance": business_relevance,
                "categories": categories,
                "tags": tags,
                "types": types,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create application filter {name!r}",
                details={"matches": matches, "body": body},
                fingerprint=body,
                blockers=blockers,
                side_effects=[
                    "Changes nothing on devices until an access rule uses it (application_filters=[...]) "
                    "and is deployed.",
                    "FMC 10.0.1 doesn't return such a filter on later REST reads, nor delete it over REST "
                    "(404): keep the id from the result for rules; it can only be removed in the FMC UI.",
                ],
            ),
            apply=create,
        )

    @reg.write(title="Create time range")
    async def fmc_create_time_range(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New time range name")],
        start: Annotated[
            str | None,
            Field(description="When it starts being in effect, e.g. 2026-10-20T08:00 (default: now)"),
        ] = None,
        end: Annotated[
            str | None,
            Field(description="When it stops being in effect, e.g. 2026-12-31T23:59 (default: never)"),
        ] = None,
        recurrences: Annotated[
            list[TimeRecurrence] | None,
            Field(
                description="Recurring windows inside start..end, e.g. [{'days': ['MON','TUE','WED','THU',"
                "'FRI'], 'start_time': '08:00', 'end_time': '18:00'}] or a weekly span [{'start_day': 'FRI', "
                "'start_time': '18:00', 'end_day': 'MON', 'end_time': '06:00'}]; none = the whole of "
                "start..end"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="Optional description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a time range object: an absolute window (start, end) and optional recurring daily or
        weekly windows. Access rules use it with time_range=... (fmc_create_access_rule /
        fmc_update_access_rule) and match only while it is in effect, in each device's time zone. Preview
        shows the windows in words and whether the range is in effect now."""
        app: FmcApp = get_client(ctx)
        s, e = _when(start, "start"), _when(end, "end")
        if s and e and e <= s:
            raise InvalidRequest("end must be after start.")
        body: dict[str, Any] = {"name": name, "type": "TimeRange"}
        if s:
            body["effectiveStartDateTime"] = s
        if e:
            body["effectiveEndDateTime"] = e
        if recurrences:
            body["recurrenceList"] = [recurrence_body(r) for r in recurrences]
        if description:
            body["description"] = description
        blockers: list[str] = []
        existing = await app.all(await app.config_path(TIME_RANGES, domain), expanded=False)
        try:
            pick_by_name(existing.items, name, "time range")
            blockers.append(f"A time range named {name!r} already exists.")
        except NotFound:
            pass
        now = datetime.now(UTC)
        row = time_range_row(body, now)
        warnings = []
        if row.get("ended"):
            warnings.append(f"It ends in the past ({e}): rules using it never match.")
        path = await app.config_path(TIME_RANGES, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_time_range",
            args={
                "name": name,
                "start": start,
                "end": end,
                "recurrences": None if recurrences is None else [r.model_dump() for r in recurrences],
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create time range {name!r}",
                details={
                    "time_range": row,
                    "in_effect_now": in_effect(body, now),
                    "now_utc": now.strftime("%Y-%m-%dT%H:%M"),
                    "body": body,
                },
                fingerprint=body,
                blockers=blockers,
                side_effects=warnings
                + [
                    TIME_NOTE + " in_effect_now reads the times as UTC.",
                    "Changes nothing on devices until an access rule uses it (time_range=...) and is "
                    "deployed.",
                ],
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )
