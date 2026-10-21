"""Application, application-filter, time-range and security-group-tag conditions of access rules (F66).

An access rule keeps them in four fields:
- `applications`: {"applications": [Application refs], "applicationFilters": [ApplicationFilter refs],
  "inlineApplicationFilters": [...]}. Application ids are the numeric VDB app ids ("676" = HTTP).
- `timeRangeObjects`: a plain list of TimeRange refs (the FMC UI allows one per rule).
- `sourceSecurityGroupTags` / `destinationSecurityGroupTags`: {"objects": [ISESecurityGroupTag or
  SecurityGroupTag refs]}.
VLAN tags (`vlanTags`) are ordinary object/literal blocks and go through refs.RefResolver.

FMC 10.0.1 quirks (recorded live 2026-10-20):
- `GET object/applications` ignores `filter=` (`name:HTTP` and `nameOrValue:HTTP` both answer the whole
  8393-row catalogue) and the spec documents none, so names resolve against an id+name index read once
  per server process (expanded=false, 1000 a page) and refreshed hourly; it is never returned whole.
  Numeric ids resolve with one GET.
- `object/securitygrouptags` (custom SGTs) answers 422 "Identity Service Engine is enabled" while an ISE
  source is on, and `object/isesecuritygrouptags` 422 "... is disabled" while none is: SGT names are
  looked up in both lists and a 422 means "none of that kind".

FMC 10.0.1 quirk (recorded live 2026-10-21): an application filter created over the API (POST 201) is not
returned by any later REST read: `GET object/applicationfilters` answers `{"paging": {"count": 0}}` (no
`items`), and GET and DELETE by id answer 404, in the creating domain and in Global. FMC still takes it by
id in an access rule (POST accessrules with `applications.applicationFilters: [{id, type, name}]` -> 201),
and rule GETs carry it as {name, id, type}. So a filter name also resolves against the filters this server
created (remembered from the POST answer, per server process) and the filters rules already use, and a UUID
FMC answers 404 for is sent as given. Whether FMC refuses a rule naming an id that exists nowhere is not
proven yet (only ids of filters that exist were sent live), so nothing here claims it does.
"""

from __future__ import annotations

import asyncio
import difflib
import re
import time
import weakref
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from fmc_mcp._core import InvalidRequest, NotFound, UpstreamError
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.tools.common import block_labels, pick_by_name, ref_label, resolve_in

APPLICATIONS = "object/applications"
APP_FILTERS = "object/applicationfilters"
APP_CATEGORIES = "object/applicationcategories"
APP_TAGS = "object/applicationtags"
TIME_RANGES = "object/timeranges"
ISE_SGTS = "object/isesecuritygrouptags"
CUSTOM_SGTS = "object/securitygrouptags"
SGT_FIELDS = ("sourceSecurityGroupTags", "destinationSecurityGroupTags")

# Fixed FMC enums (10.0.1: object/applicationrisks, /applicationproductivities, /applicationtypes).
LEVELS = (
    ("VERY_LOW", "Very Low"),
    ("LOW", "Low"),
    ("MEDIUM", "Medium"),
    ("HIGH", "High"),
    ("VERY_HIGH", "Very High"),
)
APP_TYPES = (("SERVER", "Server"), ("CLIENT", "Client"), ("WEBAPP", "Webapp"))

INDEX_TTL = 3600.0  # seconds; the application catalogue only changes with a VDB update
INDEX_CAP = 20_000
_INDEX: weakref.WeakKeyDictionary[FmcApp, tuple[float, list[dict[str, str]]]] = weakref.WeakKeyDictionary()
_LOCKS: weakref.WeakKeyDictionary[FmcApp, asyncio.Lock] = weakref.WeakKeyDictionary()
_FACETS: weakref.WeakKeyDictionary[FmcApp, dict[str, tuple[float, list[dict[str, Any]]]]] = (
    weakref.WeakKeyDictionary()
)
# Application filters this server created ({id, name, path, row}), newest last: FMC 10.0.1 doesn't list them.
_CREATED: weakref.WeakKeyDictionary[FmcApp, list[dict[str, Any]]] = weakref.WeakKeyDictionary()


# --- applications ---------------------------------------------------------------------------------


async def app_index(app: FmcApp, domain: str | None) -> list[dict[str, str]]:
    """Every application's {id, name} (FMC can't filter the list), cached per server process."""
    hit = _INDEX.get(app)
    if hit and time.monotonic() - hit[0] < INDEX_TTL:
        return hit[1]
    lock = _LOCKS.setdefault(app, asyncio.Lock())
    async with lock:
        hit = _INDEX.get(app)
        if hit and time.monotonic() - hit[0] < INDEX_TTL:
            return hit[1]
        page = await app.all(await app.config_path(APPLICATIONS, domain), expanded=False, cap=INDEX_CAP)
        rows = [{"id": str(a["id"]), "name": str(a.get("name") or "")} for a in page.items if a.get("id")]
        if page.complete:
            _INDEX[app] = (time.monotonic(), rows)
        return rows


def forget_index(app: FmcApp) -> None:
    _INDEX.pop(app, None)
    _FACETS.pop(app, None)


def app_ref(a: dict[str, Any]) -> dict[str, Any]:
    return {"id": str(a["id"]), "type": "Application", "name": a.get("name")}


def name_matches(index: list[dict[str, str]], text: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """(exact, similar): exact = same name ignoring case; similar = names that start with or contain the text
    (starts-with first), without the exact ones."""
    t = text.strip().lower()
    exact = [a for a in index if a["name"].lower() == t]
    starts = [a for a in index if a["name"].lower().startswith(t) and a["name"].lower() != t]
    contains = [a for a in index if t in a["name"].lower() and not a["name"].lower().startswith(t)]
    return exact, sorted(starts, key=lambda a: a["name"].lower()) + sorted(
        contains, key=lambda a: a["name"].lower()
    )


async def get_application(app: FmcApp, app_id: str, domain: str | None) -> dict[str, Any]:
    try:
        data: dict[str, Any] = await app.api.get(f"{await app.config_path(APPLICATIONS, domain)}/{app_id}")
    except NotFound:
        raise NotFound(
            f"No application with id {app_id} (fmc_find_application finds them by name).", 404
        ) from None
    return data


async def resolve_applications(app: FmcApp, names: list[str], domain: str | None) -> list[dict[str, Any]]:
    """Application refs by exact name (case-insensitive) or numeric app id, in order, deduplicated."""
    out: list[dict[str, Any]] = []
    index: list[dict[str, str]] | None = None
    for raw in names:
        t = str(raw).strip()
        if not t:
            continue
        if t.isdigit():
            ref = app_ref(await get_application(app, t, domain))
        else:
            index = index if index is not None else await app_index(app, domain)
            exact, similar = name_matches(index, t)
            same_case = [a for a in exact if a["name"] == t]
            picked = same_case or exact
            if not picked:
                close = difflib.get_close_matches(
                    t.lower(), [a["name"].lower() for a in index], n=5, cutoff=0.6
                )
                names_close = [a["name"] for a in index if a["name"].lower() in close][:5] or [
                    a["name"] for a in similar[:5]
                ]
                hint = f" Close: {', '.join(names_close)}." if names_close else ""
                raise NotFound(
                    f"No application named {t!r} in FMC's application catalogue.{hint} "
                    "(fmc_find_application searches it.)",
                    404,
                )
            ref = app_ref(picked[0])
        if all(r["id"] != ref["id"] for r in out):
            out.append(ref)
    return out


async def app_filter_catalog(
    app: FmcApp, domain: str | None, *, expanded: bool = False
) -> list[dict[str, Any]]:
    page = await app.all(await app.config_path(APP_FILTERS, domain), expanded=expanded)
    return [f for f in page.items if f.get("id")]


UNLISTED_FILTERS = (
    "FMC 10.0.1 doesn't return application filters created over its API: its list is empty and GET or "
    "DELETE by id answers 404, though access rules take them by id."
)
FILTER_BY_ID = (
    "pass the filter's UUID instead (the id in fmc_create_application_filter's result, or in "
    "fmc_get_access_rule of a rule that uses it); it can't be checked against FMC's list beforehand, so "
    "check the rule afterwards with fmc_get_access_rule"
)


def filter_ref(f: dict[str, Any]) -> dict[str, Any]:
    ref = {"id": str(f["id"]), "type": "ApplicationFilter", "name": f.get("name")}
    return {k: v for k, v in ref.items() if v is not None}


def remember_filter(app: FmcApp, path: str, answer: Any) -> dict[str, Any] | None:
    """Keep a filter FMC just created (its POST answer) so later rule writes find it by name."""
    if not isinstance(answer, dict) or not answer.get("id") or not answer.get("name"):
        return None
    ref = filter_ref(answer)
    rows = _CREATED.setdefault(app, [])
    rows[:] = [
        r
        for r in rows
        if r["path"] != path
        or (r["id"].lower() != ref["id"].lower() and r["name"].lower() != ref["name"].lower())
    ]
    rows.append({**ref, "path": path, "row": {**filter_row(answer), "listed_by_fmc": False}})
    return ref


def remembered_filters(app: FmcApp, path: str) -> list[dict[str, Any]]:
    """Filters this server created in the collection at `path` (newest first)."""
    return [r for r in reversed(_CREATED.get(app) or []) if r["path"] == path]


def filter_refs_in_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The application filters rules use ({id, type, name} as rule GETs carry them), first use first."""
    out: list[dict[str, Any]] = []
    for r in rules:
        for f in (r.get("applications") or {}).get("applicationFilters") or []:
            if (
                isinstance(f, dict)
                and f.get("id")
                and all(o["id"].lower() != str(f["id"]).lower() for o in out)
            ):
                out.append(filter_ref(f))
    return out


async def resolve_app_filters(
    app: FmcApp,
    names: list[str],
    domain: str | None,
    *,
    known: list[dict[str, Any]] | None = None,
    notes: list[str] | None = None,
) -> list[dict[str, Any]]:
    """ApplicationFilter refs by name or UUID: from FMC's list, else from the filters this server created
    or `known` (refs rules already use), since FMC 10.0.1 lists none it created over the API; a UUID FMC
    answers 404 for is sent as given. `notes` gets a line for each filter FMC itself didn't return."""
    path = await app.config_path(APP_FILTERS, domain)
    extra = [filter_ref(r) for r in remembered_filters(app, path)] + list(known or [])
    out: list[dict[str, Any]] = []
    catalog: list[dict[str, Any]] | None = None
    for raw in names:
        t = str(raw).strip()
        if not t:
            continue
        unlisted: str | None = None
        if is_uuid(t):
            try:
                f = await resolve_in(app, APP_FILTERS, t, "application filter", domain)
            except NotFound:
                hit = next((k for k in extra if k["id"].lower() == t.lower()), None)
                f = hit or {"id": t}
                unlisted = f"FMC answers 404 for application filter {t}; it is sent by id."
        else:
            catalog = catalog if catalog is not None else await app_filter_catalog(app, domain)
            try:
                f = pick_by_name(catalog, t, "application filter")
            except NotFound as e:
                hits = [k for k in extra if str(k.get("name", "")).lower() == t.lower()]
                if not hits:
                    head = (
                        f"No application filter named {t!r}: FMC lists none in this domain"
                        if not catalog
                        else str(e).rstrip(".")
                    )
                    raise NotFound(
                        f"{head}. {UNLISTED_FILTERS} So {FILTER_BY_ID}. New ones: "
                        "fmc_create_application_filter.",
                        404,
                    ) from None
                f = hits[0]
                unlisted = f"Application filter {t!r} ({f['id']}) isn't listed by FMC; it is sent by id."
        ref = filter_ref(f)
        if all(r["id"].lower() != ref["id"].lower() for r in out):
            out.append(ref)
            if unlisted and notes is not None:
                notes.append(
                    f"{unlisted} {UNLISTED_FILTERS} The id can't be checked beforehand: confirm the rule "
                    "carries the filter with fmc_get_access_rule after saving."
                )
    return out


def merge_app_block(
    current: dict[str, Any] | None,
    apps: list[dict[str, Any]] | None,
    filters: list[dict[str, Any]] | None,
    inline: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """A rule's `applications` block from its current one and new applications / filters / inline filters
    (None = keep the current ones, [] = none). Other settings of the current block are kept."""
    cur = dict(current or {})
    if apps is not None:
        cur["applications"] = apps
    if filters is not None:
        cur["applicationFilters"] = filters
    if inline is not None:
        cur["inlineApplicationFilters"] = inline
    out = {k: v for k, v in cur.items() if v not in (None, [], {})}
    if not any(out.get(k) for k in ("applications", "applicationFilters", "inlineApplicationFilters")):
        return {}
    return out


async def facet(app: FmcApp, path: str, domain: str | None) -> list[dict[str, Any]]:
    """Application categories or tags (small VDB lists), cached like the index."""
    cache = _FACETS.setdefault(app, {})
    hit = cache.get(path)
    if hit and time.monotonic() - hit[0] < INDEX_TTL:
        return hit[1]
    page = await app.all(await app.config_path(path, domain), expanded=False)
    rows = [{"id": str(i["id"]), "name": str(i.get("name") or "")} for i in page.items if i.get("id")]
    if page.complete:
        cache[path] = (time.monotonic(), rows)
    return rows


def pick_level(text: str, choices: tuple[tuple[str, str], ...], what: str) -> tuple[str, str]:
    key = re.sub(r"[\s\-]+", "_", text.strip().upper())
    for cid, name in choices:
        if key in (cid, name.upper().replace(" ", "_")):
            return cid, name
    raise InvalidRequest(f"Unknown {what} {text!r}; choose from {', '.join(n for _, n in choices)}.")


def pick_facet(rows: list[dict[str, Any]], text: str, what: str) -> dict[str, Any]:
    t = text.strip()
    hit = next((r for r in rows if r["id"] == t), None) or next(
        (r for r in rows if r["name"].lower() == t.lower()), None
    )
    if hit is None:
        close = difflib.get_close_matches(t.lower(), [r["name"].lower() for r in rows], n=5, cutoff=0.5)
        contains = [r["name"] for r in rows if t.lower() in r["name"].lower()][:5]
        hint = close or contains
        raise NotFound(
            f"No application {what} {text!r}."
            + (f" Did you mean: {', '.join(hint)}?" if hint else "")
            + " (fmc_find_application kind=attribute lists them.)",
            404,
        )
    return hit


class InlineAppFilter(BaseModel):
    """Application attributes matched inside one rule (FMC's inline application filter): every application
    with all the given attributes, any value within one attribute. Unknown keys are refused: a misspelt one
    ('risk') would otherwise leave the filter empty, which fmc_update_access_rule reads as "remove the rule's
    inline filters"."""

    model_config = ConfigDict(extra="forbid")

    risks: list[str] | None = Field(
        None, description="Risk levels: 'Very Low', 'Low', 'Medium', 'High', 'Very High'"
    )
    business_relevance: list[str] | None = Field(
        None, description="Business relevance (FMC 'productivity'): 'Very Low' ... 'Very High'"
    )
    categories: list[str] | None = Field(
        None, description="Application categories, e.g. 'file sharing', 'social networking'"
    )
    tags: list[str] | None = Field(None, description="Application tags, e.g. 'sends mail', 'opens port'")
    types: list[str] | None = Field(None, description="Application types: 'Server', 'Client', 'Webapp'")


async def app_condition(
    app: FmcApp,
    domain: str | None,
    *,
    risks: list[str] | None = None,
    business_relevance: list[str] | None = None,
    categories: list[str] | None = None,
    tags: list[str] | None = None,
    types: list[str] | None = None,
) -> dict[str, Any]:
    """One application condition (FMC's IAppCondition, as a named filter's `appConditions` entry and a rule's
    `inlineApplicationFilters` entry take it) from attribute names: risks and business relevance from FMC's
    fixed levels, types from its three types, categories and tags from FMC's lists (close-match hints).
    {} when nothing is given."""
    cond: dict[str, Any] = {}
    if risks:
        cond["risks"] = [
            {"id": i, "type": "ApplicationRisk", "name": n}
            for i, n in dict(pick_level(r, LEVELS, "risk") for r in risks).items()
        ]
    if business_relevance:
        cond["productivities"] = [
            {"id": i, "type": "ApplicationProductivity", "name": n}
            for i, n in dict(pick_level(r, LEVELS, "business relevance") for r in business_relevance).items()
        ]
    if types:
        cond["applicationTypes"] = [
            {"id": i, "type": "ApplicationType", "name": n}
            for i, n in dict(pick_level(t, APP_TYPES, "application type") for t in types).items()
        ]
    for given, key, path, fmc_type, what in (
        (categories, "categories", APP_CATEGORIES, "ApplicationCategory", "category"),
        (tags, "tags", APP_TAGS, "ApplicationTag", "tag"),
    ):
        if given:
            rows = await facet(app, path, domain)
            picked = {h["id"]: h for h in (pick_facet(rows, v, what) for v in given)}
            cond[key] = [{"id": h["id"], "type": fmc_type, "name": h["name"]} for h in picked.values()]
    return cond


def app_row(a: dict[str, Any]) -> dict[str, Any]:
    """One application with its risk, business relevance (productivity), categories, tags and types."""
    prod = a.get("appProductivity") or a.get("productivity") or {}
    cats = a.get("appCategories") or a.get("categories") or []
    tags = a.get("applicationTags") or a.get("tags") or []
    row = {
        "name": a.get("name"),
        "id": str(a.get("id")),
        "risk": (a.get("risk") or {}).get("name"),
        "business_relevance": prod.get("name"),
        "categories": [c.get("name") for c in cats] or None,
        "tags": [t.get("name") for t in tags] or None,
        "types": [t.get("name") for t in a.get("applicationTypes") or []] or None,
        "deprecated": a.get("deprecated") or None,
    }
    return {k: v for k, v in row.items() if v is not None}


def condition_text(c: dict[str, Any]) -> str:
    """One application filter condition in words: attributes AND-ed, values OR-ed."""
    parts = []
    for key, label in (
        ("risks", "risk"),
        ("productivities", "business relevance"),
        ("categories", "category"),
        ("tags", "tag"),
        ("applicationTypes", "type"),
    ):
        vals = [ref_label(v) for v in c.get(key) or []]
        if vals:
            parts.append(f"{label} {' or '.join(vals)}")
    return " and ".join(parts) or str(c.get("search") or c.get("filter") or "any")


FILTER_APPS_SHOWN = 10


def filter_row(f: dict[str, Any]) -> dict[str, Any]:
    """An application filter in words. The spec's GET example lists the applications the conditions
    match in `applications` (metadata.count of them), so only the first few names are shown."""
    apps = [ref_label(a) for a in f.get("applications") or []]
    row = {
        "name": f.get("name"),
        "id": f.get("id"),
        "conditions": [condition_text(c) for c in f.get("appConditions") or []] or None,
        "applications": apps[:FILTER_APPS_SHOWN] or None,
        "applications_total": len(apps) if len(apps) > FILTER_APPS_SHOWN else None,
        "matches_apps": (f.get("metadata") or {}).get("count"),
    }
    return {k: v for k, v in row.items() if v is not None}


# --- security group tags ----------------------------------------------------------------------------


async def sgt_catalog(app: FmcApp, domain: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    """ISE and custom SGTs ({id, name, type, tag, source}) and notes on lists FMC refused."""
    rows: list[dict[str, Any]] = []
    notes: list[str] = []
    for path, source in ((ISE_SGTS, "ISE"), (CUSTOM_SGTS, "custom")):
        try:
            page = await app.all(await app.config_path(path, domain))
        except UpstreamError as e:
            if getattr(e, "status_code", None) == 422 or "identity service engine" in str(e).lower():
                notes.append(f"{source} SGTs: {e}")
                continue
            raise
        rows += [{**s, "source": source} for s in page.items if s.get("id")]
    return rows, notes


def pick_sgt(catalog: list[dict[str, Any]], text: str, notes: list[str]) -> dict[str, Any]:
    t = str(text).strip()
    hits = (
        [s for s in catalog if str(s.get("id")) == t]
        or [s for s in catalog if str(s.get("name", "")).lower() == t.lower()]
        or ([s for s in catalog if str(s.get("tag")) == t] if t.isdigit() else [])
    )
    if len(hits) > 1:
        where = ", ".join(f"{s.get('name')} ({s.get('source')}, tag {s.get('tag')})" for s in hits)
        raise InvalidRequest(f"SGT {text!r} is ambiguous ({where}); pass its name or id.")
    if not hits:
        names = [str(s.get("name")) for s in catalog]
        close = difflib.get_close_matches(t, names, n=5, cutoff=0.5)
        hint = f" Did you mean: {', '.join(close)}?" if close else ""
        if not catalog:
            hint = (
                " FMC has no SGTs: ISE SGTs come from an ISE identity source over pxGrid "
                "(fmc_get_identity_sources); custom SGTs exist only while no ISE source is enabled."
            )
        raise NotFound(
            f"No security group tag {text!r}.{hint}" + (f" ({'; '.join(notes)})" if notes else ""), 404
        )
    s = hits[0]
    return {"id": str(s["id"]), "type": s.get("type") or "ISESecurityGroupTag", "name": s.get("name")}


def sgt_tags(catalog: list[dict[str, Any]]) -> dict[str, Any]:
    """id -> (tag number, source) for labels."""
    return {str(s["id"]): (s.get("tag"), s.get("source")) for s in catalog if s.get("id")}


def sgt_label(ref: dict[str, Any], tags: dict[str, Any] | None = None) -> str:
    """'Employees (SGT 4)'; the tag number from the ref, or the SGT catalogue when the rule's ref has none."""
    if not isinstance(ref, dict):
        return str(ref)
    tag = ref.get("tag")
    if tag is None and tags:
        tag = (tags.get(str(ref.get("id"))) or (None, None))[0]
    name = ref.get("name")
    if name is None:
        return f"SGT {tag}" if tag is not None else str(ref.get("id", "?"))
    return f"{name} (SGT {tag})" if tag is not None else str(name)


def sgt_labels(block: Any, tags: dict[str, Any] | None = None) -> list[str]:
    if not isinstance(block, dict):
        return []
    return [sgt_label(r, tags) for r in (block.get("objects") or []) + (block.get("literals") or [])]


# --- time ranges --------------------------------------------------------------------------------------


def _parse_local(v: Any) -> datetime | None:
    s = str(v or "").strip()
    if not s:
        return None
    try:
        t = datetime.fromisoformat(s.rstrip("Z"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def time_range_ref(tr: dict[str, Any]) -> dict[str, Any]:
    return {"id": str(tr["id"]), "type": "TimeRange", "name": tr.get("name")}


def recurrence_text(r: dict[str, Any]) -> str:
    if str(r.get("recurrenceType", "")).upper() == "RANGE":
        return (
            f"weekly {r.get('rangeStartDay')} {r.get('rangeStartTime')} to {r.get('rangeEndDay')} "
            f"{r.get('rangeEndTime')}"
        )
    days = ",".join(r.get("days") or [])
    return f"{days} {r.get('dailyStartTime')}-{r.get('dailyEndTime')}"


def time_range_row(tr: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """A time range in words, with whether its absolute window has ended (FMC times have no zone: the device
    evaluates them in its own time zone)."""
    now = now or datetime.now(UTC)
    now = now if now.tzinfo else now.replace(tzinfo=UTC)
    end = _parse_local(tr.get("effectiveEndDateTime"))
    row = {
        "name": tr.get("name"),
        "start": tr.get("effectiveStartDateTime") or "now",
        "end": tr.get("effectiveEndDateTime") or "never",
        "recurring": [recurrence_text(r) for r in tr.get("recurrenceList") or []] or None,
        "ended": bool(end and end < now) or None,
    }
    return {k: v for k, v in row.items() if v is not None}


async def resolve_time_range(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, TIME_RANGES, ref, "time range", domain)


# --- labels in previews -------------------------------------------------------------------------------


def app_labels(block: Any) -> list[str]:
    if not isinstance(block, dict):
        return []
    out = [ref_label(a) for a in block.get("applications") or []]
    out += [f"filter:{ref_label(f)}" for f in block.get("applicationFilters") or []]
    out += [f"inline-filter:{condition_text(f)}" for f in block.get("inlineApplicationFilters") or []]
    return out


def relabel_changes(
    changes: dict[str, Any],
    current: dict[str, Any],
    desired: dict[str, Any],
    tags: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replace the dotted field diffs of the F66 conditions with before/after labels ('any' when empty)."""
    labellers: dict[str, Any] = {
        "applications": app_labels,
        "timeRangeObjects": block_labels,
        "sourceSecurityGroupTags": lambda b: sgt_labels(b, tags),
        "destinationSecurityGroupTags": lambda b: sgt_labels(b, tags),
    }
    for field, fn in labellers.items():
        for k in [k for k in changes if k == field or k.startswith(field + ".")]:
            changes.pop(k)
        before, after = fn(current.get(field)), fn(desired.get(field))
        if before != after:
            changes[field] = {"from": before or "any", "to": after or "any"}
    return changes


APP_NOTE = (
    "Application conditions match once Snort has identified the application (the first packets of a "
    "connection pass the rule's other conditions first); packet tracer can't simulate that, so verify "
    "with fmc_get_hit_counts or fmc_live_connections after real traffic."
)
INLINE_NOTE = (
    "An inline filter lives in this rule only (no filter object to create or delete); FMC works out the "
    "applications it matches from the VDB, so the set changes with VDB updates."
)
TIME_NOTE = "Time ranges are evaluated in each device's own time zone (platform settings; UTC unless set)."
SGT_NOTE = (
    "SGT conditions match the tag on the connection: ISE SGTs from the session ISE publishes over pxGrid "
    "(or SXP), custom SGTs from inline tags."
)
VLAN_NOTE = (
    "VLAN tag conditions apply only to traffic on inline sets: on routed or transparent (firewall) "
    "interfaces, subinterfaces included, a rule with VLAN tags never matches (FMC configuration guide, "
    "VLAN tag conditions)."
)


class ExtraConditions:
    """Resolves the F66 parameters of one access-rule write into rule fields, preview rows and notes."""

    def __init__(self, app: FmcApp, domain: str | None) -> None:
        self.app = app
        self.domain = domain
        self.fields: dict[str, Any] = {}
        self.details: dict[str, Any] = {}
        self.warnings: list[str] = []
        self.notes: list[str] = []
        self.tags: dict[str, Any] = {}

    async def resolve(
        self,
        current: dict[str, Any] | None,
        *,
        applications: list[str] | None = None,
        application_filters: list[str] | None = None,
        time_range: str | None = None,
        source_sgts: list[str] | None = None,
        destination_sgts: list[str] | None = None,
        known_filters: list[dict[str, Any]] | None = None,
        inline_app_filter: InlineAppFilter | None = None,
    ) -> ExtraConditions:
        """`known_filters`: application filter refs the policy's rules already use (filter_refs_in_rules),
        so a name FMC doesn't list still resolves. `inline_app_filter` replaces the rule's inline filters
        (one condition; one with no attributes removes them)."""
        inline: list[dict[str, Any]] | None = None
        if inline_app_filter is not None:
            cond = await app_condition(self.app, self.domain, **inline_app_filter.model_dump())
            inline = [cond] if cond else []
            if cond:
                self.details["inline_app_filter"] = {
                    "matches": f"every application with {condition_text(cond)}",
                    "note": INLINE_NOTE,
                }
            elif current is None:
                raise InvalidRequest(
                    "inline_app_filter needs at least one attribute (risks, business_relevance, categories, "
                    "tags, types); on fmc_update_access_rule an empty one removes the rule's inline filters."
                )
        if applications is not None or application_filters is not None or inline is not None:
            apps = (
                None
                if applications is None
                else await resolve_applications(self.app, applications, self.domain)
            )
            flts = (
                None
                if application_filters is None
                else await resolve_app_filters(
                    self.app,
                    application_filters,
                    self.domain,
                    known=filter_refs_in_rules([current or {}]) + list(known_filters or []),
                    notes=self.warnings,
                )
            )
            block = merge_app_block((current or {}).get("applications"), apps, flts, inline)
            self.fields["applications"] = block
            if block:
                self.notes.append(APP_NOTE)
        if time_range is not None:
            if not time_range.strip():
                self.fields["timeRangeObjects"] = []
            else:
                tr = await resolve_time_range(self.app, time_range, self.domain)
                self.fields["timeRangeObjects"] = [time_range_ref(tr)]
                row = time_range_row(tr)
                self.details["time_range"] = row
                self.notes.append(TIME_NOTE)
                if row.get("ended"):
                    self.warnings.append(
                        f"Time range {tr.get('name')!r} ended {row['end']}: the rule will never match "
                        "(fmc_policy_audit reports it as an expired time range)."
                    )
        if source_sgts is not None or destination_sgts is not None:
            catalog, notes = await sgt_catalog(self.app, self.domain)
            self.tags = sgt_tags(catalog)
            shown: dict[str, list[dict[str, Any]]] = {}
            for key, field, given in (
                ("source", "sourceSecurityGroupTags", source_sgts),
                ("destination", "destinationSecurityGroupTags", destination_sgts),
            ):
                if given is None:
                    continue
                refs: list[dict[str, Any]] = []
                for s in given:
                    if str(s).strip():
                        ref = pick_sgt(catalog, s, notes)
                        if all(r["id"] != ref["id"] for r in refs):
                            refs.append(ref)
                self.fields[field] = {"objects": refs} if refs else {}
                by_id = {str(c["id"]): c for c in catalog}
                shown[key] = [
                    {
                        "name": r["name"],
                        "tag": by_id[r["id"]].get("tag"),
                        "source": by_id[r["id"]].get("source"),
                    }
                    for r in refs
                ]
            if any(shown.values()):
                self.details["sgts"] = shown
                self.notes.append(SGT_NOTE)
        return self
