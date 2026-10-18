"""URL category + reputation conditions in access rules (F63).

An access rule's `urls` block holds URL objects and literals plus `urlCategoriesWithReputation`:
[{"type": "UrlCategoryAndReputation", "category": {id, name, type: URLCategory}, "reputation": LEVEL}].
Category names come from `object/urlcategories` (Talos categories, 126 on FMC 10.0.1). Reputation levels
are the `IUrlCategoryAndReputation.reputation` enum of the FMC API spec, read from the spec index at run
time with FMC 10.0.1's list built in as the fallback.

Reputation, as FMC applies it: a level on a block rule matches that level and every riskier one
(QUESTIONABLE = questionable and untrusted sites); on an allow rule it matches that level and every safer
one. '*_AND_UNKNOWN' also matches sites without a reputation; ANY_AND_UNKNOWN is the whole category.
"""

from __future__ import annotations

import asyncio
import difflib
import logging
import re
from typing import Any

from pydantic import BaseModel, Field

from fmc_mcp._core import InvalidRequest, NotFound
from fmc_mcp.client import FmcApp

log = logging.getLogger(__name__)

URL_CATEGORIES = "object/urlcategories"
REPUTATION_SCHEMA = "IUrlCategoryAndReputation"
SPEC_WAIT_S = 15.0
DEFAULT_REPUTATION = "ANY_AND_UNKNOWN"
# FMC 10.0.1's spec, IUrlCategoryAndReputation.reputation (verbatim order).
FALLBACK_REPUTATIONS = (
    "ANY_EXCEPT_UNKNOWN",
    "TRUSTED",
    "FAVORABLE",
    "NEUTRAL",
    "QUESTIONABLE",
    "UNTRUSTED",
    "ANY_AND_UNKNOWN",
    "TRUSTED_AND_UNKNOWN",
    "FAVORABLE_AND_UNKNOWN",
    "NEUTRAL_AND_UNKNOWN",
    "QUESTIONABLE_AND_UNKNOWN",
    "UNTRUSTED_AND_UNKNOWN",
)
# Safest first: a block rule matches its level and everything after it, an allow rule everything before.
LEVELS = ("TRUSTED", "FAVORABLE", "NEUTRAL", "QUESTIONABLE", "UNTRUSTED")
BLOCKING = {"BLOCK", "BLOCK_RESET", "BLOCK_INTERACTIVE", "BLOCK_RESET_INTERACTIVE"}


class UrlCategoryCondition(BaseModel):
    """One URL category condition of an access rule."""

    category: str = Field(
        min_length=1,
        description="Talos URL category name or UUID, e.g. 'Gambling', 'Malware Sites', 'Social Networking' "
        "(fmc_list_objects type=url_category)",
    )
    reputation: str | None = Field(
        None,
        description="Reputation level: ANY_AND_UNKNOWN (default: the whole category), ANY_EXCEPT_UNKNOWN, "
        "TRUSTED, FAVORABLE, NEUTRAL, QUESTIONABLE, UNTRUSTED, or one of those with _AND_UNKNOWN. On a "
        "block rule a level also matches the riskier levels (QUESTIONABLE = questionable + untrusted); "
        "on an allow rule the safer ones",
    )


async def reputation_levels(ctx: Any) -> tuple[list[str], str]:
    """The reputation enum from the FMC spec index ('spec'), or FMC 10.0.1's ('built-in')."""
    store = None
    try:
        store = ctx.lifespan_context.get("specs")
    except Exception:  # noqa: BLE001 - no lifespan (used outside a tool call)
        store = None
    if store is None:
        return list(FALLBACK_REPUTATIONS), "built-in"
    task = asyncio.ensure_future(store.get())
    try:
        index = await asyncio.wait_for(asyncio.shield(task), SPEC_WAIT_S)
    except TimeoutError:
        task.add_done_callback(lambda t: t.cancelled() or t.exception())  # keep loading; no warning
        return list(FALLBACK_REPUTATIONS), "built-in"
    except Exception as e:  # noqa: BLE001 - a broken spec must not break rule writes
        log.warning("FMC spec unavailable for URL reputation levels: %s", e)
        return list(FALLBACK_REPUTATIONS), "built-in"
    levels = enum_of(
        getattr(index, "schemas", {}).get(REPUTATION_SCHEMA, {}).get("fields", {}).get("reputation")
    )
    return (levels, "spec") if levels else (list(FALLBACK_REPUTATIONS), "built-in")


def enum_of(summary: Any) -> list[str]:
    """['A', 'B'] from a spec index field summary 'enum: A|B, description...'."""
    m = re.match(r"\s*enum:\s*([A-Z0-9_|]+)", str(summary or ""))
    return [v for v in m.group(1).split("|") if v] if m else []


def normalise_reputation(text: str | None, levels: list[str], source: str) -> str:
    if text is None or not text.strip():
        return DEFAULT_REPUTATION
    key = re.sub(r"[\s\-+&]+", "_", text.strip().upper()).replace("_AND_AND_", "_AND_")
    if key in levels:
        return key
    where = "the FMC API spec" if source == "spec" else "FMC 10.0.1's API spec"
    raise InvalidRequest(f"Unknown URL reputation {text!r}; {where} allows: {', '.join(levels)}.")


async def category_catalog(app: FmcApp, domain: str | None) -> list[dict[str, Any]]:
    page = await app.all(await app.config_path(URL_CATEGORIES, domain), expanded=False)
    return [c for c in page.items if c.get("id") and c.get("name")]


def pick_category(catalog: list[dict[str, Any]], ref: str) -> dict[str, Any]:
    t = ref.strip()
    hit = next((c for c in catalog if str(c["id"]) == t), None) or next(
        (c for c in catalog if str(c["name"]).lower() == t.lower()), None
    )
    if hit is None:
        close = difflib.get_close_matches(t, [str(c["name"]) for c in catalog], n=5, cutoff=0.5)
        hint = f" Did you mean: {', '.join(close)}?" if close else ""
        raise NotFound(
            f"No URL category {ref!r}.{hint} (fmc_list_objects type=url_category lists them.)", 404
        )
    return {"id": str(hit["id"]), "type": "URLCategory", "name": hit.get("name")}


async def category_conditions(
    ctx: Any, app: FmcApp, items: list[UrlCategoryCondition], domain: str | None
) -> list[dict[str, Any]]:
    """urlCategoriesWithReputation entries for the given conditions (names resolved, levels checked)."""
    if not items:
        return []
    levels, source = await reputation_levels(ctx)
    catalog = await category_catalog(app, domain)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        cat = pick_category(catalog, item.category)
        rep = normalise_reputation(item.reputation, levels, source)
        if (cat["id"], rep) in seen:
            continue
        seen.add((cat["id"], rep))
        out.append({"type": "UrlCategoryAndReputation", "category": cat, "reputation": rep})
    return out


def reputation_meaning(rep: str | None, action: str | None) -> str:
    """What a reputation level matches on a rule with this action, in words."""
    r = str(rep or DEFAULT_REPUTATION).upper()
    unknown = r.endswith("_AND_UNKNOWN") or r == "ANY_AND_UNKNOWN"
    base = r.removesuffix("_AND_UNKNOWN")
    if base == "ANY":
        text = "every site in the category"
    elif base == "ANY_EXCEPT_UNKNOWN":
        return "every site in the category with a known reputation"
    elif base in LEVELS:
        i = LEVELS.index(base)
        blocking = str(action or "").upper() in BLOCKING
        span = LEVELS[i:] if blocking else LEVELS[: i + 1]
        text = "sites rated " + " or ".join(s.lower() for s in span)
    else:
        return r
    return text + (", and sites with no reputation" if unknown and base != "ANY" else "")


def category_details(conditions: list[dict[str, Any]], action: str | None) -> list[dict[str, Any]]:
    """Preview rows: category, reputation and what it matches with the rule's action."""
    return [
        {
            "category": (c.get("category") or {}).get("name"),
            "reputation": c.get("reputation"),
            "matches": reputation_meaning(c.get("reputation"), action),
        }
        for c in conditions
    ]


def merge_url_block(
    current: dict[str, Any] | None,
    urls_block: dict[str, Any] | None,
    categories: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """An access rule's `urls` block from its current one, a new objects/literals block (None = keep the
    current ones, {} = none) and new category conditions (None = keep the current ones, [] = none)."""
    cur = current or {}
    out: dict[str, Any] = (
        {k: v for k, v in cur.items() if k in ("objects", "literals") and v}
        if urls_block is None
        else {k: v for k, v in urls_block.items() if v}
    )
    cats = cur.get("urlCategoriesWithReputation") if categories is None else categories
    if cats:
        out["urlCategoriesWithReputation"] = cats
    return out


def url_category_match(block: Any, category: str | None) -> tuple[bool | None, bool]:
    """A rule's URL condition against the flow's URL category: (match, reputation_unknown).
    match None = can't tell (no category given, or the rule also has URL objects/literals and the
    category isn't one of its categories)."""
    if not isinstance(block, dict) or not any(
        block.get(k) for k in ("objects", "literals", "urlCategoriesWithReputation")
    ):
        return True, False
    if category is None:
        return None, False
    cats = block.get("urlCategoriesWithReputation") or []
    want = category.strip().lower()
    hits = [c for c in cats if str((c.get("category") or {}).get("name", "")).lower() == want]
    if hits:
        whole = any(str(c.get("reputation") or DEFAULT_REPUTATION).upper() == "ANY_AND_UNKNOWN" for c in hits)
        return True, not whole
    if block.get("objects") or block.get("literals"):
        return None, False  # the URL itself might match an object or literal
    return False, False
