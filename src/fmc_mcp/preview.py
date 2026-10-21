"""Preview wrapper for every FMC write (F19): names the domain the change is made in, and blocks edits
of objects or policies that a descendant domain only inherits (FMC refuses them there)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from fastmcp import Context

from fmc_mcp._core import Plan, get_client, preview_or_apply
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import is_builtin_object

REROUTE_FRESH = 300.0  # seconds; older entries on a reused task are not this call's


def owner_domain(obj: dict[str, Any] | None) -> dict[str, Any] | None:
    """The domain an FMC object/policy is defined in (`metadata.domain` of an expanded GET)."""
    dom = ((obj or {}).get("metadata") or {}).get("domain")
    return dom if isinstance(dom, dict) and dom.get("id") else None


async def fmc_preview(
    ctx: Context,
    *,
    tool: str,
    args: dict[str, Any],
    confirm: str | None,
    plan: Plan,
    apply: Callable[[], Awaitable[Any]],
    owned: Iterable[dict[str, Any] | None] = (),
) -> dict[str, Any]:
    """core preview_or_apply plus the domain in the preview details and an inherited-object check.

    `owned`: the existing objects/policies the change edits or deletes; when one is defined in another
    (ancestor) domain, the preview is blocked and says which domain to use."""
    app: FmcApp = get_client(ctx)
    uuid = await app.domain_uuid(args.get("domain"))
    name = await app.domain_name(uuid)
    if "domain" not in plan.details:
        plan.details = {"domain": name, **plan.details}
    task = asyncio.current_task()
    seen = app.rerouted.pop(task, {}) if task is not None else {}
    moved = sorted(d for d, at in seen.items() if time.monotonic() - at < REROUTE_FRESH)
    if moved:
        # The device lives in a leaf domain below the requested one; its config is changed there. Part of
        # the fingerprint, so a confirm is refused if the device has moved to another domain since.
        names = [await app.domain_name(d) for d in moved]
        plan.details["device_domain"] = ", ".join(names)
        plan.fingerprint = {"plan": plan.fingerprint, "device_domain": moved}
    for obj in owned:
        dom = owner_domain(obj)
        if dom and str(dom["id"]).lower() != uuid.lower():
            label = (obj or {}).get("name") or (obj or {}).get("id")
            if is_builtin_object(obj or {}):
                # FMC's own (fixed-id) objects: read-only in Global too, so no domain to send the user to
                plan.blockers.append(
                    f"{label!r} is an FMC built-in (system) object, read-only in every domain."
                )
                continue
            where = await app.domain_name(str(dom["id"]))
            plan.blockers.append(
                f"{label!r} is defined in domain {where!r} and only inherited by {name!r}, where FMC "
                f"won't change it. Repeat with domain={where!r} (it then applies to every domain below)."
            )
    return await preview_or_apply(ctx, tool=tool, args=args, confirm=confirm, plan=plan, apply=apply)
