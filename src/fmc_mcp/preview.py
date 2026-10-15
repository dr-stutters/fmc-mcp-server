"""Preview wrapper for every FMC write (F19): names the domain the change is made in, and blocks edits
of objects or policies that a descendant domain only inherits (FMC refuses them there)."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from fastmcp import Context
from stutters_mcp_core import Plan, get_client, preview_or_apply

from fmc_mcp.client import FmcApp


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
    moved = app.rerouted.pop(task, set()) if task is not None else set()
    if moved:
        # the device lives in a leaf domain below the requested one; its config is changed there
        plan.details["device_domain"] = ", ".join(sorted([await app.domain_name(d) for d in moved]))
    for obj in owned:
        dom = owner_domain(obj)
        if dom and str(dom["id"]).lower() != uuid.lower():
            where = await app.domain_name(str(dom["id"]))
            label = (obj or {}).get("name") or (obj or {}).get("id")
            plan.blockers.append(
                f"{label!r} is defined in domain {where!r} and only inherited by {name!r}, where FMC "
                f"won't change it. Repeat with domain={where!r} (it then applies to every domain below)."
            )
    return await preview_or_apply(ctx, tool=tool, args=args, confirm=confirm, plan=plan, apply=apply)
