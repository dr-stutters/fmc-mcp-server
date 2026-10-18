"""The FMC API spec index for helpers that take an allowlist or an enum from it (the show commands FMC passes
through, the URL reputation levels), with a bounded wait: a first spec load (~10 MB) that takes longer keeps
going in the background while the caller uses its built-in fallback."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

log = logging.getLogger(__name__)

SPEC_WAIT_S = 15.0
_loading: set[asyncio.Future[Any]] = set()  # strong references to loads that outlive their caller's wait


async def spec_index(ctx: Any, purpose: str, wait_s: float = SPEC_WAIT_S) -> Any | None:
    """The spec index from the lifespan's spec store (loaded once, disk-cached by core), or None when there is
    no store, the first load is still running after `wait_s`, or the spec is broken: the caller then uses its
    built-in `purpose` (named in the log line)."""
    try:
        store = ctx.lifespan_context.get("specs")
    except Exception:  # noqa: BLE001 - no lifespan (helper used outside a tool call)
        store = None
    if store is None:
        return None
    task = asyncio.ensure_future(store.get())
    try:
        return await asyncio.wait_for(asyncio.shield(task), wait_s)
    except TimeoutError:
        _loading.add(task)
        task.add_done_callback(_finished)
        log.info("FMC spec still loading; using the built-in %s for now", purpose)
    except Exception as e:  # noqa: BLE001 - a broken spec must not break the tool that asked
        log.warning("FMC spec unavailable for the %s: %s", purpose, e)
    return None


def _finished(task: asyncio.Future[Any]) -> None:
    _loading.discard(task)
    if not task.cancelled() and task.exception() is not None:
        log.warning("FMC spec load failed: %s", task.exception())
