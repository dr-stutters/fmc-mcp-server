"""Change references on FMC writes (F90, G102 in the roadmap; core C33).

Every write and dangerous tool takes an optional `change_ref` (a change ticket number such as CHG0012345).
When it is set:
- the preview shows it, and it is bound to the confirm token (a confirm with another reference is refused);
- with FMC change management on (7.6+), the call's requests carry the open FMC ticket of that name or id in
  `ticket-id` (for this call only; fmc_ticket's server-wide ticket is untouched). No open ticket of that
  name: the change goes into the server's current ticket (a side effect says so), or the preview is blocked
  when there is none, since FMC refuses changes outside a ticket;
- access rule writes (create, update, bulk, containment) add it to the rule's comment history
  (`newComments`), so FMC's audit and the rule itself name the change;
- the audit events record it (it is part of the write's arguments) and the result repeats it.

TODO(core C33): core will inject `change_ref` on write/dangerous tools itself (like `instance`) and expose
the value; then `ChangeRefRegistrar` goes and `current()` reads core's value. The argument keeps its name and
shape, so clients see no change.
"""

# No `from __future__ import annotations`: the wrapper's signature is read by FastMCP at runtime.
import functools
import inspect
import typing
from collections.abc import Callable
from contextvars import ContextVar
from typing import Annotated, Any, TypeVar

from pydantic import Field

from fmc_mcp._core import AuthError, Plan, ToolRegistrar, UpstreamError

F = TypeVar("F", bound=Callable[..., Any])

ARGUMENT = "change_ref"
MAX_LEN = 64  # FMC ticket names are 1-64 characters
# Tools that don't take one: the ticket tool itself (its name *is* the ticket).
SKIP = frozenset({"fmc_ticket"})

ChangeRef = Annotated[
    str | None,
    Field(
        min_length=1,
        max_length=MAX_LEN,
        description="Change reference (e.g. CHG0012345): shown in the preview, recorded in the audit log, "
        "added to rule comments, and with FMC change management on, the open FMC ticket of that name "
        "carries this change",
    ),
]

_current: ContextVar[str | None] = ContextVar("fmc_change_ref", default=None)
# The ticket id this call's requests carry instead of the server's current ticket (client._TicketHeaders).
call_ticket: ContextVar[str | None] = ContextVar("fmc_call_ticket", default=None)


def current() -> str | None:
    """The change reference of the tool call being run (None when the caller gave none)."""
    return _current.get()


def comment(text: str | None) -> str | None:
    """A rule comment carrying the change reference: '[CHG1] text', or 'Change CHG1' alone."""
    ref = current()
    if not ref:
        return text
    if not text:
        return f"Change {ref}"
    return text if text.startswith(f"[{ref}]") else f"[{ref}] {text}"


def with_change_ref(fn: F) -> F:  # noqa: UP047 - matches core's wrappers
    """Wrap a tool so it takes an optional `change_ref` and runs with it set (see the module docstring)."""
    hints = typing.get_type_hints(fn, include_extras=True)
    sig = inspect.signature(fn)
    sig = sig.replace(
        parameters=[p.replace(annotation=hints.get(n, p.annotation)) for n, p in sig.parameters.items()],
        return_annotation=hints.get("return", sig.return_annotation),
    )
    if ARGUMENT in sig.parameters:
        return fn  # the tool handles it itself

    def select(kwargs: dict[str, Any]) -> Any:
        ref = kwargs.pop(ARGUMENT, None)
        return _current.set(ref.strip() if isinstance(ref, str) and ref.strip() else None)

    wrapper: Callable[..., Any]
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            token = select(kwargs)
            try:
                return await fn(*args, **kwargs)
            finally:
                _current.reset(token)

        wrapper = async_wrapper
    else:

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            token = select(kwargs)
            try:
                return fn(*args, **kwargs)
            finally:
                _current.reset(token)

        wrapper = sync_wrapper

    param = inspect.Parameter(ARGUMENT, inspect.Parameter.KEYWORD_ONLY, default=None, annotation=ChangeRef)
    wrapper.__signature__ = sig.replace(parameters=[*sig.parameters.values(), param])  # type: ignore[union-attr]
    wrapper.__annotations__ = {**hints, ARGUMENT: ChangeRef}
    return wrapper  # type: ignore[return-value]


class ChangeRefRegistrar(ToolRegistrar):
    """The server's registrar with `change_ref` added to every write and dangerous tool. Delegates to the
    registrar it wraps (which may be a toolset-filtered one) and shares its state."""

    def __init__(self, base: ToolRegistrar) -> None:
        self.__dict__.update(base.__dict__)
        self._base = base

    def _wrap(self, name: str | None, deco: Callable[[F], F]) -> Callable[[F], F]:
        def wrap(fn: F) -> F:
            if (name or fn.__name__) in SKIP:
                return deco(fn)
            deco(with_change_ref(fn))
            return fn

        return wrap

    def read(self, **kw: Any) -> Callable[[F], F]:
        return self._base.read(**kw)

    def write(self, **kw: Any) -> Callable[[F], F]:
        return self._wrap(kw.get("name"), self._base.write(**kw))

    def dangerous(self, **kw: Any) -> Callable[[F], F]:
        return self._wrap(kw.get("name"), self._base.dangerous(**kw))

    def prompt(self, **kw: Any) -> Callable[[F], F]:
        return self._base.prompt(**kw)


def wrapped(register: Callable[[ToolRegistrar], None]) -> Callable[[ToolRegistrar], None]:
    """A module's register function whose write/dangerous tools take `change_ref`."""

    def run(reg: ToolRegistrar) -> None:
        register(ChangeRefRegistrar(reg))

    return run


async def map_to_ticket(app: Any, plan: Plan, domain: str | None) -> str | None:
    """Show the call's change reference in the preview and find the FMC ticket it maps to. Returns the
    ticket id the call's requests should carry (None: no ticket, or the server's own one)."""
    from fmc_mcp.tools.tickets import ACTIVE, TICKETS, ticket_row  # tools import this module's users

    ref = current()
    if not ref:
        return None
    plan.details["change_ref"] = ref
    try:
        page = await app.all(await app.config_path(TICKETS, domain))
    except AuthError:
        plan.details["change_ticket"] = (
            "not checked: this API user can't read change-management tickets (rule comments still carry it)"
        )
        return None
    except UpstreamError as e:
        if "not enabled" in str(e).lower():
            plan.details["change_ticket"] = (
                "FMC change management is off: recorded in the audit and rule comments"
            )
            return None
        raise
    low = ref.lower()
    hits = [
        t
        for t in page.items
        if t.get("status") in ACTIVE and (t.get("id") == ref or str(t.get("name", "")).lower() == low)
    ]
    if len(hits) > 1:
        plan.blockers.append(f"Several open FMC tickets are named {ref!r}; use the ticket id as change_ref.")
        return None
    if hits:
        t = hits[0]
        plan.details["change_ticket"] = ticket_row(t)
        if app.ticket_id and app.ticket_id != t.get("id"):
            plan.side_effects.append(
                f"This change goes into ticket {t.get('name')!r}, not the server's current ticket "
                f"({app.ticket_id}); later calls without change_ref still use the current one."
            )
        return str(t["id"])
    if app.ticket_id:
        plan.details["change_ticket"] = {"id": app.ticket_id, "note": "the server's current ticket"}
        plan.side_effects.append(
            f"No open FMC ticket is named {ref!r}: the change goes into the server's current ticket "
            f"({app.ticket_id})."
        )
        return None
    plan.blockers.append(
        f"FMC change management is on and no open ticket is named {ref!r}: open it first with "
        f"fmc_ticket(action='open', name={ref!r}) (FMC refuses changes outside a ticket)."
    )
    return None
