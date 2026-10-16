"""`fmc-mcp-server check` (F36): what an operator needs to know before connecting a client.

Token generation (reachability, TLS trust, credentials), the domains the API user can see, the user's FMC
roles vs the enabled tiers (docs/least-privilege.md), the FMC version vs the tested matrix and the server's
share of FMC's 120 requests/minute.

The check logs in like the server does, and FMC ends the same user's other sessions on every login: a
running server with the same FMC user simply logs in again on its next call.
"""

from __future__ import annotations

from typing import Any

from fmc_mcp._core import InvalidRequest, UpstreamError
from fmc_mcp._core.preflight import Preflight
from fmc_mcp.client import FmcApp, _match_domain
from fmc_mcp.config import DEFAULT_RATE_LIMIT, Settings

TESTED = ("10.0",)  # live-tested releases (README)
MINIMUM = "7.2"  # older releases lack APIs the tools rely on (hit counts, dynamic objects, change management)
FMC_RATE_BUDGET = 120  # requests per minute FMC allows per FMC (all API users and sources share it)

# FMC user roles (docs/least-privilege.md). The custom mcp-rw role covers the dangerous tier too (deploys,
# registration, HA, rollback and policy deletes need no Administration permission). Built-in roles: only
# the ones whose reach is clear; any other role is reported as unknown.
WRITE_ROLES = frozenset({"administrator", "network admin", "mcp-rw"})
READ_ONLY_ROLES = frozenset({"mcp-ro", "security analyst (read only)"})
ADMIN_USERS = frozenset({"admin"})  # FMC's built-in GUI administrator


def role_access(roles: list[str]) -> bool | None:
    """Whether these FMC roles allow writes (and the dangerous tier): True if any role does, False if every
    role is known to be read-only, None when a role is unknown."""
    names = {r.strip().lower() for r in roles if r.strip()}
    if names & WRITE_ROLES:
        return True
    if names and names <= READ_ONLY_ROLES:
        return False
    return None


async def user_roles(app: FmcApp) -> list[str] | None:
    """The API user's FMC roles from its own user record (`users/users/<USER_UUID>` in the login domain),
    or None when FMC won't say: reading users needs User Management, which mcp-ro / mcp-rw don't have."""
    if not app.user_uuid or not app.login_domain:
        return None
    path = f"/api/fmc_config/v1/domain/{app.login_domain}/users/users/{app.user_uuid}"
    try:
        user = await app.api.get(path, retry=False)
    except UpstreamError:
        return None
    if not isinstance(user, dict):
        return None
    raw: Any = user.get("roles") or user.get("userRoles") or []
    names = [str(r.get("name")) for r in raw if isinstance(r, dict) and r.get("name")]
    return names or None


async def _login(app: FmcApp) -> int:
    await app.ensure_login()
    return len(app.domains)


def _rate_budget(settings: Settings, pf: Preflight) -> None:
    configured = settings.rate_limit
    per_minute = configured or DEFAULT_RATE_LIMIT
    data: dict[str, Any] = {
        "per_minute": per_minute,
        "fmc_budget": FMC_RATE_BUDGET,
        "configured": configured is not None,
    }
    shared = "shared by every caller of this server"
    if per_minute > FMC_RATE_BUDGET:
        pf.warn(
            "rate_limit",
            f"FMC_RATE_LIMIT={per_minute:g}/min is above FMC's {FMC_RATE_BUDGET}/min per FMC",
            hint=f"Set FMC_RATE_LIMIT to {FMC_RATE_BUDGET} or less (110 leaves room for other API users of "
            "this FMC); above it FMC answers 429 and calls slow down or fail.",
            **data,
        )
        return
    source = "FMC_RATE_LIMIT" if configured is not None else "default"
    pf.ok(
        "rate_limit",
        f"{per_minute:g} requests/min ({source}; FMC allows {FMC_RATE_BUDGET}/min per FMC), {shared}",
        **data,
    )


async def preflight(settings: Settings, pf: Preflight) -> None:
    app = FmcApp(settings)
    try:
        user = settings.username or "the API user"
        if await pf.reach("api", _login(app), detail="generatetoken answered") is None:
            return
        pf.ok("auth", f"token generated for {user}")
        if (settings.username or "").strip().lower() in ADMIN_USERS:
            pf.warn(
                "api_user",
                f"{user} is FMC's built-in administrator",
                hint="Give the server its own FMC user (docs/least-privilege.md): FMC ends a user's other "
                "sessions on every login, so sharing admin logs people out of the FMC UI.",
            )

        try:
            domains = await app._known_domains()
        except UpstreamError as e:
            pf.record_error(e, check="domains")
            domains = []
        if not domains and not pf.has("domains"):
            pf.fail(
                "domains",
                f"{user} sees no FMC domain",
                hint="Assign the user a role in at least one domain (Administration > Users > User "
                "Accounts; on a multi-domain FMC per domain).",
            )
        elif domains:
            names = [d["name"] for d in domains]
            want = (settings.domain or "").strip()
            try:
                default = _match_domain(want, domains) if want else app.login_domain
            except InvalidRequest as e:
                pf.fail("domains", str(e), hint="Fix FMC_DOMAIN (a name such as Global/Child, or a UUID).")
            else:
                default_name = next((d["name"] for d in domains if d["uuid"] == default), default)
                shown = ", ".join(names[:5]) + (f" (+{len(names) - 5} more)" if len(names) > 5 else "")
                pf.ok(
                    "domains",
                    f"{len(domains)} visible: {shown}; default {default_name}",
                    domains=names,
                    default=default_name,
                )

        roles = await user_roles(app)
        if roles is None:
            pf.access(
                write=None,
                detail="FMC did not show this user's roles (reading users needs User Management, which "
                "mcp-ro / mcp-rw deliberately lack)",
            )
        else:
            can = role_access(roles)
            pf.access(write=can, dangerous=can, role=", ".join(roles))

        try:
            found: str | None = await app.server_version()
        except UpstreamError as e:
            found = None
            pf.record_error(e, check="version")
        if not pf.has("version"):
            pf.version(found, tested=TESTED, minimum=MINIMUM)
    finally:
        _rate_budget(settings, pf)  # configuration only: reported even when FMC can't be reached
        await app.aclose()
