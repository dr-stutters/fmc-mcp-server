"""The FMC "app" object: one ApiClient with token login/refresh, domain resolution and paging."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx
from stutters_mcp_core import AuthError, InvalidRequest
from stutters_mcp_core.http import (
    ApiClient,
    LoginTokenAuth,
    OffsetLimit,
    Page,
    RateLimiter,
    Token,
    basic_header,
    default_error_detail,
    fetch_all,
)

from fmc_mcp.config import DEFAULT_MAX_CONCURRENCY, DEFAULT_RATE_LIMIT, Settings

log = logging.getLogger(__name__)

LOGIN_PATH = "/api/fmc_platform/v1/auth/generatetoken"
REFRESH_PATH = "/api/fmc_platform/v1/auth/refreshtoken"
SPEC_PATH = "/api/api-explorer/fmc.json"
TOKEN_LIFETIME = 30 * 60  # seconds
LOGIN_FAILURE_BACKOFF = 30.0  # seconds a failed login is remembered
MAX_REFRESHES = 3  # FMC allows three refreshes per login, then a new login is required
ACCESS_HEADER = "X-auth-access-token"
REFRESH_HEADER = "X-auth-refresh-token"

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def is_uuid(value: str) -> bool:
    return bool(UUID_RE.match(value.strip()))


def fmc_error_detail(body: Any) -> str | None:
    """FMC errors look like {"error": {"messages": [{"description": "..."}], ...}}."""
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            msgs = err.get("messages") or []
            parts = [
                str(m.get("description")).strip()
                for m in msgs
                if isinstance(m, dict) and m.get("description")
            ]
            if parts:
                return " | ".join(parts)[:800]
    return default_error_detail(body)


def _parse_domains(raw: str | None) -> list[dict[str, str]]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    out = []
    for d in data if isinstance(data, list) else []:
        if isinstance(d, dict) and d.get("uuid"):
            out.append({"name": str(d.get("name", "")), "uuid": str(d["uuid"])})
    return out


class FmcApp:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self._auth = LoginTokenAuth(self._login, refresh=self._refresh)
        self.limiter = RateLimiter(
            settings.rate_limit or DEFAULT_RATE_LIMIT, settings.max_concurrency or DEFAULT_MAX_CONCURRENCY
        )
        self.api = ApiClient(
            settings.url,
            product="FMC",
            env_prefix="FMC_",
            auth=self._auth,
            verify=settings.verify,
            timeout=settings.timeout,
            retries=settings.retries,
            limiter=self.limiter,
            error_detail=fmc_error_detail,
            transport=transport,
        )
        self.pager = OffsetLimit(items="items", total="paging.count", max_page=1000)
        self.domains: list[dict[str, str]] = []
        self.login_domain: str | None = None
        self.user_uuid: str | None = None
        self.logins = 0
        self.refreshes = 0
        self._version: str | None = None
        self._login_failure: tuple[float, AuthError] | None = None

    async def aclose(self) -> None:
        await self.api.aclose()

    # --- auth ------------------------------------------------------------------------------

    def _remember(self, resp: httpx.Response) -> None:
        domains = _parse_domains(resp.headers.get("DOMAINS"))
        if domains:
            self.domains = domains
        self.login_domain = resp.headers.get("DOMAIN_UUID") or self.login_domain
        self.user_uuid = resp.headers.get("USER_UUID") or self.user_uuid

    async def _login(self, client: ApiClient) -> Token:
        # Never log Token objects: their data holds the refresh token.
        failed = self._login_failure
        if failed is not None and time.monotonic() < failed[0]:
            raise failed[1]
        try:
            user, password = self.settings.require_credentials("FMC_")
        except ValueError as e:
            raise InvalidRequest(str(e)) from e
        resp = await client.send_raw(
            "POST", LOGIN_PATH, headers={"Authorization": basic_header(user, password)}
        )
        if resp.status_code != 204 or ACCESS_HEADER not in resp.headers:
            if resp.status_code in (401, 403):
                err = AuthError(
                    f"FMC login failed ({resp.status_code}): {fmc_error_detail(_body(resp)) or 'denied'}. "
                    "Check FMC_USERNAME/FMC_PASSWORD; the account needs API access (REST API is enabled "
                    "under System > Configuration > REST API Preferences).",
                    resp.status_code,
                )
                # Don't hammer FMC with bad credentials (that can lock the account).
                self._login_failure = (time.monotonic() + LOGIN_FAILURE_BACKOFF, err)
                raise err
            raise client.error_from_response(resp)
        self._login_failure = None
        self.logins += 1
        self._remember(resp)
        log.info("Logged in to FMC (login #%d)", self.logins)
        return Token(
            {ACCESS_HEADER: resp.headers[ACCESS_HEADER]},
            Token.expiring_in(TOKEN_LIFETIME),
            {"refresh": resp.headers.get(REFRESH_HEADER, ""), "refreshes": 0},
        )

    async def _refresh(self, client: ApiClient, old: Token) -> Token | None:
        """Refresh instead of logging in again: each new login can end this user's other sessions."""
        used = int(old.data.get("refreshes", 0))
        if used >= MAX_REFRESHES or not old.data.get("refresh"):
            return None
        resp = await client.send_raw(
            "POST",
            REFRESH_PATH,
            headers={ACCESS_HEADER: old.headers[ACCESS_HEADER], REFRESH_HEADER: old.data["refresh"]},
        )
        if resp.status_code in (401, 403):
            log.info("FMC token refresh refused (%s); logging in again", resp.status_code)
            return None
        if resp.status_code != 204 or ACCESS_HEADER not in resp.headers:
            # Transient trouble (429/5xx): fail this request rather than log in again, because a new
            # login can end this user's other sessions.
            raise client.error_from_response(resp)
        self.refreshes += 1
        self._remember(resp)
        return Token(
            {ACCESS_HEADER: resp.headers[ACCESS_HEADER]},
            Token.expiring_in(TOKEN_LIFETIME),
            {"refresh": resp.headers.get(REFRESH_HEADER, old.data["refresh"]), "refreshes": used + 1},
        )

    async def ensure_login(self) -> None:
        await self._auth.token_for(self.api)

    # --- domains ---------------------------------------------------------------------------

    async def _known_domains(self) -> list[dict[str, str]]:
        await self.ensure_login()
        if not self.domains:
            data = await self.api.get("/api/fmc_platform/v1/info/domain", {"limit": 1000})
            self.domains = [
                {"name": str(d.get("name", "")), "uuid": str(d["uuid"])}
                for d in (data or {}).get("items", [])
                if d.get("uuid")
            ]
        return self.domains

    async def domain_uuid(self, domain: str | None = None) -> str:
        """Resolve a domain name ('Global', 'Global/Child' or just 'Child') or UUID; None means
        FMC_DOMAIN, else the login's own domain."""
        want = (domain or self.settings.domain or "").strip()
        domains = await self._known_domains()
        if not want:
            if self.login_domain:
                return self.login_domain
            if domains:
                return domains[0]["uuid"]
            raise InvalidRequest("FMC did not report a domain for this login; set FMC_DOMAIN.")
        if is_uuid(want):
            return want.lower()
        low = want.lower()
        for hits in (
            [d for d in domains if d["name"] == want],
            [d for d in domains if d["name"].lower() == low],
            [d for d in domains if d["name"].split("/")[-1].lower() == low],
        ):
            if len(hits) == 1:
                return hits[0]["uuid"]
            if len(hits) > 1:
                names = ", ".join(d["name"] for d in hits)
                raise InvalidRequest(f"Domain {want!r} is ambiguous ({names}); use the full name or UUID.")
        names = ", ".join(d["name"] for d in domains) or "none visible"
        raise InvalidRequest(f"Unknown FMC domain {want!r}. Domains this account can see: {names}.")

    async def domain_name(self, uuid: str) -> str:
        for d in await self._known_domains():
            if d["uuid"].lower() == uuid.lower():
                return d["name"]
        return uuid

    async def config_path(self, suffix: str, domain: str | None = None) -> str:
        """`/api/fmc_config/v1/domain/<uuid>/<suffix>`."""
        return f"/api/fmc_config/v1/domain/{await self.domain_uuid(domain)}/{suffix.lstrip('/')}"

    async def platform_path(self, suffix: str, domain: str | None = None) -> str:
        return f"/api/fmc_platform/v1/domain/{await self.domain_uuid(domain)}/{suffix.lstrip('/')}"

    # --- reading ---------------------------------------------------------------------------

    async def page(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        limit: int,
        offset: int = 0,
        expanded: bool = True,
    ) -> Page:
        query = dict(params or {})
        if expanded:
            query["expanded"] = "true"
        return await self.pager.fetch_page(self.api, path, query, limit=limit, offset=offset)

    async def all(
        self, path: str, params: dict[str, Any] | None = None, *, expanded: bool = True, cap: int = 10_000
    ) -> Page:
        """Every item of a collection (check `.complete`)."""
        query = dict(params or {})
        if expanded:
            query["expanded"] = "true"
        return await fetch_all(self.pager, self.api, path, query, cap=cap)

    # --- status ----------------------------------------------------------------------------

    async def server_version(self) -> str:
        if self._version is None:
            data = await self.api.get("/api/fmc_platform/v1/info/serverversion")
            items = (data or {}).get("items") or [{}]
            self._version = str(items[0].get("serverVersion", "unknown"))
        return self._version

    async def status(self) -> dict[str, Any]:
        data = await self.api.get("/api/fmc_platform/v1/info/serverversion")
        info = ((data or {}).get("items") or [{}])[0]
        self._version = str(info.get("serverVersion", "unknown"))
        default = await self.domain_uuid(None)
        devices = await self.api.get(await self.config_path("devices/devicerecords"), {"limit": 1})
        return {
            "version": self._version,
            "hostname": info.get("hostname"),
            "model": info.get("model"),
            "vdb_version": info.get("vdbVersion"),
            "sru_version": info.get("sruVersion"),
            "api_user": self.settings.username,
            "domains": self.domains,
            "default_domain": {"name": await self.domain_name(default), "uuid": default},
            "managed_devices": ((devices or {}).get("paging") or {}).get("count", 0),
            "session": {"logins": self.logins, "refreshes": self.refreshes},
            "rate_limit": {
                "per_minute": self.limiter.per_minute,
                "max_concurrency": self.limiter.max_concurrency,
            },
        }


def _body(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text
