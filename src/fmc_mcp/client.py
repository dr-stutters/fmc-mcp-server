"""The FMC "app" object: one ApiClient with token login/refresh, domain resolution and paging."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import weakref
from typing import Any

import httpx

from fmc_mcp._core import AuthError, InvalidRequest, NotFound
from fmc_mcp._core.http import (
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
CACHE_TTL = 60.0  # seconds object catalogs are reused between analysis calls
MAX_REFRESHES = 3  # FMC allows three refreshes per login, then a new login is required
ACCESS_HEADER = "X-auth-access-token"
REFRESH_HEADER = "X-auth-refresh-token"

# Device-scoped config paths. FMC lets an ancestor domain read a device in a descendant (leaf) domain but
# refuses changes there ("Object does not belong to current domain"), so these go to the device's domain.
DEVICE_PATH_RE = re.compile(
    r"^(devices/devicerecords|devicehapairs/ftddevicehapairs|deviceclusters/ftddevicecluster)/"
    r"([0-9a-fA-F-]{36})(/|$)"
)

DEVICE_LIST_RE = re.compile(
    r"/(devices/devicerecords|devicehapairs/ftddevicehapairs|deviceclusters/ftddevicecluster)/?$"
)

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


class _TicketHeaders:
    """The login-token auth plus FMC's change-management `ticket-id` header while a ticket is open."""

    def __init__(self, inner: LoginTokenAuth, app: FmcApp) -> None:
        self.inner = inner
        self.app = app

    async def headers(self, client: ApiClient) -> dict[str, str]:
        out = dict(await self.inner.headers(client))
        if self.app.ticket_id:
            out["ticket-id"] = self.app.ticket_id
        return out

    async def on_unauthorized(self, client: ApiClient, sent: dict[str, str]) -> bool:
        return await self.inner.on_unauthorized(client, sent)


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
            auth=_TicketHeaders(self._auth, self),
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
        # Seconds FMC's local clock is ahead of UTC (hit counts report local time with a 'Z'), once learned.
        self.local_offset: int | None = None
        self._version: str | None = None
        self._login_failure: tuple[float, AuthError] | None = None
        self._cache: dict[str, tuple[float, Any]] = {}
        # device/HA/cluster UUID -> the (leaf) domain that owns it, and which of them a tool call used
        self.device_domains: dict[str, str] = {}
        self.rerouted: weakref.WeakKeyDictionary[asyncio.Task[Any], dict[str, float]] = (
            weakref.WeakKeyDictionary()
        )
        # FMC deploy warnings seen per (devices, pending version), for ignore_warning (fmc_mcp.rails)
        self.deploy_warnings: dict[str, tuple[float, list[str]]] = {}
        # change-management ticket sent with every request (fmc_ticket / FMC_TICKET)
        self.ticket_id: str | None = settings.ticket or None

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
        user, password = self.settings.require_credentials("FMC_")  # AuthError if unset
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
        return _match_domain(want, domains)

    def default_domain_cached(self) -> str | None:
        """The default domain UUID without any request (None until the first login). Used to fill
        `{domainUUID}` in fmc_api_call paths; the server logs in at startup, so it is normally set."""
        want = (self.settings.domain or "").strip()
        if not want:
            return self.login_domain
        try:
            return _match_domain(want, self.domains)
        except InvalidRequest:
            return None

    async def domain_name(self, uuid: str) -> str:
        for d in await self._known_domains():
            if d["uuid"].lower() == uuid.lower():
                return d["name"]
        return uuid

    async def config_path(self, suffix: str, domain: str | None = None) -> str:
        """`/api/fmc_config/v1/domain/<uuid>/<suffix>`. Paths below one device, HA pair or cluster use
        the domain that owns it when that is a descendant of the requested domain (multi-domain FMC)."""
        suffix = suffix.lstrip("/")
        uuid = await self.domain_uuid(domain)
        m = DEVICE_PATH_RE.match(suffix)
        if m:
            uuid = await self.device_domain(m.group(1), m.group(2), uuid)
        return f"/api/fmc_config/v1/domain/{uuid}/{suffix}"

    async def device_domain(self, collection: str, device_id: str, domain_uuid: str) -> str:
        """The domain that owns a device (or HA pair/cluster) when it lies below `domain_uuid`; else
        `domain_uuid`. Looked up once per device (a GET in the requested domain shows `metadata.domain`)."""
        key = device_id.lower()
        if key not in self.device_domains and len(self.domains) > 1:
            try:
                data = await self.api.get(f"/api/fmc_config/v1/domain/{domain_uuid}/{collection}/{device_id}")
            except (
                NotFound,
                AuthError,
            ):  # not a device, or not visible here: FMC reports it on the real call
                data = None
            dom = (((data or {}).get("metadata") or {}).get("domain") or {}).get("id")
            self.device_domains[key] = str(dom).lower() if dom else ""
        owner = self.device_domains.get(key, "")
        target = domain_uuid.lower()
        if not owner or owner == target:
            return domain_uuid
        if not self._is_below(owner, target):
            if owner not in {d["uuid"].lower() for d in self.domains}:
                log.warning("Device %s is in domain %s, which this login doesn't list", device_id, owner)
            return domain_uuid
        task = asyncio.current_task()
        if task is not None:
            self.rerouted.setdefault(task, {})[owner] = time.monotonic()
        return owner

    def forget_devices(self) -> None:
        """Drop the device -> domain map (after registering, deleting or re-pairing devices)."""
        self.device_domains.clear()

    def _is_below(self, child: str, ancestor: str) -> bool:
        """Whether domain `child` is a descendant of `ancestor`, from the names ('Global/A/B')."""
        names = {d["uuid"].lower(): d["name"] for d in self.domains}
        c, a = names.get(child.lower()), names.get(ancestor.lower())
        return bool(c and a and c.startswith(a + "/"))

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
        page = await self.pager.fetch_page(self.api, path, query, limit=limit, offset=offset)
        self._note_devices(path, page.items, expanded)
        return page

    async def all(
        self, path: str, params: dict[str, Any] | None = None, *, expanded: bool = True, cap: int = 10_000
    ) -> Page:
        """Every item of a collection (check `.complete`)."""
        query = dict(params or {})
        if expanded:
            query["expanded"] = "true"
        page = await fetch_all(self.pager, self.api, path, query, cap=cap)
        self._note_devices(path, page.items, expanded)
        return page

    def _note_devices(self, path: str, items: list[dict[str, Any]], expanded: bool) -> None:
        """Remember which domain owns each listed device / HA pair / cluster (for config_path)."""
        if not expanded or not DEVICE_LIST_RE.search(path):
            return
        for item in items:
            if isinstance(item, dict) and item.get("id"):
                dom = (((item.get("metadata") or {}).get("domain")) or {}).get("id")
                # expanded rows carry metadata.domain; none means the requested domain owns it
                self.device_domains[str(item["id"]).lower()] = str(dom).lower() if dom else ""

    # --- short-lived cache (object catalogs for the offline analysis tools) ------------------

    def cache_get(self, key: str) -> Any:
        hit = self._cache.get(key)
        if hit is None or time.monotonic() - hit[0] > CACHE_TTL:
            return None
        return hit[1]

    def cache_put(self, key: str, value: Any) -> None:
        self._cache[key] = (time.monotonic(), value)

    def invalidate_cache(self) -> None:
        """Called after every write so analysis tools never see stale objects."""
        self._cache.clear()

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


def _match_domain(want: str, domains: list[dict[str, str]]) -> str:
    """A domain UUID for a UUID, full name ('Global/Child') or unique leaf name ('Child')."""
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
