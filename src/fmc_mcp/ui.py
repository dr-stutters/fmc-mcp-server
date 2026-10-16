"""A short-lived FMC web-UI session for the few things FMC 10.0's REST API can't do (F13 identity):
testing an AD/LDAP realm's directory connection and downloading its users and groups.

FMC's REST API has no AD realm test or download (`object/operational/testrealms` and
`object/realms/operational/download` are Azure AD / SAML only), so these call the same `pjb.cgi`
functions the realm page uses, logged in as FMC_UI_USERNAME. That must be its own FMC user: a web-UI
login ends the same user's REST session (and the other way round). The session is opened per call and
closed again. Not a public API: re-check after an FMC upgrade.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from fmc_mcp._core import AuthError, InvalidRequest, UpstreamError
from fmc_mcp.config import Settings

LOGIN = "/auth/login"
LOGOUT = "/auth/logout"
PJB = "/pjb.cgi"


def ui_credentials(settings: Settings) -> tuple[str, str]:
    user = (settings.ui_username or "").strip()
    secret = settings.ui_password.get_secret_value() if settings.ui_password else ""
    if not user or not secret:
        raise InvalidRequest(
            "FMC's REST API can't test or download an AD/LDAP realm, so this tool uses FMC's web UI with "
            "its own user: set FMC_UI_USERNAME / FMC_UI_PASSWORD (an FMC user whose role can modify "
            "realms, not the API user). Meanwhile use Integrations > Realms in the FMC UI (download "
            "icon, or Directory > Test); FMC also downloads on the realm's schedule (updateHour)."
        )
    api_user = (settings.username or "").strip()
    if user.lower() == api_user.lower():
        raise InvalidRequest(
            "FMC_UI_USERNAME must differ from FMC_USERNAME: a web-UI login ends the same user's REST session."
        )
    return user, secret


class FmcUiSession:
    """`async with FmcUiSession(settings) as ui: await ui.pjb(function, params)`."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.user, self._password = ui_credentials(settings)
        self.http = httpx.AsyncClient(
            base_url=settings.url.rstrip("/"),
            verify=settings.verify,
            timeout=max(settings.timeout or 60.0, 60.0),
            follow_redirects=True,
            transport=transport,
        )
        self.csrf: str | None = None

    async def __aenter__(self) -> FmcUiSession:
        try:
            resp = await self.http.post(
                LOGIN,
                files={
                    "username": (None, self.user),
                    "password": (None, self._password),
                    "endSession": (None, "1"),
                },
            )
            try:
                self.csrf = resp.json()["session"]["csrfToken"]
            except (ValueError, KeyError, TypeError):
                raise AuthError(
                    f"FMC web-UI login as FMC_UI_USERNAME failed (HTTP {resp.status_code}); check "
                    "FMC_UI_USERNAME / FMC_UI_PASSWORD.",
                    401,
                ) from None
        except BaseException:
            await self.http.aclose()
            raise
        return self

    async def __aexit__(self, *exc: object) -> None:
        try:
            if self.csrf:
                await self.http.get(LOGOUT)
        except httpx.HTTPError:
            pass
        finally:
            await self.http.aclose()

    async def pjb(self, function: str, params: list[Any]) -> Any:
        resp = await self.http.post(
            PJB,
            data={
                "function": function,
                "parameters": json.dumps(params),
                "get_all_errors": "1",
                "sf_action_id": self.csrf or "",
            },
        )
        if resp.status_code >= 400:
            raise UpstreamError(f"FMC web UI {function}: HTTP {resp.status_code}", resp.status_code)
        try:
            body = resp.json()
        except ValueError:
            raise UpstreamError(f"FMC web UI {function}: unexpected reply (not JSON)", 502) from None
        if isinstance(body, dict) and body.get("redirect_url"):
            raise AuthError(
                f"FMC web UI {function}: the session was refused or ended. The FMC_UI_USERNAME role needs "
                "Integrations > Realms modify permission (identity_realms.modify), and no one else may "
                "log in as that user at the same time.",
                403,
            )
        if isinstance(body, dict) and body.get("error"):
            raise UpstreamError(f"FMC web UI {function}: {str(body['error'])[:300]}", 502)
        return body.get("data") if isinstance(body, dict) else body
