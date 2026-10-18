"""F34 identity sources, read-only: fmc_get_identity_sources against the live FMC, and fmc_user_ip_lookup for
FMC_LIVE_IDENTITY_IP / FMC_LIVE_IDENTITY_USER when set (a user logged in through ISE, e.g. the lab's 802.1X
client). FMC_LIVE_LEAF_DOMAIN, when set, is the domain asked. Nothing is written."""

from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .live_env import live_env, need
from .test_live_ftd import call

pytestmark = pytest.mark.live

DOMAIN = live_env("FMC_LIVE_LEAF_DOMAIN") or None


def _args(**kw: Any) -> dict[str, Any]:
    return {**kw, **({"domain": DOMAIN} if DOMAIN else {})}


async def test_identity_sources_read(client: Client[Any]) -> None:
    out = await call(client, "fmc_get_identity_sources", _args())
    assert out["ise"]["state"] in ("connected", "not_configured", "failed", "degraded", "unknown"), out
    assert isinstance(out["realms"], list) and out["verdict"] and out["next"]
    if out["ise"]["state"] == "not_configured":
        assert "configure" in out["ise"]


async def test_user_ip_lookup_live(client: Client[Any]) -> None:
    ip = need("FMC_LIVE_IDENTITY_IP")
    try:
        out = await call(client, "fmc_user_ip_lookup", _args(ip=ip, history=True))
    except ToolError as e:
        if "Analysis > Users" in str(e):
            pytest.skip("the API account's role lacks Events & Logs > Analysis > Users")
        raise
    user = live_env("FMC_LIVE_IDENTITY_USER")
    if user:
        assert any(s["user"].lower() == user.lower() for s in out.get("sessions", [])), out
        assert out["identities"][0].lower().endswith(user.lower()), out
