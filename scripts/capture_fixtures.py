"""Capture a few real FMC responses (after scripts/seed_lab.py) as redacted unit-test fixtures.

    uv run python scripts/capture_fixtures.py

Redaction: the FMC address/hostname and serial are replaced, `links` are dropped. Review the diff
before committing.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

from fmc_mcp.client import FmcApp
from fmc_mcp.config import Settings

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def scrub(data: Any, host: str) -> Any:
    if isinstance(data, dict):
        out = {k: scrub(v, host) for k, v in data.items() if k != "links"}
        if data.get("type") == "ServerVersion":
            out["uuid"] = "00000000-0000-0000-0000-000000000001"
            out["serialNumber"] = "REDACTED"
        return out
    if isinstance(data, list):
        return [scrub(v, host) for v in data]
    if isinstance(data, str):
        data = data.replace(host, "fmc.test")
        data = re.sub(r"fmcv?\.[\w.-]*mitchcloud[\w.-]*", "fmc.example.com", data)
        data = re.sub(r"\b198\.18\.\d+\.\d+\b", "192.0.2.10", data)  # lab addresses (not 198.18.0.0/15)
        return data
    return data


async def main() -> None:
    settings = Settings()  # type: ignore[call-arg]
    host = re.sub(r"^https?://", "", settings.url).split("/")[0]
    app = FmcApp(settings)
    try:

        async def by_name(path: str, name: str) -> dict[str, Any]:
            page = await app.all(await app.config_path(path))
            return next(i for i in page.items if i.get("name") == name)

        acp = await by_name("policy/accesspolicies", "mcp-test-acp")
        nat = await by_name("policy/ftdnatpolicies", "mcp-test-nat")
        db = await by_name("object/hosts", "mcp-test-db")
        captures = {
            "serverversion": ("/api/fmc_platform/v1/info/serverversion", {}),
            "accesspolicies": (await app.config_path("policy/accesspolicies"), {"expanded": "true"}),
            "accessrules": (
                await app.config_path(f"policy/accesspolicies/{acp['id']}/accessrules"),
                {"expanded": "true", "limit": 1000},
            ),
            "natrules": (
                await app.config_path(f"policy/ftdnatpolicies/{nat['id']}/natrules"),
                {"expanded": "true", "limit": 1000},
            ),
            "networkaddresses": (
                await app.config_path("object/networkaddresses"),
                {"expanded": "true", "limit": 1000},
            ),
            "networkgroups": (
                await app.config_path("object/networkgroups"),
                {"expanded": "true", "limit": 1000},
            ),
            "protocolportobjects": (
                await app.config_path("object/protocolportobjects"),
                {"expanded": "true", "limit": 1000},
            ),
            "portobjectgroups": (
                await app.config_path("object/portobjectgroups"),
                {"expanded": "true", "limit": 1000},
            ),
            "usage_db": (
                await app.config_path("object/operational/usage"),
                {"filter": f"uuid:{db['id']};type:Host", "limit": 1000},
            ),
            "search_ip": (await app.config_path("search/object"), {"filter": "text:10.10.20.5"}),
        }
        OUT.mkdir(parents=True, exist_ok=True)
        for name, (path, params) in captures.items():
            data = await app.api.get(path, params)
            (OUT / f"{name}.json").write_text(json.dumps(scrub(data, host), indent=1) + "\n")
            print("captured", name)
    finally:
        await app.aclose()


if __name__ == "__main__":
    asyncio.run(main())
