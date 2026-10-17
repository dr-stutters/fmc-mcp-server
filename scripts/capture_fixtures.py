"""Capture a few real FMC responses as redacted unit-test fixtures.

    uv run python scripts/capture_fixtures.py          # policies and objects (the seeded mcp-test-* set)
    uv run python scripts/capture_fixtures.py --bundle # every GET fmc_export_policy_bundle makes for
                                                       # mcp-test-acp + mcp-test-nat (bundle_acp.json)
    uv run python scripts/capture_fixtures.py --templates # every GET fmc_get_device_template makes for
                                                       # the template named by FMC_LIVE_TEMPLATE
                                                       # (devicetemplates.json; F51d)
    uv run python scripts/capture_fixtures.py --ftd    # device fixtures from the managed FTD named by
                                                       # FMC_LIVE_DEVICE (after tests/live/test_live_ftd.py;
                                                       # also FMC_LIVE_TRACE_TARGET, docs/live-tests.md)

The first form expects the mcp-test-* objects and policies the live read tests use (docs/live-tests.md).
Redaction: the FMC address/hostname and serial are replaced, `links` are dropped. Review the diff
before committing.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from fmc_mcp.client import FmcApp
from fmc_mcp.config import Settings

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def scrub(data: Any, host: str) -> Any:
    if isinstance(data, dict):
        out = {
            k: "REDACTED" if k in ("serialNumber", "deviceSerialNumber") else scrub(v, host)
            for k, v in data.items()
            if k != "links"
        }
        if data.get("type") == "ServerVersion":
            out["uuid"] = "00000000-0000-0000-0000-000000000001"
            out["serialNumber"] = "REDACTED"
        return out
    if isinstance(data, list):
        return [scrub(v, host) for v in data]
    if isinstance(data, str):
        data = data.replace(host, "fmc.test")
        data = re.sub(r"\bfmcv?\d*\.(?!test\b)[\w-]+(?:\.[\w-]+)+", "fmc.example.com", data)  # FMC FQDNs
        data = re.sub(
            r"\b198\.1[89]\.\d+\.\d+\b", "192.0.2.10", data
        )  # 198.18.0.0/15, common in lab platforms
        data = re.sub(r"Serial Number: \S+", "Serial Number: REDACTED", data)
        return data
    return data


async def capture_ftd(app: FmcApp, host: str) -> None:
    """Device-side fixtures: interfaces, routes, show command, packet tracer, hit counts, health."""
    name = os.environ.get("FMC_LIVE_DEVICE") or sys.exit("--ftd needs FMC_LIVE_DEVICE (the FTD's name)")
    target = os.environ.get("FMC_LIVE_TRACE_TARGET") or sys.exit("--ftd needs FMC_LIVE_TRACE_TARGET")
    devs = await app.all(await app.config_path("devices/devicerecords"))
    dev = next(d for d in devs.items if d.get("name") == name)
    acps = await app.all(await app.config_path("policy/accesspolicies"))
    acp = next(p for p in acps.items if p.get("name") == "mcp-test-ftd-acp")
    base = f"devices/devicerecords/{dev['id']}"
    phys = await app.all(await app.config_path(f"{base}/physicalinterfaces"))
    inside = next(i for i in phys.items if i.get("ifname") == "inside")
    rules = await app.all(await app.config_path(f"policy/accesspolicies/{acp['id']}/accessrules"))
    ids = ",".join(r["id"] for r in rules.items)
    now = int(time.time())
    hc = await app.config_path(f"policy/accesspolicies/{acp['id']}/operational/hitcounts")
    gets: dict[str, tuple[str, dict[str, Any]]] = {
        "ftd_device": (await app.config_path(base), {}),
        "ftd_physicalinterfaces": (await app.config_path(f"{base}/physicalinterfaces"), {"expanded": "true"}),
        "ftd_ipv4staticroutes": (
            await app.config_path(f"{base}/routing/ipv4staticroutes"),
            {"expanded": "true"},
        ),
        "ftd_show_route": (
            await app.config_path(f"{base}/operational/commands"),
            {"command": "show route"},
        ),
        "ftd_hitcounts": (
            hc,
            {"filter": f"deviceId:{dev['id']};fetchZeroHitCount:true;ids:{ids}", "expanded": "true"},
        ),
        "ftd_hitcounts_default": (
            hc,
            {"filter": f"deviceId:{dev['id']};fetchZeroHitCount:true", "expanded": "true"},
        ),
        "ftd_health_alerts": (
            await app.config_path("health/alerts"),
            {"filter": f"deviceUUIDs:{dev['id']}", "limit": 1000},
        ),
        "ftd_health_metrics_mem": (
            await app.config_path("health/metrics"),
            {"filter": f"deviceUUIDs:{dev['id']};metric:mem;startTime:{now - 600};endTime:{now};step:300"},
        ),
        "ftd_deployments": (
            await app.config_path(f"deployment/deployabledevices/{dev['id']}/deployments"),
            {"filter": f"startTime:{now - 86400};endTime:{now}", "expanded": "true"},
        ),
    }
    for name, (path, params) in gets.items():
        data = await app.api.get(path, params)
        (OUT / f"{name}.json").write_text(json.dumps(scrub(data, host), indent=1) + "\n")
        print("captured", name)
    trace = {
        "device": {"id": dev["id"], "type": "Device", "name": dev["name"]},
        "interface": {"id": inside["id"], "type": "PhysicalInterface", "name": "inside"},
        "protocol": "TCP",
        "sourceIPType": "IPv4",
        "sourceIPValue": "10.99.1.10",
        "sourcePort": "40000",
        "destinationIPType": "IPv4",
        "destinationIPValue": target,
        "destinationPort": "23",
    }
    path = f"/api/fmc_troubleshoot/v1/domain/{await app.domain_uuid(None)}/packettracer/traces"
    data = await app.api.post(path, trace, timeout=180)
    (OUT / "ftd_packettracer_drop.json").write_text(json.dumps(scrub(data, host), indent=1) + "\n")
    print("captured ftd_packettracer_drop")


async def capture_bundle(app: FmcApp, host: str) -> None:
    """Record every GET of a real export (path -> response) for tests/unit/test_bundle.py to replay."""
    from fmc_mcp.tools.bundle import build_bundle

    recorded: dict[str, Any] = {}
    real_get = app.api.get

    async def get(path: str, params: dict[str, Any] | None = None, **kw: Any) -> Any:
        data = await real_get(path, params, **kw)
        if path.startswith("/api/fmc_config/"):
            recorded[path] = scrub(data, host)
        return data

    app.api.get = get  # type: ignore[method-assign]
    await build_bundle(app, "mcp-test-acp", None, ["mcp-test-nat"])
    out = {k: recorded[k] for k in sorted(recorded)}
    (OUT / "bundle_acp.json").write_text(json.dumps(out, indent=1) + "\n")
    print("captured bundle_acp", len(out), "responses")


async def capture_templates(app: FmcApp, host: str) -> None:
    """Record the GETs behind fmc_get_device_template (path -> response) for tests/unit/test_templates.py.
    Read-only: lists the templates, then reads one template's interfaces, variables, model mappings,
    VPN settings, overridable objects and associations."""
    from fmc_mcp.tools.templates import (
        OBJECT_PATHS,
        TEMPLATES,
        declared_overrides,
        template_detail,
        template_with_metadata,
    )

    name = os.environ.get("FMC_LIVE_TEMPLATE") or sys.exit("--templates needs FMC_LIVE_TEMPLATE (its name)")
    recorded: dict[str, Any] = {}
    real_get = app.api.get

    async def get(path: str, params: dict[str, Any] | None = None, **kw: Any) -> Any:
        data = await real_get(path, params, **kw)
        if path.startswith("/api/fmc_config/"):
            recorded[path] = scrub(data, host)
        return data

    app.api.get = get  # type: ignore[method-assign]
    await app.all(await app.config_path(TEMPLATES), {"addOnMetadata": "true"})
    t = await template_with_metadata(app, name, None)
    await template_detail(app, t, None)
    base = await app.config_path(f"{TEMPLATES}/{t['id']}")
    for o in await declared_overrides(app, base, t["id"]):  # what fmc_apply_device_template's preview reads
        if o.get("type") in OBJECT_PATHS and o.get("id"):
            await app.api.get(await app.config_path(f"{OBJECT_PATHS[o['type']]}/{o['id']}"))
    out = {"_source": f"recorded from FMC with scripts/capture_fixtures.py --templates ({name})"}
    out.update({k: recorded[k] for k in sorted(recorded)})
    (OUT / "devicetemplates.json").write_text(json.dumps(out, indent=1) + "\n")
    print("captured devicetemplates", len(recorded), "responses")


async def main() -> None:
    settings = Settings()  # type: ignore[call-arg]
    host = re.sub(r"^https?://", "", settings.url).split("/")[0]
    app = FmcApp(settings)
    if "--bundle" in sys.argv:
        try:
            await capture_bundle(app, host)
        finally:
            await app.aclose()
        return
    if "--templates" in sys.argv:
        try:
            await capture_templates(app, host)
        finally:
            await app.aclose()
        return
    if "--ftd" in sys.argv:
        try:
            OUT.mkdir(parents=True, exist_ok=True)
            await capture_ftd(app, host)
        finally:
            await app.aclose()
        return
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
