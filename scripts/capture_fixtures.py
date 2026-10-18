"""Capture a few real FMC responses as redacted unit-test fixtures.

    uv run python scripts/capture_fixtures.py          # policies and objects (the seeded mcp-test-* set)
    uv run python scripts/capture_fixtures.py --bundle # every GET fmc_export_policy_bundle makes for
                                                       # mcp-test-acp + mcp-test-nat (bundle_acp.json)
    uv run python scripts/capture_fixtures.py --sdwan  # the SD-WAN topology named by FMC_LIVE_SDWAN
                                                       # (default mcp-sdwan-t1) with its devices'
                                                       # interfaces, pools, zones and tunnel/path
                                                       # health (sdwan_lab.json; GETs only)
    uv run python scripts/capture_fixtures.py --templates # every GET fmc_get_device_template makes for
                                                       # the template named by FMC_LIVE_TEMPLATE
                                                       # (devicetemplates.json; F51d)
    uv run python scripts/capture_fixtures.py --ftd    # device fixtures from the managed FTD named by
                                                       # FMC_LIVE_DEVICE (after tests/live/test_live_ftd.py;
                                                       # also FMC_LIVE_TRACE_TARGET, docs/live-tests.md)
    uv run python scripts/capture_fixtures.py --interfaces  # every interface collection of the FTD named
                                                       # by FMC_LIVE_DEVICE (ftd_interface_kinds.json; F58;
                                                       # keeps the file's `created` spec examples)
    uv run python scripts/capture_fixtures.py --sdwan-routing  # app-aware routing reads (F51b) from the
                                                       # SD-WAN branch named by FMC_LIVE_SDWAN_DEVICE: WAN
                                                       # interfaces, PBR, ECMP zones, the route's ACL
    uv run python scripts/capture_fixtures.py --sdwan-metrics  # health/metrics metric=pathmonitoring (RTT,
                                                       # jitter, loss, MOS per path-monitored interface)
                                                       # for FMC_LIVE_SDWAN_DEVICE, stored under the key
                                                       # FMC_LIVE_SDWAN_LABEL (default baseline) in
                                                       # ftd_sdwan_pathmetrics.json; run it again with
                                                       # FMC_LIVE_SDWAN_LABEL=brownout during a CML brownout

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
from fmc_mcp.tools.troubleshoot import run_show

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


INTERFACE_COLLECTIONS = (
    "physicalinterfaces",
    "subinterfaces",
    "etherchannelinterfaces",
    "bridgegroupinterfaces",
    "loopbackinterfaces",
    "virtualtunnelinterfaces",
    "vlaninterfaces",
)


async def capture_interfaces(app: FmcApp, host: str) -> None:
    """F58 (GETs only): every interface collection of one FTD, expanded; a collection the model doesn't
    support is stored as its status and message (FTDv answers 405 for VLAN interfaces)."""
    from fmc_mcp._core import UpstreamError

    name = os.environ.get("FMC_LIVE_DEVICE") or sys.exit("--interfaces needs FMC_LIVE_DEVICE")
    devs = await app.all(await app.config_path("devices/devicerecords"))
    dev = next(d for d in devs.items if d.get("name") == name)
    path = OUT / "ftd_interface_kinds.json"
    out: dict[str, Any] = json.loads(path.read_text()) if path.exists() else {}
    out["device"] = {
        k: dev.get(k) for k in ("id", "name", "type", "ftdMode", "model", "sw_version") if dev.get(k)
    }
    for coll in INTERFACE_COLLECTIONS:
        try:
            out[coll] = await app.api.get(
                await app.config_path(f"devices/devicerecords/{dev['id']}/{coll}"), {"expanded": "true"}
            )
        except UpstreamError as e:
            out[coll] = {"status": e.status_code, "description": str(e).split(": ", 1)[-1]}
    path.write_text(json.dumps(scrub(out, host), indent=1) + "\n")
    print("captured ftd_interface_kinds")


async def capture_sdwan_routing(app: FmcApp, host: str) -> None:
    """F51b fixtures (GETs only): a branch FTD's interfaces with path monitoring, its policy-based routes
    and ECMP zones, and the extended access lists those routes match on (sdwan_app_routing.json)."""
    name = os.environ.get("FMC_LIVE_SDWAN_DEVICE") or sys.exit("--sdwan-routing needs FMC_LIVE_SDWAN_DEVICE")
    devs = await app.all(await app.config_path("devices/devicerecords"))
    dev = next(d for d in devs.items if d.get("name") == name)
    base = f"devices/devicerecords/{dev['id']}"
    out: dict[str, Any] = {"_source": f"recorded from FMC by capture_fixtures.py --sdwan-routing ({name})"}
    for key, sub in (
        ("physicalinterfaces", "physicalinterfaces"),
        ("virtualtunnelinterfaces", "virtualtunnelinterfaces"),
        ("policybasedroutes", "routing/policybasedroutes"),
        ("ecmpzones", "routing/ecmpzones"),
    ):
        out[key] = await app.api.get(await app.config_path(f"{base}/{sub}"), {"expanded": "true"})
    acl_ids = {
        str((a.get("matchCriteria") or {}).get("id"))
        for p in out["policybasedroutes"].get("items") or []
        for a in p.get("forwardingActions") or []
    }
    out["extendedaccesslists"] = [
        await app.api.get(await app.config_path(f"object/extendedaccesslists/{i}")) for i in sorted(acl_ids)
    ]
    out["applications_page"] = await app.api.get(
        await app.config_path("object/applications"), {"limit": 3, "offset": 1000}
    )
    (OUT / "sdwan_app_routing.json").write_text(json.dumps(scrub(out, host), indent=1) + "\n")
    print("captured sdwan_app_routing")


async def capture_sdwan_metrics(app: FmcApp, host: str) -> None:
    """fmc_sdwan_status's path metrics (GET only): the last 10 minutes of health/metrics
    metric=pathmonitoring for one branch, with its UUID replaced by the sdwan_lab id (d-sp1). FMC returns
    them only when the interface has path monitoring; its samples trail the device by up to ~5 minutes."""
    name = os.environ.get("FMC_LIVE_SDWAN_DEVICE") or sys.exit("--sdwan-metrics needs FMC_LIVE_SDWAN_DEVICE")
    label = os.environ.get("FMC_LIVE_SDWAN_LABEL", "baseline")
    devs = await app.all(await app.config_path("devices/devicerecords"))
    dev = next(d for d in devs.items if d.get("name") == name)
    now = int(time.time())
    flt = f"deviceUUIDs:{dev['id']};metric:pathmonitoring;startTime:{now - 600};endTime:{now};step:60"
    data = await app.api.get(await app.config_path("health/metrics"), {"filter": flt, "expanded": "true"})
    text = json.dumps(scrub(data, host)).replace(str(dev["id"]), "d-sp1")
    path = OUT / "ftd_sdwan_pathmetrics.json"
    out = json.loads(path.read_text()) if path.exists() else {}
    out.setdefault("_source", f"recorded from FMC by capture_fixtures.py --sdwan-metrics ({name})")
    out[label] = json.loads(text)
    path.write_text(json.dumps(out, indent=1) + "\n")
    print("captured ftd_sdwan_pathmetrics", label)


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


async def capture_sdwan(app: FmcApp, host: str) -> None:
    """Every GET the SD-WAN tools make for one AUTO_VPN topology, keyed by API path (reads only)."""
    name = os.environ.get("FMC_LIVE_SDWAN", "mcp-sdwan-t1")
    out: dict[str, Any] = {}

    async def get(path: str, params: dict[str, Any] | None = None) -> Any:
        data = await app.api.get(path, {"expanded": "true", "limit": 1000, **(params or {})})
        key = path.split("/domain/", 1)[-1].split("/", 1)[-1]  # drop the domain UUID
        out[key] = scrub(data, host)
        return data

    s2s = await app.config_path("policy/ftds2svpns")
    topo = next(t for t in (await get(s2s)).get("items") or [] if t.get("name") == name)
    eps = await get(f"{s2s}/{topo['id']}/endpoints")
    for sub in ("ikesettings", "ipsecsettings"):
        await get(f"{s2s}/{topo['id']}/{sub}")
    for e in eps.get("items") or []:
        dev = (e.get("device") or {}).get("id")
        if not dev:
            continue
        for kind in (
            "physicalinterfaces",
            "virtualtunnelinterfaces",
            "loopbackinterfaces",
            "routing/policybasedroutes",
        ):
            await get(await app.config_path(f"devices/devicerecords/{dev}/{kind}"))
        shows = out.setdefault("show", {})
        for cmd in ("show path-monitoring", "show policy-route", "show bgp summary"):
            try:
                text = await run_show(app, dev, cmd, None)
            except Exception as e:  # a command FMC doesn't allow is recorded as missing
                print("skipped", dev, cmd, e)
                continue
            shows.setdefault(dev, {})[cmd] = scrub(text, host)
    for coll in ("object/ipv4addresspools", "object/securityzones", "devices/devicerecords"):
        await get(await app.config_path(coll))
    for coll in ("health/tunnelstatuses", "health/pathmonitoredinterfaces"):
        try:
            await get(await app.config_path(coll))
        except Exception as e:  # health collections answer 404/405 on some versions
            print("skipped", coll, e)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sdwan_lab.json").write_text(json.dumps(out, indent=1) + "\n")
    print("captured sdwan_lab", len(out), "responses")


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
    if "--sdwan-metrics" in sys.argv:
        try:
            OUT.mkdir(parents=True, exist_ok=True)
            await capture_sdwan_metrics(app, host)
        finally:
            await app.aclose()
        return
    if "--interfaces" in sys.argv:
        try:
            OUT.mkdir(parents=True, exist_ok=True)
            await capture_interfaces(app, host)
        finally:
            await app.aclose()
        return
    if "--sdwan-routing" in sys.argv:
        try:
            OUT.mkdir(parents=True, exist_ok=True)
            await capture_sdwan_routing(app, host)
        finally:
            await app.aclose()
        return
    if "--sdwan" in sys.argv:
        try:
            await capture_sdwan(app, host)
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
