"""F53 live SD-WAN matrix (#110): topology x component, recorded in docs/sdwan-matrix.md.

Topologies: T1 single hub + spokes, T2 dual hub, T3 HA-pair hub, T4 spoke-to-spoke (on the T1 devices).
Components: C1 build/deploy/teardown, C2 overlay routing (iBGP; OSPF variant), C3 WAN interfaces and
application routes, C4 device-template onboarding, C5 monitoring (fmc_sdwan_status and the
fmc_sdwan_troubleshoot prompt).

Everything lab-specific comes from FMC_LIVE_SDWAN_* variables (docs/live-tests.md); a cell whose
variables are unset is skipped and the reason names them. Cells that write (create, deploy, delete)
also need FMC_LIVE_SDWAN_WRITE=1, since a run deploys every device of the topology. Fault injection
(link down, brownout, hub down) goes through cml-mcp and is not driven from here: these tests check the
FMC side, the matrix document records the fault runs.

The devices must already be registered with routed WAN and inside interfaces that have logical names,
security zones, addresses and routes to the hubs' WAN addresses (the F52 recipes plus the FMC-side
setup in docs/sdwan-matrix.md). Each cell builds its own topology and deletes it again.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from fastmcp import Client

from .live_env import live_env, missing
from .test_live_writes import apply, call

pytestmark = pytest.mark.live

TOPOLOGIES = ("T1", "T2", "T3", "T4")
COMPONENTS = ("C1", "C2", "C3", "C4", "C5")

# What each topology needs besides the shared variables.
NEEDS: dict[str, tuple[str, ...]] = {
    "T1": ("FMC_LIVE_SDWAN_T1_HUB", "FMC_LIVE_SDWAN_T1_SPOKES"),
    "T2": ("FMC_LIVE_SDWAN_T2_HUB", "FMC_LIVE_SDWAN_T2_HUB2", "FMC_LIVE_SDWAN_T2_SPOKES"),
    "T3": ("FMC_LIVE_SDWAN_T3_HA", "FMC_LIVE_SDWAN_T3_SPOKES"),
    "T4": ("FMC_LIVE_SDWAN_T1_HUB", "FMC_LIVE_SDWAN_T1_SPOKES"),
}
SHARED = ("FMC_LIVE_SDWAN_WAN", "FMC_LIVE_SDWAN_INSIDE", "FMC_LIVE_SDWAN_ZONE", "FMC_LIVE_SDWAN_POOL")


def prefix() -> str:
    return live_env("FMC_LIVE_SDWAN_PREFIX", "mcp-sdwan")


def domain_args() -> dict[str, Any]:
    dom = live_env("FMC_LIVE_SDWAN_DOMAIN")
    return {"domain": dom} if dom else {}


def spokes_of(topology: str) -> list[str]:
    key = "T1" if topology == "T4" else topology
    return [s.strip() for s in live_env(f"FMC_LIVE_SDWAN_{key}_SPOKES").split(",") if s.strip()]


def hub_of(topology: str) -> str:
    if topology == "T3":
        return live_env("FMC_LIVE_SDWAN_T3_HA")
    key = "T1" if topology == "T4" else topology
    return live_env(f"FMC_LIVE_SDWAN_{key}_HUB")


def topo_name(topology: str, component: str, overlay: str = "bgp") -> str:
    suffix = "-ospf" if overlay == "ospf" else ""
    return f"{prefix()}-{topology.lower()}-{component.lower()}{suffix}"


def skip_reason(topology: str, component: str, writes: bool = True) -> str | None:
    gone = missing(*NEEDS[topology], *SHARED)
    if writes and live_env("FMC_LIVE_SDWAN_WRITE") != "1":
        gone.append("FMC_LIVE_SDWAN_WRITE=1")
    if component == "C4" and not live_env("FMC_LIVE_SDWAN_ONBOARD"):
        gone.append("FMC_LIVE_SDWAN_ONBOARD")
    if topology == "T2" and not live_env("FMC_LIVE_SDWAN_POOL2"):
        gone.append("FMC_LIVE_SDWAN_POOL2")
    if gone:
        return f"{', '.join(gone)} not set (docs/live-tests.md, docs/sdwan-matrix.md)"
    return None


def spoke_specs(names: list[str]) -> list[dict[str, Any]]:
    wan = live_env("FMC_LIVE_SDWAN_WAN")
    inside = live_env("FMC_LIVE_SDWAN_INSIDE")
    backup = live_env("FMC_LIVE_SDWAN_BACKUP_WAN")
    specs = []
    for name in names:
        spec: dict[str, Any] = {"device": name, "wan_interface": wan, "inside_interfaces": [inside]}
        if backup:
            spec["backup_wan_interface"] = backup
        specs.append(spec)
    return specs


def create_args(
    topology: str, component: str, overlay: str = "bgp", spokes: list[str] | None = None
) -> dict[str, Any]:
    args: dict[str, Any] = {
        "name": topo_name(topology, component, overlay),
        "hub": hub_of(topology),
        "hub_wan_interface": live_env("FMC_LIVE_SDWAN_WAN"),
        "hub_inside_interfaces": [live_env("FMC_LIVE_SDWAN_INSIDE")],
        "tunnel_zone": live_env("FMC_LIVE_SDWAN_ZONE"),
        "spoke_pool": live_env("FMC_LIVE_SDWAN_POOL"),
        "spokes": spoke_specs(spokes_of(topology) if spokes is None else spokes),
        "overlay": overlay,
        **domain_args(),
    }
    if topology == "T2":
        args |= {
            "backup_hub": live_env("FMC_LIVE_SDWAN_T2_HUB2"),
            "backup_hub_wan_interface": live_env("FMC_LIVE_SDWAN_WAN"),
            "backup_hub_inside_interfaces": [live_env("FMC_LIVE_SDWAN_INSIDE")],
            "backup_spoke_pool": live_env("FMC_LIVE_SDWAN_POOL2"),
        }
    return args


def members(topology: str) -> list[str]:
    hubs = [hub_of(topology)]
    if topology == "T2":
        hubs.append(live_env("FMC_LIVE_SDWAN_T2_HUB2"))
    return hubs + spokes_of(topology)


async def deploy(client: Client[Any], devices: list[str], note: str) -> None:
    """Deploy exactly these devices (the preview must not list anything else)."""
    args = {"devices": devices, "note": note, **domain_args()}
    preview = await call(client, "fmc_deploy", args)
    if preview.get("status") == "blocked" and "nothing to deploy" in str(preview).lower():
        return
    assert preview["status"] == "preview", preview
    details = preview.get("details") or preview.get("preview") or preview
    listed = {d.get("device") or d.get("name") for d in details.get("devices", [])}
    assert listed <= set(devices), f"deploy preview lists other devices: {listed - set(devices)}"
    done = await call(client, "fmc_deploy", {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied", done


async def teardown(client: Client[Any], name: str, devices: list[str]) -> None:
    found = await call(
        client, "fmc_list_vpn_topologies", {"kind": "sdwan", "response_format": "json", **domain_args()}
    )
    if any(t.get("name") == name for t in found.get("results", [])):
        await apply(client, "fmc_delete_s2s_vpn", {"topology": name, **domain_args()})
        await deploy(client, devices, f"F53 teardown {name}")


@pytest_asyncio.fixture(loop_scope="session")
async def topology(client: Client[Any], request: pytest.FixtureRequest) -> AsyncIterator[dict[str, Any]]:
    """Build (create + deploy) the cell's topology, yield it, tear it down."""
    topo, comp, overlay = request.param
    reason = skip_reason(topo, comp)
    if reason:
        pytest.skip(reason)
    spokes = spokes_of(topo)
    if comp == "C4":  # the onboarded branch joins later, from the template
        spokes = [s for s in spokes if s != live_env("FMC_LIVE_SDWAN_ONBOARD")]
    args = create_args(topo, comp, overlay, spokes)
    devices = members(topo)
    await teardown(client, args["name"], devices)
    await apply(client, "fmc_create_sdwan_topology", args)
    await deploy(client, devices, f"F53 {topo} {comp}")
    try:
        yield {
            "topology": topo,
            "component": comp,
            "overlay": overlay,
            "name": args["name"],
            "devices": devices,
            "spokes": spokes,
        }
    finally:
        await teardown(client, args["name"], devices)


def cell(topo: str, comp: str, overlay: str = "bgp") -> Any:
    return pytest.param((topo, comp, overlay), id=f"{topo}-{comp}-{overlay}")


def show(client: Client[Any], device: str, command: str) -> Any:
    return call(client, "fmc_run_show_command", {"device": device, "command": command, **domain_args()})


# --- C1 build, deploy, teardown ---------------------------------------------------------------------


@pytest.mark.parametrize("topology", [cell(t, "C1") for t in TOPOLOGIES if t != "T4"], indirect=True)
async def test_c1_build_deploy_teardown(client: Client[Any], topology: dict[str, Any]) -> None:
    got = await call(client, "fmc_get_vpn_topology", {"topology": topology["name"], **domain_args()})
    roles = {ep.get("name"): ep.get("role", ep.get("peerType")) for ep in got.get("endpoints", [])}
    assert set(topology["spokes"]) <= set(roles), roles
    assert "manualPreSharedKey" not in str(got)
    sa = await show(client, topology["spokes"][0], "show crypto ikev2 sa")
    assert "READY" in str(sa) or "established" in str(sa).lower(), sa


# --- C2 overlay routing -----------------------------------------------------------------------------
# FMC 10.0.1 refuses 'show bgp summary', 'show bgp neighbors', 'show policy-route' and
# 'show path-monitoring' through its show-command API; 'show route bgp', 'show route ospf' and
# 'show crypto ikev2 sa' work.


async def ospf(client: Client[Any], devices: list[str], add: bool) -> None:
    networks = [n.strip() for n in live_env("FMC_LIVE_SDWAN_OSPF_NETWORKS").split(",") if n.strip()]
    for device in devices:
        args: dict[str, Any] = {"device": device, "area": "0", **domain_args()}
        args |= {"add_networks": networks} if add else {"remove_process": True}
        await apply(client, "fmc_configure_ospf", args)
    await deploy(client, devices, f"F53 C2 OSPF {'on' if add else 'off'}")


@pytest.mark.parametrize(
    "topology", [cell(t, "C2") for t in TOPOLOGIES if t != "T4"] + [cell("T1", "C2", "ospf")], indirect=True
)
async def test_c2_overlay_routing(client: Client[Any], topology: dict[str, Any]) -> None:
    hub = topology["devices"][0]
    if topology["overlay"] != "ospf":
        route = await show(client, hub, "show route bgp")
        assert str(route).count("B ") >= len(topology["spokes"]), route
        return
    if not live_env("FMC_LIVE_SDWAN_OSPF_NETWORKS"):
        pytest.skip("FMC_LIVE_SDWAN_OSPF_NETWORKS not set (docs/live-tests.md)")
    await ospf(client, topology["devices"], add=True)
    try:
        for device in [hub, *topology["spokes"]]:
            route = await show(client, device, "show route ospf")
            assert "O " in str(route), f"{device} has no OSPF routes: {route}"
    finally:
        await ospf(client, topology["devices"], add=False)


# --- C3 WAN interfaces and application routes -------------------------------------------------------


@pytest.mark.parametrize("topology", [cell(t, "C3") for t in ("T1", "T4")], indirect=True)
async def test_c3_app_route(client: Client[Any], topology: dict[str, Any]) -> None:
    spoke = topology["spokes"][0]
    wans = [w for w in (live_env("FMC_LIVE_SDWAN_WAN"), live_env("FMC_LIVE_SDWAN_BACKUP_WAN")) if w]
    monitoring = live_env("FMC_LIVE_SDWAN_PATH_MONITORING", "auto")
    for prio, wan in enumerate(wans, start=1):
        await apply(
            client,
            "fmc_configure_wan_interface",
            {
                "device": spoke,
                "interface": wan,
                "priority": prio,
                "path_monitoring": monitoring,
                **domain_args(),
            },
        )
    route = f"{prefix()}-{topology['topology'].lower()}-c3-route"
    dest = live_env("FMC_LIVE_SDWAN_APP_DEST")
    args: dict[str, Any] = {
        "device": spoke,
        "name": route,
        "ingress_interfaces": [live_env("FMC_LIVE_SDWAN_INSIDE")],
        "egress_interfaces": wans,
        "order_by": "priority",
        **({"destinations": [dest]} if dest else {"applications": ["ICMP"]}),
        **domain_args(),
    }
    await apply(client, "fmc_create_app_route", args)
    try:
        await deploy(client, [spoke], "F53 C3 app route")
        routing = await call(client, "fmc_get_routing", {"device": spoke, **domain_args()})
        assert route in str(routing), routing
        src, dst = live_env("FMC_LIVE_SDWAN_TRACE_SRC"), live_env("FMC_LIVE_SDWAN_TRACE_DST")
        if src and dst:
            trace = await call(
                client,
                "fmc_packet_tracer",
                {
                    "device": spoke,
                    "protocol": "icmp",
                    "source_ip": src,
                    "destination_ip": dst,
                    **domain_args(),
                },
            )
            assert "PBR-LOOKUP" in str(trace), trace
    finally:
        await apply(client, "fmc_delete_app_route", {"device": spoke, "name": route, **domain_args()})
        await deploy(client, [spoke], "F53 C3 app route removed")


# --- C4 device-template onboarding ------------------------------------------------------------------


@pytest.mark.parametrize("topology", [cell(t, "C4") for t in ("T1", "T2")], indirect=True)
async def test_c4_template_onboarding(client: Client[Any], topology: dict[str, Any]) -> None:
    source, new = topology["spokes"][0], live_env("FMC_LIVE_SDWAN_ONBOARD")
    template = f"{prefix()}-{topology['topology'].lower()}-c4-template"
    await apply(
        client, "fmc_create_device_template", {"name": template, "source_device": source, **domain_args()}
    )
    try:
        got = await call(client, "fmc_get_device_template", {"template": template, **domain_args()})
        variables: dict[str, str] = {}
        for var in got.get("variables", []):
            env = live_env(f"FMC_LIVE_SDWAN_ONBOARD_VAR_{var['name'].upper()}")
            if env:
                variables[var["name"]] = env
        await apply(
            client,
            "fmc_apply_device_template",
            {"template": template, "device": new, "variables": variables, **domain_args()},
        )
        await deploy(client, [*topology["devices"], new], "F53 C4 onboarding")
        topo = await call(client, "fmc_get_vpn_topology", {"topology": topology["name"], **domain_args()})
        assert new in {ep.get("name") for ep in topo.get("endpoints", [])}, topo
    finally:
        await apply(client, "fmc_delete_device_template", {"template": template, **domain_args()})


# --- C5 monitoring ----------------------------------------------------------------------------------


@pytest.mark.parametrize("topology", [cell(t, "C5") for t in TOPOLOGIES if t != "T4"], indirect=True)
async def test_c5_status_and_troubleshoot(client: Client[Any], topology: dict[str, Any]) -> None:
    status = await call(
        client,
        "fmc_sdwan_status",
        {"topology": topology["name"], "max_devices": len(topology["devices"]), **domain_args()},
    )
    text = str(status)
    for spoke in topology["spokes"]:
        assert spoke in text, f"{spoke} missing from fmc_sdwan_status"
    prompt = await client.get_prompt(
        "fmc_sdwan_troubleshoot", {"branch": topology["spokes"][0], "application": "ICMP"}
    )
    assert "fmc_sdwan_status" in str(prompt.messages)


def test_matrix_shape() -> None:
    """The matrix has every topology x component; offline, so it runs (and fails) without a lab."""
    assert len(TOPOLOGIES) * len(COMPONENTS) == 20
    assert all(t in NEEDS for t in TOPOLOGIES)
