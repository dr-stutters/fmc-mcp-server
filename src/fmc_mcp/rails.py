"""FMC deploy safety rails (F18) on top of the core rails (core G7: MCP_CHANGE_WINDOW, blast radius, ...).

- Blast radius counts physical devices: an HA pair is two, a cluster is its member count.
- FMC_DEPLOY_WINDOW limits only the tools that change what runs on devices.
- ignore_warning needs FMC_ALLOW_IGNORE_WARNING and a recorded set of FMC warnings for the exact same
  devices and pending version (from a deploy attempt without ignore_warning), listed in the preview.
"""

from __future__ import annotations

import re
import time
from typing import Any

from stutters_mcp_core import InvalidRequest, UpstreamError
from stutters_mcp_core.policy import ChangeWindow

from fmc_mcp.client import FmcApp
from fmc_mcp.config import Settings

CLUSTERS = "deviceclusters/ftddevicecluster"
WARNINGS_TTL = 3600.0  # seconds a recorded set of deploy warnings can be ignored


def deploy_window_blockers(settings: Settings, tool: str) -> tuple[dict[str, Any] | None, list[str]]:
    """(preview info, blockers) for FMC_DEPLOY_WINDOW."""
    if not settings.deploy_window:
        return None, []
    state = ChangeWindow.parse(settings.deploy_window).state()
    if state["open"]:
        return state, []
    when = f"; it next opens {state['next_open']}" if state.get("next_open") else ""
    return state, [
        f"{tool} changes what runs on devices and is only allowed inside the deploy window "
        f"(FMC_DEPLOY_WINDOW: {state['window']}){when}. Preview again inside the window."
    ]


def check_deploy_window(settings: Settings, tool: str) -> None:
    """Re-checked when a confirmed change runs: the window may have closed since the preview."""
    _, blockers = deploy_window_blockers(settings, tool)
    if blockers:
        raise InvalidRequest(f"Nothing was changed: {blockers[0]}")


async def units_of(app: FmcApp, device: dict[str, Any], domain: str | None) -> int:
    """How many physical devices a deployable/target reference stands for."""
    kind = str(device.get("type") or "")
    if "HAPair" in kind or kind == "DeviceHAPair":
        return 2
    if "Cluster" in kind and device.get("id"):
        try:
            c = await app.api.get(await app.config_path(f"{CLUSTERS}/{device['id']}", domain))
        except UpstreamError as e:  # fail closed: a safety rail must not under-count
            raise UpstreamError(
                f"Could not count the members of cluster {device.get('name')!r} for the blast radius: {e}",
                e.status_code,
            ) from e
        data = (c or {}).get("dataDevices") or (c or {}).get("slaveDevices") or []
        return 1 + len(data)
    return 1


def _key(device_ids: list[Any], version: str) -> str:
    return f"{','.join(sorted(map(str, device_ids)))}@{version}"


def remember_warnings(app: FmcApp, device_ids: list[Any], version: str, warnings: list[str]) -> None:
    app.deploy_warnings[_key(device_ids, version)] = (time.monotonic(), warnings)


def recorded_warnings(app: FmcApp, device_ids: list[Any], version: str) -> list[str] | None:
    hit = app.deploy_warnings.get(_key(device_ids, version))
    if hit is None or time.monotonic() - hit[0] > WARNINGS_TTL:
        return None
    return hit[1]


def split_warnings(text: str) -> list[str]:
    """FMC's validation messages, one per entry (fmc_error_detail joins them with ' | ')."""
    detail = re.sub(r"^.*? on [A-Z]+ \S+: ", "", text, count=1)
    return [p.strip() for p in detail.split(" | ") if p.strip()]
