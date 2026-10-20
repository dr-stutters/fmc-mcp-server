"""'Is a deployment stuck?' (#209): fmc_list_deployable_devices lists running deployments with their job
and age; fmc_pending_changes says when FMC doesn't count the device as deployable. Recorded from the lab's
real stuck cluster deployment (tests/fixtures/deploy_in_progress.json)."""

import copy
import time
from typing import Any

import httpx
import respx

from fmc_mcp._core.testing import call_tool
from fmc_mcp.server import create_server

from .conftest import CFG, fixture, items, make_settings

LAB = fixture("deploy_in_progress")
HUB = "dc0d1aac-ca82-11f1-82bc-ca1afe70919b"
IDENTITY = "71f24ba4-c9c6-11f1-b39a-f8b1a0356797"


async def call(tool: str, args: dict[str, Any]) -> Any:
    return await call_tool(create_server(make_settings()), tool, {"response_format": "json", **args})


def lab(fmc: respx.MockRouter, records: dict[str, Any] | None = None) -> respx.Route:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(
        return_value=httpx.Response(200, json=LAB["deployabledevices"])
    )
    fmc.get(f"{CFG}/devices/devicerecords").mock(
        return_value=httpx.Response(200, json=records or LAB["devicerecords"])
    )
    return fmc.get(f"{CFG}/deployment/jobhistories").mock(
        return_value=httpx.Response(200, json=LAB["jobhistories"])
    )


async def test_stuck_cluster_deployment_is_listed_with_its_job_and_age(fmc: respx.MockRouter) -> None:
    jobs = lab(fmc)
    data = await call("fmc_list_deployable_devices", {})
    cluster = next(r for r in data["results"] if r["device"] == "mcp-sdwan-t3-cluster")
    assert cluster["deploying"] is True and cluster["can_be_deployed"] is False
    assert "another deployment is in progress" in cluster["message"]
    (row,) = data["in_progress"]
    assert row["device"] == "mcp-sdwan-t3-cluster (mcp-sdwan-t3-hub)"
    assert (row["job"], row["job_status"], row["job_note"], row["user"]) == (
        "Deploy_Job_68",
        "DEPLOYING",
        "Cluster create",
        "System",
    )
    assert row["started"] == "2026-10-18T03:11:39Z" and row["device_status"] == "NONE"
    assert row["probably_stuck"] is True and row["running_for"].split()[0].endswith("d")
    assert data["probably_stuck"] == ["mcp-sdwan-t3-cluster (mcp-sdwan-t3-hub)"]
    # one job-history read, for the in-progress device only
    (call_,) = jobs.calls
    assert call_.request.url.params["filter"].startswith(f"deviceUUID:{HUB};startTime:")


async def test_a_recent_running_job_is_not_stuck_and_nothing_running_reads_no_history(
    fmc: respx.MockRouter,
) -> None:
    jobs = lab(fmc)
    recent = copy.deepcopy(LAB["jobhistories"])
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    recent["items"][0].update(startTime=started, endTime=started)
    jobs.mock(return_value=httpx.Response(200, json=recent))
    (row,) = (await call("fmc_list_deployable_devices", {}))["in_progress"]
    assert row["probably_stuck"] is False and row["running_for"] in ("4m", "5m")
    # in progress per FMC but no running job in the history: flagged, with why
    jobs.mock(return_value=items(LAB["jobhistories"]["items"][1:]))
    (row,) = (await call("fmc_list_deployable_devices", {}))["in_progress"]
    assert row["probably_stuck"] is True and "has no running job" in row["note"]
    # nothing in progress anywhere: no in_progress section, no job-history read
    idle = copy.deepcopy(LAB["devicerecords"])
    idle["items"][0]["deploymentStatus"] = "DEPLOYMENT_PENDING"
    pending = copy.deepcopy(LAB["deployabledevices"])
    pending["items"][0]["isDeploying"] = False
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=httpx.Response(200, json=pending))
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=httpx.Response(200, json=idle))
    before = jobs.call_count
    data = await call("fmc_list_deployable_devices", {})
    assert "in_progress" not in data and "probably_stuck" not in data and jobs.call_count == before


async def test_pending_changes_on_a_device_fmc_does_not_count_as_deployable(fmc: respx.MockRouter) -> None:
    lab(fmc)
    change = {
        "entityName": "mcp-pki-internal",
        "entityType": "PKI Internal Certificate",
        "action": "UPDATE",
        "valueUpdated": [{"fieldName": "Certificate", "oldValue": "a", "newValue": "b"}],
    }
    fmc.get(f"{CFG}/deployment/deployabledevices/{IDENTITY}/pendingchanges").mock(
        return_value=items([change])
    )
    data = await call("fmc_pending_changes", {"device": "mcp-ftd-identity"})
    assert data["results"][0]["entity"] == "mcp-pki-internal"
    assert "does not count this device as deployable" in data["note"] and "DEPLOYED" in data["note"]
    # a device FMC does list as pending: no such note
    fmc.get(f"{CFG}/deployment/deployabledevices/503133d6-c9c6-11f1-b434-883d23e0134a/pendingchanges").mock(
        return_value=items([change])
    )
    data = await call("fmc_pending_changes", {"device": "mcp-ftd2"})
    assert "note" not in data
