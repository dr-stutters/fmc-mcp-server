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
    # in progress per FMC but no running job in the history (finished between the reads, or filed under
    # another unit): unknown, never 'stuck'
    jobs.mock(return_value=items(LAB["jobhistories"]["items"][1:]))
    data = await call("fmc_list_deployable_devices", {})
    (row,) = data["in_progress"]
    assert row["probably_stuck"] is None and "lists no running job" in row["note"]
    assert "probably_stuck" not in data
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
    assert "does not list this device in its deployable devices" in data["note"]
    # devices FMC does list as deployable, itself or as an HA member (mcp-ftd3 only in deviceMembers):
    # no such note, whatever their record says
    for dev_id, name in (
        ("503133d6-c9c6-11f1-b434-883d23e0134a", "mcp-ftd2"),
        ("532a591e-c9c6-11f1-adb7-e0cf54ff7bd5", "mcp-ftd3"),
    ):
        fmc.get(f"{CFG}/deployment/deployabledevices/{dev_id}/pendingchanges").mock(
            return_value=items([change])
        )
        records = copy.deepcopy(LAB["devicerecords"])
        records["items"] = [r for r in records["items"] if r["id"] != dev_id]
        records["items"].append(
            {"id": dev_id, "type": "Device", "name": name, "deploymentStatus": "DEPLOYED"}
        )
        fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=httpx.Response(200, json=records))
        data = await call("fmc_pending_changes", {"device": name})
        assert "note" not in data, name


async def test_a_failed_job_history_read_is_unknown_not_stuck(fmc: respx.MockRouter) -> None:
    jobs = lab(fmc)
    jobs.mock(return_value=httpx.Response(500, json={"error": {"messages": [{"description": "boom"}]}}))
    data = await call("fmc_list_deployable_devices", {})
    (row,) = data["in_progress"]
    assert row["probably_stuck"] is None and row["note"].startswith("job history not readable")
    assert row["device"] == "mcp-sdwan-t3-cluster (mcp-sdwan-t3-hub)" and "probably_stuck" not in data


async def test_job_start_times_in_other_iso_forms(fmc: respx.MockRouter) -> None:
    """Fractional seconds and an offset are read; a start time that can't be read leaves the age unknown
    (probably_stuck null), never 'not stuck'."""
    jobs = lab(fmc)
    other = copy.deepcopy(LAB["jobhistories"])
    other["items"][0]["startTime"] = "2026-10-18T14:11:39.250+11:00"  # = 03:11:39.25Z
    jobs.mock(return_value=httpx.Response(200, json=other))
    (row,) = (await call("fmc_list_deployable_devices", {}))["in_progress"]
    assert row["probably_stuck"] is True and row["running_for"].split()[0].endswith("d")
    recent = time.strftime("%Y-%m-%dT%H:%M:%S.123456", time.gmtime(time.time() - 120))  # no zone: UTC
    other["items"][0]["startTime"] = recent
    jobs.mock(return_value=httpx.Response(200, json=other))
    (row,) = (await call("fmc_list_deployable_devices", {}))["in_progress"]
    assert row["probably_stuck"] is False and row["running_for"] in ("1m", "2m")
    other["items"][0]["startTime"] = "18/10/2026 03:11"
    jobs.mock(return_value=httpx.Response(200, json=other))
    data = await call("fmc_list_deployable_devices", {})
    (row,) = data["in_progress"]
    assert row["probably_stuck"] is None and "could not be read" in row["note"] and "running_for" not in row
    assert "probably_stuck" not in data
