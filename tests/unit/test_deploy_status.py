"""'Is a deployment stuck?' (#209): fmc_list_deployable_devices lists running deployments with their job
and age; fmc_pending_changes says when FMC doesn't count the device as deployable. Recorded from the lab's
real stuck cluster deployment (tests/fixtures/deploy_in_progress.json)."""

import copy
import json
import time
from typing import Any

import httpx
import respx

from fmc_mcp._core.formatting import max_chars
from fmc_mcp._core.testing import call_tool
from fmc_mcp.server import create_server
from fmc_mcp.tools.deploy import CHANGE_TEXT_CAP, CHANGES_PER_ROW

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


async def test_a_huge_pending_change_is_cut_to_fit(fmc: respx.MockRouter) -> None:
    """W6 live (FMC 10.0.1, 2026-10-21): after an LSP install, mcp-ftd-identity's pending changes held a
    Snort 3 network analysis policy UPDATE whose inspectorData value was 115 KB; the tool said it truncated
    the output (it dropped other rows) but still answered 115,521 characters, over the client's limit."""
    lab(fmc)
    inspector = json.dumps(
        {"inspectors": [{"name": f"binder-{i}", "rules": ["x" * 40] * 20} for i in range(120)]}
    )
    assert len(inspector) > 100_000
    nap = {
        "entityName": "Balanced Security and Connectivity",
        "entityType": "Snort3NapPolicy",
        "action": "UPDATE",
        "lastUpdatedByUsers": [{"name": "admin", "type": "User"}],
        "valueUpdated": [{"fieldName": "inspectorData", "oldValue": inspector[:-50], "newValue": inspector}],
    }
    many = {
        "entityName": "mcp-w6-acp",
        "entityType": "NGFWAccessControlPolicy",
        "action": "UPDATE",
        "valueUpdated": [{"fieldName": f"rule {i}", "oldValue": "a", "newValue": "b"} for i in range(45)],
    }
    small = {"entityName": "mcp-w6-tr-now", "entityType": "TimeRange", "action": "ADD"}
    fmc.get(f"{CFG}/deployment/deployabledevices/{IDENTITY}/pendingchanges").mock(
        return_value=items([nap, many, small])
    )
    data = await call("fmc_pending_changes", {"device": "mcp-ftd-identity"})
    assert len(json.dumps(data)) < max_chars()
    rows = {r["entity"]: r for r in data["results"]}
    assert set(rows) == {"Balanced Security and Connectivity", "mcp-w6-acp", "mcp-w6-tr-now"}  # none dropped
    (line,) = rows["Balanced Security and Connectivity"]["changes"]
    # each side is cut on its own (#273): the old value no longer hides the new one
    old_side, new_side = line.split(" -> ")
    assert old_side.startswith("inspectorData: {") and old_side.endswith(" more characters]")
    assert new_side.startswith('{"inspectors"') and new_side.endswith(" more characters]")
    assert len(line) < CHANGE_TEXT_CAP + 100
    assert len(rows["mcp-w6-acp"]["changes"]) == CHANGES_PER_ROW and rows["mcp-w6-acp"]["changes_total"] == 45
    assert "changes_total" not in rows["mcp-w6-tr-now"]
    assert "deployment preview shows them whole" in data["note"]


def test_each_side_of_a_change_is_cut_on_its_own() -> None:
    """#273: the 400-character cap cut the whole 'old -> new' line, so a long old value hid the new one."""
    from fmc_mcp.tools.deploy import VALUE_CAP, cut_note, pending_row

    row = pending_row(
        {
            "entityName": "p",
            "valueUpdated": [
                {"fieldName": "description", "oldValue": "o" * 1000, "newValue": "the new text"}
            ],
            "valueAdded": [{"fieldName": "literal", "newValue": "n" * 300}],
            "valueDeleted": [{"fieldName": "gone", "oldValue": "d" * 1000}],
        }
    )
    added, updated, deleted = row["changes"]
    assert added == "literal: " + "n" * 300  # a single value keeps the whole budget
    assert (
        updated == f"description: {'o' * VALUE_CAP}... [{1000 - VALUE_CAP:,} more characters] -> the new text"
    )
    assert deleted.startswith("-gone: ddd") and deleted.endswith("[600 more characters]")
    assert "each side of 'old -> new'" in str(cut_note([row]))
    assert (
        cut_note([pending_row({"entityName": "p", "valueAdded": [{"fieldName": "a", "newValue": "b"}]})])
        is None
    )
