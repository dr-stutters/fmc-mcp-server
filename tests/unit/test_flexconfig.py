"""F101: fmc_flexconfig_review + fmc_migrate_flexconfig.

The policy list and record follow the FMC 10.0.1 OpenAPI examples (getAllFlexConfig, getFlexConfig: name and
id only), the assignment follows createPolicyAssignment request example 3 (a FlexConfigPolicy on devices).
The migrate answer and its task are synthetic (FlexConfigMigration from the spec, the task as other FMC tasks
answer): the live writer records the real shapes in the lab proof (the lab FMC had no FlexConfig policy on
2026-10-28)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.flexconfig import classify, native_matches, object_names

from .conftest import CFG, items, make_settings

POL = "aaaaaaaa-0000-4000-8000-0000000000f1"
POL2 = "aaaaaaaa-0000-4000-8000-0000000000f2"
FTD1 = "bbbbbbbb-0000-4000-8000-000000000001"
FTD2 = "bbbbbbbb-0000-4000-8000-000000000002"
FTD3 = "bbbbbbbb-0000-4000-8000-000000000003"
TASK = "cccccccc-0000-4000-8000-000000000001"


def server(dangerous: bool = True) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=dangerous))


async def call(c: Client[Any], tool: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(tool, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def device(i: str, name: str) -> dict[str, Any]:
    return {"id": i, "name": name, "type": "Device", "model": "Cisco Secure Firewall Threat Defense for KVM"}


def mock(
    fmc: respx.MockRouter,
    record: dict[str, Any] | None = None,
    second: dict[str, Any] | None = None,
) -> None:
    pols = [{"type": "FlexConfigPolicy", "id": POL, "name": "mcp-flex-asa"}]
    if second is not None:
        pols.append({"type": "FlexConfigPolicy", "id": POL2, "name": second["name"]})
    fmc.get(f"{CFG}/policy/flexconfigpolicies").mock(return_value=items(pols))
    fmc.get(f"{CFG}/policy/flexconfigpolicies/{POL}").mock(
        return_value=httpx.Response(
            200,
            json=record
            or {
                "metadata": {"domain": {"name": "Global", "type": "Domain"}},
                "type": "FlexConfigPolicy",
                "name": "mcp-flex-asa",
                "id": POL,
            },
        )
    )
    if second is not None:
        fmc.get(f"{CFG}/policy/flexconfigpolicies/{POL2}").mock(
            return_value=httpx.Response(200, json={"type": "FlexConfigPolicy", "id": POL2, **second})
        )
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items(
            [
                {
                    "id": POL,
                    "type": "PolicyAssignment",
                    "policy": {"type": "FlexConfigPolicy", "name": "mcp-flex-asa", "id": POL},
                    "targets": [
                        {"id": FTD1, "type": "Device", "name": "mcp-ftd1"},
                        {"id": FTD2, "type": "Device", "name": "mcp-ftd2"},
                    ],
                },
                {
                    "id": "n1",
                    "type": "PolicyAssignment",
                    "policy": {"type": "FTDNatPolicy", "name": "mcp-nat", "id": "n1"},
                    "targets": [{"id": FTD3, "type": "Device", "name": "mcp-ftd3"}],
                },
            ]
        )
    )
    devs = [device(FTD1, "mcp-ftd1"), device(FTD2, "mcp-ftd2"), device(FTD3, "mcp-ftd3")]
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items(devs))
    for d in devs:
        fmc.get(f"{CFG}/devices/devicerecords/{d['id']}").mock(return_value=httpx.Response(200, json=d))
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([]))


# --- matching --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "feature"),
    [
        ("Eigrp_Configure", "EIGRP"),
        ("Eigrp_Interface_Configure", "EIGRP"),
        ("Policy_Based_Routing", "Policy-based routing"),
        ("PBR-outside", "Policy-based routing"),
        ("mcp-ecmp-zone", "ECMP"),
        ("VXLANConfigure", "VXLAN"),
        ("vtep_source", "VXLAN"),
        ("Conn_Timeouts", "Connection timeouts"),
        ("Netflow_Add_Destination", "NetFlow"),
        ("ospfV3Setup", "OSPF"),
        ("Default_DNS_Configure", "DNS"),
    ],
)
def test_names_of_native_features_are_flagged(name: str, feature: str) -> None:
    assert feature in [n.feature for n in native_matches(name)]


@pytest.mark.parametrize("name", ["Default_Inspection_Protocol_Disable", "WCCP_Redirect", "mcp-custom-cli"])
def test_names_without_a_native_feature_are_not(name: str) -> None:
    assert native_matches(name) == []
    assert classify(name)["native"] is None


def test_classify_names_the_tool_and_gui() -> None:
    row = classify("ECMP_Configure")
    assert row["native"][0]["tool"] == "fmc_configure_ecmp_zone"
    assert "FlexConfig Object > 'ECMP_Configure'" in row["gui"]


def test_object_names_reads_prepend_then_append_and_none_when_absent() -> None:
    assert object_names({"name": "x", "id": "1"}) is None
    rec = {
        "prependFlexConfigs": [{"name": "Eigrp_Configure", "type": "FlexConfigObject"}],
        "appendFlexConfigs": [{"name": "Netflow_Set_Parameters"}],
    }
    assert object_names(rec) == [
        {"name": "Eigrp_Configure", "position": "prepend"},
        {"name": "Netflow_Set_Parameters", "position": "append"},
    ]


# --- fmc_flexconfig_review --------------------------------------------------------------------------


async def test_review_of_a_policy_without_objects_in_rest_gives_the_gui_path(fmc: respx.MockRouter) -> None:
    mock(fmc)
    async with Client(server()) as c:
        out = await call(c, "fmc_flexconfig_review", {"policy": "mcp-flex-asa"})
    row = out["policies"][0]
    assert row["policy"] == "mcp-flex-asa"
    assert row["devices"] == ["mcp-ftd1", "mcp-ftd2"]
    assert row["objects"] == [] and row["objects_source"] == "not in REST"
    assert "Devices > FlexConfig > edit 'mcp-flex-asa'" in row["gui"]
    assert "objects=[...]" in out["summary"]
    assert any("does not return a FlexConfig policy's objects" in n for n in out["notes"])


async def test_review_classifies_object_names_from_the_gui(fmc: respx.MockRouter) -> None:
    mock(fmc)
    async with Client(server()) as c:
        out = await call(
            c,
            "fmc_flexconfig_review",
            {"device": "mcp-ftd2", "objects": ["Eigrp_Configure", "Default_Inspection_Protocol_Disable"]},
        )
    assert out["device"] == "mcp-ftd2"
    row = out["policies"][0]
    assert row["objects_source"] == "objects argument"
    assert [o["object"] for o in row["objects"]] == ["Eigrp_Configure", "Default_Inspection_Protocol_Disable"]
    assert row["objects"][0]["native"][0]["feature"] == "EIGRP"
    assert row["objects"][1]["native"] is None
    assert row["native_candidates"] == 1
    assert "fmc_migrate_flexconfig" in out["summary"]


async def test_review_reads_objects_from_the_record_when_fmc_includes_them(fmc: respx.MockRouter) -> None:
    rec = {
        "type": "FlexConfigPolicy",
        "id": POL,
        "name": "mcp-flex-asa",
        "description": "EIGRP to the core",
        "prependFlexConfigs": [{"name": "mcp-custom-cli"}],
        "appendFlexConfigs": [{"name": "Policy_Based_Routing"}],
    }
    mock(fmc, record=rec)
    async with Client(server()) as c:
        out = await call(c, "fmc_flexconfig_review", {})
    row = out["policies"][0]
    assert row["objects_source"] == "policy record"
    assert [(o["object"], o.get("position")) for o in row["objects"]] == [
        ("mcp-custom-cli", "prepend"),
        ("Policy_Based_Routing", "append"),
    ]
    assert row["description_mentions"] == ["EIGRP"]
    assert "gui" not in row


async def test_review_of_a_policy_with_no_native_matches(fmc: respx.MockRouter) -> None:
    rec = {"type": "FlexConfigPolicy", "id": POL, "name": "mcp-flex-asa", "appendFlexConfigs": []}
    second = {
        "name": "mcp-flex-inspect",
        "appendFlexConfigs": [{"name": "Default_Inspection_Protocol_Disable"}],
    }
    mock(fmc, record=rec, second=second)
    async with Client(server()) as c:
        out = await call(c, "fmc_flexconfig_review", {})
    assert [r["policy"] for r in out["policies"]] == ["mcp-flex-asa", "mcp-flex-inspect"]
    assert out["policies"][1]["devices"] is None  # not assigned
    assert all(r["native_candidates"] == 0 for r in out["policies"])
    assert "No FlexConfig object name matches a natively supported feature" in out["summary"]


async def test_review_of_a_device_without_flexconfig(fmc: respx.MockRouter) -> None:
    mock(fmc)
    async with Client(server()) as c:
        out = await call(c, "fmc_flexconfig_review", {"device": "mcp-ftd3"})
    assert out["policies"] == []
    assert "No FlexConfig policy is assigned to 'mcp-ftd3'" in out["summary"]


# --- fmc_migrate_flexconfig -------------------------------------------------------------------------


async def test_migrate_previews_then_posts_and_follows_the_task(fmc: respx.MockRouter) -> None:
    mock(fmc)
    post = fmc.post(f"{CFG}/policy/flexconfigpolicies/{POL}/migrate").mock(
        return_value=httpx.Response(
            202,
            json={"type": "FlexConfigMigration", "metadata": {"task": {"id": TASK, "name": "FlexConfig"}}},
        )
    )
    task = fmc.get(f"{CFG}/job/taskstatuses/{TASK}").mock(
        return_value=httpx.Response(200, json={"id": TASK, "type": "TaskStatus", "status": "SUCCESS"})
    )
    args = {"policy": "mcp-flex-asa", "devices": ["mcp-ftd1"]}
    async with Client(server()) as c:
        preview = await call(c, "fmc_migrate_flexconfig", args)
        assert preview["status"] == "preview", preview
        assert preview["blast_radius"] == 1
        body = preview["preview"]["body"]
        assert body == {
            "type": "FlexConfigMigration",
            "targetDeviceList": [{"id": FTD1, "type": "Device", "name": "mcp-ftd1"}],
        }
        assert "fmc_device_snapshot(devices=['mcp-ftd1'])" in preview["preview"]["before"]
        assert any("does not return" in w for w in preview["preview"]["warnings"])
        assert any("Nothing reaches a device until fmc_deploy" in s for s in preview["side_effects"])
        assert not post.called
        done = await call(c, "fmc_migrate_flexconfig", {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied", done
    assert json.loads(post.calls.last.request.content) == body
    assert done["result"]["task"]["status"] == "SUCCESS" and task.called
    assert "fmc_pending_changes" in done["result"]["next"]


async def test_migrate_defaults_to_every_assigned_device(fmc: respx.MockRouter) -> None:
    mock(fmc)
    fmc.post(f"{CFG}/policy/flexconfigpolicies/{POL}/migrate").mock(
        return_value=httpx.Response(202, json={"id": TASK, "type": "TaskStatus", "status": "PENDING"})
    )
    async with Client(server()) as c:
        preview = await call(c, "fmc_migrate_flexconfig", {"policy": POL, "wait": False})
        assert [t["name"] for t in preview["preview"]["body"]["targetDeviceList"]] == ["mcp-ftd1", "mcp-ftd2"]
        done = await call(
            c, "fmc_migrate_flexconfig", {"policy": POL, "wait": False, "confirm": preview["confirm"]}
        )
    assert done["result"]["task_id"] == TASK


async def test_migrate_blocks_a_device_not_on_the_policy(fmc: respx.MockRouter) -> None:
    mock(fmc)
    post = fmc.post(f"{CFG}/policy/flexconfigpolicies/{POL}/migrate")
    async with Client(server()) as c:
        preview = await call(c, "fmc_migrate_flexconfig", {"policy": "mcp-flex-asa", "devices": ["mcp-ftd3"]})
    assert preview["status"] == "blocked"
    assert any("'mcp-ftd3' is not assigned" in b for b in preview["blockers"])
    assert not post.called


async def test_migrate_warns_when_no_object_matches_a_native_feature(fmc: respx.MockRouter) -> None:
    rec = {
        "type": "FlexConfigPolicy",
        "id": POL,
        "name": "mcp-flex-asa",
        "appendFlexConfigs": [{"name": "Default_Inspection_Protocol_Disable"}],
    }
    mock(fmc, record=rec)
    async with Client(server()) as c:
        preview = await call(c, "fmc_migrate_flexconfig", {"policy": "mcp-flex-asa"})
    assert preview["status"] == "preview"
    assert preview["preview"]["objects"][0]["native"] is None
    assert any("FMC may find nothing to migrate" in w for w in preview["preview"]["warnings"])


async def test_migrate_is_dangerous_tier_and_review_is_read(fmc: respx.MockRouter) -> None:
    async with Client(server(dangerous=False)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "fmc_migrate_flexconfig" not in names
    assert "fmc_flexconfig_review" in names
