"""F43: file/malware policies, file rules, file policy on access rules, network analysis policies.

File categories, file types and the network analysis policies are recorded from FMC 10.0.1
(tests/fixtures/filecategories.json, filetypes.json, networkanalysispolicies.json). No file policy existed
on the lab FMC to record, so the file policy and file rule shapes follow FMC 10.0.1's spec examples."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server

from .conftest import ACP_ID, CFG, fixture, items, make_settings

GLOBAL = {"name": "Global", "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f", "type": "Domain"}
FP = {
    "type": "FilePolicy",
    "id": "00000000-0000-0ed3-0000-021474900001",
    "name": "mcp-fw-file",
    "description": "block executables",
    "archiveDepth": 2,
    "archiveDepthAction": False,
    "blockEncryptedArchives": False,
    "cleanList": True,
    "customDetectionList": True,
    "firstTimeFileAnalysis": True,
    "inspectArchives": False,
    "metadata": {"readOnly": {"state": False}, "domain": GLOBAL},
}
EXE_BLOCK = {
    "id": "fr1",
    "type": "FileRule",
    "action": "BLOCK_WITH_RESET",
    "protocol": "HTTP",
    "direction": "DOWNLOAD",
    "fileTypes": [{"id": "1", "type": "FileType", "name": "MSEXE"}],
}
MALWARE = {
    "id": "fr2",
    "type": "FileRule",
    "action": "DETECT_MALWARE",
    "protocol": "ANY",
    "direction": "ANY",
    "fileCategories": [{"id": "4", "type": "FileCategory", "name": "Executables"}],
    "storeFiles": ["MALWARE"],
}
FILE_RULES = f"{CFG}/policy/filepolicies/{FP['id']}/filerules"


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, **kw))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def preview_apply(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        assert preview["status"] == "preview", preview
        done = await run(c, name, {**args, "confirm": preview["confirm"]})
        return preview, done


@pytest.fixture
def files(fmc: respx.MockRouter) -> respx.MockRouter:
    fmc.get(f"{CFG}/policy/filepolicies").mock(return_value=items([FP]))
    fmc.get(f"{CFG}/object/filetypes").mock(return_value=httpx.Response(200, json=fixture("filetypes")))
    fmc.get(f"{CFG}/object/filecategories").mock(
        return_value=httpx.Response(200, json=fixture("filecategories"))
    )
    return fmc


# --- read ------------------------------------------------------------------------------------------


async def test_get_file_policy_shows_settings_and_rules(files: respx.MockRouter) -> None:
    files.get(FILE_RULES).mock(return_value=items([EXE_BLOCK, MALWARE]))
    async with Client(server()) as c:
        out = await run(c, "fmc_get_file_policy", {"policy": "mcp-fw-file", "response_format": "json"})
    assert out["settings"]["inspect_archives"] is False and out["settings"]["first_time_file_analysis"]
    first, second = out["rules"]
    assert first == {
        "index": 1,
        "action": "block files (reset)",
        "fmc_action": "BLOCK_WITH_RESET",
        "protocol": "HTTP",
        "direction": "DOWNLOAD",
        "file_types": ["MSEXE"],
        "id": "fr1",
    }
    assert second["action"] == "malware cloud lookup" and second["file_categories"] == ["Executables"]
    assert second["store_files"] == ["MALWARE"]


async def test_list_file_policies(files: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_get_file_policy", {"response_format": "json"})
    row = out["results"][0]
    assert row["name"] == "mcp-fw-file" and row["inspect_archives"] is False and row["id"] == FP["id"]


async def test_catalog_lists_categories_with_types(files: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_get_file_policy", {"catalog": True, "response_format": "json"})
    exe = next(r for r in out["results"] if r["category"] == "Executables")
    assert {"MSEXE", "EICAR", "ELF"} <= set(exe["file_types"]) and len(out["results"]) == 10


# --- file policy and rules -----------------------------------------------------------------------


async def test_create_file_policy_sends_only_given_settings(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/filepolicies").mock(return_value=items([]))
    post = fmc.post(f"{CFG}/policy/filepolicies").mock(return_value=httpx.Response(201, json=FP))
    args = {"name": "mcp-fw-file", "inspect_archives": True, "archive_depth": 2}
    preview, _ = await preview_apply("fmc_create_file_policy", args)
    body = {"name": "mcp-fw-file", "type": "FilePolicy", "inspectArchives": True, "archiveDepth": 2}
    assert preview["preview"]["body"] == body
    assert json.loads(post.calls.last.request.content) == body


async def test_create_file_policy_checks_name_and_archive_settings(files: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_create_file_policy", {"name": "MCP-FW-FILE"})
        assert out["status"] == "blocked" and "already exists" in out["blockers"][0]
        with pytest.raises(ToolError, match="inspect_archives"):
            await run(c, "fmc_create_file_policy", {"name": "x", "block_encrypted_archives": True})


async def test_block_exe_downloads_over_http(files: respx.MockRouter) -> None:
    files.get(FILE_RULES).mock(return_value=items([MALWARE]))
    post = files.post(FILE_RULES).mock(return_value=httpx.Response(201, json={**EXE_BLOCK, "id": "new"}))
    args = {
        "policy": "mcp-fw-file",
        "action": "BLOCK",
        "file_types": ["msexe"],
        "protocol": "HTTP",
        "direction": "DOWNLOAD",
    }
    preview, _ = await preview_apply("fmc_create_file_rule", args)
    assert preview["preview"]["rule"]["action"] == "block files (reset)"
    assert preview["preview"]["rules_now"] == 1
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "type": "FileRule",
        "action": "BLOCK_WITH_RESET",
        "protocol": "HTTP",
        "direction": "DOWNLOAD",
        "fileTypes": [{"id": "1", "type": "FileType", "name": "MSEXE"}],
    }


@pytest.mark.parametrize(
    ("action", "reset", "fmc_action"),
    [
        ("DETECT", True, "DETECT"),
        ("BLOCK", False, "BLOCK"),
        ("MALWARE_CLOUD_LOOKUP", True, "DETECT_MALWARE"),
        ("BLOCK_MALWARE", True, "BLOCK_MALWARE_WITH_RESET"),
        ("BLOCK_MALWARE", False, "BLOCK_MALWARE"),
    ],
)
async def test_action_mapping(files: respx.MockRouter, action: str, reset: bool, fmc_action: str) -> None:
    files.get(FILE_RULES).mock(return_value=items([]))
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_create_file_rule",
            {"policy": "mcp-fw-file", "action": action, "reset": reset, "file_categories": ["Executables"]},
        )
    assert out["preview"]["body"]["action"] == fmc_action
    assert out["preview"]["body"]["fileCategories"] == [
        {"id": "4", "type": "FileCategory", "name": "Executables"}
    ]
    malware = action in ("MALWARE_CLOUD_LOOKUP", "BLOCK_MALWARE")
    assert any("MALWARE_DEFENSE" in s for s in out["side_effects"]) is malware


async def test_malware_options_and_unknown_types(files: respx.MockRouter) -> None:
    files.get(FILE_RULES).mock(return_value=items([]))
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="Did you mean: MSEXE"):
            await run(
                c,
                "fmc_create_file_rule",
                {"policy": "mcp-fw-file", "action": "BLOCK", "file_types": ["MSEX"]},
            )
        with pytest.raises(ToolError, match="only apply to"):
            await run(
                c,
                "fmc_create_file_rule",
                {
                    "policy": "mcp-fw-file",
                    "action": "DETECT",
                    "file_types": ["PDF"],
                    "store_files": ["MALWARE"],
                },
            )
        with pytest.raises(ToolError, match="file_types and/or file_categories"):
            await run(c, "fmc_create_file_rule", {"policy": "mcp-fw-file", "action": "DETECT"})
        out = await run(
            c,
            "fmc_create_file_rule",
            {
                "policy": "mcp-fw-file",
                "action": "BLOCK_MALWARE",
                "file_types": ["EICAR", "MSEXE"],
                "store_files": ["MALWARE", "MALWARE"],
                "analysis": ["spero"],
            },
        )
    body = out["preview"]["body"]
    assert [t["name"] for t in body["fileTypes"]] == ["EICAR", "MSEXE"]
    assert body["storeFiles"] == ["MALWARE"] and body["analysis"] == ["spero"]


async def test_protocol_direction_and_duplicate_blockers(files: respx.MockRouter) -> None:
    files.get(FILE_RULES).mock(return_value=items([EXE_BLOCK]))
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_create_file_rule",
            {
                "policy": "mcp-fw-file",
                "action": "DETECT",
                "file_types": ["PDF"],
                "protocol": "POP3",
                "direction": "UPLOAD",
            },
        )
        assert out["status"] == "blocked" and "only for downloads" in out["blockers"][0]
        out = await run(
            c,
            "fmc_create_file_rule",
            {
                "policy": "mcp-fw-file",
                "action": "BLOCK",
                "file_types": ["MSEXE"],
                "protocol": "HTTP",
                "direction": "DOWNLOAD",
            },
        )
        assert out["status"] == "blocked" and "Rule 1" in out["blockers"][0]


async def test_delete_file_rule_by_index(files: respx.MockRouter) -> None:
    files.get(FILE_RULES).mock(return_value=items([EXE_BLOCK, MALWARE]))
    delete = files.delete(f"{FILE_RULES}/fr2").mock(return_value=httpx.Response(200, json=MALWARE))
    preview, _ = await preview_apply("fmc_delete_file_rule", {"policy": "mcp-fw-file", "rule": "2"})
    assert preview["preview"]["rule"]["index"] == 2 and "malware cloud lookup" in preview["action"]
    assert delete.call_count == 1
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="No file rule"):
            await run(c, "fmc_delete_file_rule", {"policy": "mcp-fw-file", "rule": "3"})


async def test_delete_policy_counts_file_rules(files: respx.MockRouter) -> None:
    files.get(FILE_RULES).mock(return_value=items([EXE_BLOCK, MALWARE]))
    files.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    async with Client(server(mcp_enable_dangerous=True)) as c:
        out = await run(c, "fmc_delete_policy", {"kind": "file", "policy": "mcp-fw-file"})
    assert out["status"] == "preview" and out["preview"]["rules"] == 2


# --- file policy on access rules -------------------------------------------------------------------


async def test_create_access_rule_with_file_policy(lab: respx.MockRouter) -> None:
    lab.get(f"{CFG}/policy/filepolicies").mock(return_value=items([FP]))
    post = lab.post(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(201, json={"id": "new", "name": "web"})
    )
    preview, _ = await preview_apply(
        "fmc_create_access_rule",
        {"policy": "mcp-test-acp", "name": "web", "action": "ALLOW", "file_policy": "mcp-fw-file"},
    )
    assert preview["preview"]["rule"]["file_policy"] == "mcp-fw-file"
    assert "files" in preview["preview"]["rule"]["logging"]
    body = json.loads(post.calls.last.request.content)
    assert body["filePolicy"] == {"id": FP["id"], "type": "FilePolicy", "name": "mcp-fw-file"}
    assert body["logFiles"] is True
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="only be set on ALLOW"):
            await run(
                c,
                "fmc_create_access_rule",
                {"policy": "mcp-test-acp", "name": "b", "action": "BLOCK", "file_policy": "mcp-fw-file"},
            )


async def test_update_access_rule_adds_and_removes_file_policy(lab: respx.MockRouter) -> None:
    lab.get(f"{CFG}/policy/filepolicies").mock(return_value=items([FP]))
    data = fixture("accessrules")
    rule = next(r for r in data["items"] if r["name"] == "mcp-test-allow-web")
    put = lab.put(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules/{rule['id']}").mock(
        return_value=httpx.Response(200, json=rule)
    )
    preview, _ = await preview_apply(
        "fmc_update_access_rule",
        {"policy": "mcp-test-acp", "rule": "mcp-test-allow-web", "file_policy": "mcp-fw-file"},
    )
    assert preview["preview"]["changes"]["filePolicy"]["to"]["name"] == "mcp-fw-file"
    assert preview["preview"]["changes"]["logFiles"] == {"from": False, "to": True}
    body = json.loads(put.calls.last.request.content)
    assert body["filePolicy"]["id"] == FP["id"] and body["logFiles"] is True

    with_fp = {
        **rule,
        "filePolicy": {"id": FP["id"], "type": "FilePolicy", "name": "mcp-fw-file"},
        "logFiles": True,
    }
    lab.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=items([with_fp if r["id"] == rule["id"] else r for r in data["items"]])
    )
    preview, _ = await preview_apply(
        "fmc_update_access_rule", {"policy": "mcp-test-acp", "rule": "mcp-test-allow-web", "file_policy": ""}
    )
    assert preview["preview"]["changes"]["filePolicy"] == {"from": "mcp-fw-file", "to": None, "removed": True}
    body = json.loads(put.calls.last.request.content)
    assert "filePolicy" not in body and body["logFiles"] is False


# --- network analysis policies -------------------------------------------------------------------

NAPS = f"{CFG}/policy/networkanalysispolicies"
CUSTOM_NAP = {
    "name": "mcp-fw-nap",
    "id": "00000000-0000-0ed3-0000-004294972222",
    "type": "NetworkAnalysisPolicy",
    "basePolicy": {
        "name": "Balanced Security and Connectivity",
        "id": "db7dc865-16b5-5eab-8b5a-c85f3a61690b",
        "type": "NetworkAnalysisPolicy",
    },
    "inspectionMode": "DETECTION",
    "isSystemDefined": False,
    "metadata": {"domain": GLOBAL, "snortEngine": "SNORT3", "usage": {"accesspolicy": 0, "devices": 0}},
}


async def test_list_network_analysis_policies(fmc: respx.MockRouter) -> None:
    fmc.get(NAPS).mock(return_value=httpx.Response(200, json=fixture("networkanalysispolicies")))
    async with Client(server()) as c:
        out = await run(c, "fmc_get_network_analysis_policy", {"response_format": "json"})
    balanced = out["results"][0]
    assert balanced["name"] == "Balanced Security and Connectivity" and balanced["system_defined"] is True
    assert balanced["access_policies"] == 7 and balanced["devices"] == 14


async def test_system_nap_lists_access_policies_using_it(fmc: respx.MockRouter) -> None:
    fmc.get(NAPS).mock(return_value=httpx.Response(200, json=fixture("networkanalysispolicies")))
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_get_network_analysis_policy",
            {"policy": "balanced security and connectivity", "response_format": "json"},
        )
    assert "mcp-test-identity-acp" in out["used_by_access_policies"] and out["snort_engine"] == "SNORT3"
    assert "inspector_overrides" not in out


async def test_custom_nap_shows_overrides_and_how_to_link(fmc: respx.MockRouter) -> None:
    data = fixture("networkanalysispolicies")
    fmc.get(NAPS).mock(return_value=items([*data["items"], CUSTOM_NAP]))
    fmc.get(f"{NAPS}/{CUSTOM_NAP['id']}/inspectoroverrideconfigs").mock(
        return_value=items(
            [{"type": "InspectorOverrideConfig", "inspectorOverrideConfig": {"http_inspect": {}}}]
        )
    )
    async with Client(server()) as c:
        out = await run(
            c, "fmc_get_network_analysis_policy", {"policy": "mcp-fw-nap", "response_format": "json"}
        )
    assert (
        out["base_policy"] == "Balanced Security and Connectivity" and out["inspection_mode"] == "DETECTION"
    )
    assert out["inspector_overrides"] == ["http_inspect"] and "Advanced" in out["note"]


async def test_create_network_analysis_policy(fmc: respx.MockRouter) -> None:
    fmc.get(NAPS).mock(return_value=httpx.Response(200, json=fixture("networkanalysispolicies")))
    post = fmc.post(NAPS).mock(return_value=httpx.Response(201, json=CUSTOM_NAP))
    preview, _ = await preview_apply(
        "fmc_create_network_analysis_policy", {"name": "mcp-fw-nap", "inspection_mode": "DETECTION"}
    )
    body = {
        "name": "mcp-fw-nap",
        "type": "NetworkAnalysisPolicy",
        "basePolicy": {"id": "db7dc865-16b5-5eab-8b5a-c85f3a61690b", "type": "NetworkAnalysisPolicy"},
        "inspectionMode": "DETECTION",
    }
    assert preview["preview"]["body"] == body and "REST API has no field" in preview["side_effects"][0]
    assert json.loads(post.calls.last.request.content) == body
    async with Client(server()) as c:
        out = await run(c, "fmc_create_network_analysis_policy", {"name": "Maximum Detection"})
    assert out["status"] == "blocked"
