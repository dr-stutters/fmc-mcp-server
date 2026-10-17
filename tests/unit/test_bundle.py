"""F44 policy bundles: export (replayed from tests/fixtures/bundle_acp.json, recorded with
scripts/capture_fixtures.py --bundle), stable ordering, and the diff planner."""

from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import yaml
from fastmcp import Client

from fmc_mcp._core import InvalidRequest
from fmc_mcp.server import create_server
from fmc_mcp.tools.bundle import access_rule, clean, diff_bundles, diff_rules, dump, parse_bundle

from .conftest import fixture, make_settings

RECORDED: dict[str, Any] = fixture("bundle_acp")
EXPORT = {"policy": "mcp-test-acp", "nat_policies": ["mcp-test-nat"]}


def replay(router: respx.MockRouter, responses: dict[str, Any]) -> dict[str, Any]:
    """Serve the recorded responses; swap state["data"] to serve others."""
    state = {"data": responses}
    for path in responses:
        router.get(path).mock(
            side_effect=lambda _req, p=path: httpx.Response(200, json=state["data"][p])  # type: ignore[misc]
        )
    return state


def scrambled(data: Any) -> Any:
    """The same data with every list of items and every dict's key order reversed (FMC promises neither)."""
    if isinstance(data, dict):
        return {k: scrambled(data[k]) for k in reversed(list(data))}
    if isinstance(data, list):
        return [scrambled(v) for v in reversed(data)]
    return data


def without_stamp(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("exported_at:"))


async def export(**kw: Any) -> dict[str, Any]:
    async with Client(create_server(make_settings(**kw))) as c:
        out = (await c.call_tool("fmc_export_policy_bundle", EXPORT)).structured_content
    assert out is not None
    return out


async def test_export_round_trip(fmc: respx.MockRouter) -> None:
    replay(fmc, RECORDED)
    out = await export()
    text = out["bundle"]
    bundle = parse_bundle(text, None)
    assert dump(bundle) == text  # parse -> serialise gives the same bytes
    assert bundle["schema"] == 1 and bundle["meta"]["policy"] == "mcp-test-acp"
    assert bundle["meta"]["domain"] == "Global" and bundle["meta"]["fmc_version"].startswith("10.0.1")
    assert out["digest"] == bundle["meta"]["digest"] and "file" not in out
    acp = bundle["access_policy"]
    assert acp["default_action"]["action"] == "BLOCK"
    assert acp["settings"]["prefilter_policy"] == "Default Prefilter Policy"
    assert [r["name"] for r in acp["rules"]][:3] == [
        "mcp-test-allow-web",
        "mcp-test-ssh-admin",
        "mcp-test-redundant",
    ]
    ssh = acp["rules"][1]
    assert ssh["src_zones"] == ["mcp-test-inside"] and ssh["dst_ports"] == ["tcp/22"]
    assert ssh["raw"]["variableSet"] == {"name": "Default-Set", "type": "VariableSet"}
    assert bundle["prefilter_policy"] == {"name": "Default Prefilter Policy", "system": True}
    nat = bundle["nat_policies"]["mcp-test-nat"]["rules"]
    assert [r["section"] for r in nat] == ["before_auto", "auto"]
    objects = bundle["objects"]
    group = objects["NetworkGroup"]["mcp-test-servers"]  # expanded: its members are bundled too
    assert {m["name"] for m in group["objects"]} == {"mcp-test-app-net", "mcp-test-web"}
    assert {"mcp-test-web", "mcp-test-db"} <= set(objects["Host"])
    assert set(objects["PortObjectGroup"]["mcp-test-web-ports"]["objects"][0]) == {"name", "type"}
    assert "mcp-test-tcp-8443" in objects["ProtocolPortObject"]  # a group member, not used directly
    assert list(bundle["security_zones"]) == ["mcp-test-inside"]
    for forbidden in ("id:", "links:", "metadata:", "refType"):
        assert forbidden not in text


async def test_export_is_stable_under_reordering(fmc: respx.MockRouter) -> None:
    state = replay(fmc, RECORDED)
    first = await export()
    state["data"] = scrambled(RECORDED)
    second = await export()
    assert second["digest"] == first["digest"]
    assert without_stamp(second["bundle"]) == without_stamp(first["bundle"])


async def test_bundle_dir_file_and_diff_against_live(fmc: respx.MockRouter, tmp_path: Path) -> None:
    replay(fmc, RECORDED)
    out = await export(bundle_dir=tmp_path)
    path = Path(out["file"])
    assert path.parent == tmp_path and path.read_text() == out["bundle"]  # noqa: ASYNC240
    async with Client(create_server(make_settings(bundle_dir=tmp_path))) as c:
        same = (await c.call_tool("fmc_diff_policy_bundle", {"a": path.name})).structured_content
    assert same["identical"] is True and same["b"]["exported_at"] == "live", same
    assert same["a"]["digest"] == same["b"]["digest"]
    with pytest.raises(InvalidRequest):
        parse_bundle("../../etc/passwd.yaml", tmp_path)  # only plain names inside the directory


async def test_diff_one_changed_rule(fmc: respx.MockRouter) -> None:
    replay(fmc, RECORDED)
    a = (await export())["bundle"]
    changed = yaml.safe_load(a)
    rule = changed["access_policy"]["rules"][1]
    rule["dst_ports"] = ["tcp/2222"]
    rule["enabled"] = False
    b = dump(changed)
    async with Client(create_server(make_settings())) as c:
        out = (await c.call_tool("fmc_diff_policy_bundle", {"a": a, "b": b})).structured_content
    assert out["identical"] is False and out["total"] == 1, out
    assert out["summary"] == {"access_policy.rules": {"changed": 1}}
    (ch,) = out["changes"]
    assert ch["key"] == "mcp-test-ssh-admin" and ch["op"] == "changed" and "position" not in ch
    assert ch["fields"] == {
        "dst_ports": {"from": ["tcp/22"], "to": ["tcp/2222"]},
        "enabled": {"from": True, "to": False},
    }


def _rules(*names: str) -> list[dict[str, Any]]:
    return [{"name": n, "action": "ALLOW"} for n in names]


def test_diff_rules_added_removed_moved() -> None:
    b = [*_rules("b", "c", "a"), {"name": "e", "action": "BLOCK"}]
    out = diff_rules("r", _rules("a", "b", "c", "d"), b)
    by_key = {c["key"]: c for c in out}
    assert by_key["a"]["op"] == "moved" and by_key["a"]["position"] == {"from": 1, "to": 3}
    assert by_key["a"]["after"] == "c"
    assert by_key["d"]["op"] == "removed" and by_key["d"]["position"] == 4
    assert by_key["e"] == {
        "section": "r",
        "op": "added",
        "key": "e",
        "position": 4,
        "after": "a",
        "value": {"name": "e", "action": "BLOCK"},
    }
    assert "b" not in by_key and "c" not in by_key


def test_diff_rules_rename_and_unnamed_fall_back_to_position() -> None:
    renamed = diff_rules("r", _rules("a", "old"), _rules("a", "new"))
    assert renamed == [
        {"section": "r", "op": "changed", "key": "new", "fields": {"name": {"from": "old", "to": "new"}}}
    ]
    nat = diff_rules("n", [{"natType": "STATIC"}, {"natType": "DYNAMIC"}], [{"natType": "STATIC"}])
    assert nat == [{"section": "n", "op": "removed", "key": "#2", "position": 2}]


def test_diff_sections_and_objects() -> None:
    a = {
        "schema": 1,
        "objects": {"Host": {"h1": {"value": "10.0.0.1"}, "h2": {"value": "10.0.0.2"}}},
        "nat_policies": {"n": {"rules": []}},
    }
    b = {
        "schema": 1,
        "objects": {"Host": {"h1": {"value": "10.0.0.9"}, "h3": {"value": "10.0.0.3"}}},
        "security_zones": {"z": {"interfaceMode": "ROUTED"}},
    }
    out = diff_bundles(a, b)
    assert [(c["section"], c["op"], c["key"]) for c in out] == [
        ("nat_policies.n", "removed", "n"),
        ("security_zones", "added", "z"),
        ("objects.Host", "changed", "h1"),
        ("objects.Host", "removed", "h2"),
        ("objects.Host", "added", "h3"),
    ]


def test_access_rule_keeps_what_the_row_format_cannot_carry() -> None:
    r = {
        "id": "r1",
        "name": "web",
        "action": "ALLOW",
        "enabled": True,
        "urls": {
            "objects": [{"name": "u", "id": "u1", "type": "Url"}],
            "urlCategoriesWithReputation": [
                {"category": {"name": "Gambling", "id": "c"}, "reputation": "ANY"}
            ],
        },
        "users": {
            "objects": [{"name": "bob", "id": "x", "type": "RealmUser", "realm": {"name": "ad", "id": "r"}}]
        },
        "filePolicy": {"name": "malware", "id": "f", "type": "FilePolicy"},
        "metadata": {"ruleIndex": 3, "section": "Mandatory"},
    }
    row = access_rule(r)
    assert row["name"] == "web" and row["section"] == "mandatory" and "index" not in row
    assert row["urls"] == ["u"] and "users" not in row  # users live in raw, with their realm
    assert row["raw"]["urls"] == {
        "urlCategoriesWithReputation": [{"category": {"name": "Gambling"}, "reputation": "ANY"}]
    }
    assert row["raw"]["users"]["objects"][0] == {"name": "bob", "realm": {"name": "ad"}, "type": "RealmUser"}
    assert row["raw"]["filePolicy"] == {"name": "malware", "type": "FilePolicy"}
    assert row["not_importable"] == ["URL categories", "file policy", "users"]


def test_clean_strips_identity_and_sorts_members() -> None:
    group = {
        "id": "g",
        "links": {"self": "x"},
        "categories": {"refType": "list", "type": "C"},
        "objects": [
            {"name": "b", "id": "2", "type": "Host", "overridable": False},
            {"name": "a", "id": "1", "type": "Host"},
        ],
        "description": "",
    }
    assert clean(group) == {"objects": [{"name": "a", "type": "Host"}, {"name": "b", "type": "Host"}]}


def test_parse_bundle_rejects_other_documents() -> None:
    with pytest.raises(InvalidRequest, match="schema"):
        parse_bundle("a: 1\n", None)
    with pytest.raises(InvalidRequest, match="isn't supported"):
        parse_bundle("schema: 2\n", None)
