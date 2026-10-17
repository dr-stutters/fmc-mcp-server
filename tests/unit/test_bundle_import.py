"""F45 policy bundle import: planning and applying against an in-memory FMC that records every write."""

import copy
import itertools
import json
from typing import Any

import httpx
import pytest
import respx
import yaml
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.bundle_import import BundleImportError, group_levels

from .conftest import CFG, items, make_settings

BUNDLE: dict[str, Any] = {
    "schema": 1,
    "meta": {"policy": "src-acp", "domain": "Global"},
    "access_policy": {
        "name": "src-acp",
        "default_action": {"action": "BLOCK", "logBegin": True, "sendEventsToFMC": True},
        "settings": {"prefilter_policy": "Default Prefilter Policy"},
        "categories": ["web"],
        "rules": [
            {
                "name": "allow-web",
                "section": "default",
                "action": "ALLOW",
                "enabled": True,
                "category": "web",
                "src_zones": ["inside"],
                "dst_networks": ["web-servers"],
                "dst_ports": ["tcp/443"],
                "log": "end",
                "raw": {"sendEventsToFMC": True},
            },
            {
                "name": "block-bad",
                "section": "default",
                "action": "BLOCK",
                "enabled": True,
                "src_networks": ["10.66.0.0/16"],
                "log": "begin",
                "raw": {"sendEventsToFMC": True},
            },
        ],
    },
    "prefilter_policy": {"name": "Default Prefilter Policy", "system": True},
    "objects": {
        "Host": {"web1": {"value": "10.1.1.10"}, "web2": {"value": "10.1.1.11"}},
        "NetworkGroup": {
            "web-core": {"objects": [{"name": "web1", "type": "Host"}]},
            "web-servers": {
                "objects": [{"name": "web-core", "type": "NetworkGroup"}, {"name": "web2", "type": "Host"}]
            },
        },
    },
    "security_zones": {"inside": {"interfaceMode": "ROUTED"}},
}


class FakeFmc:
    """Collections by path; POST/PUT/DELETE change them and are logged as (method, path, params, body)."""

    def __init__(self, router: respx.MockRouter, seed: dict[str, list[dict[str, Any]]]) -> None:
        self.store = {k: [dict(o) for o in v] for k, v in seed.items()}
        self.writes: list[tuple[str, str, dict[str, str], Any]] = []
        self._ids = itertools.count(1)
        router.route(path__startswith=f"{CFG}/").mock(side_effect=self.handle)

    def _new_id(self) -> str:
        return f"00000000-0000-0000-0000-{next(self._ids):012d}"

    def _find(self, path: str) -> tuple[str, dict[str, Any] | None]:
        coll, _, oid = path.rpartition("/")
        for o in self.store.get(coll, []):
            if o.get("id") == oid:
                return coll, o
        return path, None

    def _renumber(self, coll: str) -> None:
        if coll.endswith("accessrules"):
            for i, r in enumerate(self.store[coll], 1):
                r.setdefault("metadata", {})["ruleIndex"] = i

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix(f"{CFG}/")
        params = dict(request.url.params)
        if request.method == "GET":
            if path in self.store:
                return items(self.store[path])
            coll, obj = self._find(path)
            if obj is not None:
                return httpx.Response(200, json=obj)
            return items([])
        body = json.loads(request.content) if request.content else None
        params.pop("expanded", None)
        self.writes.append((request.method, path, params, copy.deepcopy(body)))
        if request.method == "POST":
            new = [dict(b, id=self._new_id()) for b in (body if isinstance(body, list) else [body])]
            coll = self.store.setdefault(path, [])
            at = int(params["insertBefore"]) - 1 if "insertBefore" in params else len(coll)
            if path.endswith("accessrules"):  # FMC files the rule where it was inserted
                near = (coll[at] if at < len(coll) else None) if "insertBefore" in params else None
                meta = dict((near or {}).get("metadata") or {})
                if "category" in params:
                    meta = {"section": "Default", "category": params["category"]}
                elif "section" in params:
                    meta = {"section": params["section"].title(), "category": "--Undefined--"}
                for o in new:
                    o["metadata"] = dict(meta)
            for i, o in enumerate(new):
                coll.insert(at + i, o)
            self._renumber(path)
            return httpx.Response(201, json={"items": new} if isinstance(body, list) else new[0])
        coll, obj = self._find(path)
        if obj is None:
            return httpx.Response(404, json={"error": {"messages": [{"description": "not found"}]}})
        if request.method == "PUT":
            meta = obj.get("metadata")
            obj.clear()
            obj.update(body)
            if meta is not None:
                obj["metadata"] = meta
            return httpx.Response(200, json=obj)
        self.store[coll].remove(obj)
        self._renumber(coll)
        return httpx.Response(200, json=obj)

    def posts(self, suffix: str) -> list[tuple[dict[str, str], Any]]:
        return [(p, b) for m, path, p, b in self.writes if m == "POST" and path.endswith(suffix)]


BASE_SEED: dict[str, list[dict[str, Any]]] = {
    "policy/prefilterpolicies": [
        {
            "id": "pre-1",
            "name": "Default Prefilter Policy",
            "type": "PrefilterPolicy",
            "isSystemDefined": True,
        }
    ],
    "policy/accesspolicies": [],
}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def plan(bundle: dict[str, Any], **kw: Any) -> dict[str, Any]:
    async with Client(server()) as c:
        out = await c.call_tool("fmc_plan_policy_bundle_import", {"bundle": yaml.safe_dump(bundle), **kw})
    assert out.structured_content is not None
    return out.structured_content


async def import_(bundle: dict[str, Any], **kw: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    args = {"bundle": yaml.safe_dump(bundle), **kw}
    async with Client(server()) as c:
        preview = (await c.call_tool("fmc_import_policy_bundle", args)).structured_content
        assert preview is not None and preview.get("confirm"), preview
        done = (
            await c.call_tool("fmc_import_policy_bundle", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert done is not None
    return preview, done


async def test_plan_into_empty_target(fmc: respx.MockRouter) -> None:
    FakeFmc(fmc, BASE_SEED)
    out = await plan(BUNDLE, policy="dst-acp")
    assert out["ready"] is True and "blockers" not in out
    assert out["objects"] == {"create": 4}
    assert out["zones_to_create"] == ["SecurityZone inside"]
    assert {(p["kind"], p["op"]) for p in out["policies"]} == {("prefilter", "reuse"), ("access", "create")}
    assert out["access_rules"] == {"added": 2}
    assert out["changes"] == 4 + 1 + 1 + 2


async def test_apply_into_empty_target_creates_in_dependency_order(fmc: respx.MockRouter) -> None:
    fake = FakeFmc(fmc, BASE_SEED)
    _, done = await import_(BUNDLE, policy="dst-acp")
    order = [(m, path.rsplit("/", 1)[-1]) for m, path, _, _ in fake.writes]
    assert order[:5] == [
        ("POST", "hosts"),
        ("POST", "networkgroups"),  # web-core first: web-servers contains it
        ("POST", "networkgroups"),
        ("POST", "securityzones"),
        ("POST", "accesspolicies"),
    ]
    groups = [b for _, b in fake.posts("networkgroups")]
    assert [g[0]["name"] for g in groups] == ["web-core", "web-servers"]
    members = {m["name"]: m["id"] for m in groups[1][0]["objects"]}
    created = {o["name"]: o["id"] for o in fake.store["object/hosts"] + fake.store["object/networkgroups"]}
    assert members == {"web-core": created["web-core"], "web2": created["web2"]}
    (policy_body,) = [b for _, b in fake.posts("policy/accesspolicies")]
    assert policy_body["name"] == "dst-acp" and policy_body["defaultAction"]["action"] == "BLOCK"
    assert [b["name"] for _, b in fake.posts("/categories")] == ["web"]
    put = [b for m, path, _, b in fake.writes if m == "PUT" and "accesspolicies" in path]
    assert put[0]["prefilterPolicySetting"]["id"] == "pre-1"
    rules = fake.posts("/accessrules")
    assert [(p.get("category"), p.get("section")) for p, _ in rules] == [("web", None), (None, "default")]
    web = rules[0][1]
    assert web["destinationNetworks"]["objects"][0]["id"] == created["web-servers"]
    assert web["sourceZones"]["objects"][0]["name"] == "inside"
    assert web["logEnd"] is True
    bad = rules[1][1]
    assert bad["logBegin"] is True and bad["logEnd"] is False  # block rules log at the start
    assert done["result"]["applied"] == 10 and len(fake.writes) == 9  # both hosts in one bulk POST


async def test_plan_blocks_conflicts_and_missing_prerequisites(fmc: respx.MockRouter) -> None:
    bundle = copy.deepcopy(BUNDLE)
    bundle["access_policy"]["rules"][0]["intrusion_policy"] = "custom-ips"
    bundle["intrusion_policies"] = {
        "custom-ips": {"base_policy": {"name": "Balanced", "type": "IntrusionPolicy"}}
    }
    bundle["time_ranges"] = {"xmas": {"effectiveEndDateTime": "2024-12-31T23:59"}}
    FakeFmc(
        fmc,
        {**BASE_SEED, "object/hosts": [{"id": "h1", "name": "web1", "type": "Host", "value": "10.9.9.9"}]},
    )
    out = await plan(bundle)
    assert out["ready"] is False
    text = " | ".join(out["blockers"])
    assert "Host 'web1' exists in the target with a different value (value)" in text
    assert "Time range 'xmas'" in text
    assert "IntrusionPolicy 'custom-ips' (custom)" in text
    out = await plan(bundle, update_objects=True)
    assert out["objects_to_update"] == [
        {"object": "Host web1", "fields": {"value": {"from": "10.9.9.9", "to": "10.1.1.10"}}}
    ]
    assert not any("web1" in b for b in out["blockers"])


def existing_rule(name: str, index: int, port: str) -> dict[str, Any]:
    return {
        "id": f"rule-{name}",
        "name": name,
        "type": "AccessRule",
        "action": "ALLOW",
        "enabled": True,
        "logEnd": True,
        "sendEventsToFMC": True,
        "metadata": {"ruleIndex": index, "section": "Default", "category": "web"},
        "sourceZones": {"objects": [{"id": "z1", "name": "inside", "type": "SecurityZone"}]},
        "destinationNetworks": {"objects": [{"id": "g2", "name": "web-servers", "type": "NetworkGroup"}]},
        "destinationPorts": {"literals": [{"type": "PortLiteral", "protocol": "6", "port": port}]},
    }


def existing_seed() -> dict[str, list[dict[str, Any]]]:
    return {
        **BASE_SEED,
        "object/hosts": [
            {"id": "h1", "name": "web1", "type": "Host", "value": "10.1.1.10"},
            {"id": "h2", "name": "web2", "type": "Host", "value": "10.1.1.11"},
        ],
        "object/networkgroups": [
            {
                "id": "g1",
                "name": "web-core",
                "type": "NetworkGroup",
                "objects": [{"id": "h1", "name": "web1", "type": "Host"}],
            },
            {
                "id": "g2",
                "name": "web-servers",
                "type": "NetworkGroup",
                "objects": [
                    {"id": "g1", "name": "web-core", "type": "NetworkGroup"},
                    {"id": "h2", "name": "web2", "type": "Host"},
                ],
            },
        ],
        "object/securityzones": [
            {"id": "z1", "name": "inside", "type": "SecurityZone", "interfaceMode": "ROUTED"}
        ],
        "policy/accesspolicies": [
            {
                "id": "acp-1",
                "name": "src-acp",
                "type": "AccessPolicy",
                "defaultAction": {"id": "da-1", "action": "BLOCK", "logBegin": True, "sendEventsToFMC": True},
                "prefilterPolicySetting": {
                    "id": "pre-1",
                    "name": "Default Prefilter Policy",
                    "type": "PrefilterPolicy",
                },
            }
        ],
        "policy/accesspolicies/acp-1/categories": [{"id": "c1", "name": "web", "type": "Category"}],
        "policy/accesspolicies/acp-1/accessrules": [
            existing_rule("allow-web", 1, "80"),
            existing_rule("old-rule", 2, "8080"),
        ],
    }


async def test_update_existing_policy(fmc: respx.MockRouter) -> None:
    seed = existing_seed()
    fake = FakeFmc(fmc, seed)
    out = await plan(BUNDLE)
    assert out["objects"] == {"reuse": 4}
    assert out["access_rules"] == {"changed": 1, "added": 1}
    changed = next(c for c in out["rule_changes"] if c["op"] == "changed")
    assert changed["key"] == "allow-web" and "dst_ports" in changed["fields"]
    assert any("'old-rule' isn't in the bundle and is kept" in w for w in out["warnings"])

    _, done = await import_(BUNDLE)
    puts = [(path, b) for m, path, _, b in fake.writes if m == "PUT"]
    assert [p for p, _ in puts] == ["policy/accesspolicies/acp-1/accessrules/rule-allow-web"]
    assert puts[0][1]["destinationPorts"]["literals"][0]["port"] == "443"
    (added,) = fake.posts("/accessrules")
    # block-bad has no category: it goes to the end of the default section, not into allow-web's category
    assert added[0] == {"section": "default"}
    assert not any(m == "DELETE" for m, *_ in fake.writes)
    names = [r["name"] for r in fake.store["policy/accesspolicies/acp-1/accessrules"]]
    assert names == ["allow-web", "old-rule", "block-bad"]

    fake.writes.clear()
    await import_(BUNDLE, delete_extra_rules=True)
    assert [(m, p.rsplit("/", 1)[-1]) for m, p, _, _ in fake.writes] == [("DELETE", "rule-old-rule")]


async def test_nothing_to_import_is_blocked(fmc: respx.MockRouter) -> None:
    FakeFmc(fmc, BASE_SEED)
    _, _ = await import_(BUNDLE, policy="dst-acp")
    out = await plan(BUNDLE, policy="dst-acp")
    assert out["changes"] == 0 and out["note"] == "The target already matches the bundle."


def test_group_levels() -> None:
    groups = {
        "NetworkGroup/a": {"objects": [{"name": "b", "type": "NetworkGroup"}]},
        "NetworkGroup/b": {"objects": [{"name": "h", "type": "Host"}]},
        "NetworkGroup/c": {},
    }
    assert group_levels(groups) == [["NetworkGroup/b", "NetworkGroup/c"], ["NetworkGroup/a"]]
    groups["NetworkGroup/b"]["objects"].append({"name": "a", "type": "NetworkGroup"})
    with pytest.raises(BundleImportError, match="cycle"):
        group_levels(groups)


async def test_new_rule_between_existing_rules_is_inserted_in_place(fmc: respx.MockRouter) -> None:
    fake = FakeFmc(fmc, existing_seed())
    bundle = copy.deepcopy(BUNDLE)
    web = bundle["access_policy"]["rules"][0]
    old = {**copy.deepcopy(web), "name": "old-rule", "dst_ports": ["tcp/8080"]}
    mid = {**copy.deepcopy(web), "name": "allow-api", "dst_ports": ["tcp/8443"]}
    web["dst_ports"] = ["tcp/80"]  # unchanged
    bundle["access_policy"]["rules"] = [web, mid, old]
    out = await plan(bundle)
    assert out["access_rules"] == {"added": 1} and not out.get("warnings")
    await import_(bundle)
    (added,) = fake.posts("/accessrules")
    assert added[0] == {"insertBefore": "2"}  # before old-rule, in the same category
    names = [r["name"] for r in fake.store["policy/accesspolicies/acp-1/accessrules"]]
    assert names == ["allow-web", "allow-api", "old-rule"]
