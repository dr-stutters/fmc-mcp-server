"""F100: fmc_create_health_policy / fmc_assign_health_policy / fmc_delete_health_policy.

Policy shapes are the lab FMC 10.0.1's (GET policy/healthpolicies/{id}, trimmed to three modules); the POST
body is the spec's request example 1 (basePolicyID). The spec's HealthPolicy has no device field, so the
device record's healthPolicy (IDevice) assigns it, with a policy assignment as the fallback."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.health_policies import ModuleSettings, apply_modules, module_diff

from .conftest import CFG, items, make_settings

INITIAL_ID = "1114175a-2eca-11f1-bc1d-b8e359adb5f3"
FMC_HP_ID = "5405ee6f-2d28-4165-a3f3-6c3b4e320fdf"
NEW_ID = "00000000-0000-4000-8000-0000000000e1"
A, B = "a0000000-0000-4000-8000-00000000000a", "a0000000-0000-4000-8000-00000000000b"
GROUP_ID = "c0000000-0000-4000-8000-000000000001"
DOMAIN_META = {"domain": {"name": "Global", "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f", "type": "Domain"}}

CPU = {
    "moduleId": "hm_cpu",
    "enabled": True,
    "type": "FMC_FTD",
    "criticalThreshold": 90,
    "warningThreshold": 80,
    "alertEnabled": True,
    "alertConfig": [
        {
            "name": "alert_cpu_lina",
            "enabled": True,
            "thresholds": [{"type": "red", "value": 90}, {"type": "yellow", "value": 80}],
        }
    ],
}
MEM = {
    "moduleId": "hm_mu",
    "enabled": True,
    "type": "FMC_FTD",
    "criticalThreshold": 90,
    "warningThreshold": 88,
}
CHM = {
    "moduleId": "hm_chm",
    "enabled": True,
    "type": "FMC_FTD",
    "criticalThreshold": 30,
    "warningThreshold": 90,
}
INITIAL = {
    "id": INITIAL_ID,
    "name": "Initial_Health_Policy 2026-04-02 19:28:02",
    "defaultPolicy": True,
    "type": "HealthPolicy",
    "policyType": "DevicePolicy",
    "description": "Initial Health Policy",
    "metadata": {"readOnly": {"state": False}, **DOMAIN_META},
    "healthModules": [MEM, CHM, CPU],
    "setting": {"alertEvaluationInterval": 5, "dataCollectionInterval": 1, "readOnly": False},
}
FMC_HP = {
    "id": FMC_HP_ID,
    "name": "Firewall Management Center Health Policy",
    "defaultPolicy": False,
    "type": "HealthPolicy",
    "policyType": "ManagementCenterPolicy",
    "metadata": DOMAIN_META,
    "healthModules": [MEM],
}
REF = {"id": INITIAL_ID, "name": INITIAL["name"], "type": "HealthPolicy"}


def dev(i: str, name: str) -> dict[str, Any]:
    return {
        "id": i,
        "name": name,
        "type": "Device",
        "hostName": "192.0.2.10",
        "license_caps": ["ESSENTIALS", "IPS"],
        "performanceTier": "FTDv5",
        "healthPolicy": dict(REF),
    }


class Lab:
    """A small stateful FMC: health policies and device records change with the writes."""

    def __init__(
        self, fmc: respx.MockRouter, *, record_put_works: bool = True, shuffle: bool = False
    ) -> None:
        self.shuffle, self.gets = shuffle, 0
        self.policies: dict[str, dict[str, Any]] = {INITIAL_ID: copy.deepcopy(INITIAL), FMC_HP_ID: FMC_HP}
        self.devices = {A: dev(A, "ftd-a"), B: dev(B, "ftd-b")}
        self.record_put_works = record_put_works
        hp = f"{CFG}/policy/healthpolicies"
        fmc.get(hp).mock(side_effect=lambda r: items([self.summary(p) for p in self.policies.values()]))
        fmc.get(url__regex=rf"{hp}/[0-9a-f-]+$").mock(side_effect=self.get_policy)
        self.post = fmc.post(hp).mock(side_effect=self.create)
        self.put = fmc.put(url__regex=rf"{hp}/[0-9a-f-]+$").mock(side_effect=self.put_policy)
        self.delete = fmc.delete(url__regex=rf"{hp}/[0-9a-f-]+$").mock(
            return_value=httpx.Response(200, json={})
        )
        dr = f"{CFG}/devices/devicerecords"
        fmc.get(dr).mock(side_effect=lambda r: items(list(self.devices.values())))
        fmc.get(url__regex=rf"{dr}/[0-9a-f-]+$").mock(side_effect=self.get_device)
        self.dev_put = fmc.put(url__regex=rf"{dr}/[0-9a-f-]+$").mock(side_effect=self.put_device)
        self.assign = fmc.post(f"{CFG}/assignment/policyassignments").mock(side_effect=self.assign_policy)
        group = {
            "id": GROUP_ID,
            "type": "DeviceGroup",
            "name": "edge",
            "members": [
                {"id": A, "type": "Device", "name": "ftd-a"},
                {"id": B, "type": "Device", "name": "ftd-b"},
            ],
            "metadata": DOMAIN_META,
        }
        fmc.get(f"{CFG}/devicegroups/devicegrouprecords").mock(return_value=items([group]))
        fmc.get(f"{CFG}/devicegroups/devicegrouprecords/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=group)
        )
        fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([]))
        fmc.get(f"{CFG}/deviceclusters/ftddevicecluster").mock(return_value=items([]))

    @staticmethod
    def summary(p: dict[str, Any]) -> dict[str, Any]:
        return {k: p[k] for k in ("id", "name", "type", "policyType", "defaultPolicy") if k in p}

    def get_policy(self, request: httpx.Request) -> httpx.Response:
        p = self.policies.get(request.url.path.rsplit("/", 1)[1])
        if not p:
            return httpx.Response(404, json={})
        if self.shuffle and p.get("healthModules"):  # FMC 10.0: a different module order on every GET
            self.gets += 1
            mods = p["healthModules"]
            k = self.gets % len(mods)
            p = {**p, "healthModules": mods[k:] + mods[:k]}
        return httpx.Response(200, json=p)

    def create(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        base = self.policies[body["basePolicyID"]]
        made = {
            **copy.deepcopy(base),
            "id": NEW_ID,
            "name": body["name"],
            "defaultPolicy": False,
            "description": body.get("description"),
        }
        self.policies[NEW_ID] = made
        return httpx.Response(201, json=made)

    def put_policy(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.policies[body["id"]] = {**self.policies[body["id"]], **body}
        return httpx.Response(200, json=body)

    def get_device(self, request: httpx.Request) -> httpx.Response:
        d = self.devices.get(request.url.path.rsplit("/", 1)[1])
        return httpx.Response(200, json=d) if d else httpx.Response(404, json={})

    def put_device(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if self.record_put_works:
            self.devices[body["id"]]["healthPolicy"] = body["healthPolicy"]
        return httpx.Response(200, json=self.devices[body["id"]])

    def assign_policy(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        for t in body["targets"]:
            self.devices[t["id"]]["healthPolicy"] = body["policy"]
        return httpx.Response(201, json=body)


@pytest.fixture
def lab(fmc: respx.MockRouter) -> Lab:
    return Lab(fmc)


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def confirm(name: str, args: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        assert preview.get("confirm"), preview
        return preview, await run(c, name, {**args, "confirm": preview["confirm"]})


# --- helpers ---------------------------------------------------------------------------------------


def test_apply_modules_follows_alert_thresholds_and_blocks_bad_values() -> None:
    mods, blockers = apply_modules([MEM, CPU], {"HM_CPU": ModuleSettings(warning=60)})
    cpu = mods[1]
    assert not blockers and cpu["warningThreshold"] == 60 and cpu["criticalThreshold"] == 90
    assert {"type": "yellow", "value": 60} in cpu["alertConfig"][0]["thresholds"]
    assert mods[0] is MEM  # untouched modules pass through
    _, bad = apply_modules(
        [CPU, CHM], {"hm_cpu": ModuleSettings(warning=95), "hm_nope": ModuleSettings(warning=1)}
    )
    assert "above critical" in bad[0] and "No module 'hm_nope'" in bad[1]
    _, ok = apply_modules([CHM], {"hm_chm": ModuleSettings(critical=20)})  # lower is worse: no blocker
    assert ok == []


def test_module_diff_lists_only_changes() -> None:
    new, _ = apply_modules([MEM, CPU], {"hm_cpu": ModuleSettings(warning=60)})
    assert module_diff([MEM, CPU], new) == [
        {
            "module": "hm_cpu",
            "from": {
                "module": "hm_cpu",
                "enabled": True,
                "applies_to": "FMC_FTD",
                "warning": 80,
                "critical": 90,
            },
            "to": {
                "module": "hm_cpu",
                "enabled": True,
                "applies_to": "FMC_FTD",
                "warning": 60,
                "critical": 90,
            },
        }
    ]


# --- fmc_create_health_policy ------------------------------------------------------------------------


async def test_create_from_default_with_thresholds_and_a_device(lab: Lab) -> None:
    args = {"name": "mcp-edge", "modules": {"hm_cpu": {"warning": 60}}, "devices": ["ftd-a"]}
    preview, out = await confirm("fmc_create_health_policy", args)
    p = preview["preview"]
    assert p["base"] == INITIAL["name"] and p["module_changes"][0]["to"]["warning"] == 60
    assert p["devices"][0]["device"] == "ftd-a" and p["devices"][0]["from"] == INITIAL["name"]
    assert p["devices"][0]["threshold_changes"][0]["module"] == "hm_cpu"
    assert preview["blast_radius"] == 1
    sent = json.loads(lab.post.calls.last.request.content)
    assert sent == {
        "name": "mcp-edge",
        "type": "HealthPolicy",
        "policyType": "DevicePolicy",
        "basePolicyID": INITIAL_ID,
    }
    put = json.loads(lab.put.calls.last.request.content)
    cpu = next(m for m in put["healthModules"] if m["moduleId"] == "hm_cpu")
    assert (
        cpu["warningThreshold"] == 60
        and {"type": "yellow", "value": 60} in cpu["alertConfig"][0]["thresholds"]
    )
    assert "metadata" not in put and put["id"] == NEW_ID
    dput = json.loads(lab.dev_put.calls.last.request.content)
    assert dput["healthPolicy"]["id"] == NEW_ID and dput["license_caps"] == ["ESSENTIALS", "IPS"]
    assert dput["performanceTier"] == "FTDv5" and dput["hostName"] == "192.0.2.10"
    result = out.get("result", out)
    assert result["assigned"] == [{"device": "ftd-a", "via": "device_record"}]
    assert lab.devices[A]["healthPolicy"]["id"] == NEW_ID and not lab.assign.called


async def test_create_without_modules_is_one_post(lab: Lab) -> None:
    _, out = await confirm("fmc_create_health_policy", {"name": "mcp-copy", "base": INITIAL["name"]})
    assert lab.post.call_count == 1 and not lab.put.called and not lab.dev_put.called


async def test_create_blockers(lab: Lab) -> None:
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_create_health_policy",
            {"name": INITIAL["name"].upper(), "modules": {"hm_cpu": {"warning": 95}, "hm_x": {"warning": 1}}},
        )
        fmc_base = await run(
            c, "fmc_create_health_policy", {"name": "mcp-x", "base": FMC_HP["name"], "devices": ["ftd-a"]}
        )
    assert out["status"] == "blocked"
    text = " ".join(out["blockers"])
    assert "exists" in text and "above critical" in text and "No module 'hm_x'" in text
    assert fmc_base["status"] == "blocked" and "only device policies" in fmc_base["blockers"][0]
    assert not lab.post.called


# --- fmc_assign_health_policy ------------------------------------------------------------------------


async def test_assign_group_skips_devices_already_on_the_policy(lab: Lab) -> None:
    edge = {**copy.deepcopy(INITIAL), "id": NEW_ID, "name": "mcp-edge", "defaultPolicy": False}
    edge["healthModules"][2]["warningThreshold"] = 60
    lab.policies[NEW_ID] = edge
    lab.devices[B]["healthPolicy"] = {"id": NEW_ID, "name": "mcp-edge", "type": "HealthPolicy"}
    preview, out = await confirm(
        "fmc_assign_health_policy", {"policy": "mcp-edge", "devices": ["group:edge"]}
    )
    p = preview["preview"]
    assert p["group"] == "edge" and preview["blast_radius"] == 1
    a, b = p["devices"]
    assert a["threshold_changes"] == [
        {
            "module": "hm_cpu",
            "from": {
                "module": "hm_cpu",
                "enabled": True,
                "applies_to": "FMC_FTD",
                "warning": 80,
                "critical": 90,
            },
            "to": {
                "module": "hm_cpu",
                "enabled": True,
                "applies_to": "FMC_FTD",
                "warning": 60,
                "critical": 90,
            },
        }
    ]
    assert b == {"device": "ftd-b", "from": "mcp-edge", "unchanged": True}
    assert lab.dev_put.call_count == 1 and lab.devices[A]["healthPolicy"]["id"] == NEW_ID


async def test_assign_falls_back_to_a_policy_assignment(fmc: respx.MockRouter) -> None:
    lab = Lab(fmc, record_put_works=False)
    lab.policies[NEW_ID] = {
        **copy.deepcopy(INITIAL),
        "id": NEW_ID,
        "name": "mcp-edge",
        "defaultPolicy": False,
    }
    _, out = await confirm("fmc_assign_health_policy", {"policy": "mcp-edge", "devices": ["ftd-a"]})
    body = json.loads(lab.assign.calls.last.request.content)
    assert body["policy"] == {"id": NEW_ID, "name": "mcp-edge", "type": "HealthPolicy"}
    assert body["targets"] == [{"id": A, "type": "Device", "name": "ftd-a"}]
    result = out.get("result", out)
    assert result["assigned"] == [{"device": "ftd-a", "via": "policy_assignment"}]


async def test_assign_back_to_default_and_nothing_to_do(lab: Lab) -> None:
    async with Client(server()) as c:
        same = await run(c, "fmc_assign_health_policy", {"policy": "default", "devices": ["ftd-a", "ftd-b"]})
        mc = await run(c, "fmc_assign_health_policy", {"policy": FMC_HP["name"], "devices": ["ftd-a"]})
    assert same["status"] == "blocked" and "already on" in same["blockers"][0]
    assert "only device policies" in mc["blockers"][0]


# --- fmc_delete_health_policy ------------------------------------------------------------------------


async def test_delete_refused_while_assigned_and_for_built_ins(lab: Lab) -> None:
    lab.policies[NEW_ID] = {
        **copy.deepcopy(INITIAL),
        "id": NEW_ID,
        "name": "mcp-edge",
        "defaultPolicy": False,
    }
    lab.devices[A]["healthPolicy"] = {"id": NEW_ID, "name": "mcp-edge", "type": "HealthPolicy"}
    async with Client(server()) as c:
        used = await run(c, "fmc_delete_health_policy", {"policy": "mcp-edge"})
        default = await run(c, "fmc_delete_health_policy", {"policy": INITIAL["name"]})
        own = await run(c, "fmc_delete_health_policy", {"policy": FMC_HP["name"]})
    assert used["status"] == "blocked" and "assigned to ftd-a" in used["blockers"][0]
    assert "fmc_assign_health_policy" in used["blockers"][0]
    assert "default health policy" in default["blockers"][0]
    assert "can't be deleted" in own["blockers"][0]
    assert not lab.delete.called


async def test_delete_unused_policy(lab: Lab) -> None:
    lab.policies[NEW_ID] = {
        **copy.deepcopy(INITIAL),
        "id": NEW_ID,
        "name": "mcp-edge",
        "defaultPolicy": False,
    }
    _, out = await confirm("fmc_delete_health_policy", {"policy": "mcp-edge"})
    assert lab.delete.calls.last.request.url.path.endswith(f"/policy/healthpolicies/{NEW_ID}")


# --- prompts -----------------------------------------------------------------------------------------


def test_onboarding_prompts_take_a_health_policy() -> None:
    from fmc_mcp.tools.prompts import _onboard_branch_text, _onboard_text

    ftd = _onboard_text(
        "mcp-ftd2", "192.0.2.11", None, "acp", "Ethernet0/0", "198.51.100.2/24", "198.51.100.1",
        "Ethernet0/1", "10.99.2.1/24", None, None, None, health_policy="mcp-edge",
    )  # fmt: skip
    assert "fmc_assign_health_policy" in ftd and 'policy="mcp-edge", devices=["mcp-ftd2"]' in ftd
    branch = _onboard_branch_text("br7", "192.0.2.13", "t1", health_policy="mcp-edge")
    assert "fmc_assign_health_policy" in branch and "fmc_create_health_policy" in branch
    assert "fmc_assign_health_policy" not in _onboard_branch_text("br7", "192.0.2.13", "t1")


async def test_assign_falls_back_when_the_record_put_is_refused(lab: Lab, fmc: respx.MockRouter) -> None:
    lab.policies[NEW_ID] = {
        **copy.deepcopy(INITIAL),
        "id": NEW_ID,
        "name": "mcp-edge",
        "defaultPolicy": False,
    }
    lab.dev_put.mock(
        side_effect=None,
        return_value=httpx.Response(
            400, json={"error": {"messages": [{"description": "Invalid field healthPolicy"}]}}
        ),
    )
    _, out = await confirm("fmc_assign_health_policy", {"policy": "mcp-edge", "devices": ["ftd-a"]})
    assert out.get("result", out)["assigned"] == [{"device": "ftd-a", "via": "policy_assignment"}]


# --- #363: FMC 10.0 returns healthModules in a different order on every GET ------------------------------


async def test_confirm_survives_a_reordered_module_list(fmc: respx.MockRouter) -> None:
    lab = Lab(fmc, shuffle=True)
    args = {"name": "mcp-edge", "modules": {"hm_cpu": {"warning": 60, "critical": 85}}, "devices": ["ftd-a"]}
    preview, out = await confirm("fmc_create_health_policy", args)
    assert "changed since the preview" not in json.dumps(out), out
    assert lab.post.call_count == 1 and lab.put.called and lab.devices[A]["healthPolicy"]["id"] == NEW_ID
    assert [r["module"] for r in out.get("result", out)["modules"]] == ["hm_cpu"]

    lab.policies[NEW_ID]["healthModules"].append({**MEM, "moduleId": "hm_disk_status"})
    _, moved = await confirm("fmc_assign_health_policy", {"policy": "mcp-edge", "devices": ["ftd-b"]})
    assert "changed since the preview" not in json.dumps(moved), moved
    assert lab.devices[B]["healthPolicy"]["id"] == NEW_ID

    puts = lab.put.call_count
    _, upd = await confirm(
        "fmc_update_health_policy", {"policy": "mcp-edge", "module": "hm_mu", "warning": 70}
    )
    assert "changed since the preview" not in json.dumps(upd), upd
    assert lab.put.call_count == puts + 1


async def test_previews_list_modules_in_id_order(fmc: respx.MockRouter) -> None:
    Lab(fmc, shuffle=True)
    args = {"name": "mcp-edge", "modules": {"hm_mu": {"warning": 70}, "hm_cpu": {"warning": 60}}}
    async with Client(server()) as c:
        a = await run(c, "fmc_create_health_policy", args)
        b = await run(c, "fmc_create_health_policy", args)
        got = [
            await run(c, "fmc_get_health_policy", {"policy": INITIAL_ID, "response_format": "json"})
            for _ in range(2)
        ]
    assert a["preview"]["module_changes"] == b["preview"]["module_changes"]
    assert [r["module"] for r in a["preview"]["module_changes"]] == ["hm_cpu", "hm_mu"]
    assert got[0]["modules"] == got[1]["modules"]
    assert [r["module"] for r in got[0]["modules"]] == ["hm_chm", "hm_cpu", "hm_mu"]
