"""F73 device snapshots and the state diff, replayed from tests/fixtures/device_snapshot_t1.json
(mcp-sdwan-t1-spoke1's show outputs, health alerts and deployment jobs as FMC 10.0.1 returned them,
redacted; its `wan_down` state is synthesized from it, see _source), F72's configuration recording
(device_config_t1.json via test_device_export.t1), the recorded bulkcommands refusal and the bulk task
schema (fleet_show.json), the recorded HA pair (ha_failover.json) and the VPN shapes (vpn_status.json).
The access policy's rules and hit counts are synthesized in the recorded HitCount shape."""

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import yaml
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.tools.device_export import SECTIONS, parse_export
from fmc_mcp.tools.device_snapshot import (
    diff_alerts,
    diff_hits,
    diff_lines,
    parse_ip_brief,
    running_lines,
    snapshot_sections,
)
from fmc_mcp.tools.prompts import _health_review_text, _rule_change_review_text

from .conftest import CFG, fixture, items
from .test_device_export import SP1, SP2, recorded, server, t1

FX = fixture("device_snapshot_t1")
FLEET = fixture("fleet_show")
DEV = f"{CFG}/devices/devicerecords"
BULK = f"{DEV}/operational/bulkcommands"
ACP = "00000000-0000-0ed3-0000-021474856047"  # mcp-sdwan-acp, assigned to spoke1 in the recording
DEFAULT_ACTION = "00000000-0000-0ed3-0000-000268434999"
RULES = [
    {"id": "00000000-0000-0ed3-0000-000268434490", "name": "mcp-sdwan-allow-inside", "type": "AccessRule"},
    {"id": "00000000-0000-0ed3-0000-000268434491", "name": "mcp-sdwan-block-telnet", "type": "AccessRule"},
]
STATE = [n for n, s in SECTIONS.items() if s.kind == "state"]


def hit_row(rule: dict[str, Any], count: int, default: bool = False) -> dict[str, Any]:
    kind = "AccessPolicyDefaultAction" if default else "AccessRule"
    return {
        "metadata": {"policy": {"name": "mcp-sdwan-acp", "id": ACP}, "deviceRuleId": "268434490"},
        "lastFetchTimeStamp": "2026-10-21T02:30:00Z",
        "rule": {**rule, "type": kind},
        "lastHitTimeStamp": "2026-10-21T02:29:00Z" if count else "",
        "type": "HitCount",
        "hitCount": count,
    }


def lab(
    fmc: respx.MockRouter, *, connected: bool = True, more: dict[str, dict[str, str]] | None = None
) -> dict[str, Any]:
    """spoke1 as recorded (connected), bulkcommands refused like FMC 10.0.1. Edit the returned state
    (show, alerts, hits, tunnels, jobs, deployable) to change what FMC answers. `more`: other device ids
    and their show outputs (registered before the recording's catch-all for device sub-paths)."""
    st: dict[str, Any] = {
        "show": dict(FX["show"]),
        "alerts": copy.deepcopy(FX["health/alerts"]),
        "jobs": copy.deepcopy(FX["deployment/jobhistories"]),
        "hits": {RULES[0]["id"]: 120, RULES[1]["id"]: 3, DEFAULT_ACTION: 7},
        "tunnels": [],
        "deployable": [],
        "commands": [],
    }
    fmc.post(BULK).mock(return_value=httpx.Response(403, json=FLEET["bulk_refused_403"]))

    def command(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        text = q["command"] + (f" {q['parameters']}" if "parameters" in q else "")
        st["commands"].append(text)
        if text not in st["show"]:
            return httpx.Response(404, json={"error": {"messages": [{"description": "command is invalid"}]}})
        return httpx.Response(
            200, json={"items": [{"commandInput": text, "commandOutput": st["show"][text]}]}
        )

    fmc.get(f"{DEV}/{SP1}/operational/commands").mock(side_effect=command)
    for dev_id, show in (more or {}).items():

        def answer(
            request: httpx.Request, show: dict[str, str] = show, dev_id: str = dev_id
        ) -> httpx.Response:
            q = request.url.params
            text = q["command"] + (f" {q['parameters']}" if "parameters" in q else "")
            st.setdefault("more", []).append((dev_id, text))
            return httpx.Response(200, json={"items": [{"commandInput": text, "commandOutput": show[text]}]})

        fmc.get(f"{DEV}/{dev_id}/operational/commands").mock(side_effect=answer)
    data = recorded()
    data[f"devices/devicerecords/{SP1}"].update(
        {"isConnected": connected, "deploymentStatus": "DEPLOYED", "healthStatus": "red"}
    )
    t1(fmc, data)
    fmc.get(f"{CFG}/health/alerts").mock(side_effect=lambda _r: httpx.Response(200, json=st["alerts"]))
    fmc.get(f"{CFG}/deployment/jobhistories").mock(
        side_effect=lambda _r: httpx.Response(200, json=st["jobs"])
    )
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(side_effect=lambda _r: items(st["deployable"]))
    fmc.get(f"{CFG}/health/tunnelstatuses").mock(side_effect=lambda _r: items(st["tunnels"]))
    acp = f"{CFG}/policy/accesspolicies/{ACP}"
    fmc.get(acp).mock(
        return_value=httpx.Response(
            200,
            json={
                "id": ACP,
                "name": "mcp-sdwan-acp",
                "type": "AccessPolicy",
                "defaultAction": {
                    "id": DEFAULT_ACTION,
                    "action": "BLOCK",
                    "type": "AccessPolicyDefaultAction",
                },
            },
        )
    )
    fmc.get(f"{acp}/accessrules").mock(return_value=items(RULES))
    fmc.put(f"{acp}/operational/hitcounts").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "hc1"}}, "type": "HitCount"})
    )
    fmc.get(f"{CFG}/job/taskstatuses/hc1").mock(
        return_value=httpx.Response(200, json={"id": "hc1", "status": "SUCCESS"})
    )

    def hits(request: httpx.Request) -> httpx.Response:
        flt = dict(p.split(":", 1) for p in request.url.params["filter"].split(";"))
        wanted = flt.get("ids", "").split(",")
        rows = [hit_row(r, st["hits"][r["id"]]) for r in RULES if r["id"] in wanted]
        if DEFAULT_ACTION in wanted:
            rows.append(
                hit_row({"id": DEFAULT_ACTION, "name": "Default Action"}, st["hits"][DEFAULT_ACTION], True)
            )
        return items(rows)

    fmc.get(f"{acp}/operational/hitcounts").mock(side_effect=hits)
    return st


async def call(tool: str, args: dict[str, Any], **kw: Any) -> dict[str, Any]:
    async with Client(server(**kw)) as c:
        out = (await c.call_tool(tool, args)).structured_content
    assert out is not None
    return out


async def snapshot(**args: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    kw = {k: args.pop(k) for k in ("bundle_dir",) if k in args}
    out = await call("fmc_device_snapshot", {"devices": ["mcp-sdwan-t1-spoke1"], **args}, **kw)
    text = next(iter(out["snapshots"].values()))
    return out, parse_export(text, None)


def wan_down(st: dict[str, Any]) -> None:
    st["show"].update(FX["wan_down"]["show"])
    st["alerts"] = copy.deepcopy(FX["wan_down"]["health/alerts"])


# --- the snapshot ----------------------------------------------------------------------------


async def test_snapshot_spoke1(fmc: respx.MockRouter) -> None:
    st = lab(fmc)
    out, doc = await snapshot(label="before CHG1", running_config=["route"])
    assert out["label"] == "before CHG1" and out["show_path"] == "per-device"
    assert "bulk_device_command_execution" in " ".join(out["notes"])
    assert out["sections"] == ["device", "policies", *STATE]
    meta = doc["meta"]
    assert meta["label"] == "before CHG1" and meta["running_config"] == ["route"] and "errors" not in meta
    assert meta["hit_count_refresh"] is True and meta["device"] == "mcp-sdwan-t1-spoke1"
    routes = doc["route_table"]
    assert routes["198.51.100.0/27"] == {
        "protocol": "static",
        "code": "S",
        "via": ["192.0.2.1"],
        "interfaces": ["mpls"],
    }
    assert routes["192.0.2.48/28"] == {"protocol": "connected", "code": "C", "interfaces": ["inside"]}
    assert len(routes) == 11
    assert doc["interface_state"]["Ethernet0/0"] == {
        "ip": "192.0.2.2",
        "method": "CONFIG",
        "status": "up",
        "protocol": "up",
    }
    assert not any(k.startswith("Internal-") for k in doc["interface_state"])
    assert set(doc["interface_state"]) == {
        "Ethernet0/0",
        "Ethernet0/1",
        "Ethernet0/2",
        "Ethernet0/3",
        "Management0/0",
    }
    assert doc["failover"] == {"mcp-sdwan-t1-spoke1": {"state": "standalone (not in an HA pair)"}}
    assert doc["vpn_sas"] == {"total": {"ike_sas": 0, "ipsec_sas": 0}}
    assert "tunnels" not in doc and "tunnels" in meta["sections"]  # read, none for this device
    assert doc["hit_counts"]["mcp-sdwan-allow-inside"]["hits"] == 120
    assert doc["hit_counts"]["Default Action"]["hits"] == 7
    assert set(doc["health_alerts"]) == {
        "ADVANCED_SNORT_STATS",
        "APPLIANCE_HEARTBEAT",
        "INTERFACE",
        "THREAT_DATA_UPDATES",
    }
    assert doc["health_alerts"]["INTERFACE"] == {
        "status": "RED",
        "details": "Interface 'Ethernet0/2' is not receiving any packets",
    }
    assert doc["deployment"] == {
        "status": "DEPLOYED",
        "last_job": "Deploy_Job_135",
        "last_job_status": "SUCCEEDED",
        "last_job_ended": "2026-10-19T05:14:49Z",
        "deployed_version": 37,
        "pending": [],
    }
    assert doc["running_config"] == {
        "route": [
            "route mpls 198.51.100.0 255.255.255.224 192.0.2.1 1",
            "route inet 198.51.100.32 255.255.255.224 192.0.2.17 1",
            "route lte 198.51.100.64 255.255.255.224 192.0.2.33 1",
        ]
    }
    assert doc["policies"]["access"] == {"name": "mcp-sdwan-acp"}
    # each show command ran once, on the device (FMC refused bulkcommands)
    assert sorted(st["commands"]) == sorted(
        ["show route", "show interface ip brief", "show crypto ikev2 sa", "show running-config route"]
    )


async def test_snapshot_cost(fmc: respx.MockRouter) -> None:
    """About ten FMC requests per device (the description's number), plus a few shared ones."""
    lab(fmc)
    await snapshot()
    calls = [c.request for c in fmc.calls if c.request.url.path.startswith(CFG)]
    paths = [r.url.path[len(CFG) :] for r in calls]
    per_device = [
        p for p in paths if SP1 in p or "health/alerts" in p or "jobhistories" in p or "hitcounts" in p
    ]
    per_device += [p for p in paths if "taskstatuses" in p]
    # the record, show route / interface ip brief / crypto ikev2 sa, the hit-count refresh, its task
    # and the read, health alerts, deployment jobs
    assert len(per_device) == 9, per_device
    assert len(paths) <= 19, paths  # + device list x2, groups, bulkcommands, assignments, policy, ...


async def test_wan_link_down_and_restore(fmc: respx.MockRouter) -> None:
    """The issue's test plan: snapshot spoke1, take a WAN link down, compare; restore, compare again."""
    st = lab(fmc)
    out, _ = await snapshot(label="before")
    before = next(iter(out["snapshots"].values()))
    wan_down(st)
    st["hits"][RULES[0]["id"]] = 180
    diff = await call("fmc_diff_device_config", {"a": before})
    assert diff["identical"] is False and diff["b"]["exported_at"] == "live"
    found = diff["findings"]
    assert "route lost: 198.51.100.0/27 (static via 192.0.2.1 on mpls)" in found
    assert "route lost: 192.0.2.0/28 (connected on mpls)" in found
    assert "interface Ethernet0/0: protocol up -> down; status up -> down" in found
    assert any(f.startswith("health alert INTERFACE: details Interface 'Ethernet0/2'") for f in found)
    assert "hit count mcp-sdwan-allow-inside: 120 -> 180 (+60)" in found
    assert diff["summary"] == {
        "route_table": {"removed": 3},
        "interface_state": {"changed": 1},
        "health_alerts": {"changed": 1},
    }
    assert diff["deltas"] == [
        {
            "section": "hit_counts",
            "op": "delta",
            "key": "mcp-sdwan-allow-inside",
            "from": 120,
            "to": 180,
            "delta": 60,
        }
    ]
    # restored: the state matches the snapshot again; the hit count still moved, which is no difference
    st["show"].update(FX["show"])
    st["alerts"] = copy.deepcopy(FX["health/alerts"])
    again = await call("fmc_diff_device_config", {"a": before})
    assert again["identical"] is True and again["total"] == 0
    assert again["deltas"][0]["delta"] == 60
    assert again["findings"] == ["hit count mcp-sdwan-allow-inside: 120 -> 180 (+60)"]


async def test_two_stored_snapshots_compare_offline(fmc: respx.MockRouter, tmp_path: Path) -> None:
    st = lab(fmc)
    before, _ = await snapshot(label="before", bundle_dir=tmp_path)
    wan_down(st)
    after, _ = await snapshot(label="after", bundle_dir=tmp_path)
    files = sorted(Path(x["devices"][0]["file"]).name for x in (before, after))
    assert len(files) == 2 and all(f.startswith("snapshot-mcp-sdwan-t1-spoke1-") for f in files)
    assert any("-before-" in f for f in files) and any("-after-" in f for f in files)
    n = len(fmc.calls)
    a, b = (Path(x["devices"][0]["file"]).name for x in (before, after))
    diff = await call("fmc_diff_device_config", {"a": a, "b": b}, bundle_dir=tmp_path)
    assert len(fmc.calls) - n <= 3  # login and version only: no device read
    assert diff["a"]["label"] == "before" and diff["b"]["label"] == "after"
    assert diff["summary"]["route_table"] == {"removed": 3}
    only = await call(
        "fmc_diff_device_config", {"a": a, "b": b, "sections": ["interface_state"]}, bundle_dir=tmp_path
    )
    assert only["compared"] == ["interface_state"] and only["total"] == 1


async def test_disconnected_device_keeps_fmc_sections(fmc: respx.MockRouter) -> None:
    st = lab(fmc, connected=False)
    out, doc = await snapshot()
    assert st["commands"] == []  # nothing is sent to a device FMC reports disconnected
    errors = doc["meta"]["errors"]
    assert set(errors) == {"route_table", "interface_state", "vpn_sas"}
    assert "disconnected" in errors["route_table"]
    assert {"health_alerts", "deployment", "hit_counts"} <= set(doc["meta"]["sections"])
    assert out["devices"][0]["errors"] == errors


async def test_export_tool_reads_state_sections(fmc: respx.MockRouter) -> None:
    """F72's export with sections=['state'] is a one-device snapshot (no running-config without names)."""
    lab(fmc)
    out = await call("fmc_export_device_config", {"device": SP1, "sections": ["route_table", "deployment"]})
    doc = parse_export(out["export"], None)
    assert doc["meta"]["sections"] == ["route_table", "deployment"]
    assert doc["deployment"]["deployed_version"] == 37 and len(doc["route_table"]) == 11
    state = await call("fmc_export_device_config", {"device": SP1, "sections": ["state"]})
    assert "running_config: no sections named" in " ".join(state["warnings"])


# --- several devices: bulkcommands, HA pairs ---------------------------------------------------


async def test_two_devices_share_one_bulk_request_per_command(fmc: respx.MockRouter) -> None:
    """Where FMC enables bulkcommands, each command is one request for every device (the task's
    subTasks carry each device's output, by the 10.0.1 schema)."""
    st = lab(fmc)
    posted: list[dict[str, Any]] = []

    def bulk(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        posted.append(body)
        tid = f"bulk{len(posted)}"
        return httpx.Response(
            202, json={"type": "BulkCommand", **body, "metadata": {"task": {"id": tid, "status": "RUNNING"}}}
        )

    fmc.post(BULK).mock(side_effect=bulk)

    def task(request: httpx.Request) -> httpx.Response:
        n = int(request.url.path.rsplit("bulk", 1)[1])
        command = posted[n - 1]["command"]
        subs = [
            {
                "target": {"id": i, "type": "Device"},
                "status": "SUCCESS",
                "message": st["show"][command],
            }
            for i in posted[n - 1]["devices"]
        ]
        return httpx.Response(200, json={"id": f"bulk{n}", "status": "SUCCESS", "subTasks": subs})

    fmc.get(url__regex=rf"{CFG}/job/taskstatuses/bulk\d+").mock(side_effect=task)
    for i in (SP1, SP2):
        fmc.get(f"{DEV}/{i}").mock(
            return_value=httpx.Response(
                200, json={**recorded()[f"devices/devicerecords/{i}"], "isConnected": True}
            )
        )
    out = await call("fmc_device_snapshot", {"devices": ["mcp-sdwan-t1-spoke1", "mcp-sdwan-t1-spoke2"]})
    assert out["show_path"] == "bulkcommands"
    assert [p["command"] for p in posted] == ["show route", "show interface ip brief", "show crypto ikev2 sa"]
    assert all(sorted(p["devices"]) == sorted([SP1, SP2]) for p in posted)
    assert st["commands"] == []  # nothing ran per device
    assert [d["device"] for d in out["devices"]] == ["mcp-sdwan-t1-spoke1", "mcp-sdwan-t1-spoke2"]
    docs = {k: yaml.safe_load(v) for k, v in out["snapshots"].items()}
    assert len(docs["mcp-sdwan-t1-spoke2"]["route_table"]) == 11


async def test_ha_pair_reads_both_units(fmc: respx.MockRouter) -> None:
    """An HA pair: per-unit state keyed by unit, failover from both units, counters from the active one."""
    ha = fixture("ha_failover")
    pair = copy.deepcopy(ha["pair"])
    pair["primary"]["id"] = SP1
    secondary = pair["secondary"]["id"]
    primary_state = ha["show"]["primary"]["show failover state"]
    mate_state = (  # the secondary's own view (the recording has only the primary's)
        primary_state.replace("This host  -   Primary", "This host  -   Second")
        .replace("Other host -   Secondary", "Other host -   Primary")
        .replace(
            "Second\n               Active         None", "Secondary\n               Standby Ready  None"
        )
        .replace(
            "Primary\n               Standby Ready  Comm Failure", "Primary\n               Active        "
        )
    )
    st = lab(fmc, more={secondary: {**FX["show"], "show failover state": mate_state}})
    st["show"]["show failover state"] = primary_state
    ha_base = f"{CFG}/devicehapairs/ftddevicehapairs"
    fmc.get(ha_base).mock(return_value=items([pair]))
    fmc.get(f"{ha_base}/{pair['id']}").mock(return_value=httpx.Response(200, json=pair))
    fmc.get(url__regex=rf"{ha_base}/{pair['id']}/.+").mock(return_value=items([]))
    fmc.get(f"{DEV}/{secondary}").mock(
        return_value=httpx.Response(200, json={"id": secondary, "name": "mcp-fw-ha-b", "type": "Device"})
    )
    out = await call(
        "fmc_device_snapshot",
        {"devices": ["mcp-fw-ha"], "sections": ["failover", "route_table", "hit_counts", "health_alerts"]},
    )
    doc = yaml.safe_load(out["snapshots"]["mcp-fw-ha"])
    assert doc["meta"]["kind"] == "ha_pair" and "errors" not in doc["meta"]
    assert doc["failover"]["mcp-fw-ha-a"] == {
        "role": "Primary",
        "state": "Active",
        "mate_role": "Secondary",
        "mate_state": "Standby Ready",
    }
    assert doc["failover"]["mcp-fw-ha-b"]["role"] == "Secondary"
    assert doc["failover"]["mcp-fw-ha-b"]["state"] == "Standby Ready"
    assert "mcp-fw-ha-a: 198.51.100.0/27" in doc["route_table"]
    assert "mcp-fw-ha-b: 198.51.100.0/27" in doc["route_table"]
    assert sorted(t for _, t in st["more"]) == ["show failover state", "show route"]
    assert sorted(st["commands"]) == ["show failover state", "show route"]
    # the counters come from the active unit; alerts from both
    assert doc["hit_counts"]["(counters from)"] == {"unit": "mcp-fw-ha-a"}
    assert (
        "mcp-fw-ha-a: INTERFACE" in doc["health_alerts"] and "mcp-fw-ha-b: INTERFACE" in doc["health_alerts"]
    )


async def test_vpn_sas_and_tunnels(fmc: respx.MockRouter) -> None:
    st = lab(fmc)
    vpn = fixture("vpn_status")
    st["show"]["show crypto ikev2 sa"] = vpn["show"]["d-a"]["show crypto ikev2 sa"]
    tunnel = copy.deepcopy(vpn["health/tunnelstatuses"]["items"][0])
    tunnel["peerA"]["device"] = {"id": SP1, "name": "mcp-sdwan-t1-spoke1", "type": "Device"}
    st["tunnels"] = [tunnel, vpn["health/tunnelstatuses"]["items"][2]]  # the second isn't spoke1's
    out, doc = await snapshot(sections=["vpn_sas", "tunnels"])
    assert doc["vpn_sas"] == {
        "total": {"ike_sas": 1, "ipsec_sas": 1},
        "ike 203.0.113.1 -> 203.0.113.2": {
            "state": "READY",
            "session_status": "UP-ACTIVE",
            "child_sas": 1,
            "encryption": "AES-GCM-256",
            "dh_group": 21,
            "auth": "PSK",
        },
    }
    key = "mcp-fw-vti: mcp-sdwan-t1-spoke1 (203.0.113.1) <-> branch-b (203.0.113.2)"
    assert doc["tunnels"] == {key: {"state": "TUNNEL_UP", "message": "Tunnel is up"}}
    before = out["snapshots"]["mcp-sdwan-t1-spoke1"]
    st["show"]["show crypto ikev2 sa"] = "\nThere are no IKEv2 SAs\n"
    st["tunnels"][0] = {**tunnel, "state": "TUNNEL_DOWN", "message": "Tunnel is down", "lastChange": 1}
    diff = await call("fmc_diff_device_config", {"a": before})
    assert (
        f"tunnel {key}: message Tunnel is up -> Tunnel is down; state TUNNEL_UP -> TUNNEL_DOWN"
        in diff["findings"]
    )
    assert "IKEv2 SA lost: ike 203.0.113.1 -> 203.0.113.2 (was READY)" in diff["findings"]
    assert "VPN SA counts: ike_sas 1 -> 0; ipsec_sas 1 -> 0" in diff["findings"]


async def test_new_alert_deploy_and_running_config(fmc: respx.MockRouter) -> None:
    st = lab(fmc)
    st["alerts"]["items"] = [a for a in st["alerts"]["items"] if a["moduleID"] != "INTERFACE"]
    out, _ = await snapshot(running_config=["route"])
    before = out["snapshots"]["mcp-sdwan-t1-spoke1"]
    st["alerts"] = copy.deepcopy(FX["wan_down"]["health/alerts"])
    st["show"]["show running-config route"] += "route inside 198.51.100.96 255.255.255.224 192.0.2.50 1\n"
    newest = copy.deepcopy(st["jobs"]["items"][0])
    newest.update({"jobName": "Deploy_Job_136", "endTime": "2026-10-21T03:00:00Z"})
    newest["deviceList"] = [
        {
            "deviceName": "mcp-sdwan-t1-spoke1",
            "deviceUUID": SP1,
            "deploymentStatus": "SUCCEEDED",
            "deployedVersion": 38,
        }
    ]
    st["jobs"]["items"].insert(0, newest)
    diff = await call("fmc_diff_device_config", {"a": before})
    found = diff["findings"]
    assert any(f.startswith("new health alert INTERFACE (RED): Interface 'Ethernet0/0'") for f in found)
    assert "running-config + route: route inside 198.51.100.96 255.255.255.224 192.0.2.50 1" in found
    assert (
        "deployment: deployed_version 37 -> 38; last_job Deploy_Job_135 -> Deploy_Job_136; "
        "last_job_ended 2026-10-19T05:14:49Z -> 2026-10-21T03:00:00Z" in found
    )
    assert "show running-config route" in st["commands"][-4:]  # the live side re-read a's sections


# --- refusals and helpers --------------------------------------------------------------------


async def test_refusals(fmc: respx.MockRouter) -> None:
    lab(fmc)
    async with Client(server()) as c:
        for args, match in (
            ({"sections": ["running_config"]}, "Name the running-config sections"),
            ({"running_config": ["route | include x"]}, "Pipes"),
            ({"running_config": [" "]}, "empty running-config section"),
            ({"label": "x" * 61}, "longer than 60"),
            ({"include_text": False}, "FMC_BUNDLE_DIR"),
            ({"sections": ["routes"]}, "Unknown section"),
        ):
            with pytest.raises(ToolError, match=match):
                await c.call_tool("fmc_device_snapshot", {"devices": ["mcp-sdwan-t1-spoke1"], **args})
        with pytest.raises(ToolError, match="No device"):
            await c.call_tool("fmc_device_snapshot", {"devices": ["nope"]})


def test_snapshot_sections() -> None:
    assert snapshot_sections(None, None) == [
        "device",
        "policies",
        *[n for n in STATE if n != "running_config"],
    ]
    assert snapshot_sections(None, ["nat"])[-1] == "running_config"
    assert "running_config" not in snapshot_sections(["state"], None)  # implied, nothing to capture
    assert snapshot_sections(["interfaces", "route_table"], None) == ["interfaces", "route_table"]
    # running-config sections named with a sections list that leaves running_config out: captured
    assert snapshot_sections(["route_table"], ["route"]) == ["route_table", "running_config"]


def test_parse_ip_brief_and_running_lines() -> None:
    rows = parse_ip_brief(
        "Interface   IP-Address   OK? Method Status                Protocol\n"
        "Ethernet0/4  unassigned   YES unset  administratively down down\n"
        "Internal-Data0/1 169.254.1.1 YES unset up up\n"
    )
    assert rows == [
        {
            "interface": "Ethernet0/4",
            "ip": "unassigned",
            "method": "unset",
            "status": "administratively down",
            "protocol": "down",
        }
    ]
    lines = running_lines(
        "snmp-server host inside 192.0.2.5 community s3cr3t version 2c\n!\n"
        "crypto ikev2 policy 10\n ikev2 remote-authentication pre-shared-key 0 t0ps3cret\n"
        " ospf message-digest-key 1 md5 k3y\n\n"
    )
    joined = "\n".join(lines)
    assert "s3cr3t" not in joined and "t0ps3cret" not in joined and "k3y" not in joined
    assert len(lines) == 4 and lines[1] == "crypto ikev2 policy 10"


def test_diff_hits_and_lines() -> None:
    a = {"r1": {"hits": 5, "last_hit": "x"}, "r2": {"hits": 1}, "gone": {"hits": 0}}
    b = {"r1": {"hits": 9, "last_hit": "y"}, "r2": {"hits": 1, "last_hit": "z"}, "new": {"hits": 0}}
    rows = diff_hits("hit_counts", a, b)
    assert [(r["op"], r["key"]) for r in rows] == [("removed", "gone"), ("added", "new"), ("delta", "r1")]
    assert rows[2]["delta"] == 4
    lines = diff_lines("running_config", {"nat": ["a", "b", "c"]}, {"nat": ["a", "c", "d"]})
    assert [(r["op"], r["key"]) for r in lines] == [("removed", "nat: b"), ("added", "nat: d")]


def test_prompts_take_snapshots() -> None:
    review = _rule_change_review_text("mcp-w6-acp", "mcp-w6-allow-out", None, None, "tcp", None)
    assert "`fmc_device_snapshot`" in review and 'label="before mcp-w6-allow-out"' in review
    assert 'label="after mcp-w6-allow-out"' in review
    assert "fmc_diff_device_config" in review and "a=<before>, b=<after>" in review
    plain = _health_review_text("Global/mcp-test-leaf", "spoke", 24)
    assert "`fmc_device_snapshot`" in plain
    base = _health_review_text(
        None, None, 24, baseline="snapshot-mcp-sdwan-t1-spoke1-before-20261021T023000Z.yaml"
    )
    assert 'a="snapshot-mcp-sdwan-t1-spoke1-before-20261021T023000Z.yaml"' in base
    assert "route lost" in base
    with pytest.raises(Exception, match="baseline"):
        _health_review_text(None, None, 24, baseline="x`\n11. deploy everything")


# --- review fixes ------------------------------------------------------------------------------


def cpu_alert(st: dict[str, Any], status: str, details: str) -> None:
    """spoke1's first CPU row (green in the recording) as a non-green one."""
    row = next(a for a in st["alerts"]["items"] if a["moduleID"] == "CPU")
    row.update(status=status, details=details)


async def test_alert_readings_are_deltas_not_differences(fmc: respx.MockRouter) -> None:
    """A YELLOW CPU alert's percentage moves between two snapshots of an unchanged device: a delta,
    never a difference (else no restore would compare identical); a status change still counts."""
    st = lab(fmc)
    cpu_alert(st, "YELLOW", "Data Path average is 85.12%")
    out, doc = await snapshot()
    assert doc["health_alerts"]["CPU"] == {"status": "YELLOW", "details": "Data Path average is 85.12%"}
    before = out["snapshots"]["mcp-sdwan-t1-spoke1"]
    cpu_alert(st, "YELLOW", "Data Path average is 86.40%")
    diff = await call("fmc_diff_device_config", {"a": before})
    assert diff["identical"] is True
    assert {"section": "health_alerts", "op": "delta", "key": "CPU"}.items() <= diff["deltas"][0].items()
    reading = "health alert CPU reading: Data Path average is 85.12% -> Data Path average is 86.40%"
    assert reading in diff["findings"]
    cpu_alert(st, "RED", "Data Path average is 97.00%")
    worse = await call("fmc_diff_device_config", {"a": before})
    assert worse["identical"] is False and worse["summary"] == {"health_alerts": {"changed": 1}}


def test_diff_alerts_keeps_what_the_message_says() -> None:
    """Interface names, addresses and plain counts are no readings: a change in them is a change."""
    rows = diff_alerts(
        "health_alerts",
        {
            "INTERFACE": {"status": "RED", "details": "Interface 'Ethernet0/2' is not receiving any packets"},
            "DISK_USAGE": {"status": "YELLOW", "details": "/ngfw using 81%: 49.2G (11G Avail) of 61G"},
            "TUNNEL": {"status": "RED", "details": "Peer 192.0.2.1 down"},
            "SNORT": {"status": "YELLOW", "details": "3 instances down"},
        },
        {
            "INTERFACE": {"status": "RED", "details": "Interface 'Ethernet0/0' is not receiving any packets"},
            "DISK_USAGE": {"status": "YELLOW", "details": "/ngfw using 82%: 49.8G (10.4G Avail) of 61G"},
            "TUNNEL": {"status": "RED", "details": "Peer 192.0.2.9 down"},
            "SNORT": {"status": "YELLOW", "details": "4 instances down"},
        },
    )
    ops = {r["key"]: r["op"] for r in rows}
    assert ops == {"DISK_USAGE": "delta", "INTERFACE": "changed", "SNORT": "changed", "TUNNEL": "changed"}
    interface = next(r for r in rows if r["key"] == "INTERFACE")
    assert set(interface["fields"]) == {"details"}


async def test_snapshot_against_a_named_live_device(fmc: respx.MockRouter) -> None:
    """a=<before>, b=<the device> reads the device the way the snapshot was taken (state sections
    too), so the lost routes can't hide under not_compared behind 'identical'; and the other way round."""
    st = lab(fmc)
    out, _ = await snapshot(label="before", running_config=["route"])
    before = out["snapshots"]["mcp-sdwan-t1-spoke1"]
    wan_down(st)
    diff = await call("fmc_diff_device_config", {"a": before, "b": "mcp-sdwan-t1-spoke1"})
    assert diff["identical"] is False and "not_compared" not in diff
    assert diff["summary"]["route_table"] == {"removed": 3}
    assert "route_table" in diff["compared"] and "running_config" in diff["compared"]
    assert "show running-config route" in st["commands"][-4:]
    back = await call("fmc_diff_device_config", {"a": "mcp-sdwan-t1-spoke1", "b": before})
    assert back["identical"] is False and "not_compared" not in back
    assert back["summary"]["route_table"] == {"added": 3}
    assert "route added: 198.51.100.0/27 (static via 192.0.2.1 on mpls)" in back["findings"]


async def test_too_many_devices_refused_before_reading_them(fmc: respx.MockRouter) -> None:
    lab(fmc)
    n = len(fmc.calls)
    with pytest.raises(Exception, match="at most 25"):
        await call("fmc_device_snapshot", {"devices": [f"fw-{i}" for i in range(26)]})
    paths = [c.request.url.path for c in list(fmc.calls)[n:]]
    assert not any(p.startswith(f"{DEV}/") for p in paths), paths  # no record read per device
