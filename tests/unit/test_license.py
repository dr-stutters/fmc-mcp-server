"""fmc_license_status and the VPN strong-crypto check read FMC 10's smart-licence metadata."""

import copy
from typing import Any

import httpx
import pytest
import respx

from fmc_mcp._core.testing import call_tool
from fmc_mcp.server import create_server
from fmc_mcp.tools.common import smart_license_row
from fmc_mcp.tools.vpn import strong_crypto_allowed

from .conftest import CFG, fixture, items, make_settings

SMART = "/api/fmc_platform/v1/license/smartlicenses"
DEVICE_LICENSES = "/api/fmc_platform/v1/license/devicelicenses"

# Shape recorded from FMC 10.0.1 (account name replaced): the status lives in items[].metadata.
OUT_OF_COMPLIANCE = {
    "regStatus": "REGISTERED",
    "force": "false",
    "type": "SmartLicense",
    "metadata": {
        "authStatus": "OUT_OF_COMPLIANCE",
        "virtualAccount": "mcp-test-va",
        "exportControl": False,
        "evalUsed": True,
        "evalExpiresInDays": 0,
        "lastSynchronizedTime": "2026-10-17T12:51:31UTC",
        "lastRenewedTime": "2026-10-17T11:44:05UTC",
    },
}


async def test_license_status_keeps_smart_license_metadata(fmc: respx.MockRouter) -> None:
    fmc.get(SMART).mock(return_value=items([OUT_OF_COMPLIANCE]))
    fmc.get(DEVICE_LICENSES).mock(return_value=items([]))
    data = await call_tool(create_server(make_settings()), "fmc_license_status", {})
    row = data["smart_license"][0]
    assert row["regStatus"] == "REGISTERED"
    assert row["authStatus"] == "OUT_OF_COMPLIANCE"
    assert row["virtualAccount"] == "mcp-test-va"
    assert row["evalUsed"] is True and row["evalExpiresInDays"] == 0
    assert row["exportControl"] is False
    assert row["lastSynchronizedTime"] == "2026-10-17T12:51:31UTC"
    assert "metadata" not in row and data["device_licenses"] == []


def test_smart_license_row_top_level_wins_and_links_dropped() -> None:
    row = smart_license_row(
        {"regStatus": "EVALUATION", "links": {}, "metadata": {"regStatus": "x", "links": {}}}
    )
    assert row == {"regStatus": "EVALUATION"}
    assert smart_license_row({"regStatus": "UNREGISTERED"}) == {"regStatus": "UNREGISTERED"}


class _Api:
    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body

    async def get(self, path: str, params: Any = None) -> dict[str, Any]:
        assert path == SMART
        return self.body


class _App:
    def __init__(self, body: dict[str, Any]) -> None:
        self.api = _Api(body)


async def test_strong_crypto_reads_export_control_from_metadata() -> None:
    assert await strong_crypto_allowed(_App({"items": [OUT_OF_COMPLIANCE]})) is False  # type: ignore[arg-type]
    allowed = {**OUT_OF_COMPLIANCE, "metadata": {**OUT_OF_COMPLIANCE["metadata"], "exportControl": True}}
    assert await strong_crypto_allowed(_App({"items": [allowed]})) is True  # type: ignore[arg-type]


# --- device licences by name, with what the access policy needs (#206) --------------------------------
# Eval on FMC 10.0.1: device_licenses listed 19 rows by UUID only.

LAB = fixture("license_devices")
POLICIES = {
    "mcp-fw-base-acp": "00000000-0000-0ed3-0000-021474903666",
    "mcp-test-ha-acp": "00000000-0000-0ed3-0000-021474837244",
    "mcp-fw-threat-acp": "00000000-0000-0ed3-0000-021474901848",
    "mcp-test-ftd-acp": "00000000-0000-0ed3-0000-021474837072",
    "mcp-sdwan-acp": "00000000-0000-0ed3-0000-021474856047",
}
IPS_REF = {"id": "ips-1", "name": "mcp-ips", "type": "IntrusionPolicy"}


def _rule(name: str, **kw: Any) -> dict[str, Any]:
    return {"id": f"r-{name}", "name": name, "action": "ALLOW", "enabled": True, "type": "AccessRule", **kw}


def licence_lab(fmc: respx.MockRouter) -> dict[str, respx.Route]:
    fmc.get(SMART).mock(return_value=items([OUT_OF_COMPLIANCE]))
    fmc.get(DEVICE_LICENSES).mock(return_value=httpx.Response(200, json=LAB["devicelicenses"]))
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=httpx.Response(200, json=LAB["devicerecords"]))
    default = {"action": "BLOCK", "type": "AccessPolicyDefaultAction"}
    settings = {
        # the base policy inspects with an intrusion policy on its default action
        "mcp-fw-base-acp": ({**default, "action": "PERMIT", "intrusionPolicy": IPS_REF}, []),
        "mcp-test-ha-acp": (default, [_rule("web", ipsPolicy=IPS_REF)]),
        "mcp-fw-threat-acp": (default, [_rule("files", filePolicy={"id": "f-1", "name": "mcp-files"})]),
        "mcp-test-ftd-acp": (
            default,
            [
                _rule("cats", urls={"urlCategoriesWithReputation": [{"category": {"name": "Gambling"}}]}),
                _rule("off", enabled=False, ipsPolicy=IPS_REF),
            ],
        ),
        "mcp-sdwan-acp": (default, [_rule("any"), _rule("block", action="BLOCK", ipsPolicy=IPS_REF)]),
    }
    routes = {}
    for name, pid in POLICIES.items():
        da, rules = settings[name]
        routes[name] = fmc.get(f"{CFG}/policy/accesspolicies/{pid}").mock(
            return_value=httpx.Response(200, json={"id": pid, "name": name, "defaultAction": da})
        )
        fmc.get(f"{CFG}/policy/accesspolicies/{pid}/accessrules").mock(return_value=items(rules))
    return routes


async def test_device_licences_are_named_with_role_needs_and_missing(fmc: respx.MockRouter) -> None:
    licence_lab(fmc)
    data = await call_tool(create_server(make_settings()), "fmc_license_status", {})
    rows = {r["name"]: r for r in data["device_licenses"]}
    assert len(rows) == 19 and all(r.get("id") for r in rows.values())
    ha_a = rows["mcp-fw-ha-a"]
    assert ha_a["ha_or_cluster"] == "mcp-fw-ha (primary, active)"
    assert (ha_a["licences"], ha_a["needs"], ha_a["missing"]) == (["ESSENTIALS"], ["IPS"], ["IPS"])
    assert ha_a["why"] == "IPS: intrusion policy on the default action" and ha_a["connected"] is False
    assert rows["mcp-fw-ha-b"]["ha_or_cluster"] == "mcp-fw-ha (secondary, standby)"
    # FMC's *_HA entitlements of an HA unit are the plain licences
    assert rows["mcp-ftd2"]["licences"] == ["ESSENTIALS", "IPS", "MALWARE_DEFENSE", "URL"]
    assert (rows["mcp-ftd2"]["needs"], rows["mcp-ftd2"]["missing"]) == (["IPS"], [])
    assert (
        rows["mcp-ftd-identity"]["needs"] == ["MALWARE_DEFENSE"] and rows["mcp-ftd-identity"]["missing"] == []
    )
    assert rows["mcp-ftd1"]["needs"] == ["URL"]  # the disabled rule's intrusion policy doesn't count
    assert rows["mcp-sdwan-t3-hub"]["ha_or_cluster"] == "mcp-sdwan-t3-cluster (control)"
    assert rows["mcp-sdwan-t1-hub"]["needs"] == []  # a BLOCK rule's intrusion policy doesn't count
    assert rows["mcp-fw-ha-a"]["access_policy"] == "mcp-fw-base-acp"
    assert sorted(data["missing"]) == ["mcp-fw-branch1 (IPS)", "mcp-fw-ha-a (IPS)", "mcp-fw-ha-b (IPS)"]
    assert data["summary"] == "3 of 19 device(s) lack a licence their access policy needs (see missing)"
    assert "not_checked" not in data
    assert data["smart_license"][0]["authStatus"] == "OUT_OF_COMPLIANCE" and "notes" not in data


async def test_licences_without_the_policy_check_and_unknown_devices(fmc: respx.MockRouter) -> None:
    routes = licence_lab(fmc)
    lic = copy.deepcopy(LAB["devicelicenses"])
    lic["items"].append({"licenseTypes": ["ESSENTIALS"], "id": "0f000000-0000-4000-8000-00000000000f"})
    fmc.get(DEVICE_LICENSES).mock(return_value=httpx.Response(200, json=lic))
    data = await call_tool(create_server(make_settings()), "fmc_license_status", {"check_policies": False})
    assert not any(r.called for r in routes.values())
    assert "missing" not in data and all("needs" not in r for r in data["device_licenses"])
    other = next(r for r in data["device_licenses"] if r["id"].startswith("0f000000"))
    assert "name" not in other and "1 licensed device(s) are not in this domain" in data["notes"][0]


async def test_the_all_clear_only_when_every_device_was_checked(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review of #232: a device outside the domain's list, one without an access policy, an unreadable
    policy and one past the cap are 'not checked', never part of an all-clear."""
    routes = licence_lab(fmc)
    # nobody lacks anything: the base policy no longer needs IPS
    routes["mcp-fw-base-acp"].mock(
        return_value=httpx.Response(200, json={"id": POLICIES["mcp-fw-base-acp"], "name": "mcp-fw-base-acp"})
    )
    data = await call_tool(create_server(make_settings()), "fmc_license_status", {})
    assert data["summary"] == "Every device (19) holds the licences its access policy needs"
    assert data["missing"] == [] and "not_checked" not in data
    # now: one licence row outside the domain, one device without a policy, one policy unreadable
    lic = copy.deepcopy(LAB["devicelicenses"])
    lic["items"].append({"licenseTypes": ["ESSENTIALS"], "id": "0f000000-0000-4000-8000-00000000000f"})
    fmc.get(DEVICE_LICENSES).mock(return_value=httpx.Response(200, json=lic))
    records = copy.deepcopy(LAB["devicerecords"])
    nopolicy = next(r for r in records["items"] if r["name"] == "mcp-ftd1")
    del nopolicy["accessPolicy"]
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=httpx.Response(200, json=records))
    routes["mcp-fw-threat-acp"].mock(return_value=httpx.Response(403, json={}))
    data = await call_tool(create_server(make_settings()), "fmc_license_status", {})
    assert (
        data["summary"] == "No checked device lacks a licence, but 3 of 20 were not checked (see not_checked)"
    )
    assert sorted(data["not_checked"]) == [
        "0f000000-0000-4000-8000-00000000000f (not in this domain's device list (pass `domain`))",
        "mcp-ftd-identity (access policy 'mcp-fw-threat-acp' not readable)",
        "mcp-ftd1 (no access policy assigned)",
    ]
    assert any("not readable" in n for n in data["notes"])
    # past the cap of policies read: those devices are not checked either
    from fmc_mcp.tools import system

    monkeypatch.setattr(system, "LICENCE_POLICY_CAP", 1)
    data = await call_tool(create_server(make_settings()), "fmc_license_status", {})
    assert "were not checked" in data["summary"]
    assert any("past the first 1 read" in n for n in data["not_checked"])
