"""Idempotently create the `mcp-test-*` objects and policies the live tests expect.

    uv run python scripts/seed_lab.py            # create what's missing
    uv run python scripts/seed_lab.py --delete   # remove everything seeded

Reads FMC_* from .env. Uses one FMC login.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any

from fmc_mcp._core import NotFound
from fmc_mcp.client import FmcApp
from fmc_mcp.config import Settings

HOSTS = {"mcp-test-web": "10.10.10.80", "mcp-test-db": "10.10.20.5", "mcp-test-unused": "10.99.99.99"}
NETWORKS = {"mcp-test-dmz-net": "10.10.10.0/24", "mcp-test-app-net": "10.10.20.0/24"}
RANGES = {"mcp-test-range": "10.10.30.10-10.10.30.20"}
PORTS = {"mcp-test-tcp-8443": ("TCP", "8443"), "mcp-test-udp-5000s": ("UDP", "5000-5100")}
ZONES = ["mcp-test-inside", "mcp-test-outside"]
ACP = "mcp-test-acp"
NAT = "mcp-test-nat"


class Seeder:
    def __init__(self, app: FmcApp) -> None:
        self.app = app
        self.ids: dict[str, dict[str, Any]] = {}

    async def path(self, suffix: str) -> str:
        return await self.app.config_path(suffix)

    async def find(self, collection: str, name: str) -> dict[str, Any] | None:
        page = await self.app.all(await self.path(collection), expanded=False)
        for i in page.items:
            if i.get("name") == name:
                return dict(i)
        return None

    async def ensure(self, collection: str, body: dict[str, Any]) -> dict[str, Any]:
        found = await self.find(collection, body["name"])
        if found is None:
            found = await self.app.api.post(await self.path(collection), body)
            print(f"created {collection} {body['name']}")
        assert found is not None
        ref = {"id": found["id"], "type": found["type"], "name": found["name"]}
        self.ids[body["name"]] = ref
        return ref

    async def seed(self) -> None:
        for name, value in HOSTS.items():
            await self.ensure("object/hosts", {"name": name, "value": value, "type": "Host"})
        for name, value in NETWORKS.items():
            await self.ensure("object/networks", {"name": name, "value": value, "type": "Network"})
        for name, value in RANGES.items():
            await self.ensure("object/ranges", {"name": name, "value": value, "type": "Range"})
        for name, (proto, port) in PORTS.items():
            await self.ensure(
                "object/protocolportobjects",
                {"name": name, "protocol": proto, "port": port, "type": "ProtocolPortObject"},
            )
        for name in ZONES:
            await self.ensure(
                "object/securityzones", {"name": name, "interfaceMode": "ROUTED", "type": "SecurityZone"}
            )
        https = await self.find("object/protocolportobjects", "HTTPS")
        assert https is not None
        await self.ensure(
            "object/networkgroups",
            {
                "name": "mcp-test-servers",
                "type": "NetworkGroup",
                "objects": [self.ids["mcp-test-web"], self.ids["mcp-test-app-net"]],
                "literals": [{"type": "Network", "value": "10.10.40.0/24"}],
            },
        )
        await self.ensure(
            "object/portobjectgroups",
            {
                "name": "mcp-test-web-ports",
                "type": "PortObjectGroup",
                "objects": [
                    {"id": https["id"], "type": "ProtocolPortObject"},
                    self.ids["mcp-test-tcp-8443"],
                ],
            },
        )
        await self.ensure(
            "object/urls", {"name": "mcp-test-url", "url": "https://example.com", "type": "Url"}
        )

        acp = await self.ensure(
            "policy/accesspolicies",
            {
                "name": ACP,
                "type": "AccessPolicy",
                "defaultAction": {"action": "BLOCK"},
                "description": "mcp live tests",
            },
        )
        rules_path = await self.path(f"policy/accesspolicies/{acp['id']}/accessrules")
        existing = await self.app.all(rules_path, expanded=False)
        if not existing.items:
            ids = self.ids
            rules: list[dict[str, Any]] = [
                {
                    "name": "mcp-test-allow-web",
                    "action": "ALLOW",
                    "enabled": True,
                    "destinationNetworks": {"objects": [ids["mcp-test-servers"]]},
                    "destinationPorts": {"objects": [ids["mcp-test-web-ports"]]},
                },
                {
                    "name": "mcp-test-ssh-admin",
                    "action": "ALLOW",
                    "enabled": True,
                    "sourceZones": {"objects": [ids["mcp-test-inside"]]},
                    "sourceNetworks": {"literals": [{"type": "Network", "value": "10.0.0.0/8"}]},
                    "destinationNetworks": {"objects": [ids["mcp-test-db"]]},
                    "destinationPorts": {
                        "literals": [{"type": "PortLiteral", "protocol": "6", "port": "22"}]
                    },
                },
                {
                    "name": "mcp-test-redundant",
                    "action": "ALLOW",
                    "enabled": True,
                    "destinationNetworks": {"objects": [ids["mcp-test-web"]]},
                    "destinationPorts": {"objects": [{"id": https["id"], "type": "ProtocolPortObject"}]},
                },
                {
                    "name": "mcp-test-block-app",
                    "action": "BLOCK",
                    "enabled": True,
                    "destinationNetworks": {"objects": [ids["mcp-test-app-net"]]},
                },
                {
                    "name": "mcp-test-shadowed",
                    "action": "ALLOW",
                    "enabled": True,
                    "destinationNetworks": {"objects": [ids["mcp-test-db"]]},
                    "destinationPorts": {
                        "literals": [{"type": "PortLiteral", "protocol": "6", "port": "3306"}]
                    },
                },
                {
                    "name": "mcp-test-url-rule",
                    "action": "ALLOW",
                    "enabled": True,
                    "urls": {"objects": [ids["mcp-test-url"]]},
                },
                {
                    "name": "mcp-test-disabled",
                    "action": "ALLOW",
                    "enabled": False,
                    "destinationNetworks": {"objects": [ids["mcp-test-range"]]},
                },
            ]
            await self.app.api.post(rules_path, rules, params={"bulk": "true"})
            print(f"created {len(rules)} rules in {ACP}")

        nat = await self.ensure("policy/ftdnatpolicies", {"name": NAT, "type": "FTDNatPolicy"})
        nat_rules = await self.path(f"policy/ftdnatpolicies/{nat['id']}/natrules")
        if not (await self.app.all(nat_rules, expanded=False)).items:
            await self.app.api.post(
                await self.path(f"policy/ftdnatpolicies/{nat['id']}/autonatrules"),
                {
                    "type": "FTDAutoNatRule",
                    "natType": "STATIC",
                    "originalNetwork": self.ids["mcp-test-web"],
                    "translatedNetwork": self.ids["mcp-test-db"],
                },
            )
            await self.app.api.post(
                await self.path(f"policy/ftdnatpolicies/{nat['id']}/manualnatrules"),
                {
                    "type": "FTDManualNatRule",
                    "natType": "STATIC",
                    "enabled": True,
                    "originalSource": self.ids["mcp-test-dmz-net"],
                    "translatedSource": self.ids["mcp-test-app-net"],
                    "description": "mcp live tests",
                },
                params={"section": "before_auto"},
            )
            print(f"created NAT rules in {NAT}")

    async def delete(self) -> None:
        order = [
            ("policy/accesspolicies", [ACP]),
            ("policy/ftdnatpolicies", [NAT]),
            ("object/networkgroups", ["mcp-test-servers"]),
            ("object/portobjectgroups", ["mcp-test-web-ports"]),
            ("object/urls", ["mcp-test-url"]),
            ("object/hosts", list(HOSTS)),
            ("object/networks", list(NETWORKS)),
            ("object/ranges", list(RANGES)),
            ("object/protocolportobjects", list(PORTS)),
            ("object/securityzones", ZONES),
        ]
        for collection, names in order:
            for name in names:
                found = await self.find(collection, name)
                if found:
                    try:
                        await self.app.api.delete(f"{await self.path(collection)}/{found['id']}")
                        print(f"deleted {collection} {name}")
                    except NotFound:
                        pass


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete", action="store_true")
    args = parser.parse_args()
    app = FmcApp(Settings())  # type: ignore[call-arg]
    try:
        seeder = Seeder(app)
        await (seeder.delete() if args.delete else seeder.seed())
    finally:
        await app.aclose()


if __name__ == "__main__":
    asyncio.run(main())
