"""Idempotently create the lab's identity setup (roadmap F13 identity) on FMC:

- trusted CA `mcp-test-mitchcloud-CA` (the lab AD's root CA, for LDAPS once the DC has a certificate),
- AD realm `mcp-test-mitchcloud` (DC01.mitchcloud.lab 198.18.130.11:389, group base OU=MCP-Lab),
  then a user/group download (expects the four mcp-* groups),
- identity policy `mcp-test-idp` with a PASSIVE rule for the realm (10.99.1.0/24),
- `mcp-test-idp` selected in access policy `mcp-test-ftd-acp` (FMC's REST API can't do that: drives
  the FMC web UI in headless Chromium as the administrator from .env.admin, like seed_domain.py).

    uv run --with playwright python scripts/seed_identity.py
    uv run python scripts/seed_identity.py --no-link     # skip the UI step (no Playwright needed)
    uv run python scripts/seed_identity.py --delete      # rule, policy, realm, CA (unlink in the UI first)

Reads FMC_* (and FMC_UI_* for the download) from .env, the administrator from .env.admin, and the AD bind
account LAB_AD_BIND_USER / LAB_AD_BIND_PASSWORD from the environment or ~/MCP-Suite/lab-secrets.env.
Run scripts/seed_access.py first (users mcp-api-rw / mcp-ui-svc). Deploy afterwards (fmc_deploy).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import dotenv_values
from stutters_mcp_core import NotFound

from fmc_mcp.client import FmcApp
from fmc_mcp.config import Settings
from fmc_mcp.tools.identity import fmc_fingerprint, pem_body
from fmc_mcp.ui import FmcUiSession

sys.path.insert(0, str(Path(__file__).resolve().parent))
from seed_domain import chromium, load_env  # noqa: E402

CA_NAME = "mcp-test-mitchcloud-CA"
CA_FILE = Path(os.environ.get("LAB_CA_PEM", "~/MCP-Suite/lab-ca/mitchcloud-CA.pem")).expanduser()
REALM = "mcp-test-mitchcloud"
DC = "198.18.130.11"
BASE_DN = "DC=mitchcloud,DC=lab"
GROUP_DN = "OU=MCP-Lab,DC=mitchcloud,DC=lab"
AD_DOMAIN = "mitchcloud.lab"
IDP = "mcp-test-idp"
IDP_RULE = "mcp-test-passive"
INSIDE = "10.99.1.0/24"
ACP = "mcp-test-ftd-acp"
SECRETS = Path("~/MCP-Suite/lab-secrets.env").expanduser()
FAILURE_PNG = str(Path(__file__).resolve().parent.parent / "seed_identity_failure.png")


def bind_account() -> tuple[str, str]:
    env = dict(os.environ)
    if SECRETS.exists():
        env = {**{k: v for k, v in dotenv_values(SECRETS).items() if v is not None}, **env}
    user, pw = env.get("LAB_AD_BIND_USER"), env.get("LAB_AD_BIND_PASSWORD")
    if not user or not pw:
        sys.exit("LAB_AD_BIND_USER / LAB_AD_BIND_PASSWORD missing (environment or lab-secrets.env)")
    return (user if "@" in user or "\\" in user else f"{user}@{AD_DOMAIN}"), pw


class Seeder:
    def __init__(self, app: FmcApp) -> None:
        self.app = app

    async def path(self, suffix: str) -> str:
        return await self.app.config_path(suffix)

    async def find(self, collection: str, name: str) -> dict[str, Any] | None:
        page = await self.app.all(await self.path(collection))
        return next((dict(i) for i in page.items if i.get("name") == name), None)

    async def ca(self) -> None:
        if not CA_FILE.exists():
            print(f"trusted CA: skipped ({CA_FILE} missing)")
            return
        text, der = pem_body(CA_FILE.read_text())
        fp = fmc_fingerprint(der)
        page = await self.app.all(await self.path("object/externalcacertificates"))
        same = [c for c in page.items if c.get("name") == CA_NAME or c.get("certFingerprint") == fp]
        if same:
            print(f"trusted CA {CA_NAME}: ok ({same[0].get('name')})")
            return
        body = {"name": CA_NAME, "type": "ExternalCACertificate", "cert": text}
        await self.app.api.post(await self.path("object/externalcacertificates"), body)
        print(f"trusted CA {CA_NAME}: created")

    async def realm(self) -> dict[str, Any]:
        found = await self.find("object/realms", REALM)
        if found:
            print(f"realm {REALM}: ok")
            return found
        user, pw = bind_account()
        body = {
            "name": REALM,
            "type": "Realm",
            "realmType": "AD",
            "description": "lab AD (DC01.mitchcloud.lab), scripts/seed_identity.py",
            "adPrimaryDomain": AD_DOMAIN,
            "baseDn": BASE_DN,
            "groupDn": GROUP_DN,
            "groupAttribute": "member",
            "dirUsername": user,
            "dirPassword": pw,
            "directoryConfigurations": [
                {
                    "id": 0,
                    "hostname": DC,
                    "port": 389,
                    "encryptionProtocol": "NONE",
                    "useRoutingToSelectInterface": False,
                }
            ],
            "updateHour": 0,
            "updateInterval": 24,
            "enabled": True,
        }
        created: dict[str, Any] = await self.app.api.post(await self.path("object/realms"), body)
        print(f"realm {REALM}: created")
        return created

    async def download(self, realm: dict[str, Any]) -> None:
        groups = await self.app.all(await self.path("object/realmusergroups"))
        have = {g.get("name") for g in groups.items if (g.get("realm") or {}).get("id") == realm["id"]}
        if {"mcp-employees", "mcp-contractors", "mcp-netadmins", "mcp-netreadonly"} <= have:
            print(f"realm download: ok ({len(have)} groups)")
            return
        try:
            async with FmcUiSession(self.app.settings) as ui:
                await ui.pjb("SF::IdentityRealm::IdentityRealm::refreshRealm", [realm["id"]])
        except Exception as e:  # noqa: BLE001 - report and continue (FMC also downloads daily)
            print(f"realm download: FAILED to start ({e}); use fmc_download_realm or the realm page")
            return
        for _ in range(30):
            await asyncio.sleep(3)
            groups = await self.app.all(await self.path("object/realmusergroups"))
            have = {g.get("name") for g in groups.items if (g.get("realm") or {}).get("id") == realm["id"]}
            if len(have) >= 4:
                break
        print(f"realm download: {len(have)} groups {sorted(n for n in have if n)}")

    async def identity_policy(self, realm: dict[str, Any]) -> dict[str, Any]:
        idp = await self.find("policy/identitypolicies", IDP)
        if idp is None:
            idp = await self.app.api.post(
                await self.path("policy/identitypolicies"),
                {
                    "name": IDP,
                    "type": "IdentityPolicy",
                    "description": "lab identity policy (seed_identity.py)",
                },
            )
            print(f"identity policy {IDP}: created")
        assert idp is not None
        base = await self.path(f"policy/identitypolicies/{idp['id']}")
        rules = await self.app.all(f"{base}/identityrules")
        if any(r.get("name") == IDP_RULE for r in rules.items):
            print(f"identity rule {IDP_RULE}: ok")
            return idp
        cats = await self.app.all(f"{base}/identitycategories")
        cat = next(c for c in cats.items if c.get("name") == "standard_category")
        body = {
            "name": IDP_RULE,
            "type": "IdentityPolicyRule",
            "enabled": True,
            "authenticationType": "PASSIVE",
            "realm": {"id": realm["id"], "type": "IdentityRealm", "name": REALM},
            "sourceNetworks": {"literals": [{"type": "Network", "value": INSIDE}]},
        }
        await self.app.api.post(f"{base}/identityrules", body, params={"intoCategory": cat["id"]})
        print(f"identity rule {IDP_RULE}: created")
        return idp

    async def linked(self) -> tuple[dict[str, Any] | None, bool]:
        acp = await self.find("policy/accesspolicies", ACP)
        if acp is None:
            return None, False
        full = await self.app.api.get(await self.path(f"policy/accesspolicies/{acp['id']}"))
        return acp, (full.get("identityPolicySetting") or {}).get("name") == IDP

    async def delete(self) -> None:
        acp, linked = await self.linked()
        if linked:
            sys.exit(f"{IDP} is still selected in {ACP}: pick 'None' in its Identity step (UI) first")
        for collection, name in (
            ("policy/identitypolicies", IDP),
            ("object/realms", REALM),
            ("object/externalcacertificates", CA_NAME),
        ):
            found = await self.find(collection, name)
            if found:
                with contextlib.suppress(NotFound):
                    await self.app.api.delete(f"{await self.path(collection)}/{found['id']}")
                    print(f"deleted {collection} {name}")


async def link_in_ui(url: str, admin: tuple[str, str], acp_id: str) -> None:
    """Select IDP in the access policy editor's Identity step and save (GWT UI; no REST equivalent)."""
    from playwright.async_api import async_playwright  # type: ignore[import-not-found,unused-ignore]

    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=chromium(), args=["--ignore-certificate-errors"])
        page = await (
            await browser.new_context(ignore_https_errors=True, viewport={"width": 1600, "height": 1000})
        ).new_page()
        try:
            await page.goto(url + "/ui/login", wait_until="networkidle")
            await page.get_by_label("Username").fill(admin[0])
            await page.get_by_label("Password").fill(admin[1])
            await page.keyboard.press("Enter")
            await page.wait_for_timeout(5000)
            end = page.get_by_role("button", name="End Existing Session")
            if await end.count():
                await end.click()
                await page.wait_for_timeout(8000)
            with contextlib.suppress(Exception):
                await page.goto(
                    f"{url}/ddd/#FirewallPolicyEditor;uuid={acp_id};type=PG.FIREWALL.NGFWAccessControlPolicy",
                    wait_until="domcontentloaded",
                )
            await page.wait_for_timeout(25000)
            await page.get_by_text("Identity", exact=True).first.click()
            await page.wait_for_timeout(3000)
            await page.get_by_test_id("tabPopoverSelect").first.click()
            await page.keyboard.type(IDP)
            await page.keyboard.press("Enter")
            await page.wait_for_timeout(2000)
            await page.get_by_role("button", name="Apply").first.click()
            await page.wait_for_timeout(3000)
            await page.get_by_role("button", name="Save").first.click()
            await page.wait_for_timeout(10000)
        except Exception:
            await page.screenshot(path=FAILURE_PNG)
            raise
        finally:
            await browser.close()


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--delete", action="store_true")
    ap.add_argument("--no-link", action="store_true", help="skip selecting the policy in the ACP (UI)")
    args = ap.parse_args()
    env = load_env()
    app = FmcApp(Settings())  # type: ignore[call-arg]
    try:
        seeder = Seeder(app)
        if args.delete:
            await seeder.delete()
            return
        await seeder.ca()
        realm = await seeder.realm()
        await seeder.download(realm)
        await seeder.identity_policy(realm)
        acp, linked = await seeder.linked()
        if acp is None:
            print(f"link: skipped ({ACP} missing; build the ftd-fmc lab first)")
        elif linked:
            print(f"link {ACP} -> {IDP}: ok")
        elif args.no_link:
            print(f"link {ACP} -> {IDP}: MISSING (select it in the ACP's Identity step)")
        else:
            admin = (
                env.get("FMC_ADMIN_USERNAME") or sys.exit("FMC_ADMIN_USERNAME missing (.env.admin)"),
                env.get("FMC_ADMIN_PASSWORD") or sys.exit("FMC_ADMIN_PASSWORD missing (.env.admin)"),
            )
            await link_in_ui(str(env["FMC_URL"]).rstrip("/"), admin, str(acp["id"]))
            _, linked = await seeder.linked()
            print(f"link {ACP} -> {IDP}: {'linked' if linked else 'FAILED (see seed_identity_failure.png)'}")
        print("next: fmc_deploy mcp-ftd1")
    finally:
        await app.aclose()


if __name__ == "__main__":
    asyncio.run(main())
