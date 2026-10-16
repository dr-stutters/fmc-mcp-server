"""Create the lab's leaf domain `Global/mcp-test-leaf` and move an FTD into it (roadmap F19).

    uv run --with playwright python scripts/seed_domain.py                     # mcp-test-leaf with mcp-ftd1
    uv run --with playwright python scripts/seed_domain.py --name X --device Y

FMC's REST API can't create domains (`/info/domain` is read-only) and the UI's save call
(`SF::MultiTenancy::saveDomainManagerChanges`) takes the whole domain tree, so this drives the FMC web UI
in headless Chromium as the administrator from `.env.admin`: Administration > Domains > Add Domain, add the
device, Save, keep the default event handling, Save. FMC then needs a deploy to the moved device
(`fmc_deploy`), which this script does not do. Devices can only live in leaf domains, so once Global has a
child every device must be in a leaf. Idempotent: does nothing when the domain already exists.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import glob
import os
import sys
from pathlib import Path

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for name in (".env", ".env.admin"):
        path = ROOT / name
        if path.exists():
            env.update({k: v for k, v in dotenv_values(path).items() if v is not None})
    return env


def domains(url: str, verify: bool, admin: tuple[str, str]) -> list[str]:
    with httpx.Client(base_url=url.rstrip("/"), verify=verify, timeout=60) as http:
        resp = http.post("/api/fmc_platform/v1/auth/generatetoken", auth=admin)
        if resp.status_code != 204:
            sys.exit(f"REST login failed (HTTP {resp.status_code})")
        data = http.get(
            "/api/fmc_platform/v1/info/domain",
            headers={"X-auth-access-token": resp.headers["X-auth-access-token"]},
        ).json()
    return [str(d.get("name")) for d in data.get("items", [])]


def chromium() -> str | None:
    found = sorted(glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome")))
    return found[-1] if found else None


async def create(url: str, admin: tuple[str, str], name: str, device: str) -> None:
    from playwright.async_api import async_playwright  # type: ignore[import-not-found,unused-ignore]

    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=chromium(), args=["--ignore-certificate-errors"])
        page = await (await browser.new_context(ignore_https_errors=True)).new_page()
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
            # the page keeps polling, so the load event may time out; the elements matter
            with contextlib.suppress(Exception):
                await page.goto(url + "/ddd/#Domains", wait_until="domcontentloaded")
            await page.wait_for_timeout(10000)
            await page.get_by_text("Add Domain").first.click()
            await page.wait_for_timeout(3000)
            field = page.locator("text=Name:").first.locator("xpath=following::input[1]")
            await field.click()
            await field.type(name)
            await page.get_by_text(device, exact=True).first.click()
            await page.get_by_text("Add to Domain").first.click()
            await page.wait_for_timeout(1000)
            await page.get_by_role("button", name="Save").last.click()  # the Add Domain dialog
            await page.wait_for_timeout(4000)
            await page.get_by_role("button", name="Save").first.click()  # the domain page
            await page.wait_for_timeout(15000)
            # "Archive/Inherit Events": keep the default (archive Global's events), then Save
            await page.get_by_role("button", name="Save").last.click()
            await page.wait_for_timeout(10000)
            ok = page.get_by_text("Save Successful")
            if not await ok.count():
                await page.screenshot(path=str(ROOT / "seed_domain_failure.png"))
                sys.exit("FMC did not confirm the domain save; see seed_domain_failure.png")
        finally:
            await browser.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", default="mcp-test-leaf")
    ap.add_argument("--device", default="mcp-ftd1", help="device to move into the new leaf domain")
    args = ap.parse_args()
    env = load_env()
    url = (env.get("FMC_URL") or sys.exit("FMC_URL missing in .env")).rstrip("/")
    verify = (env.get("FMC_VERIFY_SSL") or "true").lower() not in ("false", "0", "no")
    admin = (
        env.get("FMC_ADMIN_USERNAME") or sys.exit("FMC_ADMIN_USERNAME missing (.env.admin)"),
        env.get("FMC_ADMIN_PASSWORD") or sys.exit("FMC_ADMIN_PASSWORD missing (.env.admin)"),
    )
    if f"Global/{args.name}" in domains(url, verify, admin):
        print(f"domain Global/{args.name}: ok (exists)")
        return
    asyncio.run(create(url, admin, args.name, args.device))
    have = domains(url, verify, admin)
    print(f"domain Global/{args.name}: {'created' if f'Global/{args.name}' in have else 'MISSING'}")
    print(f"next: fmc_deploy {args.device} (FMC marks the moved device out of date)")


if __name__ == "__main__":
    main()
