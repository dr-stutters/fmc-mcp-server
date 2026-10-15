"""Idempotently create the least-privilege FMC roles and API users (roadmap F16), and the lab leaf domain.

    uv run python scripts/seed_access.py              # eval licence, roles mcp-ro / mcp-rw, users
    uv run python scripts/seed_access.py --check      # show what differs, change nothing
    uv run python scripts/seed_access.py --delete     # remove the users and roles again

FMC's REST API can't create user roles or users (`users/authroles` and `users/users` are GET-only in
FMC 10.0), so this drives the same internal endpoints the FMC web UI uses (`/auth/login`, `pjb.cgi`
`SF::Permission::*` for roles, the `/admin/user/user.cgi` form for users), logged in as an FMC
administrator. Those endpoints are not a public API: re-check them after an FMC upgrade
(docs/least-privilege.md explains the manual GUI steps as the fallback).

Credentials (never printed):
- `.env.admin`: FMC_ADMIN_USERNAME / FMC_ADMIN_PASSWORD, an FMC administrator (the seed login).
- `.env`: FMC_USERNAME / FMC_PASSWORD (live tests, role mcp-rw), FMC_RO_USERNAME / FMC_RO_PASSWORD
  (read-only live tests, role mcp-ro) and FMC_SVC_USERNAME / FMC_SVC_PASSWORD (the hosted container,
  role mcp-rw). A user whose variables are unset is skipped. Existing users keep their password unless
  --reset-passwords is given.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent

# --- role definitions (FMC 10.0 menu-based permission keys; docs/least-privilege.md explains each) ---------

RO_PERMISSIONS = [
    # Insights & Reports: dashboards (view)
    "overview",
    "dashboards",
    # Events & Logs > Analysis > Audit: fmc_list_audit_records, fmc_recent_activity
    "analysis",
    "container_analysis",
    "audit_log",
    # Policies (view): access control, intrusion, identity, decryption, prefilter, file, DNS, NAT, QoS
    "policy_response",
    "firewall_policy",
    "firewall",
    "intrusion_policy",
    "rules",
    "identity",
    "ssl",
    "prefilter_policy",
    "file_policy",
    "dns_policy",
    "umbrella_dns_policy",
    "network_policies",
    "nat_policy",
    "nat",
    "qos",
    # Objects (view)
    "object_manager",
    # Devices (view): device management, platform settings, FlexConfig, certificates
    "devices_container",
    "devices",
    "platform_settings",
    "flexconfig_policy",
    "certificates",
    # Secure Connections (VPN) view and the VPN dashboards: fmc_list_vpn_tunnels, fmc_get_vpn_topology
    "vpn",
    "vpn_dashboards",
    "s2s_vpn_dashboard",
    "ravpn_dashboard",
    "sd_wan_dashboard",
    # Integrations > Realms (view): identity policy realm lookups
    "registration",
    "identity_realms",
    # Troubleshooting: health monitor, health events, packet tracer, threat defense CLI (show commands)
    "advanced_troubleshooting",
    "health",
    "health_policy",
    "health_alarm_syslog",
    "troubleshooting_tools",
    "packet_tracer",
    # running a trace (simulated packet, no config change): fmc_packet_tracer is read tier
    "packet_tracer.modify",
    "threat_defense_cli",
    # Administration (view): upgrades and content updates, licences
    "system",
    "upgrade_updates",
    "device_upgrade",
    "update",
    "license",
    "smart_license",
]

RW_EXTRA = [
    # modify policies
    "firewall.modify",
    "ac_rule_inspection.modify",
    "ac_rule.modify",
    "intrusion_policy.modify",
    "rules.modify",
    "identity.modify",
    "ssl.modify",
    "prefilter_policy.modify",
    "file_policy.modify",
    "dns_policy.modify",
    "umbrella_dns_policy.modify",
    "nat.modify",
    "qos.modify",
    # modify objects, devices (interfaces, routing, HA, registration), platform settings, certificates, VPN
    "object_manager.modify",
    "devices.modify",
    "platform_settings.modify",
    "certificates.modify",
    "vpn.modify",
    # deploy configuration to devices (FMC adds the task-status permissions to any role with Deploy)
    "deploy",
    "task_status",
    "task_status.all_users",
    # health policies and CLI "modify" (run on the device)
    "health.modify",
    "health_policy.modify",
    "health_policy.apply",
    "threat_defense_cli.modify",
    # Administration > Advanced > Backup Management (device backups; no restore)
    "tools",
    "backup_management",
]

ROLES: dict[str, dict[str, Any]] = {
    "mcp-ro": {
        "description": "fmc-mcp-server read tier (view only). Managed by scripts/seed_access.py.",
        "permissions": RO_PERMISSIONS,
    },
    "mcp-rw": {
        "description": "fmc-mcp-server read + write + deploy tiers. Managed by scripts/seed_access.py.",
        "permissions": RO_PERMISSIONS + RW_EXTRA,
    },
}

# (env prefix for username/password, role)
USERS = [("FMC_RO_", "mcp-ro"), ("FMC_", "mcp-rw"), ("FMC_SVC_", "mcp-rw")]


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for name in (".env", ".env.admin"):
        path = ROOT / name
        if path.exists():
            env.update({k: v for k, v in dotenv_values(path).items() if v is not None})
    return env


class FmcUi:
    """A logged-in FMC web-UI session (cookie + CSRF token)."""

    def __init__(self, url: str, username: str, password: str, verify: bool) -> None:
        self.http = httpx.Client(base_url=url.rstrip("/"), verify=verify, timeout=60, follow_redirects=True)
        resp = self.http.post(
            "/auth/login",
            files={"username": (None, username), "password": (None, password), "endSession": (None, "1")},
        )
        try:
            self.csrf = resp.json()["session"]["csrfToken"]
        except (ValueError, KeyError, TypeError):
            sys.exit(f"FMC UI login as {username} failed (HTTP {resp.status_code}); check .env.admin")

    def close(self) -> None:
        self.http.get("/auth/logout")
        self.http.close()

    def pjb(self, function: str, params: list[Any]) -> Any:
        resp = self.http.post(
            "/pjb.cgi",
            data={
                "function": function,
                "parameters": json.dumps(params),
                "get_all_errors": "1",
                "sf_action_id": self.csrf,
            },
        )
        resp.raise_for_status()
        try:
            body = resp.json()
        except ValueError:
            raise RuntimeError(f"{function}: not JSON (session ended?): {resp.text[:200]}") from None
        if isinstance(body, dict) and body.get("redirect_url"):
            raise RuntimeError(f"{function}: the UI session ended (another login as the same user?)")
        if isinstance(body, dict) and body.get("error"):
            raise RuntimeError(f"{function}: {body['error']}")
        return body.get("data") if isinstance(body, dict) else body

    # --- roles -----------------------------------------------------------------------------------------

    def roles(self) -> dict[str, dict[str, Any]]:
        data = self.pjb("SF::Permission::getUserRolesPageData", [])
        return {r["data"]["name"]: r for r in data.get("userRoles", [])}

    def save_role(self, name: str, spec: dict[str, Any], existing: dict[str, Any] | None) -> None:
        params = [existing["uuid"]] if existing else []
        role = self.pjb("SF::Permission::getEditUserRolePageData", params)["userRole"]
        role["data"].update(
            {
                "name": name,
                "description": spec["description"],
                "is_active": 1,
                "permissions": {p: "1" for p in spec["permissions"]},
            }
        )
        self.pjb("SF::Permission::saveUserRole", [role])

    def delete_role(self, role: dict[str, Any]) -> None:
        self.pjb("SF::Permission::deleteUserRole", [role["uuid"]])

    # --- users -----------------------------------------------------------------------------------------

    def save_user(self, username: str, password: str | None, role_uuid: str, create: bool) -> None:
        form = {
            "mode": "create" if create else "edit",
            "username": username,
            "real_name": "fmc-mcp-server API user",
            "email": "",
            "minpasswordlength": "8",
            "maxfailedlogins": "5",
            "expiredate": "0",
            "warndate": "0",
            role_uuid: "on",
            "action_add": "Save",
            "sf_action_id": self.csrf,
        }
        if password is not None:
            form["new_password"] = form["new_password2"] = password
        else:  # the edit form re-posts the masked placeholder when the password is unchanged
            form["new_password"] = form["new_password2"] = "************"
        resp = self.http.post("/admin/user/user.cgi", data=form)
        resp.raise_for_status()
        if "error" in resp.url.path or "errormsg" in resp.text.lower():
            raise RuntimeError(f"saving user {username} failed (check FMC password rules)")

    def delete_user(self, username: str) -> None:
        resp = self.http.post(
            "/admin/user/user.cgi",
            data={"mode": "delete", "username": username, "sf_action_id": self.csrf},
        )
        resp.raise_for_status()


def api_users(url: str, verify: bool, admin: tuple[str, str]) -> dict[str, dict[str, Any]]:
    """Users and their roles from the REST API (users/users is readable)."""
    with httpx.Client(base_url=url.rstrip("/"), verify=verify, timeout=60) as http:
        resp = http.post("/api/fmc_platform/v1/auth/generatetoken", auth=admin)
        if resp.status_code != 204:
            sys.exit(f"REST login failed (HTTP {resp.status_code})")
        headers = {"X-auth-access-token": resp.headers["X-auth-access-token"]}
        domain = resp.headers["DOMAIN_UUID"]
        data = http.get(
            f"/api/fmc_config/v1/domain/{domain}/users/users",
            params={"expanded": "true", "limit": 1000},
            headers=headers,
        ).json()
    return {u["username"]: u for u in data.get("items", [])}


def ensure_eval_licence(url: str, verify: bool, admin: tuple[str, str]) -> str:
    """Smart Licensing evaluation mode (needs an administrator; mcp-rw can't register licences)."""
    with httpx.Client(base_url=url.rstrip("/"), verify=verify, timeout=60) as http:
        resp = http.post("/api/fmc_platform/v1/auth/generatetoken", auth=admin)
        if resp.status_code != 204:
            sys.exit(f"REST login failed (HTTP {resp.status_code})")
        headers = {"X-auth-access-token": resp.headers["X-auth-access-token"]}
        path = "/api/fmc_platform/v1/license/smartlicenses"
        items = http.get(path, headers=headers).json().get("items") or [{}]
        status = str(items[0].get("regStatus", "UNKNOWN"))
        if status in ("EVALUATION", "REGISTERED"):
            return f"licence: ok ({status})"
        done = http.post(path, headers=headers, json={"registrationType": "EVALUATION"})
        if done.is_error:
            sys.exit(f"licence: {status}; switching to evaluation mode failed (HTTP {done.status_code})")
        return f"licence: {status} -> evaluation (HTTP {done.status_code})"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="report differences only")
    ap.add_argument("--delete", action="store_true", help="delete the users and roles")
    ap.add_argument("--no-licence", action="store_true", help="don't check Smart Licensing evaluation mode")
    ap.add_argument("--reset-passwords", action="store_true", help="set existing users' passwords from .env")
    args = ap.parse_args()

    env = load_env()
    url = env.get("FMC_URL") or sys.exit("FMC_URL missing in .env")
    verify = (env.get("FMC_VERIFY_SSL") or "true").lower() not in ("false", "0", "no")
    admin_user = env.get("FMC_ADMIN_USERNAME") or sys.exit("FMC_ADMIN_USERNAME missing (.env.admin)")
    admin_pw = env.get("FMC_ADMIN_PASSWORD") or sys.exit("FMC_ADMIN_PASSWORD missing (.env.admin)")

    wanted_users = []
    for prefix, role in USERS:
        user, pw = env.get(f"{prefix}USERNAME"), env.get(f"{prefix}PASSWORD")
        if not user or not pw:
            print(f"skip {prefix}USERNAME: not set")
            continue
        if user == admin_user:
            sys.exit(f"{prefix}USERNAME is the admin user; give the server its own API user")
        if any(u == user and r != role for u, _, r in wanted_users):
            sys.exit(f"{user} is configured with two different roles; give each prefix its own user")
        wanted_users.append((user, pw, role))

    if not args.no_licence and not args.check and not args.delete:
        print(ensure_eval_licence(url, verify, (admin_user, admin_pw)))
    # A REST login ends the same user's UI session (and vice versa), so read users first.
    have_users = api_users(url, verify, (admin_user, admin_pw))
    ui = FmcUi(url, admin_user, admin_pw, verify)
    try:
        if args.delete:
            for user, _, _ in wanted_users:
                if user in have_users and not args.check:
                    ui.delete_user(user)
                    print(f"deleted user {user}")
            roles = ui.roles()
            for name in ROLES:
                if name in roles and not args.check:
                    ui.delete_role(roles[name])
                    print(f"deleted role {name}")
            return

        roles = ui.roles()
        for name, spec in ROLES.items():
            have = roles.get(name)
            want = set(spec["permissions"])
            current = set((have or {}).get("data", {}).get("permissions", {}) or {})
            if have and current == want and have["data"].get("description") == spec["description"]:
                print(f"role {name}: ok ({len(want)} permissions)")
                continue
            what = "create" if not have else f"update (+{sorted(want - current)} -{sorted(current - want)})"
            print(f"role {name}: {what}")
            if not args.check:
                ui.save_role(name, spec, have)
        roles = ui.roles()

        for user, pw, role in wanted_users:
            role_obj = roles.get(role)
            if role_obj is None:
                print(f"user {user}: role {role} missing (run without --check first)")
                continue
            have = have_users.get(user)
            have_roles = sorted(r.get("name", "") for r in (have or {}).get("roles", []))
            if have and have_roles == [role] and not args.reset_passwords:
                print(f"user {user}: ok (role {role})")
                continue
            what = "create" if not have else f"update (roles {have_roles} -> [{role}])"
            print(f"user {user}: {what}")
            if not args.check:
                new_pw = pw if (not have or args.reset_passwords) else None
                ui.save_user(user, new_pw, role_obj["uuid"], not have)
    finally:
        ui.close()
    if not args.check and not args.delete:
        after = api_users(url, verify, (admin_user, admin_pw))
        for user, _, role in wanted_users:
            got = sorted(r.get("name", "") for r in after.get(user, {}).get("roles", []))
            print(f"verify {user}: {'ok' if got == [role] else f'MISMATCH {got}'}")


if __name__ == "__main__":
    main()
