"""Identity sources (F34): where FMC learns which user is on which IP (ISE/pxGrid, the passive identity
agent, AD realms), and who is on an IP right now.

FMC 10.0.1's REST API has no identity-source object: the ISE/pxGrid connection (primary/secondary pxGrid
node, pxGrid and MNT server CAs, FMC's client certificate, the session and SXP topics) is configured only
in the web UI (FMC 10.0.1: Integrations > Identity > Identity Sources > Identity Services Engine, in the
Global domain only, by an administrator), and the UI's identity endpoints don't accept REST tokens. REST
also doesn't say why a connection fails: only the UI's Test button shows FMC's error. So
fmc_get_identity_sources assembles the state from what REST does show:

- FMC health modules (one health/alerts read, filtered by module): `ISE` (pxGrid connection status, or
  "ISE is not configured or not enabled"), the passive identity agent, the user agent and unresolved
  groups; per device `SNORT_IDENTITY_MEMORY_USAGE` (user-IP bindings in use / max) and
  `IDENTITY_PROCESS_STATUS`;
- object/isesecuritygrouptags: FMC answers 422 "Identity Service Engine is disabled" until an ISE source
  is enabled; once it is, the SGTs FMC downloaded over pxGrid;
- AD/LDAP realms (users and groups downloaded), identity policies and the access policies using them;
- FMC's identity sessions (analysis/activesessions; the role needs Events & Logs > Analysis > Users);
- internal certificates (FMC's pxGrid client certificate is one) with their expiry.

fmc_user_ip_lookup answers "who is on this IP / where is this user logged in" from FMC's identity
sessions and adds the user's realm groups: the identity a user/group access rule matches. fmc_rule_lookup
uses the same lookup (resolve_ip_identity) when no `identities` are given. The sessions are read with
live.session_items, the reader behind fmc_user_identity_sessions (F55), which lists them paged.

The same sessions feed the other user-aware tools: users_on_ip is fmc_find_address's identity lookup
(find_address.IDENTITY_LOOKUPS) and user_ips gives fmc_prove_policy a user flow's source IP
(prove.USER_IP_RESOLVERS).

FMC keeps the ISE source's sessions in Global (the only domain that can own it on FMC 10.0.1), so in a
child domain every one of these lookups falls back to the ancestor domains when the child has no session
(live.read_up) and reports the domain that answered (`sessions_domain`).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import AuthError, InvalidRequest, ToolRegistrar, UpstreamError, get_client
from fmc_mcp.client import FmcApp
from fmc_mcp.refs import REALM_GROUPS, REALM_USERS
from fmc_mcp.tools.activity import ALERTS, FMC_DEVICE, clean_details
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.device_config import resolve_device
from fmc_mcp.tools.devices import DEVICES
from fmc_mcp.tools.identity import IDENTITY, REALMS, identity_rule_row, policies_using
from fmc_mcp.tools.live import (
    activity_items,
    activity_row,
    fallback_note,
    history_error,
    refused,
    role_error,
    session_items,
    session_row,
    session_seen,
    sessions_domain,
)
from fmc_mcp.tools.policies import all_rules
from fmc_mcp.tools.system import iso

SGTS = "object/isesecuritygrouptags"
INTERNAL_CERTS = "object/internalcertificates"

FMC_MODULES = {
    "ISE": "ise",
    "PASSIVE_IDENTITY_AGENT_MONITOR": "passive_identity_agent",
    "USER_AGENT": "user_agent",
    "UNRESOLVED_GROUPS_MONITOR": "unresolved_groups",
}
DEVICE_MODULES = ("SNORT_IDENTITY_MEMORY_USAGE", "IDENTITY_PROCESS_STATUS")
POLICY_CAP = 10  # identity policies whose rules are read
REALM_CAP = 5  # realms whose users/groups are counted
USER_CAP = 3  # realm users whose groups are looked up per call
CERT_WARN_DAYS = 30
UI_PAGE = (
    "the FMC web UI, Integrations > Identity > Identity Sources (FMC 10.0.1), in the Global domain: "
    "FMC 10.0.1 offers the ISE identity source in Global only (in a child domain every option is disabled), "
    "and only to an administrator (a custom role without the Identity Sources permission doesn't see the "
    "page)"
)
ISE_UI_STEP = (
    f"FMC 10.0.1's REST API can't configure it. Open {UI_PAGE}. Choose Identity Services Engine, Advanced "
    "Configuration, and set the Primary Host (the ISE node's FQDN, as in its pxGrid certificate), the pxGrid "
    "Client Certificate (an internal certificate with its private key), the MNT Server CA and pxGrid Server "
    "CA (trusted CA objects: fmc_create_trusted_ca); the drop-downs list only objects Global can see, so "
    "create the certificate and CAs in Global. Tick Session Directory Topic (and SXP Topic for SGT "
    "mappings), Test, Save. Then approve FMC's pxGrid client in ISE (ise_list_pxgrid_clients / "
    "ise_approve_pxgrid_client) unless ISE auto-approves certificate-based clients."
)
SETTINGS_NOTE = (
    f"The pxGrid host, server CAs, FMC client certificate and topics are visible only in {UI_PAGE}. FMC "
    "10.0.1's REST API has no identity-source object. ISE's side: ise_pxgrid_status / "
    "ise_list_pxgrid_clients on the ISE MCP server."
)
FAILED_STEP = (
    "FMC's ISE connection is unhealthy and FMC 10.0.1's REST API doesn't say why: the Test button on the ISE "
    "identity source (Integrations > Identity > Identity Sources, Global domain) shows FMC's error. Check "
    "that FMC reaches the pxGrid node on 8910, the pxGrid/MNT server CAs, FMC's client certificate (expiry "
    "below) and FMC's pxGrid client in ISE (ise_list_pxgrid_clients). No FMC client in ISE means FMC's "
    "request never got through (name resolution, port 8910 or TLS); 'sslv3 alert certificate unknown' in "
    "the Test result is ISE refusing FMC's client certificate, whose issuer ISE doesn't trust "
    "(ise_list_certificates, trusted store). A pending client needs ise_approve_pxgrid_client."
)
_VAL = re.compile(r"<(?P<tag>\w+loop)>\s*<val>(?P<val>[^<]*)</val>\s*</(?P=tag)>")
_ISE_PART = re.compile(r"<iseloop>\s*<module>(?P<part>[^<]*)</module>\s*<status>(?P<status>[^<]*)</status>")


# --- shaping ------------------------------------------------------------------------------------------


def latest_alerts(raw: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """The newest alert per (device UUID, module): FMC repeats each module on every health run."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for a in raw:
        key = (str(a.get("deviceUUID", "")), str(a.get("moduleID", "")))
        if key not in out or _ts(a) >= _ts(out[key]):
            out[key] = a
    return out


def _ts(a: dict[str, Any]) -> float:
    try:
        return float(a.get("timestamp") or 0)
    except (TypeError, ValueError):
        return 0.0


def module_row(a: dict[str, Any]) -> dict[str, Any]:
    return {
        "health": a.get("status"),
        "details": clean_details(a.get("details")),
        "checked": iso(a.get("timestamp")),
    }


def ise_state(alert: dict[str, Any] | None) -> str:
    """not_configured / connected / degraded / failed / unknown, from FMC's ISE health module. The module is
    a periodic sample: fmc_get_identity_sources turns a stale not_configured into awaiting_health_check
    when FMC already answers the SGT list (a source was saved since the last health run)."""
    if alert is None:
        return "unknown"
    details = clean_details(alert.get("details")).lower()
    status = str(alert.get("status") or "").upper()
    if "not configured" in details or "not enabled" in details:
        return "not_configured"
    if status == "RED":
        return "failed"
    if status == "YELLOW":
        return "degraded"
    if status in ("GREEN", "RECOVERED"):  # RECOVERED: FMC's marker for a return to normal
        return "connected"
    return "unknown"


def ise_parts(alert: dict[str, Any]) -> dict[str, str]:
    """The ISE module's per-part status from its params, e.g. {'ISE Services': 'UNKNOWN',
    'ISEConnection': 'DOWN'} on FMC 10.0.1 when the pxGrid connection fails."""
    params = str(alert.get("params") or "")
    return {m["part"].strip(): m["status"].strip() for m in _ISE_PART.finditer(params)}


def identity_memory(alert: dict[str, Any]) -> dict[str, Any]:
    """SNORT_IDENTITY_MEMORY_USAGE params: totalloop (percent, used / size), bindingloop[0] = user-IP
    bindings in use / max, ugloop[1] = user groups / max per user."""
    vals: dict[str, list[str]] = {}
    for m in _VAL.finditer(str(alert.get("params") or "")):
        vals.setdefault(m.group("tag"), []).append(m.group("val").strip())
    out: dict[str, Any] = {"health": alert.get("status"), "details": clean_details(alert.get("details"))}
    total = vals.get("totalloop") or []
    if len(total) >= 2:
        out["memory"] = f"{total[0]} ({total[1]})"
    bindings = vals.get("bindingloop") or []
    if bindings:
        out["user_ip_bindings"] = bindings[0]
        used = bindings[0].split("/")[0].strip()
        out["bindings_in_use"] = int(used) if used.isdigit() else None
    return {k: v for k, v in out.items() if v not in (None, "")}


def cert_expiry(text: Any) -> datetime | None:
    """'Oct 17 01:04:19 2036 GMT' (OpenSSL style, as FMC returns validityEndDate)."""
    t = re.sub(r"\s+", " ", str(text or "")).strip()
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return datetime.strptime(t, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def cert_row(c: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    end = cert_expiry(c.get("validityEndDate"))
    days = None
    if end is not None:
        days = int((end.timestamp() - (now if now is not None else time.time())) // 86400)
    row = {
        "name": c.get("name"),
        "subject": c.get("subjectCommonName") or None,
        "issuer": c.get("issuerCommonName") or None,
        "expires": end.strftime("%Y-%m-%d") if end else c.get("validityEndDate"),
        "days_left": days,
        "status": None
        if days is None
        else "expired"
        if days < 0
        else "expiring"
        if days < CERT_WARN_DAYS
        else "ok",
    }
    return {k: v for k, v in row.items() if v is not None}


def split_identity(name: str) -> tuple[str | None, str]:
    """'corp\\alice' -> ('corp', 'alice'); 'alice' -> (None, 'alice')."""
    realm, _, user = name.strip().rpartition("\\")
    return (realm or None), user


def qualified(realm: str | None, name: str) -> str:
    return f"{realm}\\{name}" if realm else name


# --- lookups ------------------------------------------------------------------------------------------


async def realm_users(app: FmcApp, name: str, domain: str | None) -> list[dict[str, Any]]:
    """Downloaded realm users named exactly `name` (any realm unless 'realm\\name')."""
    realm, user = split_identity(name)
    if not user:
        return []
    page = await app.all(await app.config_path(REALM_USERS, domain), {"filter": f"name:{user}"}, cap=200)
    return [
        u
        for u in page.items
        if str(u.get("name", "")).lower() == user.lower()
        and (realm is None or str((u.get("realm") or {}).get("name", "")).lower() == realm.lower())
    ]


async def groups_of(app: FmcApp, user_id: str, domain: str | None) -> list[str]:
    page = await app.all(
        await app.config_path(REALM_GROUPS, domain), {"filter": f"userId:{user_id}"}, cap=500
    )
    return sorted({str(g.get("name")) for g in page.items if g.get("name")}, key=str.lower)


async def user_groups(app: FmcApp, user: str, realm: str | None, domain: str | None) -> dict[str, Any] | None:
    """The realm user (exact name, in `realm` when given, else any realm) and its groups, or None when
    that realm hasn't downloaded the user."""
    found = await realm_users(app, qualified(realm, user), domain)
    if not found:
        return None
    u = found[0]
    return {
        "user": u.get("name"),
        "realm": (u.get("realm") or {}).get("name"),
        "groups": await groups_of(app, str(u.get("id")), domain),
    }


@dataclass
class Resolution:
    """Who FMC has on one IP: the latest session's user and that user's realm groups."""

    ip: str
    user: str | None = None
    realm: str | None = None
    groups: list[str] = field(default_factory=list)
    others: list[str] = field(default_factory=list)  # other users with a session on the same IP
    session: dict[str, Any] | None = None
    domain: str | None = None  # the ancestor domain whose sessions answered (none in the requested one)
    error: str | None = None
    note: str | None = None

    def identities(self) -> list[str] | None:
        """For fmc_rule_lookup: None when unknown (rules stay conditional), [] when no user is on the IP."""
        if self.error:
            return None
        if not self.user:
            return []
        return [qualified(self.realm, self.user)] + [qualified(self.realm, g) for g in self.groups]

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ip": self.ip, "source": "FMC identity sessions (analysis/activesessions)"}
        if self.error:
            out["error"] = self.error
            return out
        if self.domain:
            out["sessions_domain"] = self.domain
        out["user"] = self.user
        if self.user:
            out["realm"] = self.realm
            out["groups"] = self.groups
            if self.session:
                out["session"] = self.session
        if self.others:
            out["other_users_on_ip"] = self.others
        if self.note:
            out["note"] = self.note
        return out


async def resolve_ip_identity(app: FmcApp, ip: str, domain: str | None) -> Resolution:
    """The identity FMC applies to traffic from `ip`: the newest active session's user and its realm
    groups (sessions from an ancestor domain when the requested one has none: `domain`). Errors (403
    without the role) come back in `error`, never raised."""
    res = Resolution(ip=ip)
    try:
        rows = await session_items(app, domain, ip=ip)
    except AuthError as e:
        res.error = refused() if e.status_code == 403 else str(e)
        return res
    except UpstreamError as e:
        res.error = f"FMC identity sessions unavailable: {e}"
        return res
    rows = [s for s in rows if str(s.get("currentIP", "")) == ip] or rows
    res.domain = sessions_domain(rows)
    if not rows:
        res.note = (
            f"No identity session on {ip}: the firewall sees an unknown user there, so user/group rules "
            "don't match it."
        )
        return res
    top = rows[0]
    res.session = session_row(top)
    res.user = str(top.get("username") or top.get("user") or "") or None
    res.realm = top.get("realmName") or None
    res.others = sorted(
        {str(s.get("username") or s.get("user")) for s in rows[1:]} - {str(res.user)}, key=str.lower
    )
    if res.user:
        try:
            ug = await user_groups(app, res.user, res.realm, domain)
        except UpstreamError as e:
            res.note = f"Groups not resolved ({e}); user rules on groups stay conditional."
            ug = None
        if ug is not None:
            res.groups = ug["groups"]
            res.realm = res.realm or ug["realm"]
        elif not res.note:
            res.note = await _not_downloaded(app, res.user, res.realm, domain)
    return res


async def _not_downloaded(app: FmcApp, user: str, realm: str | None, domain: str | None) -> str:
    """Why a session's user has no groups: the session's realm hasn't downloaded it (maybe another has)."""
    elsewhere = await realm_users(app, user, domain) if realm else []
    if elsewhere:
        where = ", ".join(sorted({str((u.get("realm") or {}).get("name")) for u in elsewhere}))
        return (
            f"FMC maps {user}'s session to realm {realm!r}, but the user is downloaded in {where}: rules on "
            f"{where} users and groups won't match this session (check the realm's AD primary domain matches "
            "the domain ISE reports)."
        )
    return (
        f"{user} is not a downloaded user of realm {realm!r} (fmc_get_realm / fmc_download_realm): rules on "
        "its AD groups won't match."
    )


async def expand_identities(
    app: FmcApp, identities: list[str], domain: str | None
) -> tuple[list[str], dict[str, list[str]]]:
    """Add the realm groups of the users named in `identities` (as the firewall knows them). Returns the
    new list and {user: groups added}. Entries that aren't downloaded users (groups) are kept as given."""
    have = {split_identity(i)[1].lower() for i in identities}
    out = list(identities)
    added: dict[str, list[str]] = {}
    for ident in identities[:USER_CAP]:
        realm, name = split_identity(ident)
        if not name:
            continue
        ug = await user_groups(app, name, realm, domain)
        if ug is None:
            continue
        new = [g for g in ug["groups"] if g.lower() not in have]
        if new:
            out += [qualified(ug["realm"], g) for g in new]
            have.update(g.lower() for g in new)
            added[ident] = new
    return out, added


async def users_on_ip(
    app: FmcApp, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, domain: str | None
) -> list[dict[str, Any]]:
    """fmc_find_address hook (find_address.IDENTITY_LOOKUPS): one row per user FMC has a session for on
    `ip` (from an ancestor domain's sessions when the requested domain has none, named in `via`). A
    403 (role without Analysis > Users) raises AuthError with the permission to add, which
    fmc_find_address reports as a warning."""
    try:
        rows = await session_items(app, domain, ip=str(ip))
    except AuthError as e:
        raise role_error(e) from None
    owner = sessions_domain(rows)
    where = f" in domain {owner!r}" if owner else ""
    return [
        {
            "where": f"user {qualified(s.get('realmName'), str(s.get('username') or s.get('user')))}",
            "via": f"identity session ({s.get('authenticationType') or 'session'}){where}",
            "value": s.get("currentIP"),
        }
        for s in rows
        if s.get("currentIP")
    ]


def _ip_kind(ip: str) -> tuple[bool, bool]:
    """(link-local, IPv6) for ordering a user's session IPs; an unparsable value counts as IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, True
    return addr.is_link_local, addr.version == 6


async def user_ips(app: FmcApp, user: str, domain: str | None) -> list[str]:
    """fmc_prove_policy hook (prove.USER_IP_RESOLVERS): the IPs `user` (or 'realm\\user') has sessions on,
    newest first, from an ancestor domain's sessions when the requested domain has none; [] when the
    user has none anywhere. A 403 raises AuthError naming the missing permission.

    ISE reports a dual-stack client's IPv4 and IPv6 link-local addresses as two sessions with the same
    lastSeen (seen live on FMC 10.0.1), and prove traces from the first IP: sessions seen at the same
    time list IPv4 before IPv6, and link-local addresses (fe80::/10, 169.254/16), which no firewall
    routes, come back only when the user has no other IP."""
    realm, name = split_identity(user)
    if not name:
        return []
    try:
        rows = await session_items(app, domain, user=name)
    except AuthError as e:
        raise role_error(e) from None
    seen: dict[str, float] = {}  # IP -> its newest session (rows are newest first)
    for s in rows:
        uname = str(s.get("username") or s.get("user") or "")
        if uname.lower() != name.lower():
            continue
        if realm and str(s.get("realmName") or "").lower() != realm.lower():
            continue
        ip = str(s.get("currentIP") or "")
        if ip and ip not in seen:
            seen[ip] = session_seen(s)
    routable = [ip for ip in seen if not _ip_kind(ip)[0]]
    return sorted(routable or seen, key=lambda ip: (-seen[ip], _ip_kind(ip)[1]))


def _parse_ip(value: str) -> str:
    v = value.strip()
    try:
        return str(ipaddress.ip_network(v, strict=False)) if "/" in v else str(ipaddress.ip_address(v))
    except ValueError:
        raise InvalidRequest(f"ip must be an IP address or CIDR network, got {value!r}.") from None


# --- tools --------------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Identity sources (ISE/pxGrid, realms, sessions)")
    async def fmc_get_identity_sources(
        ctx: Context,
        device: Annotated[
            str | None,
            Field(description="Only this FTD's identity state (name or UUID); default: every device"),
        ] = None,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Is FMC getting user identities, and from where? One status view of the identity sources user and
        group rules depend on: the ISE/pxGrid connection (FMC's ISE health module: connected, failed, not
        configured, or saved but not checked yet, and when FMC last checked), whether FMC downloads ISE
        SGTs, the passive identity agent,
        AD/LDAP realms (users and groups downloaded), identity policies (passive rules, which access policies
        use them), how many user sessions FMC holds by source, each device's user-IP bindings and identity
        process, and FMC's internal certificates (the pxGrid client certificate) with their expiry. Ends with
        a verdict and what to fix. Use it when user-based rules don't match, before relying on
        fmc_user_ip_lookup, or after setting up ISE. FMC 10.0.1's REST API can't show or set the ISE
        connection settings themselves (pxGrid node, CAs) or say why a connection fails; those are in the
        FMC UI, Global domain only (see `ise.configure` and `ise.settings`)."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain) if device else None
        out: dict[str, Any] = {}
        todo: list[str] = []

        # health modules (FMC + devices), one read
        raw = await app.all(
            await app.config_path(ALERTS, domain),
            {"filter": "moduleIDs:" + ",".join([*FMC_MODULES, *DEVICE_MODULES])},
            cap=2000,
        )
        latest = latest_alerts(raw.items)
        fmc_alerts = {mod: a for (d, mod), a in latest.items() if d == FMC_DEVICE}
        ise_alert = fmc_alerts.get("ISE")
        state = ise_state(ise_alert)
        ise: dict[str, Any] = {"state": state}
        if ise_alert is not None:
            ise.update(module_row(ise_alert))
            if parts := ise_parts(ise_alert):
                ise["parts"] = parts
        ise["settings"] = SETTINGS_NOTE

        # SGTs over pxGrid
        try:
            sgts = await app.all(await app.config_path(SGTS, domain), cap=500)
            ise["sgts_downloaded"] = len(sgts.items)
            if sgts.items:
                ise["sgts"] = sorted(f"{s.get('name')} ({s.get('tag')})" for s in sgts.items)[:20]
            if state == "not_configured":
                # FMC 10.0.1 refuses the SGT list (422) while ISE is disabled and answers it as soon as a
                # source is saved; the ISE health module only notices on its next run (minutes later)
                state = ise["state"] = "awaiting_health_check"
        except UpstreamError as e:
            if "disabled" in str(e).lower():
                ise["sgts_downloaded"] = 0
                ise["sgt_note"] = "FMC: Identity Service Engine is disabled (no ISE source enabled)."
                if state in ("unknown", "connected"):
                    state = ise["state"] = "not_configured"
            else:
                ise["sgt_note"] = f"SGTs not readable: {e}"
        if state == "not_configured":
            ise["configure"] = ISE_UI_STEP
            todo.append("No ISE identity source: configure it in the FMC UI (see ise.configure).")
        elif state == "awaiting_health_check":
            todo.append(
                "An ISE identity source is saved (FMC answers the SGT list, which it refuses while ISE is "
                f"disabled), but FMC's ISE health module last reported {ise.get('details')!r} at "
                f"{ise.get('checked')}, before the save. It shows connected or failed after the health "
                "monitor's next run, a few minutes later: call fmc_get_identity_sources again then. The Test "
                "button on the ISE identity source in the FMC UI shows the connection result now. If a later "
                "run still says not configured, the source isn't enabled."
            )
        elif state in ("failed", "degraded"):
            todo.append(FAILED_STEP)
        out["ise"] = ise
        for mod, key in FMC_MODULES.items():
            if mod != "ISE" and mod in fmc_alerts:
                out[key] = module_row(fmc_alerts[mod])

        # realms
        realms = await app.all(await app.config_path(REALMS, domain))
        realm_rows = []
        for r in [r for r in realms.items if r.get("realmType") not in ("SPECIAL", "DISCOVERED")][:REALM_CAP]:
            row: dict[str, Any] = {
                "name": r.get("name"),
                "type": r.get("realmType"),
                "enabled": r.get("enabled"),
                "ad_domain": r.get("adPrimaryDomain"),
            }
            for key, path in (("users", REALM_USERS), ("groups", REALM_GROUPS)):
                resp = await app.api.get(
                    await app.config_path(path, domain), params={"filter": f"realm:{r.get('id')}", "limit": 1}
                )
                row[key] = int(((resp or {}).get("paging") or {}).get("count") or 0)
            realm_rows.append({k: v for k, v in row.items() if v is not None})
        out["realms"] = realm_rows
        if not realm_rows:
            todo.append(
                "No AD/LDAP realm: user and group rules need one (fmc_create_realm, fmc_download_realm); ISE "
                "sessions for unknown domains land in 'Discovered Identities'."
            )
        elif all(not r.get("users") for r in realm_rows):
            todo.append("The realms have no downloaded users: run fmc_download_realm.")

        # identity policies and their links
        idps = await app.all(await app.config_path(IDENTITY, domain))
        used = await policies_using(app, None, domain) if idps.items else {}
        policy_rows = []
        passive_total = 0
        for p in idps.items[:POLICY_CAP]:
            rules = await all_rules(app, await app.config_path(f"{IDENTITY}/{p['id']}/identityrules", domain))
            shaped = [identity_rule_row(r) for r in rules.items]
            passive = [r for r in shaped if r.get("auth") == "PASSIVE" and r.get("enabled", True)]
            passive_total += len(passive) if used.get(str(p["id"])) else 0
            policy_rows.append(
                {
                    "name": p.get("name"),
                    "rules": len(shaped),
                    "passive_rules": [r.get("name") for r in passive],
                    "realms": sorted({str(r.get("realm")) for r in shaped if r.get("realm")}),
                    "used_by": used.get(str(p["id"]), []),
                }
            )
        out["identity_policies"] = policy_rows
        if not passive_total:
            todo.append(
                "No access policy uses an identity policy with a PASSIVE rule, so devices don't map users "
                "to IPs: fmc_create_identity_policy + fmc_create_identity_rule (PASSIVE, the AD realm, the "
                "user subnets), select it in the access policy's Identity step (FMC UI), deploy."
            )

        # sessions known to FMC
        try:
            sessions = await session_items(app, domain)
            by: dict[str, int] = {}
            for s in sessions:
                k = f"{s.get('authenticationType') or '?'} / {s.get('discoveryApplication') or '?'}"
                by[k] = by.get(k, 0) + 1
            out["sessions"] = {"active": len(sessions), "by_source": by}
            if owner := sessions_domain(sessions):
                out["sessions"]["domain"] = owner
                out["sessions"]["note"] = await fallback_note(app, domain, owner)
            if not sessions and state == "connected":
                todo.append(
                    "ISE is connected but FMC holds no user session: check that ISE has sessions with "
                    "framed IPs (ise_list_active_sessions) and that FMC subscribes to Session Directory."
                )
        except AuthError as e:
            out["sessions"] = {"error": refused() if e.status_code == 403 else str(e)}
        except UpstreamError as e:
            out["sessions"] = {"error": f"FMC identity sessions unavailable: {e}"}

        # devices
        names: dict[str, str] = {}
        if any(d != FMC_DEVICE for d, _ in latest):
            devs = await app.all(await app.config_path(DEVICES, domain), expanded=False)
            names = {str(d.get("id")): str(d.get("name")) for d in devs.items}
        dev_rows: dict[str, dict[str, Any]] = {}
        for (d, mod), a in sorted(latest.items()):
            if d == FMC_DEVICE or mod not in DEVICE_MODULES or (dev and d != dev.get("id")):
                continue
            if d not in names and dev is None:
                continue  # another domain's device
            row = dev_rows.setdefault(d, {"device": names.get(d) or (dev or {}).get("name") or d})
            if str(a.get("status")) == "DISABLED":
                row["state"] = clean_details(a.get("details")) or "not reporting"
            elif mod == "SNORT_IDENTITY_MEMORY_USAGE":
                mem = identity_memory(a)
                row["user_ip_bindings"] = mem.get("user_ip_bindings")
                row["identity_memory"] = mem.get("memory")
                row["_bindings"] = mem.get("bindings_in_use")
            else:
                row["identity_process"] = clean_details(a.get("details"))
        rows = sorted(dev_rows.values(), key=lambda r: str(r["device"]))
        active = [r for r in rows if "state" not in r]
        bound = [r for r in active if r.get("_bindings")]
        for r in rows:
            r.pop("_bindings", None)
        out["devices"] = [{k: v for k, v in r.items() if v is not None} for r in rows]
        if active and not bound and (out["sessions"].get("active") or 0) > 0:
            todo.append(
                "FMC has user sessions but no device holds a user-IP binding: deploy the access policy that "
                "uses the identity policy to the devices."
            )

        # certificates
        try:
            certs = await app.all(await app.config_path(INTERNAL_CERTS, domain), cap=200)
            cert_rows = [cert_row(c) for c in certs.items]
            out["internal_certificates"] = cert_rows
            for c in cert_rows:
                if c.get("status") in ("expired", "expiring"):
                    todo.append(
                        f"Internal certificate {c.get('name')!r} is {c['status']} ({c.get('expires')})."
                    )
        except UpstreamError as e:
            out["internal_certificates"] = {"error": str(e)}

        verdict = {
            "connected": "ISE/pxGrid is connected",
            "not_configured": "No ISE identity source",
            "awaiting_health_check": "ISE identity source saved; FMC hasn't checked the connection yet",
            "failed": "ISE/pxGrid connection FAILED",
            "degraded": "ISE/pxGrid connection degraded",
            "unknown": "ISE state unknown (no ISE health alert; is the module in the health policy?)",
        }[state]
        n_sessions = out["sessions"].get("active")
        held_in = f" (in {out['sessions']['domain']})" if out["sessions"].get("domain") else ""
        verdict += (
            f"; {n_sessions} user sessions on FMC{held_in}"
            if n_sessions is not None
            else "; sessions not readable"
        )
        if active:
            verdict += f"; {len(bound)} of {len(active)} reporting devices hold user-IP bindings"
        return {"verdict": verdict, **out, "next": todo or ["Nothing to fix."]}

    @reg.read(title="Who is on an IP / where is a user")
    async def fmc_user_ip_lookup(
        ctx: Context,
        ip: Annotated[
            str | None, Field(description="Who is on this IP (or CIDR network)? e.g. 192.0.2.57")
        ] = None,
        user: Annotated[
            str | None,
            Field(description="Where is this user logged in? AD name, e.g. alice or corp\\alice"),
        ] = None,
        device: Annotated[
            str | None, Field(description="Only sessions this FTD reported (name or UUID)")
        ] = None,
        history: Annotated[
            bool,
            Field(
                description="Also the recent logins/logoffs for the IP or user (with SGT and profile); "
                "if FMC refuses them, the rest still comes back with `history_error`"
            ),
        ] = False,
        hours: Annotated[int, Field(ge=1, le=720, description="History window in hours")] = 24,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Resolve an IP to its user, or a user to their IPs, the way the firewall does: from FMC's identity
        sessions (fed by ISE/pxGrid, the passive identity agent, captive portal or RA VPN) plus the user's
        AD/LDAP groups from the realm download. Returns the sessions (user, realm, IP, source, login and last
        seen) and, for one IP, `identities`: the user and groups ready for fmc_rule_lookup(identities=...).
        With history, also the recent logins and logoffs; if FMC refuses those (403, 422, 5xx), everything
        else still comes back, with `history_error` saying why. Use it for "who is 192.0.2.57?", "which IP is
        alice on?", or before explaining a user-based block (fmc_rule_lookup already does this lookup itself
        when you omit `identities`). The FMC account's role needs Events & Logs > Analysis > Users; without it
        the user's realm groups still come back. If no source reports users, see fmc_get_identity_sources; to
        page through every session a device reports, fmc_user_identity_sessions. In a child domain with no
        session the ancestor domains are read up to Global, where FMC keeps the ISE source's sessions (FMC
        10.0.1 configures it in Global only); `sessions_domain` names the domain that answered.
        fmc_find_address (users on an IP), fmc_rule_lookup and fmc_prove_policy (a user flow without a source
        IP) read the same sessions."""
        app: FmcApp = get_client(ctx)
        if not ip and not user:
            raise InvalidRequest("Give an ip or a user.")
        query = _parse_ip(ip) if ip else None
        realm, name = split_identity(user) if user else (None, "")
        dev_name = str((await resolve_device(app, device, domain)).get("name")) if device else None
        out: dict[str, Any] = {
            "query": {k: v for k, v in {"ip": query, "user": user, "device": dev_name}.items() if v}
        }
        sessions: list[dict[str, Any]] | None
        try:
            sessions = await session_items(app, domain, ip=query, user=name or None, device=dev_name)
        except AuthError as e:
            if e.status_code != 403:
                raise
            if not user:
                raise role_error(e) from None
            sessions = None
            out["sessions_error"] = refused()
        if sessions is not None:
            if name:
                exact = [
                    s
                    for s in sessions
                    if str(s.get("username") or s.get("user") or "").lower() == name.lower()
                    and (realm is None or str(s.get("realmName") or "").lower() == realm.lower())
                ]
                if sessions and not exact:
                    out["match"] = (
                        f"No session for exactly {user!r}; these users' names contain {name!r} (FMC "
                        "matches the user name as a substring)."
                    )
                sessions = exact or sessions
            out["sessions"] = [session_row(s) for s in sessions[:100]]
            if len(sessions) > 100:
                out["sessions_truncated"] = f"{len(sessions)} sessions; showing the 100 newest"
            if owner := sessions_domain(sessions):
                out["sessions_domain"] = owner
                out["sessions_note"] = await fallback_note(app, domain, owner)

        # the identity per user (realm groups), at most USER_CAP users. The queried user is looked up once:
        # without a realm in the query, in the realm of their newest session (the identity the firewall
        # applies), else in any realm
        wanted: list[tuple[str, str | None]] = []
        if name:
            wanted.append((name, realm))
        for s in sessions or []:
            u, r = str(s.get("username") or s.get("user") or ""), s.get("realmName")
            if (
                name
                and u.lower() == name.lower()
                and (realm is None or str(r or "").lower() == realm.lower())
            ):
                if realm is None and wanted[0][1] is None:
                    wanted[0] = (u, r)
                continue
            if u and (u, r) not in wanted:
                wanted.append((u, r))
        users: list[dict[str, Any]] = []
        for u, r in wanted[:USER_CAP]:
            ug = await user_groups(app, u, r, domain)
            users.append(ug or {"user": u, "realm": r, "groups": [], "note": "not a downloaded realm user"})
        if users:
            out["users"] = users
        if query and "/" not in query and sessions:
            top: dict[str, Any] = users[0] if users else {"user": None}
            groups: list[str] = list(top.get("groups") or [])
            out["identities"] = (
                [qualified(top.get("realm"), str(top["user"]))]
                + [qualified(top.get("realm"), g) for g in groups]
                if top.get("user")
                else []
            )
            others = {str(s.get("username") or s.get("user")) for s in sessions} - {str(top.get("user"))}
            if others:
                out["note"] = (
                    f"Several users on {query} ({', '.join(sorted(others))} too); the firewall uses the "
                    "newest session, listed first."
                )
        elif sessions == []:
            what = f"{query}" if query else f"user {user}"
            out["note"] = (
                f"FMC has no active identity session for {what} (in this domain or its ancestors): the user "
                "isn't logged in where a source sees it, or no identity source reports to FMC "
                "(fmc_get_identity_sources). Traffic from such an IP is 'unknown user' to user/group rules."
            )
        if history:
            try:
                events = await activity_items(
                    app, domain, ip=query, user=name or None, device=dev_name, hours=hours
                )
                out["history"] = [activity_row(a) for a in events][:50]
                if owner := sessions_domain(events):
                    out["history_domain"] = owner
            except UpstreamError as e:
                out["history_error"] = history_error(e)
        return out
