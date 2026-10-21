"""Threat-defense posture of an access control policy (F62): what inspects the traffic it allows (intrusion
and file policies, their modes and base policies, the default action), what bypasses inspection (TRUST,
prefilter fastpath), Security Intelligence and DNS coverage, decryption, and whether the devices it is
assigned to hold the licences those features need. Read-only; feeds the fmc_threat_defense_review prompt."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import InvalidRequest, ToolRegistrar, UpstreamError, get_client
from fmc_mcp.client import FmcApp
from fmc_mcp.licensing import licence_needs, licences
from fmc_mcp.preview import owner_domain
from fmc_mcp.tools.common import Domain, is_system, ref_label, resolve_in
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS
from fmc_mcp.tools.dns import DNS
from fmc_mcp.tools.hygiene import SEVERITY, _call, _finding, _ref, no_intrusion
from fmc_mcp.tools.intrusion import IPS
from fmc_mcp.tools.policies import ACCESS, POLICY_KINDS, PREFILTER, all_rules, policy_assignments
from fmc_mcp.tools.security_intel import _si_policy, _si_rows

# Talos Security Intelligence categories (FMC 10.0.1 names; URL and DNS ones carry a "URL " / "DNS " prefix).
TALOS = {
    "attackers",
    "banking_fraud",
    "bogon",
    "bots",
    "cnc",
    "cryptomining",
    "dga",
    "exploitkit",
    "high_risk",
    "ioc",
    "link_sharing",
    "malicious",
    "malware",
    "newly_seen",
    "open_proxy",
    "open_relay",
    "phishing",
    "response",
    "spam",
    "spyware",
    "suspicious",
    "tor_exit_node",
}
# What fmc_set_si_lists is proposed with when a policy blocks no Talos category.
SUGGESTED = {
    "ip": ["Attackers", "Bots", "CnC", "Cryptomining", "Dga", "Exploitkit", "Malware", "Phishing"],
    "url": ["URL CnC", "URL Exploitkit", "URL Malware", "URL Phishing"],
    "dns": ["DNS CnC", "DNS Dga", "DNS Exploitkit", "DNS Malware", "DNS Phishing"],
}
BALANCED = "Balanced Security and Connectivity"
NO_RULES = "No Rules Active"
RULES_LISTED = 20  # rule names in an aggregated finding
# DNS rule actions that stop a lookup (the 10.0.1 spec says BLOCK, FMC also answers DROP).
DNS_BLOCKING = ("NXDOMAIN", "BLOCK", "DROP", "SINKHOLE")
DEVICE_CAP = 10
RULE_ROWS_CAP = 100

NAP_EDITOR = "the access policy editor (Advanced > Network Analysis and Intrusion Policies)"
NAP_UI = NAP_EDITOR + "; FMC's REST API can't set it"
# FMC 10.0.1 lists, in each network analysis policy's expanded record, the access policies that use it
# (metadata.usage.asscoiatedAcPolicies, FMC's spelling); the intrusion policy used before a rule is
# determined is not exposed at all.
NAP_USAGE_KEYS = ("asscoiatedAcPolicies", "associatedAcPolicies")
EARLY_IPS_NOTE = (
    "The intrusion policy used before the access rule is determined is not in FMC's REST API; check it in "
    + NAP_EDITOR
    + "."
)


def talos_name(name: str | None) -> bool:
    n = re.sub(r"^(url|dns)\s+", "", str(name or "").strip().lower())
    return n.replace(" ", "_") in TALOS


async def _devices(app: FmcApp, acp_id: str, domain: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    """The devices (HA members included) the access policy is assigned to, with their licences."""
    assignments = await policy_assignments(app, domain)
    targets = next(
        (a.get("targets") or [] for a in assignments if (a.get("policy") or {}).get("id") == acp_id), []
    )
    ids: list[tuple[str, str]] = []
    notes: list[str] = []
    for t in targets:
        kind = str(t.get("type"))
        if kind == "Device":
            ids.append((str(t["id"]), str(t.get("name"))))
        elif kind == "DeviceHAPair":
            try:
                ha = await app.api.get(await app.config_path(f"{HA_PAIRS}/{t['id']}", domain))
            except UpstreamError:
                notes.append(f"HA pair {t.get('name')!r}: members not readable, licences not checked.")
                continue
            for role in ("primary", "secondary"):
                m = ha.get(role) or {}
                if m.get("id"):
                    ids.append((str(m["id"]), f"{t.get('name')}/{m.get('name') or role}"))
        else:
            notes.append(f"{kind} {t.get('name')!r}: licences not checked (check its members).")
    rows = []
    for dev_id, label in ids[:DEVICE_CAP]:
        try:
            d = await app.api.get(await app.config_path(f"{DEVICES}/{dev_id}", domain))
        except UpstreamError:
            notes.append(f"Device {label!r} not readable.")
            continue
        rows.append(
            {
                "name": label,
                "licences": sorted(licences(d.get("license_caps"))),
                "snort": d.get("snortEngine"),
                "connected": d.get("isConnected"),
            }
        )
    if len(ids) > DEVICE_CAP:
        notes.append(f"Only the first {DEVICE_CAP} of {len(ids)} devices were checked.")
    return rows, notes


async def threat_posture(app: FmcApp, policy: str, domain: str | None) -> dict[str, Any]:
    acp = await resolve_in(app, ACCESS, policy, "access policy", domain)
    acp = await app.api.get(await app.config_path(f"{ACCESS}/{acp['id']}", domain))  # full settings
    name = str(acp.get("name"))
    rules = (await all_rules(app, await app.config_path(f"{ACCESS}/{acp['id']}/accessrules", domain))).items
    enabled = [r for r in rules if r.get("enabled", True)]
    findings: list[dict[str, Any]] = []
    notes: list[str] = []

    # Intrusion policies: the default action's and every enabled ALLOW rule's.
    ips_all = {str(p.get("id")): p for p in (await app.all(await app.config_path(IPS, domain))).items}
    used: dict[str, list[str]] = {}
    default = acp.get("defaultAction") or {}
    d_ips = default.get("intrusionPolicy") or {}
    if d_ips.get("id"):
        used.setdefault(str(d_ips["id"]), []).append("default action")
    allow = [r for r in enabled if str(r.get("action", "")).upper() == "ALLOW"]
    for r in allow:
        ips = r.get("ipsPolicy") or {}
        if ips.get("id"):
            used.setdefault(str(ips["id"]), []).append(f"rule {r.get('name')!r}")
    ips_rows = []
    for pid, where in used.items():
        p = ips_all.get(pid) or {}
        label = p.get("name") or pid
        ips_rows.append(
            {
                "name": label,
                "base_policy": ref_label(p.get("basePolicy")) if p.get("basePolicy") else None,
                "inspection_mode": p.get("inspectionMode"),
                "system_defined": p.get("isSystemDefined"),
                "used_on": where,
            }
        )
        if p.get("inspectionMode") == "DETECTION":
            findings.append(
                _finding(
                    "ips_detection_only",
                    "high",
                    f"Intrusion policy {label!r} is in DETECTION mode: it alerts but never drops "
                    f"({', '.join(where)}).",
                    "Use a PREVENTION policy: "
                    + _call(
                        "fmc_create_intrusion_policy",
                        name="<name>",
                        base_policy=label,
                        inspection_mode="PREVENTION",
                    )
                    + ", then point the rules at it with fmc_update_access_rule(intrusion_policy=...).",
                    intrusion_policy=label,
                )
            )
        if label == NO_RULES:
            findings.append(
                _finding(
                    "ips_no_rules_active",
                    "high",
                    f"{NO_RULES!r} inspects nothing ({', '.join(where)}).",
                    "Use a real policy, e.g. "
                    + _call("fmc_update_access_rule", policy=name, rule="<rule>", intrusion_policy=BALANCED),
                    intrusion_policy=label,
                )
            )

    # Default action.
    d_action = str(default.get("action") or "").upper()
    d_logs = [n for n, f in (("begin", "logBegin"), ("end", "logEnd")) if default.get(f)]
    path_hint = await app.config_path(f"{ACCESS}/{acp['id']}/defaultactions/{default.get('id')}", domain)
    base_body = {"id": default.get("id"), "type": "AccessPolicyDefaultAction"}
    balanced: dict[str, Any] = next((p for p in ips_all.values() if p.get("name") == BALANCED), {})
    balanced_ref = {"id": balanced.get("id", "<id>"), "type": "IntrusionPolicy", "name": BALANCED}
    if d_action == "TRUST":
        findings.append(
            _finding(
                "default_action_trust",
                "high",
                "The default action trusts everything no rule matches: no intrusion, file or SI inspection.",
                "Set the default action to BLOCK (or PERMIT with an intrusion policy): "
                + _call("fmc_api_call", method="PUT", path=path_hint, body={**base_body, "action": "BLOCK"}),
            )
        )
    elif d_action in ("NETWORK_DISCOVERY", "PERMIT") and not d_ips.get("id"):
        findings.append(
            _finding(
                "default_action_uninspected",
                "high",
                f"The default action ({d_action}) allows unmatched traffic without an intrusion policy.",
                "Give it an intrusion policy or block: "
                + _call(
                    "fmc_api_call",
                    method="PUT",
                    path=path_hint,
                    body={**base_body, "action": "PERMIT", "intrusionPolicy": balanced_ref},
                ),
            )
        )
    if d_action == "BLOCK" and not d_logs:
        findings.append(
            _finding(
                "default_action_no_logging",
                "low",
                "Traffic dropped by the default action leaves no connection event.",
                "Log at the beginning of the connection: "
                + _call(
                    "fmc_api_call",
                    method="PUT",
                    path=path_hint,
                    body={**base_body, "action": "BLOCK", "logBegin": True, "sendEventsToFMC": True},
                ),
            )
        )

    # What bypasses inspection.
    for r in enabled:
        if str(r.get("action", "")).upper() == "TRUST":
            findings.append(
                _finding(
                    "trust_rule",
                    "medium",
                    "TRUST passes the traffic without intrusion, file or URL inspection.",
                    "If it isn't a deliberate exception (backups, voice): "
                    + _call(
                        "fmc_update_access_rule",
                        policy=name,
                        rule=r.get("name"),
                        action="ALLOW",
                        intrusion_policy=BALANCED,
                    ),
                    rule=_ref(r),
                )
            )
    # ALLOW rules without an intrusion policy: the same check as fmc_policy_audit's no_intrusion (#207),
    # as one finding (a policy can hold hundreds of such rules).
    no_ips = [f["rule"]["name"] for f in no_intrusion(name, allow)]
    if no_ips:
        findings.append(
            _finding(
                "allow_no_intrusion",
                "medium",
                f"{len(no_ips)} ALLOW rule(s) carry no intrusion policy, so the traffic they allow is not "
                "inspected for exploits.",
                "Add one per rule: "
                + _call("fmc_update_access_rule", policy=name, rule=no_ips[0], intrusion_policy=BALANCED)
                + (", and the same for the others" if len(no_ips) > 1 else ""),
                rules=no_ips[:RULES_LISTED],
            )
        )
    no_file = [r for r in allow if not r.get("filePolicy")]
    if no_file:
        findings.append(
            _finding(
                "allow_no_file_policy",
                "low",
                f"{len(no_file)} ALLOW rule(s) carry no file policy, so files are not checked for malware "
                "or blocked by type.",
                "Pick a file policy (fmc_list_policies(kind='file')) and add it per rule with "
                "fmc_update_access_rule (file_policy argument), starting with web and mail traffic.",
                rules=[r.get("name") for r in no_file][:RULES_LISTED],
            )
        )
    prefilter = acp.get("prefilterPolicySetting") or {}
    fastpath: list[str] = []
    if prefilter.get("id"):
        try:
            pre_rules = await all_rules(
                app, await app.config_path(f"{PREFILTER}/{prefilter['id']}/prefilterrules", domain)
            )
            for pr in pre_rules.items:
                if pr.get("enabled", True) and str(pr.get("action", "")).upper() == "FASTPATH":
                    fastpath.append(str(pr.get("name")))
                    findings.append(
                        _finding(
                            "prefilter_fastpath",
                            "medium",
                            f"Prefilter rule {pr.get('name')!r} fastpaths traffic past Snort (no "
                            "intrusion, file or URL inspection).",
                            "If it isn't a deliberate exception: "
                            + _call(
                                "fmc_update_prefilter_rule",
                                policy=prefilter.get("name"),
                                rule=pr.get("name"),
                                action="ANALYZE",
                            ),
                        )
                    )
        except UpstreamError as e:
            notes.append(f"Prefilter rules not readable: {e}")

    # Security Intelligence and DNS.
    si_rows: dict[str, Any] = {}
    try:
        _, si = await _si_policy(app, acp, domain)
        si_rows = _si_rows(si)
    except (UpstreamError, InvalidRequest) as e:
        notes.append(f"Security Intelligence not readable: {e}")
        si = {}
    if si:
        for kind, key in (("ip", "network_block"), ("url", "url_block")):
            if not any(talos_name(n) for n in si_rows.get(key) or []):
                findings.append(
                    _finding(
                        "si_no_talos_" + ("network" if kind == "ip" else "url"),
                        "medium" if kind == "ip" else "low",
                        f"The SI {'network' if kind == 'ip' else 'URL'} block list holds no Talos category "
                        "(only the Global/Domain lists and custom entries), so known-bad "
                        f"{'addresses' if kind == 'ip' else 'URLs'} are not dropped before inspection.",
                        _call("fmc_set_si_lists", policy=name, names=SUGGESTED[kind], kind=kind),
                    )
                )
        if si_rows.get("logging") is False:
            findings.append(
                _finding(
                    "si_logging_off",
                    "low",
                    "Security Intelligence drops are not logged.",
                    "Enable logging on the Security Intelligence tab of the access policy editor.",
                )
            )
        dns_ref = si.get("dnsPolicy") or {}
        if not dns_ref.get("id"):
            findings.append(
                _finding(
                    "no_dns_policy",
                    "medium",
                    "No DNS policy: lookups of known-bad domains are not blocked.",
                    "fmc_create_dns_policy, then "
                    + _call("fmc_set_dns_policy", access_policy=name, dns_policy="<name>"),
                )
            )
        else:
            try:
                dpol = await resolve_in(app, DNS, str(dns_ref["id"]), "DNS policy", domain)
                drules = (
                    await all_rules(app, await app.config_path(f"{DNS}/{dpol['id']}/dnsrules", domain))
                ).items
            except UpstreamError as e:
                notes.append(f"DNS policy not readable: {e}")
                dpol, drules = {}, []
            blocking = [r for r in drules if r.get("enabled", True) and str(r.get("action")) in DNS_BLOCKING]
            talos_dns = any(
                talos_name(o.get("name"))
                for r in blocking
                for o in ((r.get("dnsLists") or {}).get("objects") or [])
            )
            if dpol.get("name"):  # its own name, not the one in the SI reference (#204)
                si_rows["dns_policy"] = dpol["name"]
            si_rows["dns_policy_system"] = is_system(dpol) if dpol else None
            si_rows["dns_blocking_rules"] = len(blocking)
            if dpol and not talos_dns:
                own = not is_system(dpol)
                owner = owner_domain(dpol)
                here = await app.domain_uuid(domain)
                why = (
                    f"it belongs to domain {await app.domain_name(str(owner['id']))!r}, read-only here"
                    if owner and str(owner["id"]).lower() != here.lower()
                    else "it is FMC's read-only default policy"
                )
                findings.append(
                    _finding(
                        "dns_no_talos",
                        "low",
                        f"DNS policy {dpol.get('name')!r} blocks no Talos DNS category"
                        + ("" if own else f" ({why})")
                        + ".",
                        (
                            ""
                            if own
                            else "fmc_create_dns_policy + "
                            + _call("fmc_set_dns_policy", access_policy=name, dns_policy="<new policy>")
                            + ", then "
                        )
                        + _call("fmc_set_si_lists", policy=name, names=SUGGESTED["dns"], kind="dns"),
                    )
                )

    # Decryption, identity, network analysis.
    decryption = acp.get("decryptionPolicySetting") or acp.get("sslPolicySetting") or {}
    if not decryption.get("id"):
        findings.append(
            _finding(
                "no_decryption",
                "info",
                "No decryption policy: inside TLS only metadata (SNI, certificate) is inspected; intrusion, "
                "file and URL-path checks don't see encrypted payloads.",
                "Where policy allows: fmc_create_decryption_policy + fmc_create_decryption_rule, then "
                + _call("fmc_set_decryption_policy", access_policy=name, decryption_policy="<name>"),
            )
        )
    nap_names: list[str] = []
    nap: dict[str, Any] = {}
    try:
        naps = await app.all(await app.config_path(POLICY_KINDS["network_analysis"], domain))
        for n in naps.items:
            nap_names.append(str(n.get("name")))
            usage = (n.get("metadata") or {}).get("usage") or {}
            refs: list[Any] = next((usage[k] for k in NAP_USAGE_KEYS if usage.get(k)), [])
            if any(isinstance(r, dict) and str(r.get("id")) == str(acp["id"]) for r in refs):
                nap = n
    except UpstreamError as e:
        notes.append(f"Network analysis policies not readable: {e}")
    if not nap:
        findings.append(
            _finding(
                "network_analysis_policy",
                "info",
                "No network analysis policy lists this access policy as a user, so the one it runs is "
                "unknown.",
                "Check it in " + NAP_UI + ".",
            )
        )
    elif nap.get("inspectionMode") == "DETECTION":
        findings.append(
            _finding(
                "nap_detection_only",
                "medium",
                f"Network analysis policy {nap.get('name')!r} is in DETECTION mode: the preprocessors report "
                "malformed and evasive traffic but never drop it.",
                "Select a network analysis policy in PREVENTION mode in " + NAP_UI + ".",
                network_analysis_policy=nap.get("name"),
            )
        )
    notes.append(EARLY_IPS_NOTE)

    # Licences on the assigned devices.
    devices, dev_notes = await _devices(app, str(acp["id"]), domain)
    notes += dev_notes
    needs = licence_needs(acp, rules)  # IPS / MALWARE_DEFENSE / URL -> why
    for d in devices:
        missing = [lic for lic, need in needs.items() if need and lic not in d["licences"]]
        if missing:
            findings.append(
                _finding(
                    "licence_missing",
                    "high",
                    f"{d['name']} lacks {', '.join(missing)}: the deploy fails validation or the feature "
                    "does nothing there.",
                    _call("fmc_set_device_licenses", device=d["name"].split("/")[-1], add=missing),
                    device=d["name"],
                )
            )

    findings.sort(key=lambda f: SEVERITY[f["severity"]])
    by_action: dict[str, int] = {}
    for r in enabled:
        a = str(r.get("action"))
        by_action[a] = by_action.get(a, 0) + 1
    allow_rows = [
        {
            "index": (r.get("metadata") or {}).get("ruleIndex"),
            "name": r.get("name"),
            "intrusion_policy": ref_label(r["ipsPolicy"]) if r.get("ipsPolicy") else None,
            "variable_set": ref_label(r["variableSet"]) if r.get("variableSet") else None,
            "file_policy": ref_label(r["filePolicy"]) if r.get("filePolicy") else None,
            "logging": [
                n for n, f in (("begin", "logBegin"), ("end", "logEnd"), ("files", "logFiles")) if r.get(f)
            ]
            or None,
        }
        for r in allow
    ]
    if len(allow_rows) > RULE_ROWS_CAP:
        notes.append(f"Showing the first {RULE_ROWS_CAP} of {len(allow_rows)} ALLOW rules.")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    out: dict[str, Any] = {
        "policy": name,
        "summary": {"findings": len(findings), "by_severity": counts},
        "default_action": {
            k: v
            for k, v in (
                ("action", d_action or None),
                ("intrusion_policy", ref_label(d_ips) if d_ips.get("id") else None),
                ("logging", d_logs or None),
            )
            if v is not None
        },
        "rules": {"total": len(rules), "enabled": len(enabled), "by_action": by_action},
        "allow_rules": allow_rows[:RULE_ROWS_CAP],
        "intrusion_policies": ips_rows or None,
        "security_intelligence": si_rows or None,
        "prefilter": {"policy": prefilter.get("name"), "fastpath_rules": fastpath or None}
        if prefilter
        else None,
        "decryption_policy": decryption.get("name"),
        "identity_policy": (acp.get("identityPolicySetting") or {}).get("name"),
        "network_analysis_policy": {
            k: v
            for k, v in (
                ("name", nap.get("name")),
                ("inspection_mode", nap.get("inspectionMode")),
                ("system_defined", nap.get("isSystemDefined")),
            )
            if v is not None
        }
        or None,
        "network_analysis_policies_available": nap_names or None,
        "devices": devices or None,
        "findings": findings,
    }
    if notes:
        out["notes"] = notes
    return {k: v for k, v in out.items() if v is not None}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Threat-defense posture of an access policy")
    async def fmc_threat_posture(
        ctx: Context,
        policy: Annotated[str, Field(description="Access control policy name or UUID")],
        domain: Domain = None,
    ) -> dict[str, Any]:
        """How well an access control policy defends against threats, in one read: intrusion policies on
        the default action and every ALLOW rule (base policy, PREVENTION vs DETECTION, 'No Rules Active'),
        file policies, what skips inspection (TRUST rules, prefilter FASTPATH, a trusting default action),
        Security Intelligence (Talos categories in the block lists, logging) and DNS policy coverage,
        decryption, the network analysis policy it uses (and its mode), and whether the assigned devices
        hold the IPS, MALWARE_DEFENSE and URL licences the policy needs. Each finding carries a fix as a
        tool call to preview. Rule-level hygiene (shadowing, logging, any-any) is fmc_policy_audit; the
        fmc_threat_defense_review prompt combines both. Nothing is changed."""
        app: FmcApp = get_client(ctx)
        return await threat_posture(app, policy, domain)
