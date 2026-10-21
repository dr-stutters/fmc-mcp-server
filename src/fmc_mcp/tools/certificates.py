"""F71: every certificate FMC holds, with days left and a severity, for the weekly 'certificate expiring'
check: identity certificates enrolled on the devices (RA VPN, S2S, the FTD's own; devices/certificates with
the enrolment type, deployment and identity/CA status), internal certificates and internal CAs (TLS
decryption, identity), trusted CAs (LDAPS, ISE/pxGrid, decryption) and external certificates.

FMC encodes the expiry dates three ways: ISO 8601 on objects ('2036-10-13T01:31:15Z', also without seconds
'2034-10-27T09:01Z' on device enrolments), OpenSSL text on trusted CAs ('Jan  1 00:00:00 2030 GMT') and epoch
seconds on some device enrolments (0 = not applicable). All three become one ISO date and `days_left`.

Read-only. Renewing or enrolling is F75; one certificate's PEM and where it is used: fmc_get_certificate."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    InvalidRequest,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.tools.common import Domain, pick_by_name
from fmc_mcp.tools.pki import bundled, parse_date

DEVICE_CERTS = "devices/certificates"
DEVICES = "devices/devicerecords"
CRITICAL_DAYS = 30  # expired or expiring within this many days: critical
WARNING_DAYS = 90  # within this many days: warning
EPOCH_MS = 100_000_000_000  # an epoch above this is in milliseconds (year 5138 in seconds)
# Device enrolment states that need attention whatever the expiry.
BAD_DEPLOYMENT = {"FAILED", "ABORTED"}
BAD_CERT_STATUS = {"PENDING", "NOT_AVAILABLE", "AVAILABLE_PENDING"}


@dataclass(frozen=True)
class Collection:
    kind: str  # our name
    path: str  # collection under the domain
    label: str  # for messages and rows


COLLECTIONS: dict[str, Collection] = {
    c.kind: c
    for c in (
        Collection("device", DEVICE_CERTS, "device certificate"),
        Collection("internal", "object/internalcertificates", "internal certificate"),
        Collection("internal_ca", "object/internalcas", "internal CA"),
        Collection("trusted_ca", "object/externalcacertificates", "trusted CA"),
        Collection("external", "object/externalcertificates", "external certificate"),
    )
}
CertKind = Literal["device", "internal", "internal_ca", "trusted_ca", "external"]


# --- dates and severity -------------------------------------------------------------------------------


def cert_date(value: Any) -> datetime | None:
    """A certificate date in any of FMC's encodings (ISO 8601, OpenSSL text, epoch seconds or
    milliseconds as a number or a digit string); None for empty, 0 (FMC: not applicable) or garbage."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float) or (isinstance(value, str) and value.strip().isdigit()):
        n = float(value)
        if n <= 0:
            return None
        if n > EPOCH_MS:
            n /= 1000
        try:
            return datetime.fromtimestamp(n, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    return parse_date(value)


def iso(d: datetime | None) -> str | None:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def severity(days_left: int | None) -> str:
    """critical: expired or within CRITICAL_DAYS; warning: within WARNING_DAYS; ok; unknown: no date."""
    if days_left is None:
        return "unknown"
    if days_left <= CRITICAL_DAYS:
        return "critical"
    if days_left <= WARNING_DAYS:
        return "warning"
    return "ok"


def days_until(end: datetime | None, now: datetime) -> int | None:
    """Whole days to `end`: 0 = expires within a day, negative = expired."""
    return (end - now).days if end else None


# --- rows ---------------------------------------------------------------------------------------------


def object_row(c: dict[str, Any], col: Collection, now: datetime) -> dict[str, Any]:
    """One certificate object (internal, internal CA, trusted CA, external) as a row."""
    end = cert_date(c.get("validityEndDate"))
    left = days_until(end, now)
    owner = ((c.get("metadata") or {}).get("domain") or {}).get("name")
    row: dict[str, Any] = {
        "kind": col.kind,
        "name": c.get("name"),
        "subject": c.get("subjectCommonName") or c.get("subjectOrganization") or None,
        "issuer": c.get("issuerCommonName") or c.get("issuerOrganization") or None,
        "expires": iso(end),
        "days_left": left,
        "severity": severity(left),
        "expired": True if left is not None and left < 0 else None,
        "csr_pending": True
        if col.kind == "internal_ca"
        and str(c.get("csr") or "").strip()
        and not str(c.get("cert") or "").strip()
        else None,
        "bundled": True if col.kind == "trusted_ca" and bundled(c) else None,
        "domain": owner or None,
        "id": c.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def enrolment_problems(e: dict[str, Any]) -> list[str]:
    out: list[str] = []
    dep = str(e.get("deploymentStatus") or "").upper()
    if dep in BAD_DEPLOYMENT:
        out.append(f"deployment {dep}" + (f": {e['errorMessage']}" if e.get("errorMessage") else ""))
    for field, what in (("identityCertificateStatus", "identity certificate"), ("caCertificateStatus", "CA")):
        st = str(e.get(field) or "").upper()
        if st in BAD_CERT_STATUS:
            out.append(f"{what} {st}")
    if e.get("isOutdated"):
        out.append("outdated (the enrolment object changed; re-enrol)")
    if e.get("errorMessage") and dep not in BAD_DEPLOYMENT:
        out.append(str(e["errorMessage"]))
    return out


def device_rows(item: dict[str, Any], names: dict[str, str], now: datetime) -> list[dict[str, Any]]:
    """The enrolments of one devices/certificates item (its id is the device UUID). FMC lists them as
    {certificate: {id, name}} or, expanded, with id and name inline."""
    dev_id = str(item.get("id") or "")
    device = names.get(dev_id.lower()) or item.get("name") or dev_id
    rows: list[dict[str, Any]] = []
    for e in item.get("enrolledCertificates") or []:
        ref = e.get("certificate") or {}
        ident = cert_date(e.get("identityCertExpiryDate"))
        ca = cert_date(e.get("caCertExpiryDate"))
        dated = [(d, w) for d, w in ((ident, "identity"), (ca, "ca")) if d]
        first = min(dated, key=lambda t: t[0]) if dated else None
        left = days_until(first[0], now) if first else None
        problems = enrolment_problems(e)
        level = severity(left)
        if problems and level in ("ok", "unknown"):
            level = "warning"
        row: dict[str, Any] = {
            "kind": "device",
            "device": device,
            "name": e.get("name") or ref.get("name"),
            "enrollment_type": e.get("enrollmentType"),
            "deployment": e.get("deploymentStatus"),
            "identity_status": e.get("identityCertificateStatus"),
            "ca_status": e.get("caCertificateStatus"),
            "identity_expires": iso(ident),
            "ca_expires": iso(ca),
            "expires": iso(first[0]) if first else None,
            "expiring": first[1] if first and len(dated) > 1 else None,
            "days_left": left,
            "severity": level,
            "expired": True if left is not None and left < 0 else None,
            "problems": problems or None,
            "device_id": dev_id or None,
            "id": e.get("id") or ref.get("id"),
        }
        rows.append({k: v for k, v in row.items() if v is not None})
    return rows


SEVERITY_ORDER = {"critical": 0, "warning": 1, "unknown": 2, "ok": 3}


def sort_key(r: dict[str, Any]) -> tuple[int, int, str]:
    left = r.get("days_left")
    return (
        SEVERITY_ORDER.get(r.get("severity", ""), 9),
        left if left is not None else 1 << 30,
        str(r.get("name")),
    )


# --- tool ---------------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List certificates with days left")
    async def fmc_list_certificates(
        ctx: Context,
        kind: Annotated[
            CertKind | None,
            Field(
                description="device (identity certificates enrolled on the FTDs: RA/S2S VPN, the device's "
                "own), internal (internal certificates: a server's certificate + key, FMC's pxGrid client), "
                "internal_ca (decrypt-resign CAs), trusted_ca (LDAPS, ISE, decryption trust), external "
                "(external certificates); default: all"
            ),
        ] = None,
        expiring_within_days: Annotated[
            int | None,
            Field(
                ge=0,
                le=3650,
                description="Only certificates that expire within this many days (expired ones included)",
            ),
        ] = None,
        device: Annotated[
            str | None,
            Field(description="Only this device's enrolled certificates (name or UUID; implies kind=device)"),
        ] = None,
        include_bundled: Annotated[
            bool,
            Field(
                description="Also list FMC's ~100 bundled public root CAs (trusted_ca); FMC's updates "
                "replace them, so they are counted but hidden by default"
            ),
        ] = False,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        offset: Annotated[int, Field(ge=0)] = 0,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Every certificate FMC holds with its expiry, days_left and a severity (critical: expired or
        within 30 days; warning: within 90; ok; unknown: no date), most urgent first: identity
        certificates enrolled on the devices (enrolment type, deployment, identity and CA status; a failed
        or pending enrolment is at least a warning), internal certificates, internal CAs, trusted CAs and
        external certificates. The weekly 'what expires soon?' check: expiring_within_days=90. One
        certificate's PEM and what uses it: fmc_get_certificate. Read-only."""
        app: FmcApp = get_client(ctx)
        if device and kind not in (None, "device"):
            raise InvalidRequest(
                "`device` filters the device certificates only; leave kind empty or 'device'."
            )
        kinds = ["device"] if device else ([kind] if kind else list(COLLECTIONS))
        now = datetime.now(UTC)
        rows: list[dict[str, Any]] = []
        unavailable: list[str] = []
        hidden_bundled = 0
        hidden_bundled_due = 0
        incomplete: list[str] = []
        for k in kinds:
            col = COLLECTIONS[k]
            try:
                path = await app.config_path(col.path, domain)
                if k == "device":
                    rows += await _device_certificates(app, path, device, domain, now, incomplete)
                    continue
                page = await app.all(path)
            except UpstreamError as e:  # an FMC without this collection, or no permission: say so, go on
                if device:
                    raise
                unavailable.append(f"{col.label}s: {e}")
                continue
            if not page.complete:
                incomplete.append(f"{col.label}s")
            for c in page.items:
                row = object_row(c, col, now)
                if row.get("bundled") and not include_bundled:
                    hidden_bundled += 1
                    if expiring_within_days is not None and _due(row, expiring_within_days):
                        hidden_bundled_due += 1
                    continue
                rows.append(row)
        if expiring_within_days is not None:
            rows = [r for r in rows if _due(r, expiring_within_days)]
        rows.sort(key=sort_key)
        counts = {s: n for s in SEVERITY_ORDER if (n := sum(1 for r in rows if r.get("severity") == s))}
        extra: dict[str, Any] = {"severity": counts or "none"}
        if hidden_bundled:
            extra["bundled_roots_hidden"] = hidden_bundled
            if hidden_bundled_due:
                extra["bundled_roots_expiring"] = hidden_bundled_due
        if unavailable:
            extra["unavailable"] = unavailable
        if incomplete:
            extra["incomplete"] = incomplete
        if expiring_within_days is not None and not rows:
            extra["note"] = f"No certificate expires within {expiring_within_days} days."
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)


def _due(row: dict[str, Any], days: int) -> bool:
    left = row.get("days_left")
    return left is not None and left <= days


async def _device_certificates(
    app: FmcApp, path: str, device: str | None, domain: str | None, now: datetime, incomplete: list[str]
) -> list[dict[str, Any]]:
    """devices/certificates rows with device names (one devicerecords list when there are any)."""
    dev_id = None
    names: dict[str, str] = {}
    if device:
        if is_uuid(device.strip()):
            dev_id = device.strip().lower()
        else:
            devs = await app.all(await app.config_path(DEVICES, domain), expanded=False)
            hit = pick_by_name(devs.items, device.strip(), "device", partial=not devs.complete)
            dev_id = str(hit["id"]).lower()
            names[dev_id] = str(hit.get("name"))
    # Filtered here, not with FMC's filter: the spec names it deviceId:<uuid> but its example deviceUUID:.
    page = await app.all(path)
    if not page.complete:
        incomplete.append("device certificates")
    items = [i for i in page.items if not dev_id or str(i.get("id", "")).lower() == dev_id]
    if items and not names:
        devs = await app.all(await app.config_path(DEVICES, domain), expanded=False)
        names = {str(d.get("id", "")).lower(): str(d.get("name")) for d in devs.items if d.get("id")}
    return [r for i in items for r in device_rows(i, names, now)]
