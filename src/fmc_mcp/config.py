"""Settings: FMC_* connection variables plus the shared MCP_* server variables."""

from pathlib import Path

from pydantic import Field, SecretStr, field_validator

from fmc_mcp._core import BaseServerSettings, server_config
from fmc_mcp._core.policy import ChangeWindow

# FMC allows about 120 requests/minute and 10 concurrent connections per source IP.
DEFAULT_RATE_LIMIT = 110.0
DEFAULT_MAX_CONCURRENCY = 8


class Settings(BaseServerSettings):
    model_config = server_config("FMC_")

    domain: str | None = Field(
        default=None,
        description="Default FMC domain (name like 'Global' or 'Global/Child', or UUID). "
        "Default: the login's own domain.",
    )
    quarantine_object: str = Field(
        default="mcp-quarantine",
        description="Dynamic object fmc_contain_host / fmc_release_host map hosts into (created if missing).",
    )
    deploy_window: str | None = Field(
        default=None,
        description="Maintenance window for changes that reach devices (deploy, rollback, register, "
        "delete device, HA actions), same syntax as MCP_CHANGE_WINDOW; outside it they are blocked. "
        "Object and policy edits stay possible (they only reach devices with a deploy).",
    )
    ticket: str | None = Field(
        default=None,
        description="Change-management ticket id to send with every request (FMC 7.6+ change management); "
        "fmc_ticket(action='open') sets it at run time.",
    )
    ui_username: str | None = Field(
        default=None,
        description="FMC web-UI user for realm test / user-group download (fmc_test_realm, "
        "fmc_download_realm), which FMC's REST API can't do. Must not be FMC_USERNAME: a UI login ends "
        "the same user's REST session.",
    )
    ui_password: SecretStr | None = Field(default=None, description="Password of FMC_UI_USERNAME.")
    ftd_reg_key: SecretStr | None = Field(
        default=None,
        description="Registration key fmc_register_device uses when the caller passes no reg_key (the key "
        "set with `configure manager add` on the FTDs), so agents never handle it. Also as "
        "FMC_FTD_REG_KEY_FILE or FMC_FTD_REG_KEY_REF.",
    )
    bundle_dir: Path | None = Field(
        default=None,
        description="Directory fmc_export_policy_bundle and fmc_export_device_config also write each "
        "bundle or device export to (fmc_diff_policy_bundle and fmc_diff_device_config read file names "
        "from). Unset: they are only returned inline, nothing is written.",
    )
    pki_dir: Path | None = Field(
        default=None,
        description="Directory on the server host that fmc_import_certificate_files reads PEM certificate, "
        "key and passphrase files from (an existing CA for decrypt-resign, a server certificate for "
        "decrypt-known-key), so private keys never pass through MCP. Unset: file imports are off "
        "(fmc_create_internal_ca still works: FMC generates the key). fmc_create_cert_enrollment reads "
        "PKCS12 files, CA certificates and SCEP/EST password files from it too, and fmc_configure_eigrp "
        "its interface MD5 keys (key_file).",
    )
    pki_passphrase: SecretStr | None = Field(
        default=None,
        description="Passphrase of the PKCS12 files fmc_create_cert_enrollment reads from FMC_PKI_DIR, used "
        "when the call names no passphrase_file, so the passphrase never passes through MCP. Also as "
        "FMC_PKI_PASSPHRASE_FILE or FMC_PKI_PASSPHRASE_REF.",
    )
    toolsets: str | None = Field(
        default=None,
        description="Load only these areas of the tool surface, comma-separated (e.g. "
        "'troubleshoot,objects,deploy'; 'all,-ftdsdwan' for all but one): admin, deploy, devices, "
        "ftdsdwan (FTD SD-WAN; the old name 'sdwan' still works, with a warning in fmc_status), ha, "
        "identity, intel, migrate, objects, platform, policy, routing, threat, tls, troubleshoot, "
        "vpn. core (status, spec search, raw API call, domains, devices, tasks) is always loaded; the "
        "read/write/dangerous tiers still apply on top. Unset: every area.",
    )
    allow_ignore_warning: bool = Field(
        default=False,
        description="Allow fmc_deploy(ignore_warning=true). Even then the preview must list the FMC "
        "warnings being ignored, so a deploy without ignore_warning has to run (and fail) first.",
    )

    @field_validator("toolsets")
    @classmethod
    def _check_toolsets(cls, v: str | None) -> str | None:
        from fmc_mcp import toolsets

        toolsets.parse(v)  # unknown names fail at startup, listing the areas
        return v.strip() if v and v.strip() else None

    @field_validator("deploy_window")
    @classmethod
    def _check_window(cls, v: str | None) -> str | None:
        if v is not None and v.strip():
            try:
                ChangeWindow.parse(v)
            except ValueError as e:
                raise ValueError(str(e).replace("MCP_CHANGE_WINDOW", "FMC_DEPLOY_WINDOW")) from None
            return v.strip()
        return None
