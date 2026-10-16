"""Settings: FMC_* connection variables plus the shared MCP_* server variables."""

from pydantic import Field, SecretStr, field_validator
from stutters_mcp_core import BaseServerSettings, server_config
from stutters_mcp_core.policy import ChangeWindow

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
    allow_ignore_warning: bool = Field(
        default=False,
        description="Allow fmc_deploy(ignore_warning=true). Even then the preview must list the FMC "
        "warnings being ignored, so a deploy without ignore_warning has to run (and fail) first.",
    )

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
