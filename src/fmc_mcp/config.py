"""Settings: FMC_* connection variables plus the shared MCP_* server variables."""

from pydantic import Field
from stutters_mcp_core import BaseServerSettings, server_config

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
