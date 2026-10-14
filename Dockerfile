# syntax=docker/dockerfile:1
# fmc-mcp-server image. Build with
#   docker build --secret id=core_read_token,env=CORE_READ_TOKEN .
# (the secret is only needed while stutters-mcp-core is private).

# --- build: resolve dependencies with uv into a self-contained virtualenv -------------------
FROM python:3.12-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.10.9 /uv /bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=secret,id=core_read_token,required=false \
    if [ -s /run/secrets/core_read_token ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/core_read_token)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    uv sync --locked --no-dev --no-install-project && \
    rm -f /root/.gitconfig
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

# --- runtime ---------------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin mcp \
    && mkdir /cache && chown mcp /cache
COPY --from=build /app/.venv /app/.venv

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MCP_CACHE_DIR=/cache

USER mcp
WORKDIR /app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('MCP_PORT', '8000')}/health\", timeout=3)"]

CMD ["fmc-mcp-server"]
