# syntax=docker/dockerfile:1
# fmc-mcp-server image. Build with
#   docker build .
# No token: core is bundled into the wheel as fmc_mcp._core (ADR-005). When the context isn't vendored
# yet (a fresh clone), the build clones the pinned core tag from GitHub first.

# --- build: the bundled wheel plus the locked dependencies in a self-contained virtualenv -----------
FROM python:3.12-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.10.9 /uv /bin/uv
# git: scripts/bundle_core.py clones the pinned core tag when src/fmc_mcp/_core isn't vendored
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project
COPY scripts/bundle_core.py ./scripts/
COPY src ./src
RUN if [ ! -f src/fmc_mcp/_core/BUNDLE.json ]; then python scripts/bundle_core.py vendor; fi && \
    python scripts/bundle_core.py check --offline && \
    uv build --wheel --out-dir /dist && \
    python scripts/bundle_core.py check --offline --dist /dist && \
    uv pip install --python /app/.venv/bin/python --no-deps /dist/*.whl && \
    uv pip check --python /app/.venv/bin/python

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
