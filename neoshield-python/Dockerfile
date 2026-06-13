# syntax=docker/dockerfile:1

FROM ghcr.io/astral-sh/uv:0.10.9 AS uv

FROM python:3.13-slim AS base
ENV PYTHONUNBUFFERED=1
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV NEOSHIELD_SCANNER_DIR=/opt/neoshield/scanners
ENV HOME=/home/worker
ENV XDG_CACHE_HOME=/home/worker/.cache

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /app

# Install dependencies first so source edits reuse the cached layer.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN uv sync --frozen --no-dev

# Scanner binaries are downloaded on startup into this directory; the worker
# runs unprivileged and must be able to write there and to its cache.
RUN useradd --system --uid 1001 --create-home worker \
    && mkdir -p /opt/neoshield/scanners /home/worker/.cache/trivy \
    && chown -R worker:worker /opt/neoshield /home/worker
USER worker

EXPOSE 8000
CMD [\"/app/.venv/bin/uvicorn\", \"neoshield.api.main:app\", \"--host\", \"0.0.0.0\", \"--port\", \"8000\"]
