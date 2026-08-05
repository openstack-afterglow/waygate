FROM python:3.12-slim AS waygate-builder

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project

COPY waygate/ ./waygate/
RUN uv sync --frozen --no-dev

FROM python:3.12-slim AS waygate-runtime

WORKDIR /app

COPY --from=waygate-builder /app/.venv /app/.venv
COPY pyproject.toml uv.lock LICENSE ./
COPY waygate/ ./waygate/

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && python -m compileall -q waygate \
    && adduser --disabled-password --gecos "" appuser \
    && adduser appuser root \
    && chown -R appuser:appuser /app

ENV PATH="/app/.venv/bin:$PATH"

USER appuser

FROM waygate-runtime AS waygate-api
CMD ["uvicorn", "waygate.main:app", "--host", "0.0.0.0", "--port", "8010"]

FROM waygate-runtime AS waygate-worker
CMD ["python", "-m", "waygate.worker"]
