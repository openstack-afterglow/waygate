"""Waygate standalone FastAPI application."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from waygate.api import agent, attachments, clients, migration, resource_policies, servers
from waygate.cache import close_cache
from waygate.config import get_settings, require_public_callback_base_url
from waygate.db import close_db, init_db
from waygate.models.schemas import HealthResponse, RootDiscoveryResponse, VersionDiscoveryResponse
from waygate.rate_limit import limiter

_logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    require_public_callback_base_url(settings)
    init_db(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        connect_timeout=settings.database_connect_timeout,
        pool_timeout=settings.database_pool_timeout,
    )
    try:
        yield
    finally:
        await close_cache()
        await close_db()


app = FastAPI(
    title="Waygate",
    description="Waygate WireGuard VPN Gateway Service",
    version="1.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=get_settings().trusted_proxies)

for route in (servers.router, clients.router, attachments.router, migration.router, agent.router):
    app.include_router(route, prefix="/v1/servers")
app.include_router(resource_policies.router, prefix="/v1/admin", tags=["admin-resource-policies"])


def _version_document(request: Request) -> dict:
    href = f"{str(request.base_url).rstrip('/')}/v1/"
    return {
        "id": "v1.0",
        "status": "CURRENT",
        "min_version": "1.0",
        "version": "1.0",
        "links": [{"rel": "self", "href": href}],
    }


@app.get("/", response_model=RootDiscoveryResponse)
async def root_discovery(request: Request):
    return {"versions": [_version_document(request)]}


@app.get("/v1/", response_model=VersionDiscoveryResponse)
async def version_discovery(request: Request):
    return {"version": _version_document(request)}


@app.get("/v1/health", response_model=HealthResponse)
async def health():
    return {"status": "ok"}


def run() -> None:
    uvicorn.run("waygate.main:app", host="0.0.0.0", port=8010)
