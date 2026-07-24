"""FastAPI wiring, authentication, error envelopes, and CLI entry point."""

from __future__ import annotations

import argparse
import base64
import hmac
import io
import os
import re
from pathlib import Path
import sys
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID

import qrcode
from qrcode.image.pure import PyPNGImage
from qrcode.image.svg import SvgPathImage
from fastapi import Depends, FastAPI, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
import uvicorn

from .contracts import AgentError, ClientCreate, ClientListResponse, ClientPatch, ClientPut, ClientResponse, ErrorResponse, HealthResponse, QrBase64Response, ShareCreate, ShareResponse, StatusResponse, TrafficResponse
from .paths import RuntimePaths
from .services import AgentService
from .settings import Settings
from .network import LinuxNetworkControl, NetworkUnavailable
from .wireguard import WgCliControl, WireGuardUnavailable
from .db import DatabaseBusy
from .web import temporary_console

bearer = HTTPBearer(auto_error=False)


def _error(status: int, code: str, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(ErrorResponse(error={"code": code, "message": message}).model_dump(mode="json"), status_code=status, headers=headers)


def create_app(settings: Settings | None = None, *, paths: RuntimePaths | None = None, control: WgCliControl | None = None, network: object | None = None) -> FastAPI:
    settings = settings or Settings()
    service = AgentService(settings, paths or RuntimePaths.production(), control or WgCliControl(), network)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        service.startup()
        app.state.service = service
        try:
            yield
        finally:
            service.shutdown()

    app = FastAPI(docs_url="/docs" if settings.api_docs_enabled else None, redoc_url=None, openapi_url="/openapi.json" if settings.api_docs_enabled else None, lifespan=lifespan)

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > 16 * 1024):
            return _error(413, "request_too_large", "Request body too large")
        return await call_next(request)

    @app.exception_handler(AgentError)
    async def agent_error(_: Request, exc: AgentError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
        return _error(exc.status_code, exc.code, exc.message, headers)

    @app.exception_handler(ValidationError)
    async def validation_error(_: Request, exc: ValidationError) -> JSONResponse:
        return _error(422, "validation_error", "Request validation failed")

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return _error(422, "validation_error", "Request validation failed")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        if exc.status_code == 404:
            return _error(404, "route_not_found", "Route not found")
        if exc.status_code == 405:
            return _error(405, "method_not_allowed", "Method not allowed")
        return _error(exc.status_code, "internal_error", "Internal error")

    @app.exception_handler(DatabaseBusy)
    async def database_busy(_: Request, exc: DatabaseBusy) -> JSONResponse:
        return _error(503, "database_busy", "Database busy")

    @app.exception_handler(NetworkUnavailable)
    async def network_unavailable(_: Request, exc: NetworkUnavailable) -> JSONResponse:
        return _error(503, "state_reconciliation_failed", "State reconciliation failed")

    @app.exception_handler(WireGuardUnavailable)
    async def wireguard_unavailable(_: Request, exc: WireGuardUnavailable) -> JSONResponse:
        return _error(503, "wireguard_unavailable", "WireGuard unavailable")

    async def authenticated(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]) -> None:
        if credentials is None or credentials.scheme.lower() != "bearer" or not hmac.compare_digest(credentials.credentials, settings.api_auth_token.get_secret_value()):
            raise AgentError(401, "authentication_required", "Authentication required")

    @app.get("/", include_in_schema=False)
    async def console() -> Response:
        return temporary_console()

    @app.get("/healthz", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse()

    @app.get("/api/v1/status", response_model=StatusResponse, dependencies=[Depends(authenticated)])
    async def status() -> Response:
        return JSONResponse((await run_in_threadpool(service.status)).model_dump(mode="json"))

    @app.get("/api/v1/traffic", response_model=TrafficResponse, dependencies=[Depends(authenticated)])
    async def traffic() -> Response:
        response = TrafficResponse(peers=await run_in_threadpool(service.peer_traffic))
        return JSONResponse(response.model_dump(mode="json"), headers={"Cache-Control": "no-store"})

    @app.get("/api/v1/clients", response_model=ClientListResponse, dependencies=[Depends(authenticated)])
    async def clients() -> Response:
        return JSONResponse(ClientListResponse(clients=await run_in_threadpool(service.list_clients)).model_dump(mode="json"))

    @app.post("/api/v1/clients", response_model=ClientResponse, status_code=201, dependencies=[Depends(authenticated)])
    async def create(payload: ClientCreate) -> Response:
        prepared = await run_in_threadpool(service.create_client, name=payload.name, address=payload.address, allowed_ips=payload.allowed_ips, dns=payload.dns if payload.dns is not None else [settings.wg_default_dns], mtu=payload.mtu, persistent_keepalive=payload.persistent_keepalive)
        return prepared.response

    @app.put("/api/v1/clients/{client_id}", response_model=ClientResponse, dependencies=[Depends(authenticated)])
    async def put(client_id: UUID, payload: ClientPut) -> Response:
        return (await run_in_threadpool(service.update_client, client_id, name=payload.name, allowed_ips=payload.allowed_ips, dns=payload.dns, enabled=payload.enabled, mtu=payload.mtu, persistent_keepalive=payload.persistent_keepalive)).response

    @app.patch("/api/v1/clients/{client_id}", response_model=ClientResponse, dependencies=[Depends(authenticated)])
    async def patch(client_id: UUID, payload: ClientPatch) -> Response:
        def apply_patch():
            current = service.get_client(client_id)
            return service.update_client(client_id, name=current.name if payload.name is None else payload.name, allowed_ips=list(current.allowed_ips) if payload.allowed_ips is None else payload.allowed_ips, dns=list(current.dns) if payload.dns is None else payload.dns, enabled=current.enabled if payload.enabled is None else payload.enabled, mtu=current.mtu if payload.mtu is None else payload.mtu, persistent_keepalive=current.persistent_keepalive if payload.persistent_keepalive is None else payload.persistent_keepalive)
        return (await run_in_threadpool(apply_patch)).response

    @app.delete("/api/v1/clients/{client_id}", status_code=204, dependencies=[Depends(authenticated)])
    async def delete(client_id: UUID) -> Response:
        await run_in_threadpool(service.delete_client, client_id)
        return Response(status_code=204)

    @app.get("/api/v1/clients/{client_id}/config", response_class=PlainTextResponse, dependencies=[Depends(authenticated)])
    async def config(client_id: UUID) -> Response:
        return PlainTextResponse(await run_in_threadpool(service.profile, client_id), media_type="text/plain", headers={"Cache-Control": "no-store"})

    @app.get("/api/v1/clients/{client_id}/qrcode", dependencies=[Depends(authenticated)])
    async def qr(client_id: UUID, format: list[str] | None = Query(default=None)) -> Response:
        values = ["png"] if format is None else format
        if len(values) != 1 or values[0] not in {"png", "svg", "base64"}:
            raise AgentError(422, "validation_error", "Request validation failed")
        format = values[0]
        profile = await run_in_threadpool(service.profile, client_id)
        if format == "svg":
            image = qrcode.make(profile, image_factory=SvgPathImage)
            buffer = io.BytesIO(); image.save(buffer)
            return Response(buffer.getvalue(), media_type="image/svg+xml", headers={"Cache-Control": "no-store"})
        image = qrcode.make(profile, image_factory=PyPNGImage); buffer = io.BytesIO(); image.save(buffer)
        if format == "base64":
            return JSONResponse(QrBase64Response(data=base64.b64encode(buffer.getvalue()).decode("ascii")).model_dump(mode="json"), headers={"Cache-Control": "no-store"})
        return Response(buffer.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store"})

    @app.post("/api/v1/clients/{client_id}/share", response_model=ShareResponse, status_code=201, dependencies=[Depends(authenticated)])
    async def share(client_id: UUID, payload: ShareCreate = ShareCreate()) -> Response:
        return (await run_in_threadpool(service.share, client_id, payload.expires_in_seconds, payload.single_use)).response

    @app.get("/download/{token}", response_class=PlainTextResponse)
    async def download(token: str) -> Response:
        return (await run_in_threadpool(service.download_with_client, token)).response

    return app


def _mountinfo_unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _required_runtime_mounts(content: str) -> bool:
    mounts: dict[str, tuple[str, str, set[str]]] = {}
    for line in content.splitlines():
        if " - " not in line:
            continue
        before, after = line.split(" - ", 1)
        fields, post = before.split(), after.split()
        if len(fields) < 6 or len(post) < 3:
            continue
        mountpoint = _mountinfo_unescape(fields[4])
        options = set(fields[5].split(",")) | set(post[2].split(","))
        mounts[mountpoint] = (post[0], _mountinfo_unescape(post[1]), options)
    required = {"/etc/wireguard", "/var/lib/afterglow-wg-agent", "/run/afterglow-wg-agent"}
    if not required.issubset(mounts):
        return False
    wireguard_type, wireguard_source, _ = mounts["/etc/wireguard"]
    state_type, state_source, _ = mounts["/var/lib/afterglow-wg-agent"]
    run_type, _, run_options = mounts["/run/afterglow-wg-agent"]
    if wireguard_type == "tmpfs" or state_type == "tmpfs" or not wireguard_source or not state_source:
        return False
    return run_type == "tmpfs" and {"rw", "noexec", "nosuid"}.issubset(run_options) and ("mode=0700" in run_options or "mode=700" in run_options)


def run() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("serve", nargs="?")
    parser.add_argument("--require-runtime-mounts", action="store_true")
    args = parser.parse_args()
    if args.require_runtime_mounts:
        if not _required_runtime_mounts(Path("/proc/self/mountinfo").read_text(encoding="utf-8")):
            raise SystemExit("required_runtime_mount_missing")
    settings = Settings()
    uvicorn.run(create_app(settings, network=LinuxNetworkControl()), host=str(settings.api_host), port=settings.api_port, workers=1, access_log=False)
