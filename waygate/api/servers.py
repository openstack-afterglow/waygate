"""Waygate 서버 관리 API — 사용자 JWT 인증 + project_id 소유권 검증."""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException

from waygate.auth import require_action
from waygate.config import get_settings
from waygate.db import is_db_available
from waygate.models.schemas import (
    WaygateServerCreateRequest,
    WaygateServerDeleteResponse,
    WaygateServerDiagnostics,
    WaygateServerInfo,
    WaygateServerUpdateRequest,
)
from waygate.services import execution, waygate_agent_auth, waygate_agent_telemetry, waygate_db, waygate_jobs
from waygate.services.store import WaygateServerInactiveError

router = APIRouter()
_logger = logging.getLogger(__name__)

# Gateways expecting more clients than this use waygate.flavor_large when it is configured.
SMALL_TIER_MAX_CLIENTS = 50


def requested_flavor_tier(expected_clients: int | None) -> str | None:
    if expected_clients is None:
        return None
    return "small" if expected_clients <= SMALL_TIER_MAX_CLIENTS else "large"


def _require_db() -> None:
    if not is_db_available():
        raise HTTPException(status_code=503, detail="DB를 사용할 수 없습니다")


async def _merge_status(server: dict) -> WaygateServerInfo:
    """DB 레코드 + Redis 최신 상태(에이전트 마지막 보고)를 병합해 WaygateServerInfo를 만든다."""
    # Worker/OpenStack exception text is not safe tenant metadata at any grade.
    info = WaygateServerInfo(
        **{k: v for k, v in server.items() if k in WaygateServerInfo.model_fields and k != "status_reason"}
    )
    status_result = await waygate_agent_auth.get_status_result(server["id"])
    if status_result:
        info.last_status_reported_at = status_result.get("_stored_at")
        info.peer_count = len(status_result.get("peers", []))
        info.agent_source = status_result.get("agent_source")
        info.report_interval_seconds = status_result.get("report_interval_seconds")
    return info


@router.post("", status_code=201, response_model=WaygateServerInfo)
@router.post("/", status_code=201, response_model=WaygateServerInfo, include_in_schema=False)
async def create_waygate_server(
    body: WaygateServerCreateRequest,
    token_info: dict = Depends(require_action("waygate:server:create")),
):
    """Waygate 서버 프로비저닝 요청 — CREATING 상태로 즉시 응답, 백그라운드에서 부팅."""
    _require_db()
    settings = get_settings()
    project_id = token_info["project_id"]
    from waygate.services.resource_policies import get_policy_snapshot, resolve_policy_snapshot

    server_id = str(uuid.uuid4())
    flavor_tier = requested_flavor_tier(body.expected_clients)
    try:
        async with execution.admitted_operation(token_info, server_id, "provision") as (grant, conn):
            snapshot = await resolve_policy_snapshot(
                conn=conn,
                keys=("waygate.provider_network", "waygate.image", "waygate.flavor"),
            )
            optional = await get_policy_snapshot(("waygate.floating_network", "waygate.flavor_large"))
            if (floating_network := optional.get("waygate.floating_network")) is not None:
                snapshot["waygate.floating_network"] = floating_network
            flavor = snapshot["waygate.flavor"]
            if flavor_tier == "large":
                if optional.get("waygate.flavor_large") is not None:
                    large = await resolve_policy_snapshot(conn=conn, keys=("waygate.flavor_large",))
                    snapshot["waygate.flavor_large"] = flavor = large["waygate.flavor_large"]
                else:
                    # No large flavor configured: every gateway keeps the base flavor (no tiering).
                    flavor_tier = "small"
            await waygate_jobs.enqueue_provision_job(
                project_id,
                server_id,
                {
                    "name": body.name,
                    "status": "CREATING",
                    "listen_port": settings.waygate_default_listen_port,
                    "tunnel_cidr": settings.waygate_default_tunnel_cidr,
                    "dns": body.dns,
                    "persistent_keepalive": body.persistent_keepalive,
                    "flavor_id": flavor["id"],
                    "expected_clients": body.expected_clients,
                    "flavor_tier": flavor_tier,
                    "image_id": snapshot["waygate.image"]["id"],
                    "provider_network_id": snapshot["waygate.provider_network"]["id"],
                    "floating_network_id": (snapshot.get("waygate.floating_network") or {}).get("id"),
                    "resource_policy_snapshot": snapshot,
                    "agent_install_mode": settings.waygate_agent_install_mode,
                    "created_by_user_id": token_info.get("user_id"),
                    "created_by_username": token_info.get("username"),
                },
                user_id=token_info.get("user_id"),
                username=token_info.get("username"),
                execution_grant_id=grant.id,
            )
    except execution.ExecutionDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    except Exception as exc:
        _logger.warning("gateway stage=admission status=unavailable error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Waygate execution or resource policy is unavailable") from None

    server = await waygate_db.get_server(project_id, server_id)
    return await _merge_status(server)


@router.get("", response_model=list[WaygateServerInfo])
@router.get("/", response_model=list[WaygateServerInfo], include_in_schema=False)
async def list_waygate_servers(token_info: dict = Depends(require_action("waygate:server:list"))):
    _require_db()
    project_id = token_info["project_id"]
    servers = await waygate_db.list_servers(project_id)
    return [await _merge_status(s) for s in servers]


@router.get("/{server_id}", response_model=WaygateServerInfo)
async def get_waygate_server(server_id: str, token_info: dict = Depends(require_action("waygate:server:get"))):
    _require_db()
    project_id = token_info["project_id"]
    server = await waygate_db.get_server(project_id, server_id)
    if not server:
        # 정보 노출 방지 — 존재하지 않음/타 프로젝트 소유 모두 동일 404
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    return await _merge_status(server)


@router.get("/{server_id}/diagnostics", response_model=WaygateServerDiagnostics)
async def get_waygate_server_diagnostics(
    server_id: str, token_info: dict = Depends(require_action("waygate:server:get"))
):
    """Explain agent connectivity from Waygate-observed register/poll/report receive times."""
    _require_db()
    server = await waygate_db.get_server(token_info["project_id"], server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    try:
        telemetry = await waygate_agent_telemetry.get_telemetry(server_id)
    except waygate_agent_telemetry.TelemetryUnavailable:
        raise HTTPException(status_code=503, detail="Agent telemetry storage unavailable") from None
    clients = await waygate_db.list_all_active_clients(server_id)
    attachments = await waygate_db.list_active_attachment_cidrs(server_id)
    return waygate_agent_telemetry.evaluate(
        server,
        telemetry,
        enabled_clients=sum(1 for client in clients if client.get("enabled")),
        attachments=len(attachments),
        now=waygate_agent_telemetry.now(),
    )


@router.patch("/{server_id}", response_model=WaygateServerInfo)
async def update_waygate_server(
    server_id: str,
    body: WaygateServerUpdateRequest,
    token_info: dict = Depends(require_action("waygate:server:update")),
):
    _require_db()
    try:
        server = await waygate_db.update_server_defaults(
            token_info["project_id"], server_id, body.model_dump(exclude_unset=True)
        )
    except WaygateServerInactiveError as exc:
        raise HTTPException(status_code=409, detail="Waygate 서버가 ACTIVE 상태가 아닙니다") from exc
    if server is None:
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    return await _merge_status(server)


@router.post("/{server_id}/agent-token/rotate", status_code=202, response_model=WaygateServerInfo)
async def rotate_waygate_agent_token(server_id: str, token_info: dict = Depends(require_action("waygate:server:rotate-agent-token"))):
    """Stage an agent credential handoff without exposing the token to the tenant."""
    _require_db()
    project_id = token_info["project_id"]
    server = await waygate_db.get_server(project_id, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    if server["status"] != "ACTIVE":
        raise HTTPException(status_code=409, detail="Waygate 서버가 ACTIVE 상태가 아닙니다")
    try:
        await waygate_agent_auth.request_token_rotation(server_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=f"에이전트 토큰을 갱신할 수 없습니다: {exc}") from exc
    server = await waygate_db.get_server(project_id, server_id)
    return await _merge_status(server)


@router.delete("/{server_id}", status_code=202, response_model=WaygateServerDeleteResponse)
async def delete_waygate_server_endpoint(server_id: str, token_info: dict = Depends(require_action("waygate:server:delete"))):
    _require_db()
    project_id = token_info["project_id"]
    if not await waygate_db.get_server(project_id, server_id):
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    try:
        async with execution.admitted_operation(token_info, server_id, "delete") as (grant, _conn):
            found = await waygate_jobs.enqueue_delete_job(
                project_id,
                server_id,
                user_id=token_info.get("user_id"),
                username=token_info.get("username"),
                execution_grant_id=grant.id,
            )
    except execution.ExecutionDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    except execution.ExecutionUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    if not found:
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    return {"ok": True, "status": "DELETING"}
