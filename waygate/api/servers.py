"""Waygate 서버 관리 API — 사용자 JWT 인증 + project_id 소유권 검증."""

import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException

from waygate.auth import require_token
from waygate.config import get_settings
from waygate.db import is_db_available
from waygate.models.schemas import WaygateServerCreateRequest, WaygateServerInfo
from waygate.services import waygate_agent_auth, waygate_db, waygate_jobs

router = APIRouter()
_logger = logging.getLogger(__name__)


def _require_db() -> None:
    if not is_db_available():
        raise HTTPException(status_code=503, detail="DB를 사용할 수 없습니다")


async def _merge_status(server: dict) -> WaygateServerInfo:
    """DB 레코드 + Redis 최신 상태(에이전트 마지막 보고)를 병합해 WaygateServerInfo를 만든다."""
    info = WaygateServerInfo(**{k: v for k, v in server.items() if k in WaygateServerInfo.model_fields})
    status_result = await waygate_agent_auth.get_status_result(server["id"])
    if status_result:
        info.last_status_reported_at = status_result.get("_stored_at")
        info.peer_count = len(status_result.get("peers", []))
    return info


@router.post("", status_code=201, response_model=WaygateServerInfo)
@router.post("/", status_code=201, response_model=WaygateServerInfo, include_in_schema=False)
async def create_waygate_server(
    body: WaygateServerCreateRequest,
    token_info: dict = Depends(require_token),
):
    """Waygate 서버 프로비저닝 요청 — CREATING 상태로 즉시 응답, 백그라운드에서 부팅."""
    _require_db()
    settings = get_settings()
    project_id = token_info["project_id"]
    from waygate.auth import get_admin_connection_for_project
    from waygate.services.resource_policies import get_policy_snapshot, resolve_policy_snapshot

    conn = await asyncio.to_thread(get_admin_connection_for_project, project_id)
    try:
        snapshot = await resolve_policy_snapshot(
            conn=conn,
            keys=("waygate.provider_network", "waygate.image", "waygate.flavor"),
        )
        floating_network = (await get_policy_snapshot(("waygate.floating_network",)))["waygate.floating_network"]
        if floating_network is not None:
            snapshot["waygate.floating_network"] = floating_network
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Waygate resource policy is unavailable: {exc}") from exc
    finally:
        await asyncio.to_thread(conn.close)

    server_id = str(uuid.uuid4())

    await waygate_jobs.enqueue_provision_job(
        project_id,
        server_id,
        {
            "name": body.name,
            "status": "CREATING",
            "listen_port": settings.waygate_default_listen_port,
            "tunnel_cidr": settings.waygate_default_tunnel_cidr,
            "flavor_id": snapshot["waygate.flavor"]["id"],
            "image_id": snapshot["waygate.image"]["id"],
            "provider_network_id": snapshot["waygate.provider_network"]["id"],
            "floating_network_id": (snapshot.get("waygate.floating_network") or {}).get("id"),
            "resource_policy_snapshot": snapshot,
            "created_by_user_id": token_info.get("user_id"),
            "created_by_username": token_info.get("username"),
        },
        user_id=token_info.get("user_id"),
        username=token_info.get("username"),
    )

    server = await waygate_db.get_server(project_id, server_id)
    return await _merge_status(server)


@router.get("", response_model=list[WaygateServerInfo])
@router.get("/", response_model=list[WaygateServerInfo], include_in_schema=False)
async def list_waygate_servers(token_info: dict = Depends(require_token)):
    _require_db()
    project_id = token_info["project_id"]
    servers = await waygate_db.list_servers(project_id)
    return [await _merge_status(s) for s in servers]


@router.get("/{server_id}", response_model=WaygateServerInfo)
async def get_waygate_server(server_id: str, token_info: dict = Depends(require_token)):
    _require_db()
    project_id = token_info["project_id"]
    server = await waygate_db.get_server(project_id, server_id)
    if not server:
        # 정보 노출 방지 — 존재하지 않음/타 프로젝트 소유 모두 동일 404
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    return await _merge_status(server)


@router.delete("/{server_id}", status_code=202)
async def delete_waygate_server_endpoint(server_id: str, token_info: dict = Depends(require_token)):
    _require_db()
    project_id = token_info["project_id"]
    found = await waygate_jobs.enqueue_delete_job(
        project_id,
        server_id,
        user_id=token_info.get("user_id"),
        username=token_info.get("username"),
    )
    if not found:
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    return {"ok": True, "status": "DELETING"}
