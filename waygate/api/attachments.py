"""Waygate 네트워크 연결 API (Phase 2) — 사용자 JWT 인증 + 서버 소유권 검증.

servers/clients 와 동일 prefix(/api/v1/waygate/servers)에 마운트되며 상대 경로가
/{server_id}/networks[/...] 로 겹치지 않는다.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException

from waygate.auth import require_token
from waygate.db import is_db_available
from waygate.models.schemas import WaygateNetworkAttachCreateRequest, WaygateNetworkAttachmentInfo
from waygate.services import waygate_db, waygate_network
from waygate.services.network import WaygateNetworkError

router = APIRouter()
_logger = logging.getLogger(__name__)


def _require_db() -> None:
    if not is_db_available():
        raise HTTPException(status_code=503, detail="DB를 사용할 수 없습니다")


async def _get_owned_server(project_id: str, server_id: str) -> dict:
    server = await waygate_db.get_server(project_id, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    return server


def _to_info(att: dict) -> WaygateNetworkAttachmentInfo:
    return WaygateNetworkAttachmentInfo(
        **{k: v for k, v in att.items() if k in WaygateNetworkAttachmentInfo.model_fields}
    )


@router.post("/{server_id}/networks", status_code=201, response_model=WaygateNetworkAttachmentInfo)
async def attach_waygate_network(
    server_id: str,
    body: WaygateNetworkAttachCreateRequest,
    token_info: dict = Depends(require_token),
):
    """Waygate 서버에 테넌트 네트워크를 추가 연결(멀티 NIC + SNAT). 서버가 ACTIVE 여야 한다."""
    _require_db()
    project_id = token_info["project_id"]
    server = await _get_owned_server(project_id, server_id)
    try:
        att = await waygate_network.attach_network(project_id, server, body.network_id, body.subnet_id, body.nat_mode)
    except WaygateNetworkError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail) from e
    return _to_info(att)


@router.get("/{server_id}/networks", response_model=list[WaygateNetworkAttachmentInfo])
async def list_waygate_networks(server_id: str, token_info: dict = Depends(require_token)):
    _require_db()
    project_id = token_info["project_id"]
    await _get_owned_server(project_id, server_id)
    atts = await waygate_db.list_attachments(server_id, project_id)
    return [_to_info(a) for a in atts]


@router.delete("/{server_id}/networks/{attachment_id}", status_code=204)
async def detach_waygate_network(server_id: str, attachment_id: int, token_info: dict = Depends(require_token)):
    _require_db()
    project_id = token_info["project_id"]
    server = await _get_owned_server(project_id, server_id)
    try:
        await waygate_network.detach_network(project_id, server, attachment_id)
    except WaygateNetworkError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail) from e
