"""Waygate 클라이언트(peer) 관리 API — 사용자 JWT 인증 + 서버 소유권 검증."""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response

from waygate.auth import require_token
from waygate.db import is_db_available
from waygate.models.schemas import (
    WaygateClientCreateRequest,
    WaygateClientCreateResponse,
    WaygateClientInfo,
    WaygateClientUpdateRequest,
)
from waygate.services import k3s_crypto, waygate_agent_auth, waygate_config, waygate_db, waygate_ipam, waygate_keys
from waygate.services.store import WaygateClientConflictError

router = APIRouter()
_logger = logging.getLogger(__name__)


def _require_db() -> None:
    if not is_db_available():
        raise HTTPException(status_code=503, detail="DB를 사용할 수 없습니다")


async def _get_owned_server(project_id: str, server_id: str) -> dict:
    """서버 소유권 검증. 없거나 타 프로젝트 소유면 404 (정보 노출 방지)."""
    server = await waygate_db.get_server(project_id, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    return server


async def _merge_client_status(client: dict, server_id: str) -> WaygateClientInfo:
    info = WaygateClientInfo(**{k: v for k, v in client.items() if k in WaygateClientInfo.model_fields})
    status_result = await waygate_agent_auth.get_status_result(server_id)
    if status_result:
        for peer in status_result.get("peers", []):
            if peer.get("public_key") == client["public_key"]:
                info.last_handshake_at = peer.get("last_handshake_at")
                info.rx_bytes = peer.get("rx_bytes")
                info.tx_bytes = peer.get("tx_bytes")
                info.online = bool(peer.get("last_handshake_at"))
                break
        else:
            info.online = False
    return info


@router.post("/{server_id}/clients", status_code=201, response_model=WaygateClientCreateResponse)
async def create_waygate_client(
    server_id: str,
    body: WaygateClientCreateRequest,
    token_info: dict = Depends(require_token),
):
    """클라이언트 발급. 응답에는 이번 1회만이 아니라 매 조회 시 재구성 가능한 tunnel_conf 를 포함한다.

    private key는 AES-GCM 암호화 저장하므로, GET /{server_id}/clients/{cid}/config 로
    언제든 동일한 .conf 를 재다운로드할 수 있다(k3s kubeconfig 다운로드 패턴과 동일).
    """
    _require_db()
    project_id = token_info["project_id"]
    server = await _get_owned_server(project_id, server_id)
    if server["status"] != "ACTIVE":
        raise HTTPException(status_code=409, detail="Waygate 서버가 ACTIVE 상태가 아닙니다 (에이전트 register 대기 중)")
    if not server.get("server_public_key"):
        raise HTTPException(status_code=409, detail="Waygate 서버 공개키가 아직 등록되지 않았습니다")

    private_key, public_key = waygate_keys.generate_keypair()

    existing_clients = await waygate_db.list_clients(server_id, project_id)
    used_ips = [c["tunnel_ip"] for c in existing_clients]
    tunnel_ip = waygate_ipam.allocate_next_ip(server["tunnel_cidr"], used_ips)

    client_id = str(uuid.uuid4())
    private_key_encrypted = k3s_crypto.encrypt_wg_client_key(private_key)

    allowed_ips = body.allowed_ips or [server["tunnel_cidr"]]

    try:
        await waygate_db.create_client_record(
            server_id,
            project_id,
            client_id,
            {
                "name": body.name,
                "enabled": True,
                "public_key": public_key,
                "private_key_encrypted": private_key_encrypted,
                "tunnel_ip": tunnel_ip,
                "allowed_ips": allowed_ips,
                "dns": body.dns,
            },
        )
    except WaygateClientConflictError as exc:
        if exc.field == "name":
            detail = "동일한 이름의 클라이언트가 이미 존재합니다"
        elif exc.field == "tunnel_ip":
            detail = "터널 IP가 이미 사용 중입니다. 잠시 후 다시 시도해주세요"
        else:
            detail = "클라이언트 생성 중 충돌이 발생했습니다. 잠시 후 다시 시도해주세요"
        raise HTTPException(status_code=409, detail=detail) from exc

    nat_cidrs = await waygate_db.list_active_attachment_cidrs(server_id)
    tunnel_conf = waygate_config.render_client_conf(
        private_key=private_key,
        tunnel_ip=tunnel_ip,
        dns=body.dns,
        server_public_key=server["server_public_key"],
        endpoint_ip=server["endpoint_ip"] or "",
        listen_port=server["listen_port"],
        allowed_ips=allowed_ips,
        nat_cidrs=nat_cidrs,
    )

    client = await waygate_db.get_client(server_id, project_id, client_id)
    info = await _merge_client_status(client, server_id)
    return WaygateClientCreateResponse(**info.model_dump(), tunnel_conf=tunnel_conf)


@router.get("/{server_id}/clients", response_model=list[WaygateClientInfo])
async def list_waygate_clients(server_id: str, token_info: dict = Depends(require_token)):
    _require_db()
    project_id = token_info["project_id"]
    await _get_owned_server(project_id, server_id)
    clients = await waygate_db.list_clients(server_id, project_id)
    return [await _merge_client_status(c, server_id) for c in clients]


@router.patch("/{server_id}/clients/{client_id}", response_model=WaygateClientInfo)
async def update_waygate_client(
    server_id: str,
    client_id: str,
    body: WaygateClientUpdateRequest,
    token_info: dict = Depends(require_token),
):
    _require_db()
    project_id = token_info["project_id"]
    await _get_owned_server(project_id, server_id)
    updated = await waygate_db.update_client(server_id, project_id, client_id, name=body.name, enabled=body.enabled)
    if not updated:
        raise HTTPException(status_code=404, detail="Waygate 클라이언트를 찾을 수 없습니다")
    return await _merge_client_status(updated, server_id)


@router.delete("/{server_id}/clients/{client_id}", status_code=204)
async def delete_waygate_client(server_id: str, client_id: str, token_info: dict = Depends(require_token)):
    _require_db()
    project_id = token_info["project_id"]
    await _get_owned_server(project_id, server_id)
    ok = await waygate_db.soft_delete_client(server_id, project_id, client_id, token_info.get("user_id", ""))
    if not ok:
        raise HTTPException(status_code=404, detail="Waygate 클라이언트를 찾을 수 없습니다")


@router.get("/{server_id}/clients/{client_id}/config")
async def download_vpn_client_config(server_id: str, client_id: str, token_info: dict = Depends(require_token)):
    """`.conf` 파일 다운로드. 매 호출마다 복호화 후 재렌더 (k3s kubeconfig 다운로드 패턴 미러)."""
    _require_db()
    project_id = token_info["project_id"]
    server = await _get_owned_server(project_id, server_id)
    client = await waygate_db.get_client(server_id, project_id, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Waygate 클라이언트를 찾을 수 없습니다")
    if not server.get("server_public_key") or not server.get("endpoint_ip"):
        raise HTTPException(status_code=409, detail="Waygate 서버가 아직 준비되지 않았습니다")

    try:
        private_key = k3s_crypto.decrypt_wg_client_key(client["private_key_encrypted"])
    except Exception:
        _logger.error("Waygate 클라이언트 private key 복호화 실패 (client=%s)", client_id)
        raise HTTPException(status_code=500, detail="클라이언트 키 복호화에 실패했습니다. 관리자에게 문의하세요.")

    nat_cidrs = await waygate_db.list_active_attachment_cidrs(server_id)
    tunnel_conf = waygate_config.render_client_conf(
        private_key=private_key,
        tunnel_ip=client["tunnel_ip"],
        dns=client.get("dns"),
        server_public_key=server["server_public_key"],
        endpoint_ip=server["endpoint_ip"],
        listen_port=server["listen_port"],
        allowed_ips=client.get("allowed_ips") or [server["tunnel_cidr"]],
        nat_cidrs=nat_cidrs,
    )

    return Response(
        content=tunnel_conf,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{client["name"]}.conf"'},
    )
