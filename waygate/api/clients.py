"""Native client metadata, administration and assigned-user profile downloads."""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Response

from waygate.auth import (
    has_capability,
    require_clients_admin,
    require_clients_editor,
    require_clients_update,
    require_connect,
    require_inventory,
    validate_client_owner,
)
from waygate.db import is_db_available
from waygate.models.schemas import (
    WaygateClientCreateRequest,
    WaygateClientCreateResponse,
    WaygateClientInfo,
    WaygateClientUpdateRequest,
)
from waygate.services import k3s_crypto, waygate_agent_auth, waygate_config, waygate_db, waygate_ipam, waygate_keys
from waygate.services.store import WaygateClientConflictError, WaygateClientOwnerConflictError

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


_ONLINE_WINDOW = timedelta(seconds=120)
_CLOCK_SKEW = timedelta(seconds=30)


def _recent(timestamp: str | None, now: datetime) -> bool:
    """Timezone-aware timestamp within the online window, tolerating small VM clock skew."""
    if not timestamp:
        return False
    try:
        parsed = datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None:
            return False
        age = now - parsed.astimezone(UTC)
        return -_CLOCK_SKEW <= age <= _ONLINE_WINDOW
    except (TypeError, ValueError, OverflowError):
        return False


def _merge_client_status(client: dict, status_result: dict | None) -> WaygateClientInfo:
    info = WaygateClientInfo(**{k: v for k, v in client.items() if k in WaygateClientInfo.model_fields})
    info.psk_enabled = bool(client.get("preshared_key_encrypted"))
    if status_result:
        info.last_reported_at = status_result.get("_stored_at")
        info.report_interval_seconds = status_result.get("report_interval_seconds")
        info.online = False
        for peer in status_result.get("peers", []):
            if peer.get("public_key") == client["public_key"]:
                info.last_handshake_at = peer.get("last_handshake_at")
                info.rx_bytes = peer.get("rx_bytes")
                info.tx_bytes = peer.get("tx_bytes")
                now = datetime.now(UTC)
                info.online = bool(
                    info.enabled and _recent(info.last_reported_at, now) and _recent(info.last_handshake_at, now)
                )
                break
    return info


@router.post("/{server_id}/clients", status_code=201, response_model=WaygateClientCreateResponse)
async def create_waygate_client(
    server_id: str,
    body: WaygateClientCreateRequest,
    response: Response,
    token_info: dict = Depends(require_clients_editor),
):
    """Issue metadata; plaintext tunnel_conf requires current connect authority on an enabled owned profile.

    Profiles created for another member or left unassigned never expose their private key/PSK to the creator.
    """
    _require_db()
    project_id = token_info["project_id"]
    server = await _get_owned_server(project_id, server_id)
    if server["status"] != "ACTIVE":
        raise HTTPException(status_code=409, detail="Waygate 서버가 ACTIVE 상태가 아닙니다 (에이전트 register 대기 중)")
    if not server.get("server_public_key"):
        raise HTTPException(status_code=409, detail="Waygate 서버 공개키가 아직 등록되지 않았습니다")

    owner_user_id = body.owner_user_id if "owner_user_id" in body.model_fields_set else token_info["user_id"]
    await validate_client_owner(project_id, owner_user_id)

    private_key, public_key = waygate_keys.generate_keypair()

    existing_clients = await waygate_db.list_clients(server_id, project_id)
    used_ips = [c["tunnel_ip"] for c in existing_clients]
    tunnel_ip = waygate_ipam.allocate_next_ip(server["tunnel_cidr"], used_ips)

    client_id = str(uuid.uuid4())
    preshared_key = waygate_keys.generate_preshared_key()
    private_key_encrypted = k3s_crypto.encrypt_wg_client_key(private_key)

    allowed_ips = body.allowed_ips or [server["tunnel_cidr"]]
    data = {
        "name": body.name,
        "owner_user_id": owner_user_id,
        "enabled": True,
        "public_key": public_key,
        "private_key_encrypted": private_key_encrypted,
        "preshared_key_encrypted": k3s_crypto.encrypt_wg_client_key(preshared_key),
        "tunnel_ip": tunnel_ip,
        "allowed_ips": allowed_ips,
    }
    for field in ("dns", "mtu", "persistent_keepalive"):
        if field in body.model_fields_set:
            data[field] = getattr(body, field)
    for field, flag in (("dns", "inherit_dns"), ("persistent_keepalive", "inherit_persistent_keepalive")):
        data[flag] = field not in body.model_fields_set

    try:
        await waygate_db.create_client_record(
            server_id,
            project_id,
            client_id,
            data,
        )
    except WaygateClientConflictError as exc:
        if exc.field == "name":
            detail = "동일한 이름의 클라이언트가 이미 존재합니다"
        elif exc.field == "tunnel_ip":
            detail = "터널 IP가 이미 사용 중입니다. 잠시 후 다시 시도해주세요"
        else:
            detail = "클라이언트 생성 중 충돌이 발생했습니다. 잠시 후 다시 시도해주세요"
        raise HTTPException(status_code=409, detail=detail) from exc

    client = await waygate_db.get_client(server_id, project_id, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="Waygate 클라이언트를 찾을 수 없습니다")
    tunnel_conf = None
    if (
        has_capability(token_info, "waygate-connect_user")
        and client.get("owner_user_id") == token_info["user_id"]
        and client.get("enabled")
    ):
        nat_cidrs = await waygate_db.list_active_attachment_cidrs(server_id)
        tunnel_conf = waygate_config.render_client_conf(
            private_key=private_key,
            tunnel_ip=client["tunnel_ip"],
            dns=client.get("dns"),
            mtu=client.get("mtu"),
            persistent_keepalive=client.get("persistent_keepalive", 25),
            preshared_key=preshared_key,
            server_public_key=server["server_public_key"],
            endpoint_ip=server["endpoint_ip"] or "",
            listen_port=server["listen_port"],
            allowed_ips=client.get("allowed_ips") or [server["tunnel_cidr"]],
            nat_cidrs=nat_cidrs,
        )

    info = _merge_client_status(client, await waygate_agent_auth.get_status_result(server_id))
    response.headers["Cache-Control"] = "no-store"
    return WaygateClientCreateResponse(**info.model_dump(), tunnel_conf=tunnel_conf)


@router.get("/{server_id}/clients", response_model=list[WaygateClientInfo])
async def list_waygate_clients(server_id: str, token_info: dict = Depends(require_inventory)):
    _require_db()
    project_id = token_info["project_id"]
    await _get_owned_server(project_id, server_id)
    clients = await waygate_db.list_clients(server_id, project_id)
    status = await waygate_agent_auth.get_status_result(server_id)
    return [_merge_client_status(c, status) for c in clients]


@router.patch("/{server_id}/clients/{client_id}", response_model=WaygateClientInfo)
async def update_waygate_client(
    server_id: str,
    client_id: str,
    body: WaygateClientUpdateRequest,
    token_info: dict = Depends(require_clients_update),
):
    _require_db()
    project_id = token_info["project_id"]
    # Any enabled transition is revocation/reactivation of credential access and requires clients admin.
    editing_fields = body.model_fields_set - {"enabled"}
    if editing_fields and not has_capability(token_info, "waygate-clients_editor"):
        raise HTTPException(status_code=403, detail="Client editing requires Waygate clients editor")
    if "enabled" in body.model_fields_set and not has_capability(token_info, "waygate-clients_admin"):
        raise HTTPException(status_code=403, detail="Client enable/revoke requires Waygate clients admin")
    await _get_owned_server(project_id, server_id)
    if "owner_user_id" in body.model_fields_set:
        if body.owner_user_id is None:
            raise HTTPException(status_code=422, detail="An assigned client owner cannot be cleared; delete the profile")
        await validate_client_owner(project_id, body.owner_user_id)
    try:
        updated = await waygate_db.update_client(server_id, project_id, client_id, **body.model_dump(exclude_unset=True))
    except WaygateClientOwnerConflictError as exc:
        raise HTTPException(
            status_code=409, detail="Only unassigned profiles can be assigned; a known owner cannot be transferred",
        ) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Waygate 클라이언트를 찾을 수 없습니다")
    return _merge_client_status(updated, await waygate_agent_auth.get_status_result(server_id))


@router.delete("/{server_id}/clients/{client_id}", status_code=204)
async def delete_waygate_client(server_id: str, client_id: str, token_info: dict = Depends(require_clients_admin)):
    _require_db()
    project_id = token_info["project_id"]
    await _get_owned_server(project_id, server_id)
    ok = await waygate_db.soft_delete_client(server_id, project_id, client_id, token_info.get("user_id", ""))
    if not ok:
        raise HTTPException(status_code=404, detail="Waygate 클라이언트를 찾을 수 없습니다")


@router.get("/{server_id}/clients/{client_id}/config")
async def download_vpn_client_config(server_id: str, client_id: str, token_info: dict = Depends(require_connect)):
    """`.conf` 파일 다운로드. 매 호출마다 복호화 후 재렌더 (k3s kubeconfig 다운로드 패턴 미러)."""
    _require_db()
    project_id = token_info["project_id"]
    server = await _get_owned_server(project_id, server_id)
    client = await waygate_db.get_client(server_id, project_id, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Waygate 클라이언트를 찾을 수 없습니다")
    # Private profiles stay private even for service/system administrators.
    owner = client.get("owner_user_id")
    if not owner or owner != token_info.get("user_id") or not client.get("enabled"):
        raise HTTPException(status_code=403, detail="Only your assigned enabled client profile may be downloaded")
    if not server.get("server_public_key") or not server.get("endpoint_ip"):
        raise HTTPException(status_code=409, detail="Waygate 서버가 아직 준비되지 않았습니다")

    try:
        private_key = k3s_crypto.decrypt_wg_client_key(client["private_key_encrypted"])
    except Exception:
        _logger.error("Waygate 클라이언트 private key 복호화 실패 (client=%s)", client_id)
        raise HTTPException(status_code=500, detail="클라이언트 키 복호화에 실패했습니다. 관리자에게 문의하세요.")
    preshared_key = None
    if client.get("preshared_key_encrypted"):
        try:
            preshared_key = k3s_crypto.decrypt_wg_client_key(client["preshared_key_encrypted"])
        except Exception:
            _logger.error("Waygate 클라이언트 preshared key 복호화 실패 (client=%s)", client_id)
            raise HTTPException(status_code=500, detail="클라이언트 키 복호화에 실패했습니다. 관리자에게 문의하세요.")

    nat_cidrs = await waygate_db.list_active_attachment_cidrs(server_id)
    tunnel_conf = waygate_config.render_client_conf(
        private_key=private_key,
        tunnel_ip=client["tunnel_ip"],
        dns=client.get("dns"),
        mtu=client.get("mtu"),
        persistent_keepalive=client.get("persistent_keepalive", 25),
        preshared_key=preshared_key,
        server_public_key=server["server_public_key"],
        endpoint_ip=server["endpoint_ip"],
        listen_port=server["listen_port"],
        allowed_ips=client.get("allowed_ips") or [server["tunnel_cidr"]],
        nat_cidrs=nat_cidrs,
    )

    return Response(
        content=tunnel_conf,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="{client["name"]}.conf"',
            "Cache-Control": "no-store",
        },
    )
