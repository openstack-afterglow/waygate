"""VPN 에이전트 대면 API — 베어러 토큰 인증(사용자 JWT 아님), fail-closed.

`app/api/compute/instance_health.py` 의 Bearer 추출 + rate-limit + fail-closed 패턴을
정확히 미러링한다. get_token_info(사용자 JWT)를 사용하지 않으므로
request.state.token_info 가 설정되지 않아 activity_audit_middleware 는 이 경로를
자동으로 건너뛴다(오탐 없음).
"""

import logging

from fastapi import APIRouter, HTTPException, Request

from waygate.models.schemas import WaygateAgentDesiredState, WaygateAgentRegisterRequest, WaygateAgentStatusReport
from waygate.rate_limit import limiter
from waygate.services import waygate_agent_auth, waygate_config, waygate_db

router = APIRouter()
_logger = logging.getLogger(__name__)


def _extract_bearer(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer 토큰 필요")
    return auth[len("Bearer ") :]


async def _verify_and_bind(request: Request, server_id: str) -> dict:
    """토큰 검증. server-scoped — 경로의 server_id 에 귀속된 토큰만 통과. fail-closed(무효 시 401).

    검증이 server_id 로 직접 이뤄지므로 다른 서버의 토큰은 이 서버에 대해 그냥 무효(401)다
    (과거의 별도 403 바인딩 분기는 server-scoped 검증에 흡수됨).
    """
    token = _extract_bearer(request)
    token_data = await waygate_agent_auth.verify_report_token(server_id, token)
    if not token_data:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰")
    return token_data


@router.post("/{server_id}/agent/register", status_code=204)
@limiter.limit("30/minute")
async def register_waygate_agent(
    request: Request,
    server_id: str,
    body: WaygateAgentRegisterRequest,
):
    """에이전트가 부팅 후 서버 public key를 보고. CREATING/PROVISIONING→ACTIVE 전이.

    반복 호출 가능(재부팅 시 재등록) — 매번 public key를 갱신하되, status는 이미
    ACTIVE라면 유지한다. CREATING도 허용 대상에 포함하는 이유: cloud-init의 register
    호출이 provisioner의 PROVISIONING 상태 기록보다 먼저 도착할 수 있는 경합 상황에서
    서버가 영구히 PROVISIONING 대기로 발이 묶이는 것을 방지한다.
    """
    await _verify_and_bind(request, server_id)

    server = await waygate_db.get_server_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")

    new_status = "ACTIVE" if server["status"] in ("CREATING", "PROVISIONING", "ACTIVE") else server["status"]
    await waygate_db.update_server_status(
        server_id,
        new_status,
        "" if new_status == "ACTIVE" else server.get("status_reason"),
        server_public_key=body.public_key,
    )
    _logger.info("waygate agent register: server=%s status=%s->%s", server_id, server["status"], new_status)


@router.get("/{server_id}/agent/desired-state", response_model=WaygateAgentDesiredState)
@limiter.limit("120/minute")
async def get_desired_state(request: Request, server_id: str):
    """에이전트가 주기적으로 폴링하는 desired-state (peer 목록 + 설정)."""
    await _verify_and_bind(request, server_id)

    server = await waygate_db.get_server_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")

    clients = await waygate_db.list_all_active_clients(server_id)
    from waygate.services import k3s_crypto

    client_payload = []
    for c in clients:
        preshared_key = None
        if c.get("preshared_key_encrypted"):
            try:
                preshared_key = k3s_crypto.decrypt_wg_client_key(c["preshared_key_encrypted"])
            except Exception:
                _logger.warning("waygate agent desired-state: preshared_key 복호화 실패 (client=%s)", c["id"])
        client_payload.append(
            {
                "public_key": c["public_key"],
                "preshared_key": preshared_key,
                "tunnel_ip": c["tunnel_ip"],
                "enabled": c["enabled"],
            }
        )

    nat_networks = await waygate_db.list_active_attachment_cidrs(server_id)

    return waygate_config.render_agent_desired_state(
        listen_port=server["listen_port"],
        tunnel_cidr=server["tunnel_cidr"],
        clients=client_payload,
        nat_networks=nat_networks,
    )


@router.post("/{server_id}/agent/status", status_code=204)
@limiter.limit("60/minute")
async def report_waygate_status(
    request: Request,
    server_id: str,
    body: WaygateAgentStatusReport,
):
    """에이전트가 주기적으로 POST하는 wg show 상태 — Redis 캐시(TTL 5분)."""
    await _verify_and_bind(request, server_id)
    await waygate_agent_auth.store_status_result(server_id, body)
