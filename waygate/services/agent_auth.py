"""Waygate 에이전트 베어러 토큰 발급/검증 + Redis 상태 캐시.

**durable 제어채널 자격증명**: 에이전트가 무기한(15초 주기) 사용하는 토큰이므로, 휘발성인
Redis 가 아니라 waygate_servers 행(AES-256-GCM 암호화 컬럼 agent_token_encrypted)을 **원천(source
of truth)** 으로 두고 Redis 는 캐시로만 사용한다. 이렇게 해야 Redis 재시작/eviction 이나 이전
7일 TTL 만료 후에도 채널이 유지된다(과거 결함 수정).

검증은 **server-scoped** 다: 요청 경로의 server_id 로 그 서버의 저장 토큰을 조회해 제시 토큰과
`hmac.compare_digest`(타이밍 안전)로 비교한다. 별도 역인덱스가 필요 없고, 다른 서버의 토큰은
이 서버에 대해 그냥 무효(401)다.
"""

import hmac
import json
import logging
import secrets
from datetime import UTC, datetime

from waygate.models.schemas import WaygateAgentStatusReport

_logger = logging.getLogger(__name__)

# server_id → {"token", "project_id"} 캐시. DB 가 원천이므로 캐시는 DB 히트를 줄이는 용도.
# TTL 이 지나거나 Redis 가 비면 verify 가 DB 에서 복원(repopulate)한다.
_SRVTOKEN_CACHE_PREFIX = "afterglow:waygate:srvtoken:"
_STATUS_PREFIX = "afterglow:waygate:status:"
_TOKEN_CACHE_TTL = 86400 * 7  # 캐시 수명(원천은 DB) — DB 일시 장애 시에도 warm 캐시로 인증 유지
_STATUS_TTL = 300  # 5분 (reconcile 주기 15초 대비 충분한 여유)


async def _redis():
    from waygate.cache import _get_client

    return _get_client()


# ---------------------------------------------------------------------------
# 토큰 lifecycle
# ---------------------------------------------------------------------------


async def issue_report_token(server_id: str, project_id: str) -> str:
    """Waygate reconcile 베어러 토큰 발급. 이미 존재하면 폐기 후 재발급.

    토큰을 (1) DB 행에 암호화 저장(durable 원천) + (2) Redis 캐시에 평문 저장한다.
    DB 미가용(단위 테스트 등) 시에도 캐시만으로 발급/검증이 성립한다.
    """
    await revoke_report_token_by_server(server_id)

    token = secrets.token_urlsafe(32)

    # (1) durable: DB 행에 암호화 저장
    try:
        from waygate.services import k3s_crypto, waygate_db

        await waygate_db.set_agent_token(server_id, k3s_crypto.encrypt_wg_agent_token(token))
    except Exception:
        _logger.warning("waygate_agent_auth: 토큰 DB 저장 실패 (server=%s) — 캐시로 degrade", server_id, exc_info=True)

    # (2) cache
    try:
        r = await _redis()
        payload = json.dumps({"token": token, "project_id": project_id})
        await r.setex(f"{_SRVTOKEN_CACHE_PREFIX}{server_id}", _TOKEN_CACHE_TTL, payload)
    except Exception:
        _logger.warning("waygate_agent_auth: 토큰 캐시 저장 실패 (server=%s)", server_id, exc_info=True)

    return token


async def verify_report_token(server_id: str, token: str) -> dict | None:
    """server_id 에 귀속된 토큰인지 타이밍 안전 검증. 성공 시 {server_id, project_id}, 실패 시 None.

    캐시 우선 조회 → miss 시 DB(원천)에서 복호화·복원. fail-closed(예외/불일치/부재 시 None).
    """
    if not token:
        return None
    try:
        stored, project_id = await _load_server_token(server_id)
        if not stored:
            return None
        if not hmac.compare_digest(token, stored):
            return None
        return {"server_id": server_id, "project_id": project_id}
    except Exception:
        _logger.warning("waygate_agent_auth: 토큰 검증 실패 (server=%s)", server_id, exc_info=True)
        return None


async def _load_server_token(server_id: str) -> tuple[str | None, str | None]:
    """(plaintext_token, project_id) 반환. 캐시 → DB 순. DB 히트 시 캐시 repopulate."""
    r = await _redis()
    raw = await r.get(f"{_SRVTOKEN_CACHE_PREFIX}{server_id}")
    if raw:
        if isinstance(raw, bytes):
            raw = raw.decode()
        data = json.loads(raw)
        return data.get("token"), data.get("project_id")

    # 캐시 miss — DB(원천)에서 복원
    from waygate.services import k3s_crypto, waygate_db

    enc = await waygate_db.get_agent_token_encrypted(server_id)
    if not enc:
        return None, None
    token = k3s_crypto.decrypt_wg_agent_token(enc)
    server = await waygate_db.get_server_by_id(server_id)
    project_id = server.get("project_id") if server else None
    try:
        payload = json.dumps({"token": token, "project_id": project_id})
        await r.setex(f"{_SRVTOKEN_CACHE_PREFIX}{server_id}", _TOKEN_CACHE_TTL, payload)
    except Exception:
        pass  # 캐시 실패는 무시 — 다음 요청이 DB 에서 다시 복원
    return token, project_id


async def revoke_report_token_by_server(server_id: str) -> None:
    """Waygate 서버 삭제/재발급 시 토큰 무효화 — DB 컬럼 NULL + 캐시 삭제."""
    try:
        from waygate.services import waygate_db

        await waygate_db.set_agent_token(server_id, None)
    except Exception:
        _logger.warning("waygate_agent_auth: 토큰 DB 폐기 실패 (server=%s)", server_id, exc_info=True)
    try:
        r = await _redis()
        await r.delete(f"{_SRVTOKEN_CACHE_PREFIX}{server_id}")
    except Exception:
        _logger.warning("waygate_agent_auth: 토큰 캐시 폐기 실패 (server=%s)", server_id, exc_info=True)


# ---------------------------------------------------------------------------
# 상태 캐시 (wg show 결과)
# ---------------------------------------------------------------------------


async def store_status_result(server_id: str, report: WaygateAgentStatusReport) -> None:
    """에이전트가 보고한 wg show 상태를 Redis에 저장 (TTL 5분)."""
    try:
        r = await _redis()
        payload = report.model_dump()
        payload["_stored_at"] = datetime.now(UTC).isoformat()
        await r.setex(f"{_STATUS_PREFIX}{server_id}", _STATUS_TTL, json.dumps(payload))
    except Exception:
        _logger.warning("waygate_agent_auth: Redis 상태 저장 실패 (server=%s)", server_id, exc_info=True)


async def get_status_result(server_id: str) -> dict | None:
    """Redis에서 최신 wg show 상태를 조회한다. 없거나 만료 시 None."""
    try:
        r = await _redis()
        raw = await r.get(f"{_STATUS_PREFIX}{server_id}")
        if not raw:
            return None
        return json.loads(raw)
    except Exception:
        _logger.warning("waygate_agent_auth: Redis 상태 조회 실패 (server=%s)", server_id, exc_info=True)
        return None
