"""DB-authoritative agent credentials and best-effort Redis status reports.

Current/pending bearer tokens are encrypted in waygate_servers. Authentication
always reads durable state: stale Redis data must never revive a retired token.
Issuance and rotation require a successful DB commit; pending-token promotion is
conditional on the ciphertext that was authenticated. Database errors fail closed.
"""

import hmac
import json
import logging
import secrets
from datetime import UTC, datetime

from waygate.models.schemas import WaygateAgentStatusReport

_logger = logging.getLogger(__name__)

_STATUS_PREFIX = "afterglow:waygate:status:"
_STATUS_TTL = 300  # 5분 (reconcile 주기 15초 대비 충분한 여유)


async def _redis():
    from waygate.cache import _get_client

    return _get_client()


# ---------------------------------------------------------------------------
# 토큰 lifecycle
# ---------------------------------------------------------------------------


async def issue_report_token(server_id: str) -> str:
    """Return a new bearer only after its durable replacement has committed."""
    from waygate.services import k3s_crypto, waygate_db

    token = secrets.token_urlsafe(32)
    await waygate_db.set_agent_token(server_id, k3s_crypto.encrypt_wg_agent_token(token))
    return token


async def verify_report_token(server_id: str, token: str) -> dict | None:
    """Authenticate against durable state, atomically promoting a pending bearer."""
    if not token:
        return None
    try:
        from waygate.services import waygate_db

        stored, next_token, project_id, next_encrypted = await _load_server_token(server_id)
        if stored and hmac.compare_digest(token, stored):
            return {"server_id": server_id, "project_id": project_id}
        if next_token and hmac.compare_digest(token, next_token):
            if await waygate_db.promote_agent_token(server_id, next_encrypted):
                _logger.info("waygate_agent_auth: agent token rotated (server=%s)", server_id)
                return {"server_id": server_id, "project_id": project_id}
            # Another request may have promoted this bearer, rotated again, or
            # revoked it while this authentication was in flight.
            stored, _, project_id, _ = await _load_server_token(server_id)
            if stored and hmac.compare_digest(token, stored):
                return {"server_id": server_id, "project_id": project_id}
        return None
    except Exception:
        _logger.warning("waygate_agent_auth: 토큰 검증 실패 (server=%s)", server_id, exc_info=True)
        return None


async def _load_server_token(server_id: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Return current/pending plaintext, owner, and the pending CAS ciphertext."""
    from waygate.services import k3s_crypto, waygate_db

    enc, next_enc = await waygate_db.get_agent_tokens_encrypted(server_id)
    if not enc:
        return None, None, None, None
    server = await waygate_db.get_server_by_id(server_id)
    if not server:
        return None, None, None, None
    token = k3s_crypto.decrypt_wg_agent_token(enc)
    next_token = k3s_crypto.decrypt_wg_agent_token(next_enc) if next_enc else None
    return token, next_token, server["project_id"], next_enc


async def request_token_rotation(server_id: str) -> None:
    """Durably stage one replacement; concurrent requests retain the first one."""
    from waygate.services import k3s_crypto, waygate_db

    token, pending, _, _ = await _load_server_token(server_id)
    if token is None:
        raise RuntimeError("no active agent token for server")
    if pending is not None:
        return
    next_encrypted = k3s_crypto.encrypt_wg_agent_token(secrets.token_urlsafe(32))
    if not await waygate_db.set_agent_next_token(server_id, next_encrypted):
        token, pending, _, _ = await _load_server_token(server_id)
        if token is None or pending is None:
            raise RuntimeError("agent token changed during rotation")


async def get_pending_next_token(server_id: str) -> str | None:
    """Return only a durably persisted replacement to the authenticated agent."""
    _, next_token, _, _ = await _load_server_token(server_id)
    return next_token


async def revoke_report_token_by_server(server_id: str) -> None:
    """Revoke both credentials durably; database failures are not success."""
    from waygate.services import waygate_db

    await waygate_db.set_agent_token(server_id, None)


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
