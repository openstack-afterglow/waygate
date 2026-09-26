"""Agent HTTP authentication and durable token transitions against isolated SQLite.

The session adapter preserves real SQLAlchemy queries/transactions without a live
database or an additional async SQLite driver. Redis is used only for status and
for injecting obsolete credential entries that must never authorize requests.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from waygate.main import app
from waygate.models.orm import Base, WaygateServer
from waygate.services import waygate_agent_auth, waygate_config, waygate_db


def _server_record(**overrides) -> dict:
    base = {
        "id": "server-1",
        "project_id": "test-project-123",
        "name": "waygate-gw-1",
        "status": "PROVISIONING",
        "status_reason": "에이전트 register 대기 중",
        "server_public_key": None,
        "endpoint_ip": "203.0.113.10",
        "listen_port": 51820,
        "tunnel_cidr": "10.8.0.0/24",
    }
    base.update(overrides)
    return base


@pytest.fixture
async def api_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# 인증 실패 (401/403) — 3개 엔드포인트 공통
# ---------------------------------------------------------------------------

_AGENT_ENDPOINTS = [
    ("post", "/v1/servers/server-1/agent/register", {"public_key": "A" * 43 + "="}),
    ("get", "/v1/servers/server-1/agent/desired-state", None),
    ("post", "/v1/servers/server-1/agent/status", {"peers": []}),
]


class TestAgentAuthMissingToken:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path,body", _AGENT_ENDPOINTS)
    async def test_no_bearer_token_returns_401(self, api_client, method, path, body):
        call = getattr(api_client, method)
        resp = await (call(path, json=body) if body is not None else call(path))
        assert resp.status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path,body", _AGENT_ENDPOINTS)
    async def test_non_bearer_auth_scheme_returns_401(self, api_client, method, path, body):
        headers = {"Authorization": "Basic dXNlcjpwYXNz"}
        call = getattr(api_client, method)
        resp = await (call(path, json=body, headers=headers) if body is not None else call(path, headers=headers))
        assert resp.status_code == 401


class TestAgentAuthInvalidToken:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path,body", _AGENT_ENDPOINTS)
    async def test_invalid_token_returns_401(self, api_client, method, path, body):
        headers = {"Authorization": "Bearer totally-invalid-token-that-was-never-issued"}
        call = getattr(api_client, method)
        resp = await (call(path, json=body, headers=headers) if body is not None else call(path, headers=headers))
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_revoked_token_returns_401(self, api_client):
        """토큰 발급 후 폐기(revoke)되면 이후 요청은 401이어야 한다."""
        token = await waygate_agent_auth.issue_report_token("server-1")
        await waygate_agent_auth.revoke_report_token_by_server("server-1")
        resp = await api_client.get(
            "/v1/servers/server-1/agent/desired-state",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401


class TestAgentAuthServerIdMismatch:
    """server-scoped 검증: 다른 서버의 토큰은 이 서버에 대해 무효(401)다.

    과거엔 token→server 역인덱스로 귀속을 확인해 불일치를 403 으로 구분했으나, 이제 경로의
    server_id 로 그 서버의 저장 토큰과 직접 비교하므로 타 서버 토큰은 '유효하지 않은 토큰'(401)이다.
    """

    @pytest.mark.asyncio
    async def test_token_bound_to_different_server_returns_401(self, api_client):
        """server-A 용 토큰으로 server-B 경로를 호출하면 401(server-B 에는 무효)."""
        token = await waygate_agent_auth.issue_report_token("server-A")
        resp = await api_client.get(
            "/v1/servers/server-B/agent/desired-state",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_register_with_mismatched_server_id_returns_401(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-A")
        resp = await api_client.post(
            "/v1/servers/server-B/agent/register",
            json={"public_key": "A" * 43 + "="},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_status_with_mismatched_server_id_returns_401(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-A")
        resp = await api_client.post(
            "/v1/servers/server-B/agent/status",
            json={"peers": []},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 정상 흐름 (대조군 — false positive 방지)
# ---------------------------------------------------------------------------


class TestAgentRegisterHappyPath:
    @pytest.mark.asyncio
    async def test_valid_token_register_updates_public_key_and_status(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1")
        with patch("waygate.api.agent.waygate_db") as mock_db:
            mock_db.get_server_by_id = AsyncMock(return_value=_server_record(status="CREATING"))
            mock_db.update_server_status = AsyncMock()
            resp = await api_client.post(
                "/v1/servers/server-1/agent/register",
                json={"public_key": "A" * 43 + "="},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 204
        mock_db.update_server_status.assert_called_once()
        call_args = mock_db.update_server_status.call_args
        assert call_args.args[0] == "server-1"
        assert call_args.args[1] == "ACTIVE"
        assert call_args.kwargs["server_public_key"] == "A" * 43 + "="

    @pytest.mark.asyncio
    async def test_register_404_when_server_not_found(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1")
        with patch("waygate.api.agent.waygate_db") as mock_db:
            mock_db.get_server_by_id = AsyncMock(return_value=None)
            resp = await api_client.post(
                "/v1/servers/server-1/agent/register",
                json={"public_key": "A" * 43 + "="},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_register_rejects_invalid_public_key_format(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1")
        resp = await api_client.post(
            "/v1/servers/server-1/agent/register",
            json={"public_key": "not-a-valid-wg-key"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_register_with_matching_listen_port_confirm_succeeds(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1")
        with patch("waygate.api.agent.waygate_db") as mock_db:
            mock_db.get_server_by_id = AsyncMock(return_value=_server_record(status="CREATING", listen_port=51820))
            mock_db.update_server_status = AsyncMock()
            resp = await api_client.post(
                "/v1/servers/server-1/agent/register",
                json={"public_key": "A" * 43 + "=", "listen_port_confirm": 51820},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 204
        mock_db.update_server_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_register_with_mismatched_listen_port_confirm_fails_closed(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1")
        with patch("waygate.api.agent.waygate_db") as mock_db:
            mock_db.get_server_by_id = AsyncMock(return_value=_server_record(status="CREATING", listen_port=51820))
            mock_db.update_server_status = AsyncMock()
            resp = await api_client.post(
                "/v1/servers/server-1/agent/register",
                json={"public_key": "A" * 43 + "=", "listen_port_confirm": 51821},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 409
        mock_db.update_server_status.assert_not_called()


class TestAgentDesiredStateHappyPath:
    @pytest.mark.asyncio
    async def test_valid_token_returns_desired_state(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1")
        with patch("waygate.api.agent.waygate_db") as mock_db:
            mock_db.get_server_by_id = AsyncMock(
                return_value=_server_record(status="ACTIVE", server_public_key="A" * 43 + "=")
            )
            mock_db.list_all_active_clients = AsyncMock(return_value=[])
            mock_db.list_active_attachment_cidrs = AsyncMock(return_value=[])
            resp = await api_client.get(
                "/v1/servers/server-1/agent/desired-state",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["listen_port"] == 51820
        assert body["tunnel_cidr"] == "10.8.0.0/24"
        assert body["peers"] == []
        assert body["nat_networks"] == []

    @pytest.mark.asyncio
    async def test_desired_state_404_when_server_not_found(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1")
        with patch("waygate.api.agent.waygate_db") as mock_db:
            mock_db.get_server_by_id = AsyncMock(return_value=None)
            resp = await api_client.get(
                "/v1/servers/server-1/agent/desired-state",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_desired_state_excludes_disabled_clients(self, api_client):
        """enabled=False 클라이언트는 peers 목록에서 제외되어야 한다 (soft-disable)."""
        token = await waygate_agent_auth.issue_report_token("server-1")
        clients = [
            {
                "id": "c1",
                "public_key": "enabled-client-pub-AAAAAAAAAAAAAAAAAAAAAAAAA=",
                "preshared_key_encrypted": None,
                "tunnel_ip": "10.8.0.2",
                "enabled": True,
            },
            {
                "id": "c2",
                "public_key": "disabled-client-pub-AAAAAAAAAAAAAAAAAAAAAAAA=",
                "preshared_key_encrypted": None,
                "tunnel_ip": "10.8.0.3",
                "enabled": False,
            },
        ]
        with patch("waygate.api.agent.waygate_db") as mock_db:
            mock_db.get_server_by_id = AsyncMock(
                return_value=_server_record(status="ACTIVE", server_public_key="A" * 43 + "=")
            )
            mock_db.list_all_active_clients = AsyncMock(return_value=clients)
            mock_db.list_active_attachment_cidrs = AsyncMock(return_value=[])
            resp = await api_client.get(
                "/v1/servers/server-1/agent/desired-state",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["peers"]) == 1
        assert body["peers"][0]["public_key"] == "enabled-client-pub-AAAAAAAAAAAAAAAAAAAAAAAAA="
        assert body["peers"][0]["allowed_ips"] == ["10.8.0.2/32"]

    @pytest.mark.asyncio
    async def test_desired_state_uses_stored_psk_without_generating_for_legacy_client(self, api_client):
        from waygate.services import k3s_crypto, waygate_keys

        token = await waygate_agent_auth.issue_report_token("server-1")
        psk = waygate_keys.generate_preshared_key()
        clients = [
            {"id": "new", "public_key": "A" * 43 + "=", "preshared_key_encrypted":
             k3s_crypto.encrypt_wg_client_key(psk), "tunnel_ip": "10.8.0.2", "enabled": True},
            {"id": "legacy", "public_key": "B" * 43 + "=", "preshared_key_encrypted": None,
             "tunnel_ip": "10.8.0.3", "enabled": True},
        ]
        with patch("waygate.api.agent.waygate_db") as mock_db:
            mock_db.get_server_by_id = AsyncMock(
                return_value=_server_record(status="ACTIVE", server_public_key="C" * 43 + "=")
            )
            mock_db.list_all_active_clients = AsyncMock(return_value=clients)
            mock_db.list_active_attachment_cidrs = AsyncMock(return_value=[])
            response = await api_client.get(
                "/v1/servers/server-1/agent/desired-state", headers={"Authorization": f"Bearer {token}"}
            )
        assert response.status_code == 200
        assert [p["preshared_key"] for p in response.json()["peers"]] == [psk, None]

    @pytest.mark.asyncio
    async def test_desired_state_drops_peer_when_stored_psk_cannot_be_decrypted(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1")
        clients = [
            {"id": "corrupt", "public_key": "A" * 43 + "=", "preshared_key_encrypted": "invalid",
             "tunnel_ip": "10.8.0.2", "enabled": True},
            {"id": "legacy", "public_key": "B" * 43 + "=", "preshared_key_encrypted": None,
             "tunnel_ip": "10.8.0.3", "enabled": True},
        ]
        with patch("waygate.api.agent.waygate_db") as mock_db:
            mock_db.get_server_by_id = AsyncMock(
                return_value=_server_record(status="ACTIVE", server_public_key="C" * 43 + "=")
            )
            mock_db.list_all_active_clients = AsyncMock(return_value=clients)
            mock_db.list_active_attachment_cidrs = AsyncMock(return_value=[])
            response = await api_client.get(
                "/v1/servers/server-1/agent/desired-state", headers={"Authorization": f"Bearer {token}"}
            )
        assert response.status_code == 200
        assert [p["public_key"] for p in response.json()["peers"]] == ["B" * 43 + "="]


class TestAgentStatusHappyPath:
    @pytest.mark.asyncio
    async def test_valid_token_stores_status_report(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1")
        resp = await api_client.post(
            "/v1/servers/server-1/agent/status",
            json={
                "agent_source": "prebuilt",
                "peers": [
                    {
                        "public_key": "A" * 43 + "=",
                        "last_handshake_at": "2026-07-12T00:00:00+00:00",
                        "rx_bytes": 100,
                        "tx_bytes": 200,
                    }
                ],
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 204
        stored = await waygate_agent_auth.get_status_result("server-1")
        assert stored is not None
        assert stored["peers"][0]["rx_bytes"] == 100
        assert stored["agent_source"] == "prebuilt"

    @pytest.mark.asyncio
    async def test_status_report_rejects_invalid_public_key(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1")
        resp = await api_client.post(
            "/v1/servers/server-1/agent/status",
            json={"peers": [{"public_key": "not-valid"}]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Durable token transitions, cache isolation, and delayed authentication races.
# ---------------------------------------------------------------------------




@pytest.fixture(autouse=True)
def agent_token_store(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([
            WaygateServer(id="server-1", project_id="test-project-123", name="gateway"),
            WaygateServer(id="server-A", project_id="test-project-123", name="other-gateway"),
            WaygateServer(id="srv-rotation", project_id="proj-rotation", name="rotation-gateway"),
        ])
        session.commit()

    @asynccontextmanager
    async def session_factory():
        with Session(engine) as session:
            yield SimpleNamespace(
                execute=AsyncMock(side_effect=session.execute),
                commit=AsyncMock(side_effect=session.commit),
            )

    monkeypatch.setattr(waygate_db, "is_db_available", lambda: True)
    monkeypatch.setattr(waygate_db, "get_session_factory", lambda: session_factory)
    yield engine
    engine.dispose()


@pytest.mark.asyncio
class TestAgentTokenRotation:
    async def test_old_token_remains_valid_until_next_used(self):
        old = await waygate_agent_auth.issue_report_token("srv-rotation")
        await waygate_agent_auth.request_token_rotation("srv-rotation")
        pending = await waygate_agent_auth.get_pending_next_token("srv-rotation")
        assert pending is not None and pending != old
        assert await waygate_agent_auth.verify_report_token("srv-rotation", old) == {
            "server_id": "srv-rotation", "project_id": "proj-rotation"
        }
        assert await waygate_agent_auth.verify_report_token("another-server", pending) is None
        assert await waygate_agent_auth.verify_report_token("srv-rotation", "wrong-token") is None
        assert await waygate_agent_auth.verify_report_token("srv-rotation", pending) is not None
        assert await waygate_agent_auth.get_pending_next_token("srv-rotation") is None
        assert await waygate_agent_auth.verify_report_token("srv-rotation", old) is None

    async def test_stale_redis_credentials_cannot_survive_promotion_or_revocation(self):
        old = await waygate_agent_auth.issue_report_token("srv-rotation")
        await waygate_agent_auth.request_token_rotation("srv-rotation")
        pending = await waygate_agent_auth.get_pending_next_token("srv-rotation")
        redis = await waygate_agent_auth._redis()
        await redis.setex(
            "afterglow:waygate:srvtoken:srv-rotation", 604800,
            json.dumps({"token": old, "next_token": pending, "project_id": "proj-rotation"}),
        )
        with patch.object(redis, "setex", AsyncMock(side_effect=ConnectionError("Redis unavailable"))):
            assert await waygate_agent_auth.verify_report_token("srv-rotation", pending) is not None
        assert await waygate_agent_auth.verify_report_token("srv-rotation", old) is None
        await waygate_agent_auth.revoke_report_token_by_server("srv-rotation")
        assert await waygate_agent_auth.verify_report_token("srv-rotation", pending) is None
        assert await waygate_agent_auth.get_pending_next_token("srv-rotation") is None

    async def test_second_rotation_retains_pending_token(self):
        old = await waygate_agent_auth.issue_report_token("srv-rotation")
        await waygate_agent_auth.request_token_rotation("srv-rotation")
        first = await waygate_agent_auth.get_pending_next_token("srv-rotation")
        await waygate_agent_auth.request_token_rotation("srv-rotation")
        assert await waygate_agent_auth.get_pending_next_token("srv-rotation") == first
        assert await waygate_agent_auth.verify_report_token("srv-rotation", old) is not None
        assert await waygate_agent_auth.verify_report_token("srv-rotation", first) is not None

    async def test_rotation_requires_active_token(self):
        with pytest.raises(RuntimeError, match="no active agent token for server"):
            await waygate_agent_auth.request_token_rotation("srv-rotation")
        assert await waygate_agent_auth.get_pending_next_token("srv-rotation") is None

    async def test_failed_rotation_write_preserves_current_credential(self):
        old = await waygate_agent_auth.issue_report_token("srv-rotation")
        with patch.object(waygate_db, "set_agent_next_token", AsyncMock(side_effect=RuntimeError("DB unavailable"))):
            with pytest.raises(RuntimeError, match="DB unavailable"):
                await waygate_agent_auth.request_token_rotation("srv-rotation")
        assert await waygate_agent_auth.get_pending_next_token("srv-rotation") is None
        assert await waygate_agent_auth.verify_report_token("srv-rotation", old) is not None

    async def test_failed_promotion_cannot_retire_current_credential(self):
        old = await waygate_agent_auth.issue_report_token("srv-rotation")
        await waygate_agent_auth.request_token_rotation("srv-rotation")
        pending = await waygate_agent_auth.get_pending_next_token("srv-rotation")
        with patch.object(waygate_db, "promote_agent_token", AsyncMock(side_effect=RuntimeError("DB unavailable"))):
            assert await waygate_agent_auth.verify_report_token("srv-rotation", pending) is None
        assert await waygate_agent_auth.verify_report_token("srv-rotation", old) is not None
        assert await waygate_agent_auth.get_pending_next_token("srv-rotation") == pending
        assert await waygate_agent_auth.verify_report_token("srv-rotation", pending) is not None

    async def test_database_outage_never_publishes_or_authenticates_credentials(self, monkeypatch):
        old = await waygate_agent_auth.issue_report_token("srv-rotation")
        monkeypatch.setattr(waygate_db, "is_db_available", lambda: False)
        with pytest.raises(RuntimeError, match="database unavailable"):
            await waygate_agent_auth.issue_report_token("srv-rotation")
        with pytest.raises(RuntimeError, match="database unavailable"):
            await waygate_agent_auth.revoke_report_token_by_server("srv-rotation")
        assert await waygate_agent_auth.verify_report_token("srv-rotation", old) is None

    @pytest.mark.parametrize("transition", ["promoted", "rotated_again", "revoked"])
    async def test_delayed_pending_authentication_cannot_restore_retired_token(self, monkeypatch, transition):
        await waygate_agent_auth.issue_report_token("srv-rotation")
        await waygate_agent_auth.request_token_rotation("srv-rotation")
        pending = await waygate_agent_auth.get_pending_next_token("srv-rotation")
        entered, resume = asyncio.Event(), asyncio.Event()
        promote = waygate_db.promote_agent_token

        async def delay_first_promotion(server_id, ciphertext):
            if not entered.is_set():
                entered.set()
                await resume.wait()
            return await promote(server_id, ciphertext)

        monkeypatch.setattr(waygate_db, "promote_agent_token", delay_first_promotion)
        delayed = asyncio.create_task(waygate_agent_auth.verify_report_token("srv-rotation", pending))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            assert await waygate_agent_auth.verify_report_token("srv-rotation", pending) is not None
            if transition == "rotated_again":
                await waygate_agent_auth.request_token_rotation("srv-rotation")
                replacement = await waygate_agent_auth.get_pending_next_token("srv-rotation")
                assert await waygate_agent_auth.verify_report_token("srv-rotation", replacement) is not None
            elif transition == "revoked":
                await waygate_agent_auth.revoke_report_token_by_server("srv-rotation")
        finally:
            resume.set()
            result = await asyncio.wait_for(delayed, 2)
        assert (result is not None) == (transition == "promoted")
        assert (await waygate_agent_auth.verify_report_token("srv-rotation", pending) is not None) == (
            transition == "promoted"
        )
        if transition == "rotated_again":
            assert await waygate_agent_auth.verify_report_token("srv-rotation", replacement) is not None

    async def test_concurrent_rotation_requests_share_the_durable_pending_token(self, monkeypatch):
        await waygate_agent_auth.issue_report_token("srv-rotation")
        entered, resume = asyncio.Event(), asyncio.Event()
        set_next = waygate_db.set_agent_next_token

        async def delay_first_write(server_id, ciphertext):
            if not entered.is_set():
                entered.set()
                await resume.wait()
            return await set_next(server_id, ciphertext)

        monkeypatch.setattr(waygate_db, "set_agent_next_token", delay_first_write)
        delayed = asyncio.create_task(waygate_agent_auth.request_token_rotation("srv-rotation"))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            await waygate_agent_auth.request_token_rotation("srv-rotation")
            pending = await waygate_agent_auth.get_pending_next_token("srv-rotation")
        finally:
            resume.set()
            await asyncio.wait_for(delayed, 2)
        assert await waygate_agent_auth.get_pending_next_token("srv-rotation") == pending
        assert await waygate_agent_auth.verify_report_token("srv-rotation", pending) is not None


# ---------------------------------------------------------------------------
# desired-state 렌더 로직 (순수 함수 — waygate_config.render_agent_desired_state)
# ---------------------------------------------------------------------------


class TestRenderAgentDesiredState:
    def test_excludes_disabled_clients(self):
        clients = [
            {"public_key": "pub-a", "tunnel_ip": "10.8.0.2", "enabled": True},
            {"public_key": "pub-b", "tunnel_ip": "10.8.0.3", "enabled": False},
        ]
        result = waygate_config.render_agent_desired_state(
            listen_port=51820, tunnel_cidr="10.8.0.0/24", clients=clients
        )
        pubkeys = [p["public_key"] for p in result["peers"]]
        assert "pub-a" in pubkeys
        assert "pub-b" not in pubkeys

    def test_includes_all_enabled_clients(self):
        clients = [
            {"public_key": "pub-a", "tunnel_ip": "10.8.0.2", "enabled": True},
            {"public_key": "pub-b", "tunnel_ip": "10.8.0.3", "enabled": True},
        ]
        result = waygate_config.render_agent_desired_state(
            listen_port=51820, tunnel_cidr="10.8.0.0/24", clients=clients
        )
        assert len(result["peers"]) == 2

    def test_default_enabled_true_when_key_missing(self):
        """enabled 키가 없으면 기본값 True로 처리되어야 한다."""
        clients = [{"public_key": "pub-a", "tunnel_ip": "10.8.0.2"}]
        result = waygate_config.render_agent_desired_state(
            listen_port=51820, tunnel_cidr="10.8.0.0/24", clients=clients
        )
        assert len(result["peers"]) == 1

    def test_peer_allowed_ips_is_tunnel_ip_slash_32(self):
        clients = [{"public_key": "pub-a", "tunnel_ip": "10.8.0.5", "enabled": True}]
        result = waygate_config.render_agent_desired_state(
            listen_port=51820, tunnel_cidr="10.8.0.0/24", clients=clients
        )
        assert result["peers"][0]["allowed_ips"] == ["10.8.0.5/32"]

    def test_empty_clients_returns_empty_peers(self):
        result = waygate_config.render_agent_desired_state(listen_port=51820, tunnel_cidr="10.8.0.0/24", clients=[])
        assert result["peers"] == []
        assert result["listen_port"] == 51820
        assert result["tunnel_cidr"] == "10.8.0.0/24"
