"""VPN 에이전트 대면 API(register/desired-state/status) 베어러 토큰 인증 테스트.

에이전트 엔드포인트는 사용자 JWT가 아닌 베어러 토큰(waygate_agent_auth)으로 인증하며
fail-closed(무효/불일치 시 401/403)이다. `_verify_and_bind`가 DB 조회 이전에 실행되므로
인증 실패 케이스는 DB mock 없이도 검증 가능하다. 토큰 자체는 fakeredis(conftest 전역
fixture)에 실제로 저장/조회되므로 real end-to-end 토큰 발급 흐름으로 테스트한다.
"""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from waygate.main import app
from waygate.services import waygate_agent_auth, waygate_config


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
        token = await waygate_agent_auth.issue_report_token("server-1", "test-project-123")
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
        token = await waygate_agent_auth.issue_report_token("server-A", "test-project-123")
        resp = await api_client.get(
            "/v1/servers/server-B/agent/desired-state",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_register_with_mismatched_server_id_returns_401(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-A", "test-project-123")
        resp = await api_client.post(
            "/v1/servers/server-B/agent/register",
            json={"public_key": "A" * 43 + "="},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_status_with_mismatched_server_id_returns_401(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-A", "test-project-123")
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
        token = await waygate_agent_auth.issue_report_token("server-1", "test-project-123")
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
        token = await waygate_agent_auth.issue_report_token("server-1", "test-project-123")
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
        token = await waygate_agent_auth.issue_report_token("server-1", "test-project-123")
        resp = await api_client.post(
            "/v1/servers/server-1/agent/register",
            json={"public_key": "not-a-valid-wg-key"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422


class TestAgentDesiredStateHappyPath:
    @pytest.mark.asyncio
    async def test_valid_token_returns_desired_state(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1", "test-project-123")
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
        token = await waygate_agent_auth.issue_report_token("server-1", "test-project-123")
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
        token = await waygate_agent_auth.issue_report_token("server-1", "test-project-123")
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


class TestAgentStatusHappyPath:
    @pytest.mark.asyncio
    async def test_valid_token_stores_status_report(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1", "test-project-123")
        resp = await api_client.post(
            "/v1/servers/server-1/agent/status",
            json={
                "peers": [
                    {
                        "public_key": "A" * 43 + "=",
                        "last_handshake_at": "2026-07-12T00:00:00+00:00",
                        "rx_bytes": 100,
                        "tx_bytes": 200,
                    }
                ]
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 204
        stored = await waygate_agent_auth.get_status_result("server-1")
        assert stored is not None
        assert stored["peers"][0]["rx_bytes"] == 100

    @pytest.mark.asyncio
    async def test_status_report_rejects_invalid_public_key(self, api_client):
        token = await waygate_agent_auth.issue_report_token("server-1", "test-project-123")
        resp = await api_client.post(
            "/v1/servers/server-1/agent/status",
            json={"peers": [{"public_key": "not-valid"}]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 토큰 durability — Redis 캐시 유실(재시작/eviction/TTL 만료) 후에도 DB 원천에서 복원.
# 과거 결함: 토큰이 Redis 에만 7일 TTL 로 저장돼, 만료/eviction 시 제어채널이 영구 소실됐다.
# ---------------------------------------------------------------------------


class TestAgentTokenDurability:
    @pytest.mark.asyncio
    async def test_verify_falls_back_to_db_when_cache_evicted(self):
        """캐시가 비어도 DB(원천)에 저장된 토큰으로 검증에 성공해야 한다."""
        from waygate.services import k3s_crypto

        token = await waygate_agent_auth.issue_report_token("srv-dur", "proj-dur")
        enc = k3s_crypto.encrypt_wg_agent_token(token)

        # Redis 캐시 강제 무효화(eviction/재시작/TTL 만료 시뮬레이션)
        r = await waygate_agent_auth._redis()
        await r.delete(f"{waygate_agent_auth._SRVTOKEN_CACHE_PREFIX}srv-dur")

        # DB 원천이 토큰을 보유하도록 mock (실제 배포에선 set_agent_token 이 이미 저장)
        with (
            patch("waygate.services.store.get_agent_token_encrypted", AsyncMock(return_value=enc)),
            patch("waygate.services.store.get_server_by_id", AsyncMock(return_value={"project_id": "proj-dur"})),
        ):
            result = await waygate_agent_auth.verify_report_token("srv-dur", token)
        assert result is not None
        assert result["server_id"] == "srv-dur"
        assert result["project_id"] == "proj-dur"

    @pytest.mark.asyncio
    async def test_verify_rejects_wrong_token_even_with_db_source(self):
        """DB 원천이 있어도 잘못된 토큰은 타이밍 안전 비교로 거부(None)."""
        from waygate.services import k3s_crypto

        real = await waygate_agent_auth.issue_report_token("srv-dur2", "proj-dur")
        enc = k3s_crypto.encrypt_wg_agent_token(real)
        r = await waygate_agent_auth._redis()
        await r.delete(f"{waygate_agent_auth._SRVTOKEN_CACHE_PREFIX}srv-dur2")
        with (
            patch("waygate.services.store.get_agent_token_encrypted", AsyncMock(return_value=enc)),
            patch("waygate.services.store.get_server_by_id", AsyncMock(return_value={"project_id": "proj-dur"})),
        ):
            assert await waygate_agent_auth.verify_report_token("srv-dur2", "not-the-real-token") is None

    @pytest.mark.asyncio
    async def test_revoke_invalidates_cache_and_db(self):
        """revoke 후에는 캐시·DB 모두 비어 검증이 실패(None)해야 한다."""
        token = await waygate_agent_auth.issue_report_token("srv-rev", "proj-dur")
        await waygate_agent_auth.revoke_report_token_by_server("srv-rev")
        # DB 도 비었다고 가정(set_agent_token(None) 호출됨) — get 이 None 반환
        with patch("waygate.services.store.get_agent_token_encrypted", AsyncMock(return_value=None)):
            assert await waygate_agent_auth.verify_report_token("srv-rev", token) is None


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
