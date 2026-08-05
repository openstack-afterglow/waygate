"""VPN 클라이언트 생성/조회/수정/삭제, IPAM 유일성, project_id 소유권, `.conf` 렌더 테스트.

DB 계층(waygate_db)은 test_k3s_callback.py/test_k3s_clusters.py 컨벤션을 따라
`waygate.api.clients.waygate_db` 모듈을 patch 하여 모의한다(실 MariaDB 불필요).
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import IntegrityError

from waygate.main import app
from waygate.services import waygate_config, waygate_ipam

_VALID_KEY_HEX = "a" * 64


def _server_record(**overrides) -> dict:
    base = {
        "id": "server-1",
        "project_id": "test-project-123",
        "name": "waygate-gw-1",
        "status": "ACTIVE",
        "server_public_key": "server-pub-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "endpoint_ip": "203.0.113.10",
        "listen_port": 51820,
        "tunnel_cidr": "10.8.0.0/24",
        "dns": None,
    }
    base.update(overrides)
    return base


def _client_record(**overrides) -> dict:
    base = {
        "id": "client-1",
        "server_id": "server-1",
        "project_id": "test-project-123",
        "name": "laptop",
        "enabled": True,
        "public_key": "client-pub-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "private_key_encrypted": "encrypted-blob",
        "tunnel_ip": "10.8.0.2",
        "allowed_ips": ["10.8.0.0/24"],
        "dns": None,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def _encryption_key(monkeypatch):
    """모든 테스트에서 k3s_crypto._get_key() 가 유효 키를 얻도록 설정."""
    monkeypatch.setattr(
        "waygate.crypto.get_settings",
        lambda: SimpleNamespace(waygate_encryption_key=_VALID_KEY_HEX),
    )


@pytest.fixture(autouse=True)
def _db_available(monkeypatch):
    """엔드포인트의 _require_db() 가드가 503을 반환하지 않도록 DB 가용 상태로 설정."""
    monkeypatch.setattr("waygate.api.clients.is_db_available", lambda: True)


@pytest.fixture
async def api_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


def _override_token_info(project_id: str = "test-project-123"):
    from waygate.auth import require_token

    async def _fn():
        return {
            "project_id": project_id,
            "user_id": "test-user-123",
            "username": "testuser",
        }

    app.dependency_overrides[require_token] = _fn


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 클라이언트 생성
# ---------------------------------------------------------------------------


class TestCreateClient:
    @pytest.mark.asyncio
    async def test_create_client_success(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.list_clients = AsyncMock(return_value=[])
            mock_db.list_active_attachment_cidrs = AsyncMock(return_value=[])
            mock_db.create_client_record = AsyncMock()
            mock_db.get_client = AsyncMock(return_value=_client_record())
            with patch("waygate.api.clients.waygate_agent_auth") as mock_auth:
                mock_auth.get_status_result = AsyncMock(return_value=None)
                resp = await api_client.post(
                    "/v1/servers/server-1/clients",
                    json={"name": "laptop"},
                )
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "laptop"
        assert "tunnel_conf" in body
        assert "PrivateKey" in body["tunnel_conf"]
        mock_db.create_client_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_client_rejects_when_server_not_active(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record(status="PROVISIONING"))
            resp = await api_client.post(
                "/v1/servers/server-1/clients",
                json={"name": "laptop"},
            )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_create_client_rejects_when_server_public_key_missing(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record(server_public_key=None))
            resp = await api_client.post(
                "/v1/servers/server-1/clients",
                json={"name": "laptop"},
            )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_create_client_404_when_server_not_found(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=None)
            resp = await api_client.post(
                "/v1/servers/nonexistent/clients",
                json={"name": "laptop"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_create_client_rejects_invalid_name(self, api_client):
        _override_token_info()
        resp = await api_client.post(
            "/v1/servers/server-1/clients",
            json={"name": "evil\nruncmd: rm -rf /"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_create_client_allocates_next_free_ip(self, api_client):
        """기존 클라이언트가 .2, .3 을 쓰고 있으면 신규 클라이언트는 .4 를 할당받는다."""
        _override_token_info()
        existing = [
            _client_record(id="c1", tunnel_ip="10.8.0.2"),
            _client_record(id="c2", tunnel_ip="10.8.0.3"),
        ]
        created_payload = {}

        async def _capture_create(server_id, project_id, client_id, data):
            created_payload.update(data)

        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.list_clients = AsyncMock(return_value=existing)
            mock_db.list_active_attachment_cidrs = AsyncMock(return_value=[])
            mock_db.create_client_record = AsyncMock(side_effect=_capture_create)
            mock_db.get_client = AsyncMock(return_value=_client_record(tunnel_ip="10.8.0.4"))
            with patch("waygate.api.clients.waygate_agent_auth") as mock_auth:
                mock_auth.get_status_result = AsyncMock(return_value=None)
                resp = await api_client.post(
                    "/v1/servers/server-1/clients",
                    json={"name": "third-client"},
                )
        assert resp.status_code == 201
        assert created_payload["tunnel_ip"] == "10.8.0.4"

    @pytest.mark.asyncio
    async def test_create_client_duplicate_name_returns_409(self, api_client):
        """동일 서버에 동일 이름의 클라이언트를 두 번 생성하면 두 번째는 500이 아닌 409여야 한다
        (uq_waygate_client_server_name 위반 → waygate_db.VpnClientConflictError → HTTPException 409)."""
        _override_token_info()
        from waygate.services.store import WaygateClientConflictError

        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.list_clients = AsyncMock(return_value=[])
            mock_db.create_client_record = AsyncMock(side_effect=WaygateClientConflictError(field="name"))
            resp = await api_client.post(
                "/v1/servers/server-1/clients",
                json={"name": "laptop"},
            )
        assert resp.status_code == 409
        # 내부 SQL 에러 원문이 아니라 안내 메시지만 노출되어야 한다 (CLAUDE.md §6)
        detail = resp.json()["detail"]
        assert "이름" in detail
        assert "uq_waygate_client_server_name" not in detail
        assert "IntegrityError" not in detail

    @pytest.mark.asyncio
    async def test_create_client_duplicate_tunnel_ip_returns_409(self, api_client):
        """tunnel_ip unique 위반(uq_waygate_client_server_tunnel_ip)도 500이 아닌 409로 매핑되어야 한다."""
        _override_token_info()
        from waygate.services.store import WaygateClientConflictError

        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.list_clients = AsyncMock(return_value=[])
            mock_db.create_client_record = AsyncMock(side_effect=WaygateClientConflictError(field="tunnel_ip"))
            resp = await api_client.post(
                "/v1/servers/server-1/clients",
                json={"name": "laptop"},
            )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_create_client_unclassified_conflict_returns_409(self, api_client):
        """field를 판별할 수 없는 경우에도(예: 알 수 없는 제약) 500이 아닌 409로 방어적으로 처리한다."""
        _override_token_info()
        from waygate.services.store import WaygateClientConflictError

        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.list_clients = AsyncMock(return_value=[])
            mock_db.create_client_record = AsyncMock(side_effect=WaygateClientConflictError(field=None))
            resp = await api_client.post(
                "/v1/servers/server-1/clients",
                json={"name": "laptop"},
            )
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# IPAM 유일성 (순수 함수 — waygate_ipam.allocate_next_ip)
# ---------------------------------------------------------------------------


class TestIpamUniqueness:
    def test_first_client_gets_second_host(self):
        """서버 자신이 .1 이므로 첫 클라이언트는 .2 를 받는다."""
        ip = waygate_ipam.allocate_next_ip("10.8.0.0/24", used_ips=[])
        assert ip == "10.8.0.2"

    def test_skips_used_ips(self):
        ip = waygate_ipam.allocate_next_ip("10.8.0.0/24", used_ips=["10.8.0.2", "10.8.0.3"])
        assert ip == "10.8.0.4"

    def test_skips_server_ip_even_if_not_in_used_list(self):
        """used_ips 에 서버 IP(.1)가 없어도 자동으로 예약 처리되어 재할당되지 않는다."""
        ip = waygate_ipam.allocate_next_ip("10.8.0.0/24", used_ips=[])
        assert ip != "10.8.0.1"

    def test_no_duplicate_across_many_allocations(self):
        """동일 서브넷에서 순차 할당 시 중복 없이 서로 다른 IP가 나와야 한다."""
        used: list[str] = []
        allocated = []
        for _ in range(20):
            ip = waygate_ipam.allocate_next_ip("10.8.0.0/24", used_ips=used)
            assert ip not in used
            used.append(ip)
            allocated.append(ip)
        assert len(set(allocated)) == len(allocated)

    def test_raises_when_subnet_exhausted(self):
        """/30 서브넷(호스트 2개)에서 서버(.1) 외 1개만 할당 가능 — 초과 시 RuntimeError."""
        with pytest.raises(RuntimeError):
            waygate_ipam.allocate_next_ip("10.8.0.0/30", used_ips=["10.8.0.2"])

    def test_db_enforces_uniqueness_via_constraint(self):
        """allocate_next_ip는 애플리케이션 레벨 회피일 뿐, 실제 중복 방지 보증은
        VpnClient.__table_args__의 UniqueConstraint(server_id, tunnel_ip)가 담당한다.
        경합 상태(두 요청이 동시에 같은 IP를 계산)에서도 DB가 최종 방어선이 되어야
        하므로, 모델에 제약이 실제로 선언되어 있는지 회귀 검증한다."""
        from waygate.models.orm import WaygateClient

        constraint_names = {c.name for c in WaygateClient.__table_args__ if hasattr(c, "name")}
        assert "uq_waygate_client_server_tunnel_ip" in constraint_names

        uq = next(
            c for c in WaygateClient.__table_args__ if getattr(c, "name", None) == "uq_waygate_client_server_tunnel_ip"
        )
        column_names = {col.name if hasattr(col, "name") else col for col in uq.columns}
        assert column_names == {"server_id", "tunnel_ip"}


# ---------------------------------------------------------------------------
# 클라이언트 조회
# ---------------------------------------------------------------------------


class TestListClients:
    @pytest.mark.asyncio
    async def test_list_clients_success(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.list_clients = AsyncMock(return_value=[_client_record()])
            with patch("waygate.api.clients.waygate_agent_auth") as mock_auth:
                mock_auth.get_status_result = AsyncMock(return_value=None)
                resp = await api_client.get("/v1/servers/server-1/clients")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["name"] == "laptop"

    @pytest.mark.asyncio
    async def test_list_clients_merges_online_status(self, api_client):
        """Redis 상태 캐시에 handshake 기록이 있으면 online=True."""
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.list_clients = AsyncMock(return_value=[_client_record()])
            with patch("waygate.api.clients.waygate_agent_auth") as mock_auth:
                mock_auth.get_status_result = AsyncMock(
                    return_value={
                        "peers": [
                            {
                                "public_key": "client-pub-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                "last_handshake_at": "2026-07-12T00:00:00+00:00",
                                "rx_bytes": 100,
                                "tx_bytes": 200,
                            }
                        ]
                    }
                )
                resp = await api_client.get("/v1/servers/server-1/clients")
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["online"] is True
        assert body[0]["rx_bytes"] == 100


# ---------------------------------------------------------------------------
# project_id 소유권 (IDOR/BOLA 방어)
# ---------------------------------------------------------------------------


class TestClientOwnership:
    @pytest.mark.asyncio
    async def test_other_project_cannot_list_clients_of_foreign_server(self, api_client):
        """다른 프로젝트 토큰으로 서버에 접근하면 waygate_db.get_server 가 None을 반환(project_id 필터)
        해야 하고, 엔드포인트는 이를 404로 매핑해야 한다(정보 노출 방지)."""
        _override_token_info(project_id="attacker-project-999")
        with patch("waygate.api.clients.waygate_db") as mock_db:
            # get_server 는 project_id 로 필터하므로 다른 프로젝트에서는 None
            mock_db.get_server = AsyncMock(return_value=None)
            resp = await api_client.get("/v1/servers/server-1/clients")
        assert resp.status_code == 404
        # project_id 필터가 실제로 전달됐는지 확인
        mock_db.get_server.assert_called_once_with("attacker-project-999", "server-1")

    @pytest.mark.asyncio
    async def test_other_project_cannot_create_client_on_foreign_server(self, api_client):
        _override_token_info(project_id="attacker-project-999")
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=None)
            resp = await api_client.post(
                "/v1/servers/server-1/clients",
                json={"name": "attacker-client"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_other_project_cannot_delete_foreign_client(self, api_client):
        _override_token_info(project_id="attacker-project-999")
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=None)
            resp = await api_client.delete("/v1/servers/server-1/clients/client-1")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_other_project_cannot_update_foreign_client(self, api_client):
        _override_token_info(project_id="attacker-project-999")
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=None)
            resp = await api_client.patch(
                "/v1/servers/server-1/clients/client-1",
                json={"enabled": False},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_other_project_cannot_download_foreign_client_config(self, api_client):
        _override_token_info(project_id="attacker-project-999")
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=None)
            resp = await api_client.get("/v1/servers/server-1/clients/client-1/config")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_owner_project_can_access_own_server_clients(self, api_client):
        """대조군 — 동일 프로젝트는 정상 접근 가능해야 한다(false-positive 방지)."""
        _override_token_info(project_id="test-project-123")
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record(project_id="test-project-123"))
            mock_db.list_clients = AsyncMock(return_value=[])
            resp = await api_client.get("/v1/servers/server-1/clients")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 수정 / 삭제
# ---------------------------------------------------------------------------


class TestUpdateDeleteClient:
    @pytest.mark.asyncio
    async def test_update_client_toggles_enabled(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.update_client = AsyncMock(return_value=_client_record(enabled=False))
            with patch("waygate.api.clients.waygate_agent_auth") as mock_auth:
                mock_auth.get_status_result = AsyncMock(return_value=None)
                resp = await api_client.patch(
                    "/v1/servers/server-1/clients/client-1",
                    json={"enabled": False},
                )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    @pytest.mark.asyncio
    async def test_update_client_404_when_not_found(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.update_client = AsyncMock(return_value=None)
            resp = await api_client.patch(
                "/v1/servers/server-1/clients/nonexistent",
                json={"enabled": False},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_client_success(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.soft_delete_client = AsyncMock(return_value=True)
            resp = await api_client.delete("/v1/servers/server-1/clients/client-1")
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_client_404_when_not_found(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.soft_delete_client = AsyncMock(return_value=False)
            resp = await api_client.delete("/v1/servers/server-1/clients/nonexistent")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# `.conf` 렌더 정확성 (순수 함수 — waygate_config.render_client_conf)
# ---------------------------------------------------------------------------


class TestRenderClientConf:
    def test_conf_contains_required_interface_fields(self):
        conf = waygate_config.render_client_conf(
            private_key="client-priv-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            tunnel_ip="10.8.0.2",
            dns="1.1.1.1",
            server_public_key="server-pub-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            endpoint_ip="203.0.113.10",
            listen_port=51820,
            allowed_ips=["10.8.0.0/24"],
        )
        assert "[Interface]" in conf
        assert "PrivateKey = client-priv-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" in conf
        assert "Address = 10.8.0.2/32" in conf
        assert "DNS = 1.1.1.1" in conf

    def test_conf_contains_required_peer_fields(self):
        conf = waygate_config.render_client_conf(
            private_key="client-priv-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            tunnel_ip="10.8.0.2",
            dns=None,
            server_public_key="server-pub-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            endpoint_ip="203.0.113.10",
            listen_port=51820,
            allowed_ips=["10.8.0.0/24", "192.168.1.0/24"],
        )
        assert "[Peer]" in conf
        assert "PublicKey = server-pub-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" in conf
        assert "Endpoint = 203.0.113.10:51820" in conf
        assert "AllowedIPs = 10.8.0.0/24, 192.168.1.0/24" in conf
        assert "PersistentKeepalive = 25" in conf

    def test_conf_omits_dns_line_when_none(self):
        conf = waygate_config.render_client_conf(
            private_key="k",
            tunnel_ip="10.8.0.2",
            dns=None,
            server_public_key="pub",
            endpoint_ip="203.0.113.10",
            listen_port=51820,
            allowed_ips=["10.8.0.0/24"],
        )
        assert "DNS" not in conf

    def test_conf_field_order_interface_before_peer(self):
        conf = waygate_config.render_client_conf(
            private_key="k",
            tunnel_ip="10.8.0.2",
            dns=None,
            server_public_key="pub",
            endpoint_ip="203.0.113.10",
            listen_port=51820,
            allowed_ips=["10.8.0.0/24"],
        )
        assert conf.index("[Interface]") < conf.index("[Peer]")


class TestDownloadClientConfigEndpoint:
    @pytest.mark.asyncio
    async def test_download_config_returns_conf_with_content_disposition(self, api_client):
        _override_token_info()
        from waygate.services import k3s_crypto

        priv_key = "client-priv-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        encrypted = k3s_crypto.encrypt_wg_client_key(priv_key)

        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.get_client = AsyncMock(return_value=_client_record(private_key_encrypted=encrypted))
            mock_db.list_active_attachment_cidrs = AsyncMock(return_value=[])
            resp = await api_client.get("/v1/servers/server-1/clients/client-1/config")
        assert resp.status_code == 200
        assert "laptop.conf" in resp.headers["content-disposition"]
        assert "PrivateKey = " + priv_key in resp.text

    @pytest.mark.asyncio
    async def test_download_config_404_when_client_missing(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record())
            mock_db.get_client = AsyncMock(return_value=None)
            resp = await api_client.get("/v1/servers/server-1/clients/client-1/config")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_download_config_409_when_server_not_ready(self, api_client):
        _override_token_info()
        with patch("waygate.api.clients.waygate_db") as mock_db:
            mock_db.get_server = AsyncMock(return_value=_server_record(server_public_key=None))
            mock_db.get_client = AsyncMock(return_value=_client_record())
            resp = await api_client.get("/v1/servers/server-1/clients/client-1/config")
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# waygate_db.py 레이어 회귀 테스트 — 소프트삭제 후 재생성, unique 충돌 → 도메인 예외 변환
#
# 실 MariaDB(pytest.mark.db, AFTERGLOW_TEST_DATABASE_URL) 없이도 waygate_db.py의 실제
# 코드(soft_delete_client의 NULL-out, create_client_record의 IntegrityError 변환)를
# 직접 실행해 검증한다. get_session_factory()만 in-memory 페이크로 교체하고, 그 페이크는
# (server_id, name)/(server_id, tunnel_ip) UniqueConstraint를 실제로 흉내 낸다 — 즉
# "메서드 호출만 확인"하는 테스트가 아니라, soft_delete가 필드를 비우지 않으면 이 테스트도
# 실제로 실패한다.
# ---------------------------------------------------------------------------


class _FakeUniqueConstraintStore:
    """VpnClient 행을 흉내 내는 in-memory 저장소.

    (server_id, name)과 (server_id, tunnel_ip) 조합의 유일성을 실제로 검사해서, 값이
    None이 아닌 두 행이 같은 조합을 가지면 commit 시 IntegrityError를 발생시킨다
    (MySQL/MariaDB의 UniqueConstraint 동작을 그대로 재현 — NULL은 여러 번 허용).
    """

    def __init__(self):
        self.rows: dict[str, SimpleNamespace] = {}

    def _conflict_field(self, row) -> str | None:
        for other_id, other in self.rows.items():
            if other_id == row.id:
                continue
            if row.name is not None and other.name is not None:
                if (row.server_id, row.name) == (other.server_id, other.name):
                    return "name"
            if row.tunnel_ip is not None and other.tunnel_ip is not None:
                if (row.server_id, row.tunnel_ip) == (other.server_id, other.tunnel_ip):
                    return "tunnel_ip"
        return None


class _FakeSession:
    """waygate_db.py가 사용하는 최소 AsyncSession 인터페이스(add/commit/rollback/execute)를
    _FakeUniqueConstraintStore 위에서 구현한 페이크."""

    def __init__(self, store: _FakeUniqueConstraintStore):
        self._store = store
        self._pending = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def add(self, obj):
        self._pending = obj

    async def commit(self):
        row = self._pending
        if row is not None and row.id not in self._store.rows:
            field = self._store._conflict_field(row)
            if field is not None:
                constraint_name = (
                    "uq_waygate_client_server_name" if field == "name" else "uq_waygate_client_server_tunnel_ip"
                )
                orig = Exception(
                    f"(pymysql.err.IntegrityError) (1062, \"Duplicate entry for key '{constraint_name}'\")"
                )
                raise IntegrityError(statement="INSERT INTO waygate_clients ...", params={}, orig=orig)
        if row is not None:
            self._store.rows[row.id] = row
        self._pending = None

    async def rollback(self):
        self._pending = None

    async def execute(self, stmt):
        # soft_delete_client의 select(...).where(id==..., server_id==..., project_id==...,
        # deleted_at.is_(None)) 를 흉내: 테스트에서는 select 대상 id를 stmt에서 직접
        # 추출하지 않고, 테스트 헬퍼가 _selected_id를 세팅해 둔 값을 사용한다.
        result = MagicMock()
        row = self._store.rows.get(getattr(self, "_selected_id", None))
        result.scalar_one_or_none = MagicMock(return_value=row)
        return result


def _make_client_row(**overrides) -> SimpleNamespace:
    base = dict(
        id="client-1",
        server_id="server-1",
        project_id="test-project-123",
        name="laptop",
        enabled=True,
        public_key="pub",
        private_key_encrypted="enc",
        preshared_key_encrypted=None,
        tunnel_ip="10.8.0.2",
        allowed_ips=[],
        dns=None,
        deleted_at=None,
        deleted_by_user_id=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class TestVpnDbSoftDeleteRegression:
    """soft_delete_client가 실제로 unique 슬롯을 해제하는지, create_client_record가
    IntegrityError를 VpnClientConflictError로 변환하는지 — waygate_db.py 실제 코드를 실행해 검증."""

    @pytest.mark.asyncio
    async def test_recreate_after_delete_succeeds_when_soft_delete_nulls_fields(self, monkeypatch):
        """버그 재현 시나리오: 클라이언트를 삭제한 뒤 같은 이름/IP로 재생성하면
        soft_delete_client가 name/tunnel_ip를 NULL로 비우지 않는 한 IntegrityError → 500이
        발생해야 한다. 수정 후에는 soft_delete가 필드를 비우므로 재생성이 성공해야 한다."""
        from waygate.services import waygate_db

        store = _FakeUniqueConstraintStore()
        store.rows["client-1"] = _make_client_row()

        session = _FakeSession(store)
        session._selected_id = "client-1"

        factory = MagicMock(return_value=session)
        monkeypatch.setattr(waygate_db, "get_session_factory", lambda: factory)

        # 1) 소프트삭제 — name/tunnel_ip가 NULL로 비워져야 unique 슬롯이 해제된다
        ok = await waygate_db.soft_delete_client("server-1", "test-project-123", "client-1", "user-1")
        assert ok is True
        deleted_row = store.rows["client-1"]
        assert deleted_row.deleted_at is not None
        assert deleted_row.name is None, "soft_delete_client가 name을 비우지 않으면 재생성 시 unique 충돌이 재발한다"
        assert deleted_row.tunnel_ip is None, (
            "soft_delete_client가 tunnel_ip를 비우지 않으면 재생성 시 unique 충돌이 재발한다"
        )

        # 2) 동일한 이름/IP로 재생성 — 소프트삭제된 행과 더 이상 충돌하지 않아야 한다
        await waygate_db.create_client_record(
            "server-1",
            "test-project-123",
            "client-2",
            {
                "name": "laptop",
                "public_key": "pub2",
                "private_key_encrypted": "enc2",
                "tunnel_ip": "10.8.0.2",
            },
        )
        assert store.rows["client-2"].name == "laptop"
        assert store.rows["client-2"].tunnel_ip == "10.8.0.2"

    @pytest.mark.asyncio
    async def test_create_client_record_raises_conflict_on_duplicate_name(self, monkeypatch):
        """활성 클라이언트와 이름이 겹치면 IntegrityError가 그대로 전파되지 않고
        VpnClientConflictError(field='name')로 변환되어야 한다(라우터가 409로 매핑)."""
        from waygate.services import waygate_db

        store = _FakeUniqueConstraintStore()
        store.rows["client-1"] = _make_client_row(name="laptop", tunnel_ip="10.8.0.2")

        session = _FakeSession(store)
        factory = MagicMock(return_value=session)
        monkeypatch.setattr(waygate_db, "get_session_factory", lambda: factory)

        with pytest.raises(waygate_db.WaygateClientConflictError) as excinfo:
            await waygate_db.create_client_record(
                "server-1",
                "test-project-123",
                "client-2",
                {
                    "name": "laptop",  # 활성 client-1과 이름 중복
                    "public_key": "pub2",
                    "private_key_encrypted": "enc2",
                    "tunnel_ip": "10.8.0.3",
                },
            )
        assert excinfo.value.field == "name"
        # 실패한 INSERT는 저장소에 반영되지 않아야 한다 (rollback 확인)
        assert "client-2" not in store.rows

    @pytest.mark.asyncio
    async def test_create_client_record_raises_conflict_on_duplicate_tunnel_ip(self, monkeypatch):
        from waygate.services import waygate_db

        store = _FakeUniqueConstraintStore()
        store.rows["client-1"] = _make_client_row(name="laptop", tunnel_ip="10.8.0.2")

        session = _FakeSession(store)
        factory = MagicMock(return_value=session)
        monkeypatch.setattr(waygate_db, "get_session_factory", lambda: factory)

        with pytest.raises(waygate_db.WaygateClientConflictError) as excinfo:
            await waygate_db.create_client_record(
                "server-1",
                "test-project-123",
                "client-2",
                {
                    "name": "desktop",
                    "public_key": "pub2",
                    "private_key_encrypted": "enc2",
                    "tunnel_ip": "10.8.0.2",  # 활성 client-1과 IP 중복
                },
            )
        assert excinfo.value.field == "tunnel_ip"
        assert "client-2" not in store.rows
