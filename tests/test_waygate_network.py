"""Waygate 네트워크 연결(Phase 2) API + 서비스 + 렌더 로직 테스트.

- API: 소유권(IDOR), 입력 검증(network_id/nat_mode), 상태 매핑(409/404/201/204).
- 서비스: attach_network 중복/비ACTIVE 거부, happy path(mock conn/nova/db).
- 렌더: desired-state nat_networks, client .conf 의 nat_cidrs 병합·중복 제거.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from waygate.main import app
from waygate.services import waygate_config, waygate_network
from waygate.services.network import WaygateNetworkError

_VALID_UUID = "11111111-2222-3333-4444-555555555555"


def _server(**overrides) -> dict:
    base = {
        "id": "srv-1",
        "project_id": "test-project-123",
        "name": "gw",
        "status": "ACTIVE",
        "server_vm_id": "vm-1",
        "tunnel_cidr": "10.8.0.0/24",
        "listen_port": 51820,
        "endpoint_ip": "203.0.113.10",
        "server_public_key": "A" * 43 + "=",
    }
    base.update(overrides)
    return base


def _attachment(**overrides) -> dict:
    base = {
        "id": 1,
        "server_id": "srv-1",
        "project_id": "test-project-123",
        "network_id": _VALID_UUID,
        "subnet_id": "22222222-3333-4444-5555-666666666666",
        "port_id": "port-1",
        "cidr": "192.168.9.0/24",
        "nat_mode": "snat",
        "status": "ACTIVE",
        "created_at": None,
        "updated_at": None,
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def _db_available(monkeypatch):
    monkeypatch.setattr("waygate.api.attachments.is_db_available", lambda: True)


@pytest.fixture
async def api_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


def _override_token_info(project_id: str = "test-project-123"):
    from waygate.auth import require_token

    async def _fn():
        return {"project_id": project_id, "user_id": "test-user-123", "username": "testuser"}

    app.dependency_overrides[require_token] = _fn


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# attach API
# ---------------------------------------------------------------------------


class TestAttachNetworkApi:
    @pytest.mark.asyncio
    async def test_attach_404_when_server_not_owned(self, api_client):
        _override_token_info()
        with patch("waygate.api.attachments.waygate_db") as db:
            db.get_server = AsyncMock(return_value=None)  # 없음/타 프로젝트 → 404
            resp = await api_client.post("/v1/servers/srv-x/networks", json={"network_id": _VALID_UUID})
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_attach_422_on_invalid_network_id(self, api_client):
        _override_token_info()
        resp = await api_client.post(
            "/v1/servers/srv-1/networks", json={"network_id": "not-a-uuid; rm -rf /"}
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_attach_422_on_invalid_nat_mode(self, api_client):
        _override_token_info()
        resp = await api_client.post(
            "/v1/servers/srv-1/networks",
            json={"network_id": _VALID_UUID, "nat_mode": "dnat"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_attach_success_201(self, api_client):
        _override_token_info()
        with (
            patch("waygate.api.attachments.waygate_db") as db,
            patch("waygate.api.attachments.waygate_network") as net,
        ):
            db.get_server = AsyncMock(return_value=_server())
            net.attach_network = AsyncMock(return_value=_attachment())
            resp = await api_client.post("/v1/servers/srv-1/networks", json={"network_id": _VALID_UUID})
        assert resp.status_code == 201
        body = resp.json()
        assert body["network_id"] == _VALID_UUID
        assert body["cidr"] == "192.168.9.0/24"
        assert body["status"] == "ACTIVE"

    @pytest.mark.asyncio
    async def test_attach_conflict_maps_to_409(self, api_client):
        _override_token_info()
        with (
            patch("waygate.api.attachments.waygate_db") as db,
            patch("waygate.api.attachments.waygate_network") as net,
        ):
            db.get_server = AsyncMock(return_value=_server())
            net.attach_network = AsyncMock(side_effect=WaygateNetworkError(409, "이미 연결된 네트워크입니다"))
            resp = await api_client.post("/v1/servers/srv-1/networks", json={"network_id": _VALID_UUID})
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# list / detach API
# ---------------------------------------------------------------------------


class TestListDetachNetworkApi:
    @pytest.mark.asyncio
    async def test_list_returns_attachments(self, api_client):
        _override_token_info()
        with patch("waygate.api.attachments.waygate_db") as db:
            db.get_server = AsyncMock(return_value=_server())
            db.list_attachments = AsyncMock(return_value=[_attachment()])
            resp = await api_client.get("/v1/servers/srv-1/networks")
        assert resp.status_code == 200
        assert resp.json()[0]["cidr"] == "192.168.9.0/24"

    @pytest.mark.asyncio
    async def test_list_404_when_not_owned(self, api_client):
        _override_token_info()
        with patch("waygate.api.attachments.waygate_db") as db:
            db.get_server = AsyncMock(return_value=None)
            resp = await api_client.get("/v1/servers/srv-x/networks")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_detach_success_204(self, api_client):
        _override_token_info()
        with (
            patch("waygate.api.attachments.waygate_db") as db,
            patch("waygate.api.attachments.waygate_network") as net,
        ):
            db.get_server = AsyncMock(return_value=_server())
            net.detach_network = AsyncMock(return_value=None)
            resp = await api_client.delete("/v1/servers/srv-1/networks/1")
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_detach_404_when_attachment_missing(self, api_client):
        _override_token_info()
        with (
            patch("waygate.api.attachments.waygate_db") as db,
            patch("waygate.api.attachments.waygate_network") as net,
        ):
            db.get_server = AsyncMock(return_value=_server())
            net.detach_network = AsyncMock(side_effect=WaygateNetworkError(404, "네트워크 연결을 찾을 수 없습니다"))
            resp = await api_client.delete("/v1/servers/srv-1/networks/999")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 서비스 로직 (mock conn/nova/db)
# ---------------------------------------------------------------------------


class TestAttachNetworkService:
    @pytest.mark.asyncio
    async def test_rejects_when_server_not_active(self):
        server = _server(status="PROVISIONING")
        with pytest.raises(WaygateNetworkError) as ei:
            await waygate_network.attach_network("test-project-123", server, "net-1", None, "snat")
        assert ei.value.status_code == 409

    @pytest.mark.asyncio
    async def test_rejects_duplicate_network(self, monkeypatch):
        monkeypatch.setattr(
            waygate_network.waygate_db,
            "list_attachments",
            AsyncMock(return_value=[{"network_id": "net-1", "status": "ACTIVE"}]),
        )
        with pytest.raises(WaygateNetworkError) as ei:
            await waygate_network.attach_network("test-project-123", _server(), "net-1", None, "snat")
        assert ei.value.status_code == 409

    @pytest.mark.asyncio
    async def test_happy_path_resolves_cidr_and_attaches(self, monkeypatch):
        conn = MagicMock()
        net = MagicMock()
        net.project_id = "test-project-123"
        conn.network.get_network.return_value = net
        subnet = MagicMock()
        subnet.network_id = "net-1"
        subnet.cidr = "192.168.9.0/24"
        subnet.id = "sub-1"
        conn.network.get_subnet.return_value = subnet
        conn.close = MagicMock()

        monkeypatch.setattr(waygate_network.keystone, "get_admin_connection_for_project", lambda pid: conn)
        monkeypatch.setattr(
            waygate_network.nova,
            "attach_interface",
            lambda c, vm, nid: {"port_id": "port-1", "net_id": nid, "fixed_ips": []},
        )
        monkeypatch.setattr(waygate_network.waygate_db, "list_attachments", AsyncMock(return_value=[]))
        monkeypatch.setattr(
            waygate_network.waygate_db,
            "create_attachment_record",
            AsyncMock(
                return_value={
                    "id": 1,
                    "server_id": "srv-1",
                    "project_id": "test-project-123",
                    "network_id": "net-1",
                    "subnet_id": "sub-1",
                    "cidr": "192.168.9.0/24",
                    "nat_mode": "snat",
                    "status": "CREATING",
                }
            ),
        )
        upd = AsyncMock()
        monkeypatch.setattr(waygate_network.waygate_db, "update_attachment", upd)

        result = await waygate_network.attach_network("test-project-123", _server(), "net-1", "sub-1", "snat")
        assert result["status"] == "ACTIVE"
        assert result["port_id"] == "port-1"
        assert result["cidr"] == "192.168.9.0/24"
        # ACTIVE 로 승격 업데이트가 호출됐는지
        assert upd.await_args.kwargs["status"] == "ACTIVE"
        assert upd.await_args.kwargs["port_id"] == "port-1"

    @pytest.mark.asyncio
    async def test_rejects_cross_project_network(self, monkeypatch):
        conn = MagicMock()
        net = MagicMock()
        net.project_id = "other-project"  # 타 프로젝트 소유
        conn.network.get_network.return_value = net
        conn.close = MagicMock()
        monkeypatch.setattr(waygate_network.keystone, "get_admin_connection_for_project", lambda pid: conn)
        monkeypatch.setattr(waygate_network.waygate_db, "list_attachments", AsyncMock(return_value=[]))
        with pytest.raises(WaygateNetworkError) as ei:
            await waygate_network.attach_network("test-project-123", _server(), "net-1", "sub-1", "snat")
        assert ei.value.status_code == 404  # 정보 노출 방지 — 동일 404


# ---------------------------------------------------------------------------
# 렌더 로직 (순수 함수)
# ---------------------------------------------------------------------------


class TestRenderNatNetworks:
    def test_desired_state_includes_nat_networks(self):
        r = waygate_config.render_agent_desired_state(
            listen_port=51820, tunnel_cidr="10.8.0.0/24", clients=[], nat_networks=["192.168.5.0/24"]
        )
        assert r["nat_networks"] == ["192.168.5.0/24"]

    def test_desired_state_default_empty_nat(self):
        r = waygate_config.render_agent_desired_state(listen_port=51820, tunnel_cidr="10.8.0.0/24", clients=[])
        assert r["nat_networks"] == []


class TestRenderClientConfNat:
    def test_conf_merges_nat_cidrs_and_dedups(self):
        conf = waygate_config.render_client_conf(
            private_key="k",
            tunnel_ip="10.8.0.2",
            dns=None,
            server_public_key="pub",
            endpoint_ip="1.2.3.4",
            listen_port=51820,
            allowed_ips=["10.8.0.0/24"],
            nat_cidrs=["192.168.5.0/24", "10.8.0.0/24"],
        )
        allowed_line = next(line for line in conf.splitlines() if line.startswith("AllowedIPs"))
        assert "192.168.5.0/24" in allowed_line
        # 중복 10.8.0.0/24 는 한 번만
        assert allowed_line.count("10.8.0.0/24") == 1
