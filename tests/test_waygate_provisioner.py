"""Waygate provisioning uses immutable database snapshots."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waygate.services import provisioner as waygate_provisioner


def _settings() -> SimpleNamespace:
    return SimpleNamespace(waygate_callback_base_url="https://backend.example.com")


def _record(*, floating_network_id: str | None = None) -> dict:
    snapshot = {
        "waygate.provider_network": {"id": "net-provider-1", "name": "Provider"},
        "waygate.image": {"id": "img-ubuntu-1", "name": "Ubuntu"},
        "waygate.flavor": {"id": "flavor-abc", "name": "CPU"},
    }
    if floating_network_id:
        snapshot["waygate.floating_network"] = {"id": floating_network_id, "name": "External"}
    return {
        "id": "server-1",
        "name": "waygate-gw-1",
        "listen_port": 51820,
        "provider_network_id": "net-provider-1",
        "image_id": "img-ubuntu-1",
        "flavor_id": "flavor-abc",
        "floating_network_id": floating_network_id,
        "resource_policy_snapshot": snapshot,
    }


@pytest.mark.asyncio
async def test_provision_uses_persisted_snapshot_without_fip():
    conn = MagicMock()
    conn.close = MagicMock()
    server = MagicMock(id="vm-123")
    conn.compute.create_server.return_value = server
    conn.compute.get_server.return_value = server

    with (
        patch("waygate.services.provisioner.get_settings", return_value=_settings()),
        patch("waygate.auth.get_admin_connection_for_project", return_value=conn),
        patch("waygate.services.store.get_server_by_id", new=AsyncMock(return_value=_record())),
        patch("waygate.services.provisioner._ensure_wireguard_sg", return_value="sg-1"),
        patch("waygate.services.openstack_ops.create_port", return_value={"id": "port-1"}) as create_port,
        patch("waygate.services.agent_auth.issue_report_token", new=AsyncMock(return_value="token")),
        patch("waygate.services.config_render.render_agent_userdata", return_value="userdata") as render_userdata,
        patch("waygate.services.store.update_server_status", new=AsyncMock()) as update_status,
        patch("waygate.services.provisioner._wait_for_active", new=AsyncMock()),
        patch("waygate.services.provisioner._extract_fixed_ip", return_value="10.0.0.5"),
    ):
        await waygate_provisioner.provision_waygate_server("project-1", "server-1", "user-1", "tester")

    create_port.assert_called_once_with(conn, "net-provider-1", "waygate-gw-1-port", ["sg-1"])
    kwargs = conn.compute.create_server.call_args.kwargs
    assert kwargs["image_id"] == "img-ubuntu-1"
    assert kwargs["flavor_id"] == "flavor-abc"
    assert "key_name" not in kwargs
    assert update_status.call_args_list[-1].kwargs["endpoint_ip"] == "10.0.0.5"
    render_kwargs = render_userdata.call_args.kwargs
    assert render_kwargs["register_url"] == "https://backend.example.com/v1/servers/server-1/agent/register"
    assert render_kwargs["desired_state_url"] == "https://backend.example.com/v1/servers/server-1/agent/desired-state"
    assert render_kwargs["status_url"] == "https://backend.example.com/v1/servers/server-1/agent/status"


@pytest.mark.asyncio
async def test_provision_uses_optional_persisted_floating_network():
    conn = MagicMock()
    conn.close = MagicMock()
    server = MagicMock(id="vm-123")
    conn.compute.create_server.return_value = server
    conn.compute.get_server.return_value = server

    with (
        patch("waygate.services.provisioner.get_settings", return_value=_settings()),
        patch("waygate.auth.get_admin_connection_for_project", return_value=conn),
        patch(
            "waygate.services.store.get_server_by_id",
            new=AsyncMock(return_value=_record(floating_network_id="net-external-1")),
        ),
        patch("waygate.services.provisioner._ensure_wireguard_sg", return_value="sg-1"),
        patch("waygate.services.openstack_ops.create_port", return_value={"id": "port-1"}),
        patch("waygate.services.agent_auth.issue_report_token", new=AsyncMock(return_value="token")),
        patch("waygate.services.config_render.render_agent_userdata", return_value="userdata"),
        patch("waygate.services.store.update_server_status", new=AsyncMock()) as update_status,
        patch("waygate.services.provisioner._wait_for_active", new=AsyncMock()),
        patch("waygate.services.provisioner._extract_fixed_ip", return_value="10.0.0.5"),
        patch(
            "waygate.services.provisioner._allocate_new_fip", new=AsyncMock(return_value=("203.0.113.9", "fip-1"))
        ) as allocate_fip,
    ):
        await waygate_provisioner.provision_waygate_server("project-1", "server-1", "user-1", "tester")

    allocate_fip.assert_awaited_once_with(conn, "vm-123", "net-external-1")
    assert update_status.call_args_list[-1].kwargs["endpoint_ip"] == "203.0.113.9"


@pytest.mark.asyncio
async def test_provision_rejects_incomplete_snapshot_before_resource_creation():
    conn = MagicMock()
    conn.close = MagicMock()
    with (
        patch("waygate.services.provisioner.get_settings", return_value=_settings()),
        patch("waygate.auth.get_admin_connection_for_project", return_value=conn),
        patch(
            "waygate.services.store.get_server_by_id",
            new=AsyncMock(return_value={"id": "server-1", "name": "waygate-gw-1", "listen_port": 51820}),
        ),
        patch("waygate.services.store.update_server_status", new=AsyncMock()) as update_status,
    ):
        await waygate_provisioner.provision_waygate_server("project-1", "server-1", "user-1", "tester")

    conn.compute.create_server.assert_not_called()
    assert update_status.call_args.args[1] == "ERROR"


class _FakeServerSessionStore:
    def __init__(self):
        self.servers = {}


class _FakeServerSession:
    def __init__(self, store: _FakeServerSessionStore):
        self.store = store
        self.pending = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def add(self, obj):
        self.pending = obj

    async def commit(self):
        if self.pending is not None:
            self.store.servers[self.pending.id] = self.pending
            self.pending = None

    async def execute(self, stmt):
        result = MagicMock()
        server = list(self.store.servers.values())[-1] if self.store.servers else None
        result.scalar_one_or_none.return_value = server
        return result


@pytest.mark.asyncio
async def test_create_server_record_and_provision_with_full_snapshot():
    from waygate.services import waygate_db

    snapshot = {
        "waygate.provider_network": {"id": "net-provider-1", "name": "Provider"},
        "waygate.image": {"id": "img-ubuntu-1", "name": "Ubuntu"},
        "waygate.flavor": {"id": "flavor-abc", "name": "CPU"},
        "waygate.floating_network": {"id": "net-external-1", "name": "External"},
    }

    store = _FakeServerSessionStore()
    factory = MagicMock(return_value=_FakeServerSession(store))

    with patch("waygate.services.store.get_session_factory", lambda: factory):
        await waygate_db.create_server_record(
            "project-1",
            "server-999",
            {
                "name": "waygate-gw-999",
                "status": "CREATING",
                "listen_port": 51820,
                "tunnel_cidr": "10.8.0.0/24",
                "flavor_id": "flavor-abc",
                "image_id": "img-ubuntu-1",
                "provider_network_id": "net-provider-1",
                "floating_network_id": "net-external-1",
                "resource_policy_snapshot": snapshot,
            },
        )

        record = await waygate_db.get_server_by_id("server-999")
        assert record is not None
        assert record["image_id"] == "img-ubuntu-1"
        assert record["floating_network_id"] == "net-external-1"
        assert record["resource_policy_snapshot"] == snapshot
        assert record["flavor_id"] == "flavor-abc"

    conn = MagicMock()
    conn.close = MagicMock()
    server = MagicMock(id="vm-999")
    conn.compute.create_server.return_value = server
    conn.compute.get_server.return_value = server

    with (
        patch("waygate.services.provisioner.get_settings", return_value=_settings()),
        patch("waygate.auth.get_admin_connection_for_project", return_value=conn),
        patch("waygate.services.store.get_server_by_id", new=AsyncMock(return_value=record)),
        patch("waygate.services.provisioner._ensure_wireguard_sg", return_value="sg-1"),
        patch("waygate.services.openstack_ops.create_port", return_value={"id": "port-1"}),
        patch("waygate.services.agent_auth.issue_report_token", new=AsyncMock(return_value="token")),
        patch("waygate.services.config_render.render_agent_userdata", return_value="userdata"),
        patch("waygate.services.store.update_server_status", new=AsyncMock()),
        patch("waygate.services.provisioner._wait_for_active", new=AsyncMock()),
        patch("waygate.services.provisioner._extract_fixed_ip", return_value="10.0.0.5"),
        patch(
            "waygate.services.provisioner._allocate_new_fip", new=AsyncMock(return_value=("203.0.113.9", "fip-1"))
        ),
    ):
        await waygate_provisioner.provision_waygate_server("project-1", "server-999", "user-1", "tester")

    kwargs = conn.compute.create_server.call_args.kwargs
    assert kwargs["image_id"] == "img-ubuntu-1"
    assert kwargs["flavor_id"] == "flavor-abc"
