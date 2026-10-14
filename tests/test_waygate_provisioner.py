"""Waygate provisioning uses immutable database snapshots."""

import contextlib
import copy
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waygate.services import provisioner as waygate_provisioner


def _settings(callback_base_url: str = "https://backend.example.com") -> SimpleNamespace:
    return SimpleNamespace(waygate_callback_base_url=callback_base_url)


def _record(*, floating_network_id: str | None = None, agent_install_mode: str = "cloud-init") -> dict:
    snapshot = {
        "waygate.provider_network": {"id": "net-provider-1", "name": "Provider"},
        "waygate.image": {"id": "img-ubuntu-1", "name": "Ubuntu"},
        "waygate.flavor": {"id": "flavor-abc", "name": "CPU"},
    }
    if floating_network_id:
        snapshot["waygate.floating_network"] = {"id": floating_network_id, "name": "External"}
    return {
        "id": "server-1",
        "project_id": "project-1",
        "status": "CREATING",
        "name": "waygate-gw-1",
        "listen_port": 51820,
        "tunnel_cidr": "10.8.0.0/24",
        "agent_install_mode": agent_install_mode,
        "provider_network_id": "net-provider-1",
        "image_id": "img-ubuntu-1",
        "flavor_id": "flavor-abc",
        "floating_network_id": floating_network_id,
        "resource_policy_snapshot": snapshot,
    }


@contextlib.contextmanager
def _provision_fixture(record, callback_base_url="https://backend.example.com"):
    """Mutable durable store; each intent is readable before its provider POST."""
    conn = MagicMock()
    conn.compute.get_flavor.return_value = SimpleNamespace(disk=20)
    conn.compute.create_server.return_value = SimpleNamespace(id="vm-123")
    conn.compute.get_server.return_value = SimpleNamespace(id="vm-123", status="ACTIVE")
    conn.network.create_port.return_value = SimpleNamespace(id="port-1")
    conn.network.create_ip.return_value = SimpleNamespace(id="fip-1", floating_ip_address="203.0.113.9")

    async def read(_server_id):
        return copy.deepcopy(record)

    async def update(server_id, status=None, reason=None, *, only_if_status=None, **fields):
        assert server_id == record["id"]
        if status is not None and (only_if_status is None or record["status"] == only_if_status):
            record["status"] = status
            record["status_reason"] = reason
        record.update(copy.deepcopy(fields))

    with (
        patch("waygate.services.provisioner.get_settings", return_value=_settings(callback_base_url)),
        patch("waygate.services.store.get_server_by_id", new=AsyncMock(side_effect=read)),
        patch("waygate.services.store.update_server_status", new=AsyncMock(side_effect=update)) as update_status,
        patch("waygate.services.provisioner._ensure_wireguard_sg", new=AsyncMock(return_value="sg-1")),
        patch("waygate.services.agent_auth.issue_report_token", new=AsyncMock(return_value="token")),
        patch("waygate.services.config_render.render_agent_userdata", return_value="userdata") as render_userdata,
        patch("waygate.services.provisioner._wait_for_active", new=AsyncMock()),
        patch("waygate.services.provisioner._extract_fixed_ip", return_value="10.0.0.5"),
    ):
        yield SimpleNamespace(conn=conn, update_status=update_status, render_userdata=render_userdata)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["cloud-init", "prebuilt"])
async def test_provision_uses_persisted_snapshot_without_fip(mode):
    record = _record(agent_install_mode=mode)
    original_policies = copy.deepcopy(record["resource_policy_snapshot"])
    with _provision_fixture(record) as fixture:
        conn = fixture.conn
        await waygate_provisioner.provision_waygate_server("project-1", "server-1", "user-1", "tester", conn=conn)

    intents = record["resource_policy_snapshot"]["waygate.provision_intents"]
    marker = str(uuid.UUID(intents["port"]["marker"]))
    conn.network.create_port.assert_called_once_with(
        network_id="net-provider-1", name="waygate-gw-1-port", security_groups=["sg-1"],
        description=f"waygate:server-1:port:{marker}",
    )
    kwargs = conn.compute.create_server.call_args.kwargs
    assert kwargs["image_id"] == "img-ubuntu-1"
    assert kwargs["flavor_id"] == "flavor-abc"
    assert kwargs["networks"] == [{"port": "port-1"}]
    assert kwargs["metadata"]["waygate_create_intent"] == intents["vm"]["marker"]
    assert "key_name" not in kwargs
    assert (record["status"], record["endpoint_ip"], record["provider_port_id"], record["server_vm_id"]) == (
        "PROVISIONING", "10.0.0.5", "port-1", "vm-123",
    )
    assert intents["port"]["resource_id"] == "port-1" and intents["vm"]["resource_id"] == "vm-123"
    for key, value in original_policies.items():
        assert record["resource_policy_snapshot"][key] == value
    conn.network.create_ip.assert_not_called()
    render_kwargs = fixture.render_userdata.call_args.kwargs
    assert render_kwargs["install_packages"] is (mode == "cloud-init")
    assert render_kwargs["tunnel_cidr"] == "10.8.0.0/24"
    assert render_kwargs["register_url"] == "https://backend.example.com/v1/servers/server-1/agent/register"
    assert render_kwargs["desired_state_url"] == "https://backend.example.com/v1/servers/server-1/agent/desired-state"
    assert render_kwargs["status_url"] == "https://backend.example.com/v1/servers/server-1/agent/status"


@pytest.mark.asyncio
async def test_provision_uses_optional_persisted_floating_network():
    record = _record(floating_network_id="net-external-1")
    with _provision_fixture(record) as fixture:
        await waygate_provisioner.provision_waygate_server(
            "project-1", "server-1", "user-1", "tester", conn=fixture.conn,
        )
    intent = record["resource_policy_snapshot"]["waygate.provision_intents"]["fip"]
    fixture.conn.network.create_ip.assert_called_once_with(
        floating_network_id="net-external-1", port_id="port-1",
        description=f"waygate:server-1:fip:{intent['marker']}",
    )
    assert (intent["project_id"], intent["network_id"], intent["port_id"], intent["resource_id"]) == (
        "project-1", "net-external-1", "port-1", "fip-1",
    )
    assert (record["endpoint_ip"], record["fip_id"]) == ("203.0.113.9", "fip-1")


@pytest.mark.asyncio
async def test_provision_rejects_missing_callback_before_openstack_resources():
    record = _record()
    with _provision_fixture(record, callback_base_url="") as fixture:
        with pytest.raises(RuntimeError, match="callback"):
            await waygate_provisioner.provision_waygate_server(
                "project-1", "server-1", "user-1", "tester", conn=fixture.conn,
            )
    fixture.conn.compute.create_server.assert_not_called()
    fixture.conn.network.create_port.assert_not_called()
    assert record["status"] == "ERROR"
    assert "waygate.provision_intents" not in record["resource_policy_snapshot"]


@pytest.mark.asyncio
async def test_provision_rejects_incomplete_snapshot_before_resource_creation():
    record = {"id": "server-1", "project_id": "project-1", "status": "CREATING", "name": "waygate-gw-1", "listen_port": 51820}
    with _provision_fixture(record) as fixture:
        with pytest.raises(RuntimeError, match="snapshot is incomplete"):
            await waygate_provisioner.provision_waygate_server(
                "project-1", "server-1", "user-1", "tester", conn=fixture.conn,
            )
    fixture.conn.compute.create_server.assert_not_called()
    fixture.conn.network.create_port.assert_not_called()
    assert record["status"] == "ERROR"
    assert "resource_policy_snapshot" not in record


