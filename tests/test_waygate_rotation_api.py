"""Tenant rotation and agent handoff HTTP contracts without external services."""

from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from waygate.api import servers
from waygate.auth import require_token
from waygate.main import app
from waygate.services import waygate_agent_auth, waygate_db


@pytest.fixture
async def rotation_api(monkeypatch):
    record = {
        "id": "server-1",
        "project_id": "project-1",
        "name": "gateway-1",
        "status": "ACTIVE",
        "listen_port": 51820,
        "tunnel_cidr": "10.8.0.0/24",
        "agent_install_mode": "prebuilt",
        "agent_token_rotation_pending": False,
    }

    async def get_server(project_id, server_id):
        if (project_id, server_id) == (record["project_id"], record["id"]):
            return dict(record)
        return None

    async def get_server_by_id(server_id):
        return dict(record) if server_id == record["id"] else None

    async def set_agent_token(server_id, encrypted):
        assert server_id == record["id"]
        record["agent_token_encrypted"] = encrypted
        record["agent_token_next_encrypted"] = None
        record["agent_token_rotation_pending"] = False
        record["agent_token_issued_at"] = "2026-09-26T12:00:00+00:00"

    async def set_agent_next_token(server_id, encrypted):
        assert server_id == record["id"]
        if not record.get("agent_token_encrypted") or record.get("agent_token_next_encrypted"):
            return False
        record["agent_token_next_encrypted"] = encrypted
        record["agent_token_rotation_pending"] = True
        return True

    async def promote_agent_token(server_id, encrypted):
        if record.get("agent_token_next_encrypted") != encrypted:
            return False
        await set_agent_token(server_id, encrypted)
        return True

    async def get_agent_tokens_encrypted(server_id):
        if server_id != record["id"]:
            return None, None
        return record.get("agent_token_encrypted"), record.get("agent_token_next_encrypted")

    monkeypatch.setattr(servers, "is_db_available", lambda: True)
    monkeypatch.setattr(waygate_db, "get_server", get_server)
    monkeypatch.setattr(waygate_db, "get_server_by_id", get_server_by_id)
    monkeypatch.setattr(waygate_db, "set_agent_token", set_agent_token)
    monkeypatch.setattr(waygate_db, "set_agent_next_token", set_agent_next_token)
    monkeypatch.setattr(waygate_db, "promote_agent_token", promote_agent_token)
    monkeypatch.setattr(waygate_db, "get_agent_tokens_encrypted", get_agent_tokens_encrypted)
    monkeypatch.setattr(waygate_db, "list_all_active_clients", AsyncMock(return_value=[]))
    monkeypatch.setattr(waygate_db, "list_active_attachment_cidrs", AsyncMock(return_value=[]))
    token = await waygate_agent_auth.issue_report_token(record["id"])
    monkeypatch.setitem(app.dependency_overrides, require_token, lambda: {"project_id": "project-1"})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client, record, token


@pytest.mark.asyncio
@pytest.mark.parametrize("server_id,owner", [("missing", "project-1"), ("server-1", "other-project")])
async def test_rotation_hides_missing_and_foreign_servers(rotation_api, server_id, owner):
    client, record, _ = rotation_api
    record["project_id"] = owner
    response = await client.post(f"/v1/servers/{server_id}/agent-token/rotate")
    assert response.status_code == 404
    assert response.json() == {"detail": "Waygate 서버를 찾을 수 없습니다"}
    assert record["agent_token_next_encrypted"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["CREATING", "PROVISIONING", "DELETING", "DELETED", "ERROR"])
async def test_rotation_requires_active_server(rotation_api, status):
    client, record, _ = rotation_api
    record["status"] = status
    response = await client.post("/v1/servers/server-1/agent-token/rotate")
    assert response.status_code == 409
    assert record["agent_token_next_encrypted"] is None
    assert record["agent_token_rotation_pending"] is False


@pytest.mark.asyncio
async def test_rotation_requires_available_database(rotation_api, monkeypatch):
    client, record, _ = rotation_api
    monkeypatch.setattr(servers, "is_db_available", lambda: False)
    response = await client.post("/v1/servers/server-1/agent-token/rotate")
    assert response.status_code == 503
    assert record["agent_token_next_encrypted"] is None


@pytest.mark.asyncio
async def test_accepted_rotation_hands_token_only_to_agent_and_retires_old_bearer(rotation_api):
    client, record, current_token = rotation_api
    desired_path = "/v1/servers/server-1/agent/desired-state"
    current_headers = {"Authorization": f"Bearer {current_token}"}
    before = await client.get(desired_path, headers=current_headers)
    assert before.status_code == 200
    assert before.json()["next_token"] is None

    response = await client.post("/v1/servers/server-1/agent-token/rotate")
    assert response.status_code == 202
    metadata = response.json()
    assert metadata["id"] == record["id"]
    assert metadata["status"] == "ACTIVE"
    assert metadata["agent_install_mode"] == "prebuilt"
    assert metadata["agent_token_rotation_pending"] is True
    assert metadata["agent_token_issued_at"] == record["agent_token_issued_at"]
    assert not {"token", "next_token", "agent_token_encrypted", "agent_token_next_encrypted"} & metadata.keys()
    assert current_token not in response.text

    unauthenticated = await client.get(desired_path)
    assert unauthenticated.status_code == 401
    desired = await client.get(desired_path, headers=current_headers)
    assert desired.status_code == 200
    pending = desired.json()["next_token"]
    assert isinstance(pending, str)
    assert pending != current_token
    assert pending not in response.text

    adopted = await client.get(desired_path, headers={"Authorization": f"Bearer {pending}"})
    assert adopted.status_code == 200
    assert adopted.json()["next_token"] is None
    retired = await client.get(desired_path, headers=current_headers)
    assert retired.status_code == 401
    refreshed = await client.get("/v1/servers/server-1")
    assert refreshed.status_code == 200
    assert refreshed.json()["agent_token_rotation_pending"] is False


@pytest.mark.asyncio
async def test_rotation_without_active_token_returns_conflict(rotation_api):
    client, record, _ = rotation_api
    await waygate_agent_auth.revoke_report_token_by_server(record["id"])
    response = await client.post("/v1/servers/server-1/agent-token/rotate")
    assert response.status_code == 409
    assert record["agent_token_rotation_pending"] is False
