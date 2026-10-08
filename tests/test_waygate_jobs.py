"""Durable Waygate provision/delete queue contracts."""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient, MockTransport, Response
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from waygate.api import servers as server_api
from waygate.auth import require_token
from waygate.db import Base
from waygate.main import app
from waygate.models.orm import (
    WaygateClient,
    WaygateExecutionGrant,
    WaygateJob,
    WaygateNetworkAttachment,
    WaygateServer,
)
from waygate.models.schemas import WaygateServerCreateRequest
from waygate.services import execution, waygate_db, waygate_jobs
from waygate.services import network as waygate_network
from waygate.services import provisioner as waygate_provisioner
from waygate.services.network import WaygateNetworkError

pytestmark = pytest.mark.asyncio


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Transaction:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *_args):
        return False


class _Session:
    def __init__(self, *, execute_values=(), objects=None):
        self.execute_values = list(execute_values)
        self.objects = objects or {}
        self.added = []
        self.statements = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def begin(self):
        return _Transaction(self)

    def add(self, value):
        self.added.append(value)

    async def execute(self, statement):
        self.statements.append(statement)
        return _Result(self.execute_values.pop(0) if self.execute_values else None)

    async def get(self, model, object_id, **_kwargs):
        return self.objects.get((model, object_id))


def _factory(session):
    return lambda: session


def _active_grant(purpose: str, project_id: str, server_id: str, user_id: str = "user-1"):
    return SimpleNamespace(
        status="active", project_id=project_id, server_id=server_id, user_id=user_id, purpose=purpose,
        capability=execution._CAPABILITIES[purpose], trust_id="trust-1", trustee_user_id="waygate-service",
        role_id="role-member", expires_at=datetime.now(UTC) + timedelta(hours=2),
    )


def _grant(engine, project_id: str, server_id: str, purpose: str, user_id: str = "user-1") -> str:
    grant_id = str(uuid.uuid4())
    with Session(engine) as session:
        session.add(WaygateExecutionGrant(
            id=grant_id, project_id=project_id, server_id=server_id, user_id=user_id, purpose=purpose,
            capability=execution._CAPABILITIES[purpose], trust_id="trust-" + grant_id,
            trustee_user_id="waygate-service", role_id="role-member", status="active",
            expires_at=datetime.now(UTC) + timedelta(hours=2),
        ))
        session.commit()
    return grant_id


async def _enqueue_delete(engine, project_id: str = "project-1", server_id: str = "server-1") -> bool:
    return await waygate_jobs.enqueue_delete_job(
        project_id, server_id, user_id="user-1", username="alice",
        execution_grant_id=_grant(engine, project_id, server_id, "delete"),
    )


def _delegate(monkeypatch, conn) -> list:
    """Replace only the Keystone Trust connection; grant binding and job semantics stay real."""
    opened = []
    monkeypatch.setattr(execution, "_open_connection", lambda grant: opened.append(grant) or conn)
    monkeypatch.setattr(execution, "_close_connection", lambda _conn: None)
    monkeypatch.setattr(execution, "_revoke_trust", lambda *_args: None)
    return opened


async def test_enqueue_provision_commits_server_and_job_in_one_transaction(monkeypatch):
    session = _Session(objects={(WaygateExecutionGrant, "grant-1"): _active_grant("provision", "project-1", "server-1")})
    monkeypatch.setattr(waygate_jobs, "get_session_factory", lambda: _factory(session))

    job_id = await waygate_jobs.enqueue_provision_job(
        "project-1",
        "server-1",
        {
            "name": "gateway-1",
            "status": "CREATING",
            "listen_port": 51820,
            "tunnel_cidr": "10.8.0.0/24",
            "dns": "1.1.1.1",
            "persistent_keepalive": 0,
        },
        user_id="user-1",
        username="alice",
        execution_grant_id="grant-1",
    )

    assert (session.added[0].dns, session.added[0].mtu, session.added[0].persistent_keepalive) == (
        "1.1.1.1",
        None,
        0,
    )
    assert isinstance(session.added[0], WaygateServer)
    assert isinstance(session.added[1], WaygateJob)
    assert session.added[0].id == "server-1"
    assert session.added[1].id == job_id
    assert session.added[1].kind == "provision"
    assert session.added[1].status == "queued"
    assert session.added[1].execution_grant_id == "grant-1"


async def test_enqueue_delete_marks_server_and_avoids_duplicate_active_job(monkeypatch):
    server = SimpleNamespace(status="ACTIVE", status_reason=None, updated_at=None)
    session = _Session(
        execute_values=[server, SimpleNamespace(status="running")],
        objects={(WaygateExecutionGrant, "grant-1"): _active_grant("delete", "project-1", "server-1")},
    )
    monkeypatch.setattr(waygate_jobs, "get_session_factory", lambda: _factory(session))

    found = await waygate_jobs.enqueue_delete_job(
        "project-1",
        "server-1",
        user_id="user-1",
        username="alice",
        execution_grant_id="grant-1",
    )

    assert found is True
    assert server.status == "DELETING"
    assert server.status_reason == "삭제 작업 대기 중"
    assert session.added == []


async def test_claim_reclaims_only_expired_lease_and_fences_old_worker(deletion_store, monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(waygate_jobs, "_now", lambda: now)
    with Session(deletion_store) as session:
        session.add_all([
            WaygateJob(
                id="fresh", server_id="server-1", project_id="project-1", kind="provision",
                status="running", attempts=1, claimed_at=now, created_at=now - timedelta(seconds=20),
            ),
            WaygateJob(
                id="stale", server_id="server-2", project_id="project-2", kind="delete",
                status="running", attempts=1, claimed_at=now - timedelta(seconds=901),
                created_at=now - timedelta(seconds=10),
            ),
        ])
        session.commit()

    assert (await waygate_jobs._claim_one())[:5] == ("stale", 2, "delete", "project-2", "server-2")
    assert await waygate_jobs._complete("stale", attempt=1) is False
    assert await waygate_jobs._retry_or_fail("stale", attempt=1, error="late failure") is False
    assert await waygate_jobs._claim_one() is None
    with Session(deletion_store) as session:
        fresh = session.get(WaygateJob, "fresh")
        stale = session.get(WaygateJob, "stale")
        assert (fresh.status, fresh.attempts) == ("running", 1)
        assert (stale.status, stale.attempts, stale.last_error) == ("running", 2, None)


async def test_immediate_delete_waits_while_provision_job_runs(deletion_store):
    now = datetime.now(UTC)
    with Session(deletion_store) as session:
        session.add(WaygateJob(
            id="provision", server_id="server-1", project_id="project-1", kind="provision",
            status="running", attempts=1, claimed_at=now,
        ))
        session.commit()
    await _enqueue_delete(deletion_store)

    assert await waygate_jobs._claim_one() is None
    with Session(deletion_store) as session:
        delete = session.scalar(select(WaygateJob).where(WaygateJob.kind == "delete"))
        assert (delete.status, delete.attempts, delete.claimed_at) == ("queued", 0, None)
        assert session.get(WaygateServer, "server-1").status == "DELETING"

    assert await waygate_jobs._complete("provision", attempt=1) is True
    claimed = await waygate_jobs._claim_one()
    assert claimed[1:5] == (1, "delete", "project-1", "server-1")


async def test_third_failure_terminalizes_job_and_server(monkeypatch):
    job = SimpleNamespace(
        id="job-1",
        server_id="server-1",
        kind="delete",
        status="running",
        attempts=3,
        claimed_at=object(),
        last_error=None,
        updated_at=None,
    )
    server = SimpleNamespace(status="DELETING", status_reason=None, updated_at=None, deleted_at=None)
    session = _Session(objects={(WaygateJob, "job-1"): job, (WaygateServer, "server-1"): server})
    monkeypatch.setattr(waygate_jobs, "get_session_factory", lambda: _factory(session))

    assert await waygate_jobs._retry_or_fail("job-1", attempt=3, error="OpenStack unavailable") is True
    assert job.status == "failed"
    assert job.last_error == "OpenStack unavailable"
    assert server.status == "ERROR"
    assert server.status_reason == "OpenStack unavailable"


@pytest.mark.parametrize("outcome,expected", [
    ("PROVISIONING", "completed"), ("ACTIVE", "completed"), ("ERROR", "queued"),
])
async def test_provision_completion_requires_durable_server_progress(deletion_store, monkeypatch, outcome, expected):
    grant_id = _grant(deletion_store, "project-1", "server-1", "provision")
    with Session(deletion_store) as session:
        session.get(WaygateServer, "server-1").status = "ERROR"
        session.add(WaygateJob(
            id="provision", server_id="server-1", project_id="project-1", kind="provision",
            status="queued", attempts=1, execution_grant_id=grant_id, user_id="user-1",
        ))
        session.commit()

    async def provision(_project, server, *_identity, conn):
        assert (await waygate_db.get_server_by_id(server))["status"] == "CREATING"
        await waygate_db.update_server_status(server, outcome, "quota exceeded" if outcome == "ERROR" else "")

    monkeypatch.setattr(waygate_jobs, "provision_waygate_server", provision)
    _delegate(monkeypatch, SimpleNamespace())
    assert await waygate_jobs.process_one_job() is True

    with Session(deletion_store) as session:
        job = session.get(WaygateJob, "provision")
        assert (job.status, job.attempts, job.claimed_at) == (expected, 2, None)
        assert job.last_error == ("quota exceeded" if outcome == "ERROR" else None)
        assert session.get(WaygateServer, "server-1").status == outcome


async def test_server_create_handler_waits_for_durable_enqueue(monkeypatch):
    calls = []
    conn = SimpleNamespace(close=lambda: None)

    async def resolve_policy_snapshot(**_kwargs):
        return {
            "waygate.provider_network": {"id": "network-1"},
            "waygate.image": {"id": "image-1"},
            "waygate.flavor": {"id": "flavor-1"},
        }

    async def get_policy_snapshot(_keys):
        return {"waygate.floating_network": None}

    async def enqueue(project_id, server_id, data, **identity):
        calls.append((project_id, server_id, data, identity))
        return "job-1"

    async def get_server(project_id, server_id):
        assert calls
        return {
            "id": server_id,
            "project_id": project_id,
            "name": "gateway-1",
            "status": "CREATING",
            "listen_port": 51820,
            "tunnel_cidr": "10.8.0.0/24",
        }

    async def no_status(_server_id):
        return None

    monkeypatch.setattr(server_api, "_require_db", lambda: None)
    monkeypatch.setattr(
        server_api,
        "get_settings",
        lambda: SimpleNamespace(
            waygate_default_listen_port=51820,
            waygate_default_tunnel_cidr="10.8.0.0/24",
            waygate_agent_install_mode="prebuilt",
        ),
    )

    @contextlib.asynccontextmanager
    async def admitted(token_info, server_id, purpose):
        assert (token_info["user_id"], purpose) == ("user-1", "provision")
        yield SimpleNamespace(id="grant-1"), conn

    monkeypatch.setattr(server_api.execution, "admitted_operation", admitted)
    monkeypatch.setattr("waygate.services.resource_policies.resolve_policy_snapshot", resolve_policy_snapshot)
    monkeypatch.setattr("waygate.services.resource_policies.get_policy_snapshot", get_policy_snapshot)
    monkeypatch.setattr(server_api.waygate_jobs, "enqueue_provision_job", enqueue)
    monkeypatch.setattr(server_api.waygate_db, "get_server", get_server)
    monkeypatch.setattr(server_api.waygate_agent_auth, "get_status_result", no_status)

    response = await server_api.create_waygate_server(
        WaygateServerCreateRequest(name="gateway-1", dns="1.1.1.1", persistent_keepalive=0),
        {
            "project_id": "project-1", "user_id": "user-1", "username": "alice",
            "roles": ["member", "waygate-inventory_reader", "waygate-gateways_editor", "waygate-gateways_admin"], "is_system_admin": False,
        },
    )

    assert response.status == "CREATING"
    assert calls[0][2]["flavor_id"] == "flavor-1"
    assert calls[0][2]["agent_install_mode"] == "prebuilt"
    assert calls[0][3] == {"user_id": "user-1", "username": "alice", "execution_grant_id": "grant-1"}
    assert (calls[0][2]["dns"], calls[0][2]["persistent_keepalive"]) == ("1.1.1.1", 0)
    assert "mtu" not in calls[0][2]


async def test_merge_status_exposes_agent_source_and_install_mode(monkeypatch):
    async def status(_server_id):
        return {
            "peers": [],
            "_stored_at": "2026-01-01T00:00:00+00:00",
            "agent_source": "prebuilt",
            "report_interval_seconds": 3,
        }

    monkeypatch.setattr(server_api.waygate_agent_auth, "get_status_result", status)
    info = await server_api._merge_status(
        {
            "id": "server-1",
            "project_id": "project-1",
            "name": "gateway-1",
            "status": "ACTIVE",
            "listen_port": 51820,
            "tunnel_cidr": "10.8.0.0/24",
            "agent_install_mode": "prebuilt",
        }
    )
    assert info.agent_install_mode == "prebuilt"
    assert info.agent_source == "prebuilt"
    assert info.report_interval_seconds == 3


class _SqlSession:
    """Execute async store calls against real SQLAlchemy rows and SQLite constraints."""

    def __init__(self, engine):
        self.session = Session(engine)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        self.session.close()

    def begin(self):
        return _SqlTransaction(self.session.begin())

    async def execute(self, statement):
        return self.session.execute(statement)

    async def commit(self):
        self.session.commit()

    async def rollback(self):
        self.session.rollback()

    async def delete(self, obj):
        self.session.delete(obj)

    async def refresh(self, obj):
        self.session.refresh(obj)

    async def get(self, model, object_id, **_kwargs):
        return self.session.get(model, object_id)

    def add(self, obj):
        self.session.add(obj)


class _SqlTransaction:
    def __init__(self, transaction):
        self.transaction = transaction

    async def __aenter__(self):
        self.transaction.__enter__()

    async def __aexit__(self, *args):
        self.transaction.__exit__(*args)


@pytest.fixture
def deletion_store(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all(
            [
                WaygateServer(
                    id="server-1",
                    project_id="project-1",
                    name="gateway",
                    status="ACTIVE",
                    agent_token_encrypted="old-token",
                    agent_token_next_encrypted="next-token",
                ),
                WaygateServer(id="server-2", project_id="project-2", name="other", status="ACTIVE"),
                WaygateClient(
                    id="client-1",
                    server_id="server-1",
                    project_id="project-1",
                    name="laptop",
                    enabled=True,
                    public_key="public",
                    private_key_encrypted="private-ciphertext",
                    preshared_key_encrypted="psk-ciphertext",
                    tunnel_ip="10.8.0.2",
                ),
                WaygateNetworkAttachment(
                    server_id="server-1", project_id="project-1", network_id="net-1", port_id="port-1", status="ACTIVE"
                ),
            ]
        )
        session.commit()
    monkeypatch.setattr(waygate_db, "get_session_factory", lambda: lambda: _SqlSession(engine))
    monkeypatch.setattr(waygate_jobs, "get_session_factory", lambda: lambda: _SqlSession(engine))
    monkeypatch.setattr(execution, "get_session_factory", lambda: lambda: _SqlSession(engine))
    yield engine
    engine.dispose()


async def test_server_defaults_patch_is_scoped_atomic_and_preserves_legacy_clients(deletion_store):
    with Session(deletion_store) as session:
        original = session.get(WaygateClient, "client-1")
        original.dns = "8.8.8.8"
        original.mtu = 1300
        original.persistent_keepalive = 15
        session.commit()

    assert await waygate_db.update_server_defaults("project-2", "server-1", {"dns": "1.1.1.1"}) is None
    updated = await waygate_db.update_server_defaults(
        "project-1", "server-1", {"dns": "9.9.9.9", "persistent_keepalive": 0}
    )
    assert (updated["dns"], updated["persistent_keepalive"]) == ("9.9.9.9", 0)
    assert (await waygate_db.get_server("project-1", "server-1"))["persistent_keepalive"] == 0
    await waygate_db.update_server_defaults("project-1", "server-1", {"dns": None})
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        client = session.get(WaygateClient, "client-1")
        assert (server.dns, server.persistent_keepalive) == (None, 0)
        assert (client.dns, client.mtu, client.persistent_keepalive) == ("8.8.8.8", 1300, 15)
        assert (client.inherit_dns, client.inherit_persistent_keepalive) == (False, False)
    with Session(deletion_store) as session:
        session.get(WaygateServer, "server-1").status = "PROVISIONING"
        session.commit()
    with pytest.raises(waygate_db.WaygateServerInactiveError):
        await waygate_db.update_server_defaults("project-1", "server-1", {"dns": "4.4.4.4"})
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        assert server.dns is None
        server.status = "ACTIVE"
        session.commit()

    assert await _enqueue_delete(deletion_store)
    with pytest.raises(waygate_db.WaygateServerInactiveError):
        await waygate_db.update_server_defaults("project-1", "server-1", {"dns": "4.4.4.4"})
    with Session(deletion_store) as session:
        assert session.get(WaygateServer, "server-1").dns is None


async def test_client_inheritance_hydrates_values_without_snapshot_or_cross_project_reads(deletion_store):
    await waygate_db.update_server_defaults(
        "project-1",
        "server-1",
        {
            "dns": "9.9.9.9",
            "persistent_keepalive": 45,
        },
    )
    base = {"public_key": "pub", "private_key_encrypted": "ciphertext"}
    await waygate_db.create_client_record(
        "server-1",
        "project-1",
        "inherited",
        {
            **base,
            "name": "inherited",
            "tunnel_ip": "10.8.0.3",
        },
    )
    await waygate_db.create_client_record(
        "server-1",
        "project-1",
        "explicit",
        {
            **base,
            "name": "explicit",
            "tunnel_ip": "10.8.0.4",
            "dns": None,
            "mtu": None,
            "persistent_keepalive": 0,
        },
    )
    inherited = await waygate_db.get_client("server-1", "project-1", "inherited")
    explicit = await waygate_db.get_client("server-1", "project-1", "explicit")
    assert (inherited["dns"], inherited["mtu"], inherited["persistent_keepalive"]) == (
        "9.9.9.9",
        None,
        45,
    )
    assert (inherited["inherit_dns"], inherited["inherit_persistent_keepalive"]) == (True, True)
    assert (explicit["dns"], explicit["persistent_keepalive"]) == (None, 0)
    with Session(deletion_store) as session:
        stored = session.get(WaygateClient, "inherited")
        assert (stored.dns, stored.persistent_keepalive) == (None, 25)

    await waygate_db.update_server_defaults(
        "project-1",
        "server-1",
        {
            "dns": "1.1.1.1",
            "persistent_keepalive": 65,
        },
    )
    assert (await waygate_db.get_client("server-1", "project-1", "inherited"))["dns"] == "1.1.1.1"
    assert (await waygate_db.get_client("server-1", "project-1", "explicit"))["persistent_keepalive"] == 0
    assert {c["name"]: c["dns"] for c in await waygate_db.list_clients("server-1", "project-1")} == {
        "laptop": None,
        "inherited": "1.1.1.1",
        "explicit": None,
    }
    assert await waygate_db.list_clients("server-1", "project-2") == []
    assert await waygate_db.get_client("server-1", "project-2", "inherited") is None
    transitioned = await waygate_db.update_client("server-1", "project-1", "explicit", inherit_dns=True)
    assert (transitioned["dns"], transitioned["inherit_dns"]) == ("1.1.1.1", True)
    with Session(deletion_store) as session:
        assert session.get(WaygateClient, "explicit").dns is None


async def test_client_http_create_list_patch_and_config_resolve_current_defaults(deletion_store, monkeypatch):
    from waygate.api import clients as client_api

    monkeypatch.setattr(client_api, "is_db_available", lambda: True)
    monkeypatch.setattr("waygate.crypto.get_settings", lambda: SimpleNamespace(waygate_encryption_key="a" * 64))
    monkeypatch.setattr(client_api.waygate_agent_auth, "get_status_result", AsyncMock(return_value=None))
    monkeypatch.setattr(client_api, "validate_client_owner", AsyncMock())
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        server.server_public_key = "A" * 43 + "="
        server.endpoint_ip = "203.0.113.10"
        server.dns = "9.9.9.9"
        server.persistent_keepalive = 40
        session.commit()

    async def token():
        return {
            "project_id": "project-1", "user_id": "user-1",
            "roles": ["member", "waygate-inventory_reader", "waygate-connect_user", "waygate-clients_editor", "waygate-clients_admin", "waygate-gateways_editor", "waygate-gateways_admin"], "is_system_admin": False,
        }

    app.dependency_overrides[require_token] = token
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            inherited = await client.post("/v1/servers/server-1/clients", json={"name": "inherited"})
            explicit = await client.post(
                "/v1/servers/server-1/clients",
                json={
                    "name": "explicit",
                    "dns": None,
                    "persistent_keepalive": 0,
                    "mtu": 1380,
                },
            )
            assert inherited.status_code == explicit.status_code == 201
            assert (inherited.json()["inherit_dns"], inherited.json()["inherit_persistent_keepalive"]) == (True, True)
            assert (explicit.json()["inherit_dns"], explicit.json()["inherit_persistent_keepalive"]) == (False, False)
            assert "DNS = 9.9.9.9" in inherited.json()["tunnel_conf"]
            assert "PersistentKeepalive = 40" in inherited.json()["tunnel_conf"]
            assert "DNS =" not in explicit.json()["tunnel_conf"]
            assert "MTU = 1380" in explicit.json()["tunnel_conf"]

            await waygate_db.update_server_defaults(
                "project-1",
                "server-1",
                {
                    "dns": "1.1.1.1",
                    "persistent_keepalive": 55,
                },
            )
            listed = await client.get("/v1/servers/server-1/clients")
            rows = {row["name"]: row for row in listed.json()}
            assert (rows["inherited"]["dns"], rows["inherited"]["persistent_keepalive"]) == ("1.1.1.1", 55)
            assert (rows["explicit"]["dns"], rows["explicit"]["persistent_keepalive"]) == (None, 0)
            conf = await client.get(f"/v1/servers/server-1/clients/{inherited.json()['id']}/config")
            assert "DNS = 1.1.1.1" in conf.text and "PersistentKeepalive = 55" in conf.text
            assert "DNS = 9.9.9.9" not in conf.text
            assert "PrivateKey =" in conf.text and "PresharedKey =" in conf.text
            assert conf.text != inherited.json()["tunnel_conf"]
            from waygate.services import k3s_crypto, waygate_migration

            bundle = await waygate_migration.export_bundle(
                "project-1", await waygate_db.get_server("project-1", "server-1"), "pw-abcdefgh", caller_user_id="user-1",
            )
            entries = {entry["name"]: entry for entry in bundle["clients"]}
            assert (entries["inherited"]["dns"], entries["inherited"]["persistent_keepalive"]) == ("1.1.1.1", 55)
            assert (entries["explicit"]["dns"], entries["explicit"]["persistent_keepalive"]) == (None, 0)
            with Session(deletion_store) as session:
                session.add(
                    WaygateServer(
                        id="server-import",
                        project_id="project-1",
                        name="import",
                        status="ACTIVE",
                        dns="8.8.8.8",
                        persistent_keepalive=12,
                    )
                )
                session.commit()
            imported = await waygate_migration.import_bundle(
                "project-1", await waygate_db.get_server("project-1", "server-import"), bundle, "pw-abcdefgh"
            )
            assert imported["imported"] == 2
            restored = {row["name"]: row for row in await waygate_db.list_clients("server-import", "project-1")}
            assert (restored["inherited"]["dns"], restored["inherited"]["persistent_keepalive"]) == ("1.1.1.1", 55)
            assert (restored["inherited"]["inherit_dns"], restored["inherited"]["inherit_persistent_keepalive"]) == (
                False,
                False,
            )
            source = await waygate_db.get_client("server-1", "project-1", inherited.json()["id"])
            assert k3s_crypto.decrypt_wg_client_key(restored["inherited"]["private_key_encrypted"]) == (
                k3s_crypto.decrypt_wg_client_key(source["private_key_encrypted"])
            )
            assert k3s_crypto.decrypt_wg_client_key(restored["inherited"]["preshared_key_encrypted"]) == (
                k3s_crypto.decrypt_wg_client_key(source["preshared_key_encrypted"])
            )

            patched = await client.patch(
                f"/v1/servers/server-1/clients/{explicit.json()['id']}",
                json={
                    "inherit_dns": True,
                    "inherit_persistent_keepalive": True,
                },
            )
            assert patched.status_code == 200
            assert (patched.json()["dns"], patched.json()["persistent_keepalive"]) == ("1.1.1.1", 55)
            await waygate_db.update_server_defaults(
                "project-1",
                "server-1",
                {
                    "dns": None,
                    "persistent_keepalive": 0,
                },
            )
            after = await client.get(f"/v1/servers/server-1/clients/{explicit.json()['id']}/config")
            assert "DNS =" not in after.text and "PersistentKeepalive = 0" in after.text
            override = await client.patch(
                f"/v1/servers/server-1/clients/{inherited.json()['id']}",
                json={
                    "persistent_keepalive": 7,
                },
            )
            assert (override.json()["inherit_dns"], override.json()["inherit_persistent_keepalive"]) == (
                True,
                False,
            )
            await waygate_db.update_server_defaults(
                "project-1",
                "server-1",
                {
                    "dns": "8.8.4.4",
                    "persistent_keepalive": 33,
                },
            )
            final = await client.get(f"/v1/servers/server-1/clients/{inherited.json()['id']}/config")
            assert "DNS = 8.8.4.4" in final.text and "PersistentKeepalive = 7" in final.text
    finally:
        app.dependency_overrides.pop(require_token, None)


async def test_server_defaults_http_owner_validation_and_readback(deletion_store, monkeypatch):
    monkeypatch.setattr(server_api, "is_db_available", lambda: True)
    monkeypatch.setattr(server_api.waygate_agent_auth, "get_status_result", AsyncMock(return_value=None))

    async def request_as(project_id):
        async def token():
            return {
                "project_id": project_id, "roles": ["member", "waygate-inventory_reader", "waygate-gateways_editor"], "is_system_admin": False,
            }

        app.dependency_overrides[require_token] = token
        return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")

    try:
        async with await request_as("project-2") as client:
            assert (await client.patch("/v1/servers/server-1", json={"dns": "9.9.9.9"})).status_code == 404
            assert (await client.get("/v1/servers/server-1")).status_code == 404
        async with await request_as("project-1") as client:
            for bad in (
                {"dns": "8.8.8.8\\n[Peer]"},
                {"mtu": 575},
                {"mtu": True},
                {"persistent_keepalive": None},
                {"persistent_keepalive": -1},
                {"persistent_keepalive": True},
                {"bogus": 1},
            ):
                assert (await client.patch("/v1/servers/server-1", json=bad)).status_code == 422
            response = await client.patch(
                "/v1/servers/server-1",
                json={
                    "dns": " 9.9.9.9 , 1.1.1.1 ",
                    "persistent_keepalive": 0,
                },
            )
            assert response.status_code == 200
            assert (response.json()["dns"], response.json()["persistent_keepalive"]) == (
                "9.9.9.9, 1.1.1.1",
                0,
            )
            assert "mtu" not in response.json()
            assert (await client.get("/v1/servers/server-1")).json()["persistent_keepalive"] == 0
            listed = await client.get("/v1/servers")
            assert listed.status_code == 200
            assert listed.json()[0]["persistent_keepalive"] == 0
            cleared = await client.patch("/v1/servers/server-1", json={"dns": None})
            assert cleared.json()["dns"] is None
            assert cleared.json()["persistent_keepalive"] == 0
            await _enqueue_delete(deletion_store)
            assert (await client.patch("/v1/servers/server-1", json={"dns": "4.4.4.4"})).status_code == 409
    finally:
        app.dependency_overrides.pop(require_token, None)


async def test_server_create_rejects_invalid_default_values(monkeypatch):
    monkeypatch.setattr(server_api, "is_db_available", lambda: True)

    async def token():
        return {
            "project_id": "project-1", "roles": ["member", "waygate-inventory_reader", "waygate-gateways_editor", "waygate-gateways_admin"], "is_system_admin": False,
        }

    app.dependency_overrides[require_token] = token
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            for bad in (
                {"dns": "a,b,c"},
                {"dns": "invalid\\n[Peer]"},
                {"mtu": 9001},
                {"mtu": False},
                {"persistent_keepalive": None},
                {"persistent_keepalive": 65536},
                {"server_public_key": "unauthorized"},
            ):
                response = await client.post("/v1/servers", json={"name": "gateway", **bad})
                assert response.status_code == 422
    finally:
        app.dependency_overrides.pop(require_token, None)


@pytest.mark.parametrize("transition", ["ownership_changed", "deleted"])
async def test_client_delete_rechecks_parent_authority_after_stale_lookup(deletion_store, transition):
    with Session(deletion_store) as session:
        parent = session.get(WaygateServer, "server-1")
        if transition == "ownership_changed":
            parent.project_id = "project-2"
        else:
            parent.status = "DELETED"
            parent.deleted_at = datetime.now(UTC)
        session.commit()

    assert not await waygate_db.soft_delete_client("server-1", "project-1", "client-1", "stale-owner")
    with Session(deletion_store) as session:
        child = session.get(WaygateClient, "client-1")
        assert child.deleted_at is None
        assert child.enabled is True
        assert (child.name, child.tunnel_ip) == ("laptop", "10.8.0.2")
        assert (child.private_key_encrypted, child.preshared_key_encrypted) == (
            "private-ciphertext",
            "psk-ciphertext",
        )


async def test_terminal_delete_removes_child_access_and_preserves_ownership(deletion_store):
    with Session(deletion_store) as session:
        att = session.scalar(select(WaygateNetworkAttachment).where(WaygateNetworkAttachment.server_id == "server-1"))
        att.port_id = None  # Cloud cleanup has completed before DB finalization.
        att.status = "DELETED"
        session.commit()

    assert await waygate_db.soft_delete_server("project-2", "server-1", "intruder") is False
    assert await waygate_db.soft_delete_server("project-1", "server-1", "user-1", "사용자 요청") is True
    assert await waygate_db.soft_delete_server("project-1", "server-1", "user-1", "사용자 요청") is True
    assert await waygate_db.get_server("project-1", "server-1") is None
    assert await waygate_db.get_server_deletion_state("project-1", "server-1") == ("DELETED", True)
    assert await waygate_db.get_server_deletion_state("project-2", "server-1") is None
    assert await waygate_db.update_client("server-1", "project-1", "client-1", enabled=True) is None
    await waygate_db.update_server_status("server-1", "DELETING", "late worker")
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        client = session.get(WaygateClient, "client-1")
        assert (server.status, server.status_reason, server.deleted_reason) == ("DELETED", "사용자 요청", "사용자 요청")
        assert server.deleted_by_user_id == "user-1" and server.agent_token_encrypted is None
        assert server.agent_token_next_encrypted is None
        assert (client.deleted_by_user_id, client.enabled, client.name, client.tunnel_ip) == (
            "user-1",
            False,
            None,
            None,
        )
        assert client.private_key_encrypted == "" and client.preshared_key_encrypted is None
        assert (
            session.scalars(
                select(WaygateNetworkAttachment).where(WaygateNetworkAttachment.server_id == "server-1")
            ).all()
            == []
        )
        assert session.get(WaygateServer, "server-2").status == "ACTIVE"


async def test_deleting_server_blocks_new_children_and_unfinished_port_finalization(deletion_store):
    assert await _enqueue_delete(deletion_store)
    with pytest.raises(waygate_db.WaygateClientConflictError):
        await waygate_db.create_client_record(
            "server-1",
            "project-1",
            "new-client",
            {"name": "new", "public_key": "pub", "private_key_encrypted": "secret", "tunnel_ip": "10.8.0.3"},
        )
    with pytest.raises(RuntimeError, match="no longer active"):
        await waygate_db.create_attachment_record("server-1", "project-1", {"network_id": "net-2"})
    with pytest.raises(RuntimeError, match="attachment cleanup"):
        await waygate_db.soft_delete_server("project-1", "server-1", "user-1")
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        assert server.deleted_at is None and server.status == "DELETING"
        assert session.get(WaygateClient, "client-1").deleted_at is None
        assert session.scalars(select(WaygateNetworkAttachment)).all()[0].port_id == "port-1"


async def test_raced_attachment_request_returns_conflict_without_allocating_port(deletion_store, monkeypatch):
    stale_server = await waygate_db.get_server("project-1", "server-1")
    stale_server["server_vm_id"] = "vm-1"
    assert await _enqueue_delete(deletion_store)
    conn = SimpleNamespace(
        network=SimpleNamespace(
            get_network=MagicMock(return_value=SimpleNamespace(project_id="project-1")),
            get_subnet=MagicMock(return_value=SimpleNamespace(network_id="net-2", id="sub-2", cidr="10.9.0.0/24")),
        ),
        close=MagicMock(),
    )
    create_port = MagicMock()
    monkeypatch.setattr(waygate_network.neutron, "create_port", create_port)

    with pytest.raises(WaygateNetworkError) as exc:
        await waygate_network.attach_network("project-1", stale_server, "net-2", "sub-2", "snat", conn=conn)
    assert exc.value.status_code == 409
    create_port.assert_not_called()
    with Session(deletion_store) as session:
        assert len(session.scalars(select(WaygateNetworkAttachment)).all()) == 1


async def test_inflight_attachment_cannot_be_terminalized_before_port_assignment(deletion_store):
    with Session(deletion_store) as session:
        att = session.scalar(select(WaygateNetworkAttachment).where(WaygateNetworkAttachment.server_id == "server-1"))
        att.status = "CREATING"
        att.port_id = None
        session.commit()

    assert await _enqueue_delete(deletion_store)
    with pytest.raises(RuntimeError, match="attachment cleanup"):
        await waygate_db.soft_delete_server("project-1", "server-1", "user-1")
    with Session(deletion_store) as session:
        assert session.get(WaygateServer, "server-1").deleted_at is None
        assert session.scalar(select(WaygateNetworkAttachment)).status == "CREATING"


async def test_cloud_delete_waits_for_inflight_attachment(deletion_store, monkeypatch):
    with Session(deletion_store) as session:
        att = session.scalar(select(WaygateNetworkAttachment))
        att.status = "CREATING"
        att.port_id = None
        session.commit()
    conn = SimpleNamespace(close=MagicMock())
    delete_port = MagicMock()
    monkeypatch.setattr(waygate_provisioner.neutron, "delete_port", delete_port)

    with pytest.raises(RuntimeError, match="creation is still in progress"):
        await waygate_provisioner.delete_waygate_server("project-1", "server-1", "user-1", conn=conn)
    delete_port.assert_not_called()
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        assert server.deleted_at is None and server.status == "ERROR"
        assert session.scalar(select(WaygateNetworkAttachment)).status == "CREATING"


@pytest.mark.parametrize("failure", ["vm_timeout", "attachment_port"])
async def test_delete_job_retries_cloud_failure_before_terminal_cleanup(deletion_store, monkeypatch, failure):
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        server.server_vm_id = "vm-1"
        server.provider_port_id = "provider-port"
        server.fip_id = "fip-1"
        session.commit()

    conn = SimpleNamespace(network=SimpleNamespace(delete_ip=MagicMock()), close=MagicMock())
    ports = []
    fail_port_once = failure == "attachment_port"

    def delete_port(_conn, port_id):
        nonlocal fail_port_once
        ports.append(port_id)
        if port_id == "port-1" and fail_port_once:
            fail_port_once = False
            raise RuntimeError("port busy")

    wait = MagicMock(side_effect=[TimeoutError("VM deletion timed out"), None] if failure == "vm_timeout" else None)
    _delegate(monkeypatch, conn)
    monkeypatch.setattr(waygate_provisioner.neutron, "cleanup_instance_fips", MagicMock())
    monkeypatch.setattr(waygate_provisioner.neutron, "delete_port", delete_port)
    monkeypatch.setattr(waygate_provisioner.nova, "delete_server", MagicMock())
    monkeypatch.setattr(waygate_provisioner.nova, "wait_server_deleted", wait)
    monkeypatch.setattr(waygate_provisioner.waygate_agent_auth, "revoke_report_token_by_server", AsyncMock())

    assert await _enqueue_delete(deletion_store)
    assert await waygate_jobs.process_one_job() is True
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        job = session.scalar(select(WaygateJob).where(WaygateJob.server_id == "server-1"))
        assert server.deleted_at is None and server.status == "ERROR"
        assert job.status == "queued" and job.last_error
        assert session.get(WaygateClient, "client-1").deleted_at is None
        assert (
            session.scalar(
                select(WaygateNetworkAttachment).where(WaygateNetworkAttachment.server_id == "server-1")
            ).port_id
            == "port-1"
        )

    assert await waygate_jobs.process_one_job() is True
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        job = session.scalar(select(WaygateJob).where(WaygateJob.server_id == "server-1"))
        assert server.status == "DELETED" and server.deleted_at is not None
        assert job.status == "completed" and job.last_error is None
        assert session.get(WaygateClient, "client-1").deleted_at is not None
        assert (
            session.scalars(
                select(WaygateNetworkAttachment).where(WaygateNetworkAttachment.server_id == "server-1")
            ).all()
            == []
        )
    assert ports[-2:] == ["port-1", "provider-port"]
    if failure == "vm_timeout":
        assert len(ports) == 2
    else:
        assert ports == ["port-1", "port-1", "provider-port"]
    assert conn.network.delete_ip.call_count == (1 if failure == "vm_timeout" else 2)


@pytest.mark.parametrize("failure", ["ports", "floating_ips", "delete_ip"])
async def test_discovered_floating_ip_remains_retryable_until_removed(deletion_store, monkeypatch, failure):
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        server.server_vm_id = "vm-1"
        session.commit()

    floating_ips = {
        "attached": SimpleNamespace(id="attached", port_id="port-1"),
        "foreign": SimpleNamespace(id="foreign", port_id="other-port"),
    }
    failed = False

    def maybe_fail(operation):
        nonlocal failed
        if operation == failure and not failed:
            failed = True
            raise RuntimeError("Neutron unavailable")

    def ports(**_kwargs):
        maybe_fail("ports")
        return [SimpleNamespace(id="port-1")]

    def ips():
        maybe_fail("floating_ips")
        return list(floating_ips.values())

    def delete_ip(ip_id, **_kwargs):
        maybe_fail("delete_ip")
        floating_ips.pop(ip_id, None)

    def update_ip(ip_id, *, port_id):
        floating_ips[ip_id].port_id = port_id

    conn = SimpleNamespace(
        network=SimpleNamespace(
            ports=ports,
            ips=ips,
            delete_ip=delete_ip,
            update_ip=update_ip,
        ),
        close=MagicMock(),
    )
    delete_vm = MagicMock()
    _delegate(monkeypatch, conn)
    monkeypatch.setattr(waygate_provisioner.neutron, "delete_port", MagicMock())
    monkeypatch.setattr(waygate_provisioner.nova, "delete_server", delete_vm)
    monkeypatch.setattr(waygate_provisioner.nova, "wait_server_deleted", MagicMock())
    monkeypatch.setattr(waygate_provisioner.waygate_agent_auth, "revoke_report_token_by_server", AsyncMock())

    await _enqueue_delete(deletion_store)
    await waygate_jobs.process_one_job()
    assert floating_ips["attached"].port_id == "port-1"
    delete_vm.assert_not_called()
    with Session(deletion_store) as session:
        assert session.get(WaygateServer, "server-1").deleted_at is None
        assert session.scalar(select(WaygateJob)).status == "queued"

    await waygate_jobs.process_one_job()
    assert set(floating_ips) == {"foreign"}
    with Session(deletion_store) as session:
        assert session.get(WaygateServer, "server-1").status == "DELETED"
        assert session.scalar(select(WaygateJob)).status == "completed"


async def test_detach_preserves_an_attachment_still_being_created(deletion_store, monkeypatch):
    with Session(deletion_store) as session:
        attachment = session.scalar(select(WaygateNetworkAttachment))
        attachment.status = "CREATING"
        attachment.port_id = None
        attachment_id = attachment.id
        session.commit()
    server = await waygate_db.get_server("project-1", "server-1")

    with pytest.raises(WaygateNetworkError) as exc:
        await waygate_network.detach_network("project-1", server, attachment_id, conn=SimpleNamespace())
    assert exc.value.status_code == 409
    with Session(deletion_store) as session:
        assert session.get(WaygateNetworkAttachment, attachment_id).status == "CREATING"


@pytest.mark.parametrize("status,attempts", [("queued", 0), ("queued", 2), ("running", 3)])
async def test_delete_supersedes_unstarted_or_expired_provision(deletion_store, monkeypatch, status, attempts):
    now = datetime.now(UTC)
    monkeypatch.setattr(waygate_jobs, "_now", lambda: now)
    with Session(deletion_store) as session:
        session.get(WaygateServer, "server-1").status = "ERROR" if attempts else "CREATING"
        session.add(WaygateJob(
            id="provision", server_id="server-1", project_id="project-1", kind="provision",
            status=status, attempts=attempts, claimed_at=now - timedelta(seconds=901) if attempts else None,
            created_at=now - timedelta(seconds=10),
        ))
        session.commit()
    await _enqueue_delete(deletion_store)

    claimed = await waygate_jobs._claim_one()
    assert claimed[1:5] == (1, "delete", "project-1", "server-1")
    with Session(deletion_store) as session:
        provision = session.get(WaygateJob, "provision")
        assert (provision.status, provision.attempts, provision.claimed_at) == ("failed", attempts, None)
        assert session.get(WaygateServer, "server-1").status == "DELETING"


async def test_final_provision_failure_does_not_overwrite_pending_deletion(deletion_store):
    with Session(deletion_store) as session:
        session.add(WaygateJob(
            id="provision", server_id="server-1", project_id="project-1", kind="provision",
            status="running", attempts=3, claimed_at=datetime.now(UTC),
        ))
        session.commit()
    await _enqueue_delete(deletion_store)

    assert await waygate_jobs._retry_or_fail("provision", attempt=3, error="cloud unavailable") is True
    with Session(deletion_store) as session:
        assert session.get(WaygateJob, "provision").status == "failed"
        assert session.get(WaygateServer, "server-1").status == "DELETING"
    assert (await waygate_jobs._claim_one())[2] == "delete"


@pytest.mark.parametrize("kind,terminal_status,expected", [
    ("delete", "DELETED", "completed"),
    ("delete", "DELETING", "failed"),
    ("provision", "DELETED", "failed"),
])
@pytest.mark.parametrize("attempts", [1, 3])
async def test_claim_reconciles_tombstone_before_retry_limit(
    deletion_store, monkeypatch, kind, terminal_status, expected, attempts
):
    now = datetime.now(UTC)
    monkeypatch.setattr(waygate_jobs, "_now", lambda: now)
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-2")
        server.status = terminal_status
        server.deleted_at = now
        session.add(WaygateJob(
            id="interrupted", server_id="server-2", project_id="project-2", kind=kind,
            status="running", attempts=attempts, claimed_at=now - timedelta(seconds=901),
            last_error="previous transient failure",
        ))
        session.commit()

    assert await waygate_jobs._claim_one() is None
    with Session(deletion_store) as session:
        job = session.get(WaygateJob, "interrupted")
        assert (job.status, job.attempts, job.claimed_at) == (expected, attempts, None)
        assert (job.last_error is None) == (expected == "completed")
        assert session.get(WaygateServer, "server-2").status == terminal_status


async def test_worker_recovers_poll_error_and_preserves_cancelled_job_lease(deletion_store, monkeypatch):
    from waygate import worker

    now = datetime.now(UTC)
    monkeypatch.setattr(waygate_jobs, "_now", lambda: now)
    await _enqueue_delete(deletion_store, "project-2", "server-2")
    process = waygate_jobs.process_one_job
    polls = 0

    async def recover_poll():
        nonlocal polls
        polls += 1
        if polls == 1:
            raise RuntimeError("database connection unavailable")
        return await process()

    async def cancelled_delete(*_args, **_kwargs):
        raise asyncio.CancelledError

    pauses = []
    sleep = asyncio.sleep

    async def pause(seconds):
        pauses.append(seconds)
        await sleep(0)

    close = AsyncMock()
    monkeypatch.setattr(worker, "get_settings", lambda: SimpleNamespace(
        database_url="sqlite://", database_pool_size=1, database_max_overflow=0,
        database_connect_timeout=1, database_pool_timeout=1,
    ))
    monkeypatch.setattr(worker, "require_public_callback_base_url", lambda _settings: None)
    monkeypatch.setattr(worker, "init_db", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(worker, "close_db", close)
    monkeypatch.setattr(worker, "process_one_job", recover_poll)
    monkeypatch.setattr(worker.asyncio, "sleep", pause)
    monkeypatch.setattr(waygate_jobs, "delete_waygate_server", cancelled_delete)
    _delegate(monkeypatch, SimpleNamespace())

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(worker.serve(), timeout=1)
    assert polls == 2 and pauses == [0.5]
    close.assert_awaited_once()
    with Session(deletion_store) as session:
        job = session.scalar(select(WaygateJob))
        assert (job.status, job.attempts, job.last_error) == ("running", 1, None)
        assert session.get(WaygateServer, "server-2").deleted_at is None

    monkeypatch.setattr(waygate_jobs, "_now", lambda: now + timedelta(seconds=901))
    assert (await waygate_jobs._claim_one())[1:5] == (2, "delete", "project-2", "server-2")


async def test_completion_write_failure_does_not_fail_successful_last_delete(deletion_store, monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(waygate_jobs, "_now", lambda: now)
    grant_id = _grant(deletion_store, "project-2", "server-2", "delete")
    with Session(deletion_store) as session:
        session.add(WaygateJob(
            id="last-delete", server_id="server-2", project_id="project-2", kind="delete",
            status="queued", attempts=2, execution_grant_id=grant_id, user_id="user-1",
        ))
        session.commit()

    async def finalize(project, server, user, *, conn):
        await waygate_db.soft_delete_server(project, server, user)

    async def fail_completion(*_args, **_kwargs):
        raise RuntimeError("completion write unavailable")

    monkeypatch.setattr(waygate_jobs, "delete_waygate_server", finalize)
    _delegate(monkeypatch, SimpleNamespace())
    monkeypatch.setattr(waygate_jobs, "_complete", fail_completion)

    with pytest.raises(RuntimeError, match="completion write unavailable"):
        await waygate_jobs.process_one_job()
    with Session(deletion_store) as session:
        job = session.get(WaygateJob, "last-delete")
        assert (job.status, job.attempts, job.last_error) == ("running", 3, None)
        assert session.get(WaygateServer, "server-2").status == "DELETED"

    monkeypatch.setattr(waygate_jobs, "_now", lambda: now + timedelta(seconds=901))
    assert await waygate_jobs._claim_one() is None
    with Session(deletion_store) as session:
        job = session.get(WaygateJob, "last-delete")
        assert (job.status, job.attempts, job.claimed_at, job.last_error) == ("completed", 3, None, None)


@pytest.fixture
def lifecycle_polling(monkeypatch):
    path = Path(__file__).with_name("test_live_waygate_lifecycle.py")
    spec = importlib.util.spec_from_file_location("isolated_lifecycle_polling", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    clock = SimpleNamespace(now=0.0)

    async def advance(seconds):
        clock.now += seconds

    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock.now))
    monkeypatch.setattr(module.asyncio, "sleep", advance)
    return module


@pytest.mark.parametrize("expected,statuses", [
    ("ACTIVE", ["ERROR", "PROVISIONING", "ACTIVE"]),
    ("DELETED", ["ERROR", "DELETING", None]),
])
async def test_lifecycle_wait_allows_worker_retry_status(lifecycle_polling, expected, statuses):
    responses = iter(statuses)

    def respond(request):
        status = next(responses)
        return Response(404 if status is None else 200, json={"status": status}, request=request)

    async with AsyncClient(transport=MockTransport(respond), base_url="http://gateway.test") as client:
        result = await lifecycle_polling._wait_for_server(
            client, "server", expected_status=expected, timeout_seconds=15
        )
    assert result["status"] == expected


async def test_lifecycle_wait_still_fails_at_deadline_for_persistent_error(lifecycle_polling):
    transport = MockTransport(lambda request: Response(200, json={"status": "ERROR"}, request=request))
    async with AsyncClient(transport=transport, base_url="http://gateway.test") as client:
        with pytest.raises(pytest.fail.Exception, match="timed out waiting"):
            await lifecycle_polling._wait_for_server(
                client, "server", expected_status="DELETED", timeout_seconds=10
            )


@pytest.mark.parametrize("status", ["PROVISIONING", "ACTIVE"])
@pytest.mark.parametrize("attempts", [1, 3])
async def test_successful_provision_lease_reconciles_without_replacing_gateway(
    deletion_store, monkeypatch, status, attempts
):
    now = datetime.now(UTC)
    monkeypatch.setattr(waygate_jobs, "_now", lambda: now)
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        server.status = status
        server.server_vm_id = "existing-vm"
        server.endpoint_ip = "192.0.2.10"
        session.add(WaygateJob(
            id="successful-provision", server_id="server-1", project_id="project-1", kind="provision",
            status="running", attempts=attempts, claimed_at=now - timedelta(seconds=901),
        ))
        session.commit()
    provision = AsyncMock(side_effect=AssertionError("successful gateway must not be provisioned again"))
    monkeypatch.setattr(waygate_jobs, "provision_waygate_server", provision)

    assert await waygate_jobs.process_one_job() is False
    provision.assert_not_awaited()
    with Session(deletion_store) as session:
        job = session.get(WaygateJob, "successful-provision")
        server = session.get(WaygateServer, "server-1")
        assert (job.status, job.attempts, job.claimed_at, job.last_error) == ("completed", attempts, None, None)
        assert (server.status, server.server_vm_id, server.endpoint_ip) == (status, "existing-vm", "192.0.2.10")
        assert (server.agent_token_encrypted, server.agent_token_next_encrypted) == ("old-token", "next-token")


async def test_pending_delete_takes_precedence_over_successful_provision_reconciliation(deletion_store, monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(waygate_jobs, "_now", lambda: now)
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        server.server_vm_id = "existing-vm"
        server.endpoint_ip = "192.0.2.10"
        session.add(WaygateJob(
            id="successful-provision", server_id="server-1", project_id="project-1", kind="provision",
            status="running", attempts=3, claimed_at=now - timedelta(seconds=901),
        ))
        session.commit()
    await _enqueue_delete(deletion_store)

    assert (await waygate_jobs._claim_one())[2] == "delete"
    with Session(deletion_store) as session:
        assert session.get(WaygateJob, "successful-provision").status == "failed"
        server = session.get(WaygateServer, "server-1")
        assert (server.status, server.server_vm_id, server.endpoint_ip) == ("DELETING", "existing-vm", "192.0.2.10")


async def test_worker_job_success_and_failed_retry_logs_only_safe_stage_metadata(deletion_store, monkeypatch, caplog):
    import logging

    claims = iter([
        ("job-1", 1, "provision", "project-1", "server-1", None, None, "grant-1"),
        ("job-2", 3, "provision", "project-2", "server-2", None, None, "grant-2"),
    ])

    async def claim():
        return next(claims)

    async def provision(_project, server_id, *_identity, conn):
        if server_id == "server-2":
            raise RuntimeError("private-secret raw SQL values")

    async def complete(_job_id, *, attempt):
        return True

    async def retry(_job_id, *, attempt, error, terminal):
        assert terminal is False
        assert attempt == 3
        assert error == "private-secret raw SQL values"
        return True

    @contextlib.asynccontextmanager
    async def connection(grant_id, *_scope):
        assert grant_id in {"grant-1", "grant-2"}
        yield SimpleNamespace()

    monkeypatch.setattr(execution, "execution_connection", connection)
    monkeypatch.setattr(waygate_jobs, "_claim_one", claim)
    monkeypatch.setattr(waygate_jobs, "provision_waygate_server", provision)
    monkeypatch.setattr(waygate_jobs, "_complete", complete)
    monkeypatch.setattr(waygate_jobs, "_retry_or_fail", retry)
    with caplog.at_level(logging.DEBUG, logger="waygate.services.jobs"):
        assert await waygate_jobs.process_one_job()
        assert await waygate_jobs.process_one_job()
    messages = " ".join(record.getMessage() for record in caplog.records if record.name == "waygate.services.jobs")
    assert "stage=finish kind=provision attempt=1 status=completed" in messages
    assert "stage=finish kind=provision attempt=3 status=failed" in messages
    assert "query=claim result=found" in messages
    assert "private-secret" not in messages
    assert "server-1" not in messages
