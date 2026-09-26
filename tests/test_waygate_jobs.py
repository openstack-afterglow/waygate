"""Durable Waygate provision/delete queue contracts."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Session

from waygate.api import servers as server_api
from waygate.db import Base
from waygate.models.orm import WaygateClient, WaygateJob, WaygateNetworkAttachment, WaygateServer
from waygate.models.schemas import WaygateServerCreateRequest
from waygate.services import network as waygate_network
from waygate.services import provisioner as waygate_provisioner
from waygate.services import waygate_db, waygate_jobs
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


async def test_enqueue_provision_commits_server_and_job_in_one_transaction(monkeypatch):
    session = _Session()
    monkeypatch.setattr(waygate_jobs, "get_session_factory", lambda: _factory(session))

    job_id = await waygate_jobs.enqueue_provision_job(
        "project-1",
        "server-1",
        {"name": "gateway-1", "status": "CREATING", "listen_port": 51820, "tunnel_cidr": "10.8.0.0/24"},
        user_id="user-1",
        username="alice",
    )

    assert isinstance(session.added[0], WaygateServer)
    assert isinstance(session.added[1], WaygateJob)
    assert session.added[0].id == "server-1"
    assert session.added[1].id == job_id
    assert session.added[1].kind == "provision"
    assert session.added[1].status == "queued"


async def test_enqueue_delete_marks_server_and_avoids_duplicate_active_job(monkeypatch):
    server = SimpleNamespace(status="ACTIVE", status_reason=None, updated_at=None)
    session = _Session(execute_values=[server, "existing-job"])
    monkeypatch.setattr(waygate_jobs, "get_session_factory", lambda: _factory(session))

    found = await waygate_jobs.enqueue_delete_job(
        "project-1",
        "server-1",
        user_id="user-1",
        username="alice",
    )

    assert found is True
    assert server.status == "DELETING"
    assert server.status_reason == "삭제 작업 대기 중"
    assert session.added == []


async def test_claim_reclaims_work_with_transactional_skip_locked(monkeypatch):
    job = SimpleNamespace(
        id="job-1",
        attempts=1,
        kind="delete",
        project_id="project-1",
        server_id="server-1",
        user_id="user-1",
        username="alice",
        status="running",
        claimed_at=None,
        updated_at=None,
        last_error="worker exited",
    )
    session = _Session(
        execute_values=[job, None],
        objects={(WaygateServer, "server-1"): SimpleNamespace()},
    )
    monkeypatch.setattr(waygate_jobs, "get_session_factory", lambda: _factory(session))

    claimed = await waygate_jobs._claim_one()

    assert claimed == ("job-1", 2, "delete", "project-1", "server-1", "user-1", "alice")
    assert job.status == "running"
    assert job.attempts == 2
    assert job.claimed_at is not None
    sql = str(session.statements[0].compile(dialect=mysql.dialect())).upper()
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "WAYGATE_JOBS.CLAIMED_AT" in sql


async def test_immediate_delete_waits_while_provision_job_runs(monkeypatch):
    delete_job = SimpleNamespace(
        id="delete-job",
        attempts=0,
        kind="delete",
        project_id="project-1",
        server_id="server-1",
        user_id="user-1",
        username="alice",
        status="queued",
        claimed_at=None,
        updated_at=None,
        last_error=None,
    )
    session = _Session(
        execute_values=[delete_job, "provision-job"],
        objects={(WaygateServer, "server-1"): SimpleNamespace()},
    )
    monkeypatch.setattr(waygate_jobs, "get_session_factory", lambda: _factory(session))

    assert await waygate_jobs._claim_one() is None
    assert delete_job.status == "queued"
    assert delete_job.attempts == 0
    candidate_sql = str(session.statements[0].compile(dialect=mysql.dialect())).upper()
    assert "NOT (EXISTS" in candidate_sql
    assert "WAYGATE_JOBS_1.STATUS" in candidate_sql


async def test_old_worker_cannot_complete_reclaimed_attempt(monkeypatch):
    job = SimpleNamespace(status="running", attempts=2, claimed_at=object(), last_error=None, updated_at=None)
    session = _Session(objects={(WaygateJob, "job-1"): job})
    monkeypatch.setattr(waygate_jobs, "get_session_factory", lambda: _factory(session))

    assert await waygate_jobs._complete("job-1", attempt=1) is False
    assert job.status == "running"


async def test_third_failure_terminalizes_job_and_server(monkeypatch):
    job = SimpleNamespace(
        id="job-1",
        server_id="server-1",
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


async def test_provision_job_completes_only_after_server_progresses(monkeypatch):
    completed = []
    retried = []

    async def claim():
        return "job-1", 1, "provision", "project-1", "server-1", "user-1", "alice"

    async def provision(*args):
        assert args == ("project-1", "server-1", "user-1", "alice")

    async def get_server(_server_id):
        return {"status": "PROVISIONING", "status_reason": None}

    async def complete(job_id, *, attempt):
        completed.append((job_id, attempt))
        return True

    async def retry(*args, **kwargs):
        retried.append((args, kwargs))
        return True

    monkeypatch.setattr(waygate_jobs, "_claim_one", claim)
    monkeypatch.setattr(waygate_jobs, "provision_waygate_server", provision)
    monkeypatch.setattr(waygate_jobs.waygate_db, "get_server_by_id", get_server)
    monkeypatch.setattr(waygate_jobs, "_complete", complete)
    monkeypatch.setattr(waygate_jobs, "_retry_or_fail", retry)

    assert await waygate_jobs.process_one_job() is True
    assert completed == [("job-1", 1)]
    assert retried == []



async def test_failed_provision_is_requeued(monkeypatch):
    retried = []

    async def claim():
        return "job-1", 2, "provision", "project-1", "server-1", "user-1", "alice"

    async def update(*_args, **_kwargs):
        return None

    async def provision(*_args):
        return None

    async def get_server(_server_id):
        return {"status": "ERROR", "status_reason": "quota exceeded"}

    async def retry(job_id, *, attempt, error):
        retried.append((job_id, attempt, error))
        return True

    monkeypatch.setattr(waygate_jobs, "_claim_one", claim)
    monkeypatch.setattr(waygate_jobs.waygate_db, "update_server_status", update)
    monkeypatch.setattr(waygate_jobs, "provision_waygate_server", provision)
    monkeypatch.setattr(waygate_jobs.waygate_db, "get_server_by_id", get_server)
    monkeypatch.setattr(waygate_jobs, "_retry_or_fail", retry)

    assert await waygate_jobs.process_one_job() is True
    assert retried == [("job-1", 2, "quota exceeded")]


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
    monkeypatch.setattr("waygate.auth.get_admin_connection_for_project", lambda _project_id: conn)
    monkeypatch.setattr("waygate.services.resource_policies.resolve_policy_snapshot", resolve_policy_snapshot)
    monkeypatch.setattr("waygate.services.resource_policies.get_policy_snapshot", get_policy_snapshot)
    monkeypatch.setattr(server_api.waygate_jobs, "enqueue_provision_job", enqueue)
    monkeypatch.setattr(server_api.waygate_db, "get_server", get_server)
    monkeypatch.setattr(server_api.waygate_agent_auth, "get_status_result", no_status)

    response = await server_api.create_waygate_server(
        WaygateServerCreateRequest(name="gateway-1"),
        {"project_id": "project-1", "user_id": "user-1", "username": "alice"},
    )

    assert response.status == "CREATING"
    assert calls[0][2]["flavor_id"] == "flavor-1"
    assert calls[0][2]["agent_install_mode"] == "prebuilt"
    assert calls[0][3] == {"user_id": "user-1", "username": "alice"}


async def test_merge_status_exposes_agent_source_and_install_mode(monkeypatch):
    async def status(_server_id):
        return {"peers": [], "_stored_at": "2026-01-01T00:00:00+00:00", "agent_source": "prebuilt"}

    monkeypatch.setattr(server_api.waygate_agent_auth, "get_status_result", status)
    info = await server_api._merge_status({
        "id": "server-1", "project_id": "project-1", "name": "gateway-1", "status": "ACTIVE",
        "listen_port": 51820, "tunnel_cidr": "10.8.0.0/24", "agent_install_mode": "prebuilt",
    })
    assert info.agent_install_mode == "prebuilt"
    assert info.agent_source == "prebuilt"


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
        session.add_all([
            WaygateServer(id="server-1", project_id="project-1", name="gateway", status="ACTIVE",
                          agent_token_encrypted="old-token", agent_token_next_encrypted="next-token"),
            WaygateServer(id="server-2", project_id="project-2", name="other", status="ACTIVE"),
            WaygateClient(id="client-1", server_id="server-1", project_id="project-1", name="laptop",
                          enabled=True, public_key="public", private_key_encrypted="private-ciphertext",
                          preshared_key_encrypted="psk-ciphertext", tunnel_ip="10.8.0.2"),
            WaygateNetworkAttachment(server_id="server-1", project_id="project-1", network_id="net-1",
                                     port_id="port-1", status="ACTIVE"),
        ])
        session.commit()
    monkeypatch.setattr(waygate_db, "get_session_factory", lambda: lambda: _SqlSession(engine))
    monkeypatch.setattr(waygate_jobs, "get_session_factory", lambda: lambda: _SqlSession(engine))
    yield engine
    engine.dispose()


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
        assert (client.deleted_by_user_id, client.enabled, client.name, client.tunnel_ip) == ("user-1", False, None, None)
        assert client.private_key_encrypted == "" and client.preshared_key_encrypted is None
        assert session.scalars(select(WaygateNetworkAttachment).where(WaygateNetworkAttachment.server_id == "server-1")).all() == []
        assert session.get(WaygateServer, "server-2").status == "ACTIVE"


async def test_deleting_server_blocks_new_children_and_unfinished_port_finalization(deletion_store):
    assert await waygate_jobs.enqueue_delete_job("project-1", "server-1", user_id="user-1", username="alice")
    with pytest.raises(waygate_db.WaygateClientConflictError):
        await waygate_db.create_client_record("server-1", "project-1", "new-client", {
            "name": "new", "public_key": "pub", "private_key_encrypted": "secret", "tunnel_ip": "10.8.0.3"
        })
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
    assert await waygate_jobs.enqueue_delete_job("project-1", "server-1", user_id="user-1", username="alice")
    conn = SimpleNamespace(network=SimpleNamespace(
        get_network=MagicMock(return_value=SimpleNamespace(project_id="project-1")),
        get_subnet=MagicMock(return_value=SimpleNamespace(network_id="net-2", id="sub-2", cidr="10.9.0.0/24")),
    ), close=MagicMock())
    create_port = MagicMock()
    monkeypatch.setattr("waygate.services.keystone.get_admin_connection_for_project", lambda _project: conn)
    monkeypatch.setattr(waygate_network.neutron, "create_port", create_port)

    with pytest.raises(WaygateNetworkError) as exc:
        await waygate_network.attach_network("project-1", stale_server, "net-2", "sub-2", "snat")
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

    assert await waygate_jobs.enqueue_delete_job("project-1", "server-1", user_id="user-1", username="alice")
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
    monkeypatch.setattr("waygate.services.keystone.get_admin_connection_for_project", lambda _project: conn)
    monkeypatch.setattr(waygate_provisioner.neutron, "delete_port", delete_port)

    with pytest.raises(RuntimeError, match="creation is still in progress"):
        await waygate_provisioner.delete_waygate_server("project-1", "server-1", "user-1")
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
    monkeypatch.setattr("waygate.services.keystone.get_admin_connection_for_project", lambda _project: conn)
    monkeypatch.setattr(waygate_provisioner.neutron, "cleanup_instance_fips", MagicMock())
    monkeypatch.setattr(waygate_provisioner.neutron, "delete_port", delete_port)
    monkeypatch.setattr(waygate_provisioner.nova, "delete_server", MagicMock())
    monkeypatch.setattr(waygate_provisioner.nova, "wait_server_deleted", wait)
    monkeypatch.setattr(waygate_provisioner.waygate_agent_auth, "revoke_report_token_by_server", AsyncMock())

    assert await waygate_jobs.enqueue_delete_job("project-1", "server-1", user_id="user-1", username="alice")
    assert await waygate_jobs.process_one_job() is True
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        job = session.scalar(select(WaygateJob).where(WaygateJob.server_id == "server-1"))
        assert server.deleted_at is None and server.status == "ERROR"
        assert job.status == "queued" and job.last_error
        assert session.get(WaygateClient, "client-1").deleted_at is None
        assert session.scalar(select(WaygateNetworkAttachment).where(
            WaygateNetworkAttachment.server_id == "server-1"
        )).port_id == "port-1"

    assert await waygate_jobs.process_one_job() is True
    with Session(deletion_store) as session:
        server = session.get(WaygateServer, "server-1")
        job = session.scalar(select(WaygateJob).where(WaygateJob.server_id == "server-1"))
        assert server.status == "DELETED" and server.deleted_at is not None
        assert job.status == "completed" and job.last_error is None
        assert session.get(WaygateClient, "client-1").deleted_at is not None
        assert session.scalars(select(WaygateNetworkAttachment).where(
            WaygateNetworkAttachment.server_id == "server-1"
        )).all() == []
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

    conn = SimpleNamespace(network=SimpleNamespace(
        ports=ports, ips=ips, delete_ip=delete_ip, update_ip=update_ip,
    ), close=MagicMock())
    delete_vm = MagicMock()
    monkeypatch.setattr("waygate.services.keystone.get_admin_connection_for_project", lambda _project: conn)
    monkeypatch.setattr(waygate_provisioner.neutron, "delete_port", MagicMock())
    monkeypatch.setattr(waygate_provisioner.nova, "delete_server", delete_vm)
    monkeypatch.setattr(waygate_provisioner.nova, "wait_server_deleted", MagicMock())
    monkeypatch.setattr(waygate_provisioner.waygate_agent_auth, "revoke_report_token_by_server", AsyncMock())

    await waygate_jobs.enqueue_delete_job("project-1", "server-1", user_id="user-1", username="alice")
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
    monkeypatch.setattr("waygate.services.keystone.get_admin_connection_for_project", lambda _project: SimpleNamespace(close=lambda: None))

    with pytest.raises(WaygateNetworkError) as exc:
        await waygate_network.detach_network("project-1", server, attachment_id)
    assert exc.value.status_code == 409
    with Session(deletion_store) as session:
        assert session.get(WaygateNetworkAttachment, attachment_id).status == "CREATING"
