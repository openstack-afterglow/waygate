"""Durable Waygate provision/delete queue contracts."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import mysql

from waygate.api import servers as server_api
from waygate.models.orm import WaygateJob, WaygateServer
from waygate.models.schemas import WaygateServerCreateRequest
from waygate.services import waygate_jobs

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


async def test_delete_job_completes_after_soft_delete(monkeypatch):
    completed = []

    async def claim():
        return "job-1", 1, "delete", "project-1", "server-1", "user-1", "alice"

    async def delete(*args):
        assert args == ("project-1", "server-1", "user-1")

    async def get_server(_project_id, _server_id):
        return None

    async def complete(job_id, *, attempt):
        completed.append((job_id, attempt))
        return True

    monkeypatch.setattr(waygate_jobs, "_claim_one", claim)
    monkeypatch.setattr(waygate_jobs, "delete_waygate_server", delete)
    monkeypatch.setattr(waygate_jobs.waygate_db, "get_server", get_server)
    monkeypatch.setattr(waygate_jobs, "_complete", complete)

    assert await waygate_jobs.process_one_job() is True
    assert completed == [("job-1", 1)]


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
        lambda: SimpleNamespace(waygate_default_listen_port=51820, waygate_default_tunnel_cidr="10.8.0.0/24"),
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
    assert calls[0][3] == {"user_id": "user-1", "username": "alice"}
