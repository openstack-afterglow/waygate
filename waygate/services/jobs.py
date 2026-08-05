"""Durable Waygate provision/delete queue.

The database is authoritative. Workers claim one row transactionally with
``FOR UPDATE SKIP LOCKED`` and may reclaim a lease after 15 minutes.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import exists, or_, select
from sqlalchemy.orm import aliased

from waygate.db import get_session_factory
from waygate.models.orm import WaygateJob, WaygateServer
from waygate.services import waygate_db
from waygate.services.provisioner import delete_waygate_server, provision_waygate_server

_logger = logging.getLogger(__name__)
_LEASE_SECONDS = 900
_MAX_ATTEMPTS = 3


def _now() -> datetime:
    return datetime.now(UTC)


def _new_job(
    *,
    server_id: str,
    project_id: str,
    kind: str,
    user_id: str | None,
    username: str | None,
) -> WaygateJob:
    if kind not in {"provision", "delete"}:
        raise ValueError(f"unsupported Waygate job kind: {kind}")
    return WaygateJob(
        id=str(uuid.uuid4()),
        server_id=server_id,
        project_id=project_id,
        kind=kind,
        status="queued",
        user_id=user_id or None,
        username=username or None,
    )


async def enqueue_provision_job(
    project_id: str,
    server_id: str,
    server_data: dict,
    *,
    user_id: str | None,
    username: str | None,
) -> str:
    """Create the server and its provision job in one transaction."""
    factory = get_session_factory()
    if factory is None:
        raise RuntimeError("Waygate database is unavailable")
    async with factory() as session, session.begin():
        waygate_db.add_server_record(session, project_id, server_id, server_data)
        job = _new_job(
            server_id=server_id,
            project_id=project_id,
            kind="provision",
            user_id=user_id,
            username=username,
        )
        session.add(job)
        return job.id


async def enqueue_delete_job(
    project_id: str,
    server_id: str,
    *,
    user_id: str | None,
    username: str | None,
) -> bool:
    """Mark a caller-owned server deleting and enqueue exactly one active job."""
    factory = get_session_factory()
    if factory is None:
        raise RuntimeError("Waygate database is unavailable")
    async with factory() as session, session.begin():
        server = (
            await session.execute(
                select(WaygateServer)
                .where(
                    WaygateServer.id == server_id,
                    WaygateServer.project_id == project_id,
                    WaygateServer.deleted_at.is_(None),
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if server is None:
            return False

        existing = (
            await session.execute(
                select(WaygateJob.id)
                .where(
                    WaygateJob.server_id == server_id,
                    WaygateJob.project_id == project_id,
                    WaygateJob.kind == "delete",
                    WaygateJob.status.in_(("queued", "running")),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        server.status = "DELETING"
        server.status_reason = "삭제 작업 대기 중"
        server.updated_at = _now()
        if existing is None:
            session.add(
                _new_job(
                    server_id=server_id,
                    project_id=project_id,
                    kind="delete",
                    user_id=user_id,
                    username=username,
                )
            )
        return True


async def _mark_server_failed(session, job: WaygateJob, error: str) -> None:
    server = await session.get(WaygateServer, job.server_id, with_for_update=True)
    if server is not None and server.deleted_at is None:
        server.status = "ERROR"
        server.status_reason = error
        server.updated_at = _now()


async def _claim_one() -> tuple[str, int, str, str, str, str | None, str | None] | None:
    factory = get_session_factory()
    if factory is None:
        raise RuntimeError("Waygate database is unavailable")
    now = _now()
    stale_before = now - timedelta(seconds=_LEASE_SECONDS)
    active_job = aliased(WaygateJob)
    async with factory() as session, session.begin():
        while True:
            job = (
                await session.execute(
                    select(WaygateJob)
                    .where(
                        or_(
                            WaygateJob.status == "queued",
                            (WaygateJob.status == "running")
                            & (WaygateJob.claimed_at.is_not(None))
                            & (WaygateJob.claimed_at < stale_before),
                        ),
                        ~exists(
                            select(active_job.id).where(
                                active_job.server_id == WaygateJob.server_id,
                                active_job.status == "running",
                                active_job.claimed_at.is_not(None),
                                active_job.claimed_at >= stale_before,
                            )
                        ),
                    )
                    .order_by(WaygateJob.created_at)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
            ).scalar_one_or_none()
            if job is None:
                return None
            server = await session.get(WaygateServer, job.server_id, with_for_update=True)
            if server is None:
                job.status = "failed"
                job.last_error = "Waygate server not found"
                job.claimed_at = None
                job.updated_at = now
                continue
            active_other = (
                await session.execute(
                    select(WaygateJob.id)
                    .where(
                        WaygateJob.server_id == job.server_id,
                        WaygateJob.id != job.id,
                        WaygateJob.status == "running",
                        WaygateJob.claimed_at.is_not(None),
                        WaygateJob.claimed_at >= stale_before,
                    )
                    .limit(1)
                )
            ).scalar_one_or_none()
            if active_other is not None:
                return None
            if job.attempts >= _MAX_ATTEMPTS:
                error = job.last_error or "Waygate job retry limit exceeded"
                job.status = "failed"
                job.last_error = error
                job.claimed_at = None
                job.updated_at = now
                await _mark_server_failed(session, job, error)
                continue
            job.status = "running"
            job.claimed_at = now
            job.attempts += 1
            job.updated_at = now
            return (
                job.id,
                job.attempts,
                job.kind,
                job.project_id,
                job.server_id,
                job.user_id,
                job.username,
            )


async def _complete(job_id: str, *, attempt: int) -> bool:
    factory = get_session_factory()
    if factory is None:
        raise RuntimeError("Waygate database is unavailable")
    async with factory() as session, session.begin():
        job = await session.get(WaygateJob, job_id, with_for_update=True)
        if job is None or job.status != "running" or job.attempts != attempt:
            return False
        job.status = "completed"
        job.claimed_at = None
        job.last_error = None
        job.updated_at = _now()
        return True


async def _retry_or_fail(job_id: str, *, attempt: int, error: str) -> bool:
    factory = get_session_factory()
    if factory is None:
        raise RuntimeError("Waygate database is unavailable")
    clean_error = (error.strip() or "Waygate job failed")[:4096]
    async with factory() as session, session.begin():
        job = await session.get(WaygateJob, job_id, with_for_update=True)
        if job is None or job.status != "running" or job.attempts != attempt:
            return False
        job.last_error = clean_error
        job.claimed_at = None
        job.updated_at = _now()
        if job.attempts >= _MAX_ATTEMPTS:
            job.status = "failed"
            await _mark_server_failed(session, job, clean_error)
        else:
            job.status = "queued"
        return True


async def process_one_job() -> bool:
    """Claim and process at most one durable Waygate job."""
    claimed = await _claim_one()
    if claimed is None:
        return False
    job_id, attempt, kind, project_id, server_id, user_id, username = claimed
    try:
        if kind == "provision":
            if attempt > 1:
                await waygate_db.update_server_status(server_id, "CREATING", "프로비저닝 재시도 중")
            await provision_waygate_server(project_id, server_id, user_id or "", username or "")
            server = await waygate_db.get_server_by_id(server_id)
            if server is None:
                raise RuntimeError("Waygate server disappeared during provisioning")
            if server["status"] not in {"PROVISIONING", "ACTIVE"}:
                raise RuntimeError(server.get("status_reason") or f"unexpected server status: {server['status']}")
        elif kind == "delete":
            if attempt > 1:
                await waygate_db.update_server_status(server_id, "DELETING", "삭제 재시도 중")
            await delete_waygate_server(project_id, server_id, user_id or "")
            server = await waygate_db.get_server(project_id, server_id)
            if server is not None:
                raise RuntimeError(server.get("status_reason") or f"unexpected server status: {server['status']}")
        else:
            raise RuntimeError(f"unsupported Waygate job kind: {kind}")
        await _complete(job_id, attempt=attempt)
    except Exception as exc:
        _logger.exception("Waygate job failed job_id=%s kind=%s attempt=%d", job_id, kind, attempt)
        await _retry_or_fail(job_id, attempt=attempt, error=str(exc))
    return True
