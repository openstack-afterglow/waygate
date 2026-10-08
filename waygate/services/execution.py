"""Operation-owned Keystone delegation, current authority and durable cleanup."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from keystoneauth1 import session as ks_session
from keystoneauth1.exceptions.http import Forbidden, NotFound, Unauthorized
from keystoneauth1.identity import v3
from keystoneclient.v3 import client as ks_client
from sqlalchemy import exists, or_, select

from waygate import auth
from waygate.config import get_settings
from waygate.db import get_session_factory
from waygate.models.orm import WaygateExecutionGrant, WaygateJob

_logger = logging.getLogger(__name__)
_TRUST_LIFETIME = timedelta(hours=2)
_CLEANUP_INTERVAL = timedelta(seconds=30)
_CAPABILITIES = {
    "provision": "waygate-gateways_editor",
    "delete": "waygate-gateways_admin",
    "attach": "waygate-routing_admin",
    "detach": "waygate-routing_admin",
}


class ExecutionDenied(PermissionError):
    """The actor or delegation no longer authorizes this operation."""


class ExecutionUnavailable(RuntimeError):
    """The current execution authority cannot be verified."""


@dataclass(frozen=True)
class ExecutionGrant:
    id: str
    project_id: str
    server_id: str
    user_id: str
    purpose: str
    capability: str
    expires_at: datetime
    trust_id: str | None = None
    trustee_user_id: str | None = None
    role_id: str | None = None


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _expiry(value) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise ExecutionDenied("Delegation expiry is unavailable")
    return _utc(value)


def _factory():
    factory = get_session_factory()
    if factory is None:
        raise ExecutionUnavailable("Waygate database is unavailable")
    return factory


def _close_session(session) -> None:
    session.session.close()


def _current_authority(client, grant: ExecutionGrant) -> str:
    if datetime.now(UTC) >= grant.expires_at:
        raise ExecutionDenied("Waygate execution delegation expired")
    try:
        user = client.users.get(grant.user_id)
        project = client.projects.get(grant.project_id)
    except NotFound:
        raise ExecutionDenied("Waygate execution actor or project was removed") from None
    except Exception as exc:
        raise ExecutionUnavailable("Waygate execution directory is unavailable") from exc
    if user.id != grant.user_id or getattr(user, "enabled", None) is not True:
        raise ExecutionDenied("Waygate execution actor is not enabled")
    if project.id != grant.project_id or getattr(project, "enabled", None) is not True:
        raise ExecutionDenied("Waygate execution project is not enabled")
    try:
        info = {
            "user_id": grant.user_id,
            "project_id": grant.project_id,
            "roles": auth._current_project_roles(grant.user_id, grant.project_id, client),
            "is_system_admin": auth._is_system_admin(grant.user_id, client),
        }
    except auth.AuthorityRejected:
        raise ExecutionDenied("Waygate execution role graph was rejected") from None
    except Exception as exc:
        raise ExecutionUnavailable("Waygate execution role graph is unavailable") from exc
    if "member" not in info["roles"] or not auth.has_capability(info, grant.capability):
        raise ExecutionDenied("Current Waygate execution capability is required")
    roles = [
        role
        for role in client.roles.list(name="member")
        if role.name == "member" and not getattr(role, "domain_id", None)
    ]
    if len(roles) != 1 or (grant.role_id is not None and roles[0].id != grant.role_id):
        raise ExecutionDenied("Waygate execution role is ambiguous or changed")
    return roles[0].id


def _validate_trust(trust, grant: ExecutionGrant) -> None:
    data = trust.to_dict()
    roles = data.get("roles")
    if (
        data.get("id") != grant.trust_id
        or data.get("project_id") != grant.project_id
        or data.get("trustor_user_id") != grant.user_id
        or data.get("trustee_user_id") != grant.trustee_user_id
        or data.get("impersonation") is not True
        or not isinstance(roles, list)
        or {role.get("id") for role in roles} != {grant.role_id}
        or _expiry(data.get("expires_at")) != grant.expires_at
        or datetime.now(UTC) >= grant.expires_at
    ):
        raise ExecutionDenied("Waygate execution delegation scope does not match")


def _validate_access(access, grant: ExecutionGrant) -> None:
    if (
        access.trust_id != grant.trust_id
        or access.trustor_user_id != grant.user_id
        or access.trustee_user_id != grant.trustee_user_id
        or access.user_id != grant.user_id
        or access.project_id != grant.project_id
        or grant.role_id not in access.role_ids
        or not set(access.role_names) <= {"member", "reader"}
        or not access.expires
        or _utc(access.expires) > grant.expires_at
        or _utc(access.expires) <= datetime.now(UTC)
    ):
        raise ExecutionDenied("Waygate execution token scope does not match")


def _verify_current(grant: ExecutionGrant) -> None:
    client = None
    try:
        client = auth._get_admin_ks_client()
        try:
            service_access = client.session.auth.get_access(client.session)
        except Exception as exc:
            raise ExecutionUnavailable("Waygate service-project identity is unavailable") from exc
        if service_access.trust_scoped or service_access.user_id != grant.trustee_user_id:
            raise ExecutionDenied("Waygate execution trustee changed")
        _current_authority(client, grant)
        _validate_trust(client.trusts.get(grant.trust_id), grant)
    except (ExecutionDenied, auth.AuthorityRejected):
        raise ExecutionDenied("Waygate execution authority was revoked or rejected") from None
    except (Forbidden, Unauthorized, NotFound):
        raise ExecutionDenied("Waygate execution delegation is not authorized") from None
    except Exception as exc:
        raise ExecutionUnavailable("Waygate execution authority is unavailable") from exc
    finally:
        if client is not None:
            _close_session(client.session)


class _TrustPassword(v3.Password):
    def __init__(self, grant: ExecutionGrant):
        settings = get_settings()
        super().__init__(
            auth_url=settings.os_auth_url,
            user_id=grant.trustee_user_id,
            password=settings.os_password,
            trust_id=grant.trust_id,
        )
        self.grant = grant

    def get_auth_ref(self, session):
        access = super().get_auth_ref(session)
        _validate_access(access, self.grant)
        return access


class _ExecutionSession(ks_session.Session):
    def __init__(self, grant: ExecutionGrant):
        settings = get_settings()
        super().__init__(auth=_TrustPassword(grant), timeout=30, verify=settings.ssl_verify)
        self.grant = grant

    def request(self, url, method, **kwargs):
        # This also fences cached tokens and authentication/discovery requests.
        _verify_current(self.grant)
        return super().request(url, method, **kwargs)


def _create_trust(token: str, grant: ExecutionGrant) -> ExecutionGrant:
    settings = get_settings()
    directory = auth._get_admin_ks_client()
    caller_session = ks_session.Session(
        auth=v3.Token(auth_url=settings.os_auth_url, token=token, project_id=grant.project_id),
        timeout=30,
        verify=settings.ssl_verify,
    )
    trust = None
    caller = ks_client.Client(session=caller_session)
    try:
        role_id = _current_authority(directory, grant)
        trustee_access = directory.session.auth.get_access(directory.session)
        if trustee_access.trust_scoped or not trustee_access.user_id or not trustee_access.project_id:
            raise ExecutionDenied("A service-project trustee identity is required")
        caller_access = caller_session.auth.get_access(caller_session)
        if (
            caller_access.user_id != grant.user_id
            or caller_access.project_id != grant.project_id
            or caller_access.trust_scoped
            or caller_access.application_credential_id
        ):
            raise ExecutionDenied("An original project-scoped user token is required for delegation")
        grant = replace(grant, trustee_user_id=trustee_access.user_id, role_id=role_id)
        trust = caller.trusts.create(
            trustee_user=grant.trustee_user_id,
            trustor_user=grant.user_id,
            role_ids=[role_id],
            project=grant.project_id,
            impersonation=True,
            expires_at=grant.expires_at,
        )
        grant = replace(grant, trust_id=trust.id)
        _validate_trust(trust, grant)
        return grant
    except Exception:
        if trust is not None:
            try:
                caller.trusts.delete(trust.id)
            except Exception as exc:
                _logger.warning("execution stage=admission_cleanup status=pending error_type=%s", type(exc).__name__)
        raise
    finally:
        _close_session(caller_session)
        _close_session(directory.session)


async def create_grant(token_info: dict, server_id: str, purpose: str) -> ExecutionGrant:
    if purpose not in _CAPABILITIES:
        raise ValueError("Unsupported Waygate execution purpose")
    if not all(token_info.get(key) for key in ("project_id", "user_id", "token")):
        raise ExecutionDenied("An authenticated project-scoped actor is required")
    grant = ExecutionGrant(
        id=str(uuid.uuid4()),
        project_id=token_info["project_id"],
        server_id=server_id,
        user_id=token_info["user_id"],
        purpose=purpose,
        capability=_CAPABILITIES[purpose],
        expires_at=(datetime.now(UTC) + _TRUST_LIFETIME).replace(microsecond=0),
    )
    async with _factory()() as session, session.begin():
        session.add(WaygateExecutionGrant(**grant.__dict__, status="admitting"))
    created = None
    try:
        created = await asyncio.to_thread(_create_trust, token_info["token"], grant)
        async with _factory()() as session, session.begin():
            row = await session.get(WaygateExecutionGrant, grant.id, with_for_update=True)
            if row is None or row.status != "admitting":
                raise ExecutionDenied("Waygate execution admission was abandoned")
            row.trust_id = created.trust_id
            row.trustee_user_id = created.trustee_user_id
            row.role_id = created.role_id
            row.status = "active"
            row.updated_at = datetime.now(UTC)
        return created
    except BaseException as exc:
        # A creation still in flight after cancellation is bounded by Trust expiry.
        if created is not None:
            try:
                await asyncio.shield(asyncio.to_thread(_revoke_trust, created.trust_id, created.trustee_user_id))
            except Exception as cleanup_exc:
                _logger.warning(
                    "execution stage=admission_cleanup status=pending error_type=%s", type(cleanup_exc).__name__
                )
                # Persist the reference even when the active-state write failed.
                async with _factory()() as session, session.begin():
                    row = await session.get(WaygateExecutionGrant, grant.id, with_for_update=True)
                    if row is not None:
                        row.trust_id = created.trust_id
                        row.trustee_user_id = created.trustee_user_id
                        row.role_id = created.role_id
        try:
            await asyncio.shield(retire_grant(grant.id))
        except Exception as cleanup_error:
            _logger.warning(
                "execution stage=admission_cleanup status=pending error_type=%s", type(cleanup_error).__name__
            )
        if isinstance(exc, (ExecutionDenied, auth.AuthorityRejected, Forbidden, Unauthorized)):
            raise ExecutionDenied("Waygate execution delegation is not authorized") from None
        if isinstance(exc, Exception):
            raise ExecutionUnavailable("Waygate execution admission is unavailable") from exc
        raise


async def load_grant(
    grant_id: str | None, project_id: str, server_id: str, user_id: str, purpose: str
) -> ExecutionGrant:
    if not grant_id:
        raise ExecutionDenied("This operation requires a newly admitted delegation")
    async with _factory()() as session:
        row = await session.get(WaygateExecutionGrant, grant_id)
        if (
            row is None
            or row.status != "active"
            or (row.project_id, row.server_id, row.user_id, row.purpose) != (project_id, server_id, user_id, purpose)
            or row.capability != _CAPABILITIES.get(purpose)
            or not all((row.trust_id, row.trustee_user_id, row.role_id))
            or _utc(row.expires_at) <= datetime.now(UTC)
        ):
            raise ExecutionDenied("Waygate execution delegation is expired or does not match")
        return ExecutionGrant(
            **{field: getattr(row, field) for field in ExecutionGrant.__dataclass_fields__ if field != "expires_at"},
            expires_at=_utc(row.expires_at),
        )


def _open_connection(grant: ExecutionGrant):
    from openstack import connection

    settings = get_settings()
    session = _ExecutionSession(grant)
    try:
        session.auth.get_access(session)
        # openstack.connect(session=...) ignores the session and loads config auth;
        # Connection(session=...) binds every proxy to this guarded Trust session.
        return connection.Connection(
            session=session,
            region_name=settings.os_region_name,
            interface=settings.os_interface,
            api_timeout=30,
        )
    except BaseException:
        _close_session(session)
        raise


def _close_connection(conn) -> None:
    try:
        conn.close()
    finally:
        _close_session(conn.session)


@contextlib.asynccontextmanager
async def execution_connection(grant_id: str | None, project_id: str, server_id: str, user_id: str, purpose: str):
    grant = await load_grant(grant_id, project_id, server_id, user_id, purpose)
    conn = await asyncio.to_thread(_open_connection, grant)
    try:
        yield conn
    finally:
        await asyncio.shield(asyncio.to_thread(_close_connection, conn))


@contextlib.asynccontextmanager
async def admitted_operation(token_info: dict, server_id: str, purpose: str):
    grant = None
    try:
        grant = await create_grant(token_info, server_id, purpose)
        async with execution_connection(
            grant.id, grant.project_id, grant.server_id, grant.user_id, grant.purpose
        ) as conn:
            yield grant, conn
    except (auth.AuthorityRejected, Forbidden, Unauthorized):
        raise ExecutionDenied("Waygate execution delegation is not authorized") from None
    finally:
        if grant is not None:
            await asyncio.shield(retire_unbound_grant(grant.id))


def _revoke_trust(trust_id: str | None, trustee_user_id: str | None) -> None:
    if not trust_id:
        return
    client = auth._get_admin_ks_client()
    try:
        access = client.session.auth.get_access(client.session)
        if access.trust_scoped or access.user_id != trustee_user_id:
            raise ExecutionDenied("Waygate execution trustee changed")
        try:
            client.trusts.delete(trust_id)
        except NotFound:
            pass
    finally:
        _close_session(client.session)


async def _cleanup_grant(grant_id: str) -> bool:
    async with _factory()() as session, session.begin():
        row = await session.get(WaygateExecutionGrant, grant_id, with_for_update=True)
        if row is None or row.status == "revoked":
            return False
        row.status = "cleanup_pending"
        row.updated_at = datetime.now(UTC)
        trust_id, trustee_user_id = row.trust_id, row.trustee_user_id
    try:
        await asyncio.to_thread(_revoke_trust, trust_id, trustee_user_id)
    except Exception as exc:
        _logger.warning("execution stage=cleanup status=pending error_type=%s", type(exc).__name__)
        return False
    async with _factory()() as session, session.begin():
        row = await session.get(WaygateExecutionGrant, grant_id, with_for_update=True)
        if row is not None:
            row.status = "revoked"
            row.updated_at = datetime.now(UTC)
    return True


async def retire_grant(grant_id: str) -> None:
    await _cleanup_grant(grant_id)


async def retire_unbound_grant(grant_id: str) -> None:
    async with _factory()() as session:
        bound = (
            await session.execute(select(WaygateJob.id).where(WaygateJob.execution_grant_id == grant_id).limit(1))
        ).scalar_one_or_none()
    if bound is None:
        await retire_grant(grant_id)


async def cleanup_one_grant() -> bool:
    now = datetime.now(UTC)
    terminal = exists(
        select(WaygateJob.id).where(
            WaygateJob.execution_grant_id == WaygateExecutionGrant.id,
            WaygateJob.status.in_(("completed", "failed")),
        )
    )
    async with _factory()() as session:
        grant_id = (
            await session.execute(
                select(WaygateExecutionGrant.id)
                .where(
                    or_(
                        (WaygateExecutionGrant.status == "cleanup_pending")
                        & (WaygateExecutionGrant.updated_at <= now - _CLEANUP_INTERVAL),
                        WaygateExecutionGrant.status.in_(("admitting", "active"))
                        & ((WaygateExecutionGrant.expires_at <= now) | terminal),
                    )
                )
                .order_by(WaygateExecutionGrant.updated_at)
                .limit(1)
            )
        ).scalar_one_or_none()
    return await _cleanup_grant(grant_id) if grant_id else False
