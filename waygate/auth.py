"""Keystone token validation and service-scoped OpenStack connections."""

from __future__ import annotations

import asyncio
import logging

from fastapi import Depends, Header, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from keystoneauth1 import session as ks_session
from keystoneauth1.identity import v3

from waygate.config import get_settings

_logger = logging.getLogger(__name__)

keystone_token_header = APIKeyHeader(
    name="X-Auth-Token",
    scheme_name="KeystoneToken",
    auto_error=False,
    description="Keystone authentication token",
)


def _get_admin_ks_client():
    from keystoneclient.v3 import client as ks_client

    settings = get_settings()
    auth = v3.Password(
        auth_url=settings.os_auth_url,
        username=settings.os_username,
        password=settings.os_password,
        project_name=settings.os_project_name,
        user_domain_name=settings.os_user_domain_name,
        project_domain_name=settings.os_project_domain_name,
    )
    session = ks_session.Session(auth=auth, timeout=15, verify=settings.ssl_verify)
    return ks_client.Client(session=session)


class AuthorityUnavailable(RuntimeError):
    """Keystone authority metadata could not be read or was malformed."""


class AuthorityRejected(ValueError):
    """The current role graph is readable but unsafe or ambiguous for authorization."""


def _resolve_admin_role_id(client) -> str | None:
    roles = client.roles.list(name="admin")
    global_roles = [role for role in roles if role.name == "admin" and not getattr(role, "domain_id", None)]
    return global_roles[0].id if len(global_roles) == 1 else None


def _is_system_admin(user_id: str, client=None) -> bool:
    """Fail closed unless the user has admin on Keystone system scope."""
    if not user_id:
        return False
    try:
        client = client or _get_admin_ks_client()
        role_id = _resolve_admin_role_id(client)
        if not role_id:
            return False
        assignments = client.role_assignments.list(
            user=user_id,
            role=role_id,
            system="all",
            effective=True,
        )
        return any(
            assignment.to_dict().get("scope", {}).get("system", {}).get("all") is True
            and assignment.to_dict().get("role", {}).get("id") == role_id
            and assignment.to_dict().get("user", {}).get("id") == user_id
            for assignment in assignments
        )
    except Exception:
        _logger.warning("Keystone system-admin check failed", exc_info=True)
        return False


def validate_token(token: str, project_id: str = "") -> dict:
    settings = get_settings()
    kwargs: dict = {"auth_url": settings.os_auth_url, "token": token}
    if project_id:
        kwargs["project_id"] = project_id
    auth_plugin = v3.Token(**kwargs)
    session = ks_session.Session(auth=auth_plugin, timeout=30, verify=settings.ssl_verify)
    access = auth_plugin.get_access(session)
    return {
        "token": access.auth_token,
        "project_id": access.project_id or "",
        "project_name": access.project_name or "",
        "user_id": access.user_id or "",
        "username": access.username or "",
        "expires_at": access.expires.isoformat() if access.expires else "",
    }


def resolve_authority(info: dict) -> dict:
    """Resolve current authority with one uncached service client; never reuse issuance-time token roles."""
    try:
        client = _get_admin_ks_client()
        roles = _current_project_roles(info["user_id"], info["project_id"], client)
    except AuthorityRejected:
        raise
    except Exception as exc:
        raise AuthorityUnavailable("Keystone authority unavailable") from exc
    return {**info, "roles": roles, "is_system_admin": _is_system_admin(info["user_id"], client)}


async def require_token(
    request: Request,
    x_auth_token: str | None = Security(keystone_token_header),
    x_project_id: str | None = Header(default=None, alias="X-Project-Id"),
) -> dict:
    if not x_auth_token:
        raise HTTPException(status_code=401, detail="X-Auth-Token header is required")
    try:
        info = await asyncio.to_thread(validate_token, x_auth_token, x_project_id or "")
    except Exception:
        _logger.info("Keystone token validation failed", exc_info=True)
        raise HTTPException(status_code=401, detail="Invalid or expired Keystone token") from None
    if not info.get("project_id"):
        raise HTTPException(status_code=401, detail="A project-scoped Keystone token is required")
    if x_project_id and info["project_id"] != x_project_id:
        raise HTTPException(status_code=403, detail="Token project does not match X-Project-Id")
    try:
        info = await asyncio.to_thread(resolve_authority, info)
    except AuthorityRejected:
        _logger.warning("Keystone role graph rejected for Waygate authorization", exc_info=True)
        raise HTTPException(status_code=403, detail="Waygate role graph is not authorized") from None
    except AuthorityUnavailable:
        _logger.warning("Keystone authority lookup failed", exc_info=True)
        raise HTTPException(status_code=503, detail="Waygate authorization is temporarily unavailable") from None
    request.state.token_info = info
    return info


def require_admin(token_info: dict = Depends(require_token)) -> dict:
    if token_info.get("is_system_admin") is not True:
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다")
    return token_info


_READER = frozenset({"waygate-inventory_reader"})
_CAPABILITIES = _READER | {
    "waygate-connect_user",
    "waygate-clients_editor",
    "waygate-gateways_editor",
    "waygate-clients_admin",
    "waygate-gateways_admin",
    "waygate-routing_admin",
}
_SERVICE_PARENTS = frozenset({"waygate_reader", "waygate_user", "waygate_editor", "waygate_admin"})
_PLATFORM_ROLE_NAMES = frozenset({"admin", "manager"})

# Safety ceilings validate a graph, never grant a missing implication. Leaves may depend on inventory
# but must not reach another use/write leaf; otherwise a fine-grained grant could become service admin.
_SAFE_READER = _READER | {"waygate_reader"}
_SAFE_USER = _SAFE_READER | {"waygate_user", "waygate-connect_user"}
_SAFE_EDITOR = _SAFE_USER | {"waygate_editor", "waygate-clients_editor", "waygate-gateways_editor"}
_SAFE_DESCENDANTS = {
    "waygate_reader": _SAFE_READER,
    "waygate_user": _SAFE_USER,
    "waygate_editor": _SAFE_EDITOR,
    "waygate_admin": _SERVICE_PARENTS | _CAPABILITIES,
    **{leaf: _SAFE_READER | {leaf} for leaf in _CAPABILITIES},
}


def _current_project_roles(user_id: str, project_id: str, client) -> list[str]:
    """Do not reconstruct missing parent implications or trust issuance-time token role names."""
    if not user_id or not project_id:
        return []
    catalog = [role.to_dict() for role in client.roles.list()]
    rows: dict[str, dict] = {}
    names: dict[str, list[str]] = {}
    for role in catalog:
        role_id, name = role.get("id"), role.get("name")
        if not isinstance(role_id, str) or not role_id or not isinstance(name, str) or not name or role_id in rows:
            raise ValueError("Malformed Keystone role catalog")
        rows[role_id] = role
        names.setdefault(name, []).append(role_id)
    graph = {role_id: set() for role_id in rows}
    for rule in client.inference_rules.list_inference_roles():
        data = rule.to_dict() if hasattr(rule, "to_dict") else rule
        prior = data.get("prior_role", {}).get("id")
        children = data.get("implies")
        if not isinstance(prior, str) or not prior or not isinstance(children, list):
            raise ValueError("Malformed Keystone role graph")
        # /roles without domain_id returns global roles, while /role_inferences also contains
        # unrelated domain-prior rules. They cannot bind builtin global authority and are ignored.
        if prior not in rows:
            continue
        for child in children:
            child_id = child.get("id")
            if child_id not in rows:
                raise ValueError("Unknown implied Keystone role")
            graph[prior].add(child_id)

    def closure(role_id: str, visiting: frozenset[str] = frozenset()) -> set[str]:
        if role_id in visiting:
            raise AuthorityRejected("Cyclic Keystone role graph")
        result = {role_id}
        for child in graph[role_id]:
            result.update(closure(child, visiting | {role_id}))
        return result

    effective_ids: set[str] = set()
    for assignment in client.role_assignments.list(user=user_id, project=project_id, effective=True):
        data = assignment.to_dict()
        if data.get("scope", {}).get("project", {}).get("id") != project_id:
            raise ValueError("Unexpected Keystone assignment scope")
        if data.get("user", {}).get("id") != user_id:
            raise ValueError("Unexpected Keystone assignment subject")
        role_id = data.get("role", {}).get("id")
        if role_id not in rows:
            raise AuthorityRejected("Assigned role is not a global Keystone authority")
        effective_ids.update(closure(role_id))
    service_roles = _SERVICE_PARENTS | _CAPABILITIES
    for role_id in effective_ids:
        role = rows[role_id]
        if role.get("domain_id") or len(names[role["name"]]) != 1:
            raise AuthorityRejected("Ambiguous or domain-specific Keystone authority")
        if role["name"] in service_roles:
            descendants = {rows[child]["name"] for child in closure(role_id)}
            if descendants - _SAFE_DESCENDANTS[role["name"]]:
                raise AuthorityRejected("Unsafe service role implication")
    return sorted(rows[role_id]["name"] for role_id in effective_ids)


def has_capability(token_info: dict, capability: str) -> bool:
    """Use only current effective roles resolved against Keystone's uncached global DAG."""
    if token_info.get("is_system_admin") is True:
        return True
    roles = set(token_info.get("roles") or [])
    if roles & _PLATFORM_ROLE_NAMES:
        return False
    base = {"member"} if capability not in _READER else {"member", "reader"}
    if not roles & base:
        return False
    return capability in _CAPABILITIES and capability in roles


def require_clients_update(token_info: dict = Depends(require_token)) -> dict:
    if not (has_capability(token_info, "waygate-clients_editor") or has_capability(token_info, "waygate-clients_admin")):
        raise HTTPException(status_code=403, detail="Waygate client administration capability required")
    return token_info


def _require_capabilities(*capabilities: str):
    def dependency(token_info: dict = Depends(require_token)) -> dict:
        if not all(has_capability(token_info, capability) for capability in capabilities):
            raise HTTPException(status_code=403, detail="Waygate service capability required")
        return token_info

    return dependency


require_inventory = _require_capabilities("waygate-inventory_reader")
require_connect = _require_capabilities("waygate-connect_user")
require_clients_editor = _require_capabilities("waygate-clients_editor")
require_clients_admin = _require_capabilities("waygate-clients_admin")
require_gateways_editor = _require_capabilities("waygate-gateways_editor")
require_gateways_admin = _require_capabilities("waygate-gateways_admin")
require_routing_admin = _require_capabilities("waygate-routing_admin")
require_credentials_admin = _require_capabilities("waygate-clients_admin", "waygate-routing_admin")


def _validate_client_owner(project_id: str, owner_user_id: str) -> bool:
    from keystoneauth1.exceptions.http import NotFound

    client = _get_admin_ks_client()
    try:
        user = client.users.get(owner_user_id)
    except NotFound:
        return False
    if user.id != owner_user_id or getattr(user, "enabled", None) is not True:
        return False
    # Assignable owners must be able to use the profile: effective native member through the current DAG.
    roles = set(_current_project_roles(owner_user_id, project_id, client))
    return "member" in roles and not roles & _PLATFORM_ROLE_NAMES


async def validate_client_owner(project_id: str, owner_user_id: str | None) -> None:
    """Explicit clearing is permitted; an assignment requires current enabled project membership."""
    if owner_user_id is None:
        return
    try:
        valid = await asyncio.to_thread(_validate_client_owner, project_id, owner_user_id)
    except AuthorityRejected:
        raise HTTPException(status_code=403, detail="Waygate role graph is not authorized") from None
    except Exception:
        raise HTTPException(status_code=503, detail="Client owner membership could not be verified") from None
    if not valid:
        raise HTTPException(status_code=422, detail="Client owner must be an enabled member of this project")


