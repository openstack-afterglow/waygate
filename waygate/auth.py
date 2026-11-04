"""Keystone credential validation, current capabilities and logical target selection."""

from __future__ import annotations

import asyncio
import logging
from functools import lru_cache
from urllib.parse import quote, urlencode

from fastapi import Depends, Header, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from keystoneauth1 import access as ks_access
from keystoneauth1 import session as ks_session
from keystoneauth1.exceptions.http import Forbidden, NotFound, Unauthorized
from keystoneauth1.identity import v3

from waygate import policy
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


def _identity_collection(client, path: str, key: str) -> list[dict]:
    """Inspect complete native envelopes; SDK list wrappers discard authority metadata."""
    payload = client.get(path)[1]
    if not isinstance(payload, dict) or not isinstance(payload.get(key), list):
        raise ValueError("Incomplete Keystone identity collection")
    links = payload.get("links", {})
    if (
        not isinstance(links, dict)
        or links.get("next") is not None
        or (payload.get("truncated") is not None and payload["truncated"] is not False)
        or any(not isinstance(row, dict) for row in payload[key])
    ):
        raise ValueError("Incomplete Keystone identity collection")
    return payload[key]


def _is_system_admin(user_id: str, client=None) -> bool:
    """Expand exact raw system user/group grants; Keystone effective listings omit them."""
    if not user_id:
        return False
    owns_client = client is None
    try:
        client = client or _get_admin_ks_client()
        user_query = urlencode({"user.id": user_id, "scope.system": "all"})
        assignments = [
            (row, "user", user_id)
            for row in _identity_collection(client, "/role_assignments?" + user_query, "role_assignments")
        ]
        group_ids = set()
        for group in _identity_collection(client, f"/users/{quote(user_id, safe='')}/groups", "groups"):
            group_id = group.get("id")
            if (
                not isinstance(group_id, str) or not group_id or group_id != group_id.strip()
                or group_id in group_ids
            ):
                raise ValueError("Keystone native group identity is unavailable or duplicated")
            group_ids.add(group_id)
        for group_id in sorted(group_ids):
            group_query = urlencode({"group.id": group_id, "scope.system": "all"})
            assignments.extend(
                (row, "group", group_id)
                for row in _identity_collection(client, "/role_assignments?" + group_query, "role_assignments")
            )
        assigned_ids = set()
        for data, principal, principal_id in assignments:
            scope = data.get("scope")
            if not isinstance(scope, dict) or set(scope) != {"system"}:
                continue
            system = scope["system"]
            subject = data.get(principal)
            if (
                not isinstance(system, dict) or set(system) != {"all"} or system["all"] is not True
                or not isinstance(subject, dict) or subject.get("id") != principal_id
                or data.get("group" if principal == "user" else "user") is not None
            ):
                continue
            role = data.get("role")
            if not isinstance(role, dict) or not isinstance(role.get("id"), str) or not role["id"]:
                raise AuthorityRejected("Assigned system role identity is unavailable")
            assigned_ids.add(role["id"])
        if not assigned_ids:
            return False
        rows, closure = _current_role_graph(client)
        admins = [role for role in rows.values() if role["name"].casefold() == "admin" and not role.get("domain_id")]
        if len(admins) != 1 or admins[0]["name"] != "admin":
            return False
        effective_ids = set()
        for role_id in assigned_ids:
            effective_ids.update(closure(role_id))
        return admins[0]["id"] in effective_ids
    except AuthorityRejected:
        raise
    except Exception as exc:
        raise AuthorityUnavailable("Keystone system-admin authority unavailable") from exc
    finally:
        if owns_client and client is not None:
            client.session.session.close()


def _require_enabled_identity_domain(client, subject):
    """Assignment listings and project.enabled do not establish parent-domain enabledness."""
    domain_id = getattr(subject, "domain_id", None)
    if not isinstance(domain_id, str) or not domain_id:
        raise AuthorityRejected("Keystone identity domain is unavailable")
    try:
        domain = client.domains.get(domain_id)
    except NotFound:
        raise AuthorityRejected("Keystone identity domain was removed") from None
    if domain.id != domain_id or getattr(domain, "enabled", None) is not True:
        raise AuthorityRejected("Keystone identity domain is not enabled")
    return domain




def validate_token(token: str) -> dict:
    """Validate the original credential, never exchange it and erase its attenuation."""
    client = _get_admin_ks_client()
    try:
        body = client.tokens.get_token_data(token, include_catalog=False)
    finally:
        client.session.session.close()
    access = ks_access.create(body=body, auth_token=token)
    data = body["token"]
    methods = data.get("methods") or []
    restricted = (
        not methods
        or bool(set(methods) - {"password", "token", "totp", "mapped", "external", "openid"})
        or access.trust_scoped
        or bool(data.get("application_credential"))
        or bool(data.get("OS-OAUTH1"))
        or bool(data.get("oauth2_credential"))
    )
    return {
        "token": token,
        "project_id": access.project_id or "",
        "connection_project_id": access.project_id or "",
        "project_name": access.project_name or "",
        "user_id": access.user_id or "",
        "username": access.username or "",
        "expires_at": access.expires.isoformat() if access.expires else "",
        "credential_restricted": restricted,
        "credential_access_rules": bool((data.get("application_credential") or {}).get("access_rules")),
        "token_roles": access.role_names or [],
    }


def resolve_authority(info: dict, target_project_id: str = "") -> dict:
    """Resolve uncached caller authority and a separately selected logical project."""
    client = None
    try:
        if info.get("credential_access_rules"):
            raise AuthorityRejected("Application credential access rules are not supported by Waygate")
        client = _get_admin_ks_client()
        user = client.users.get(info["user_id"])
        if user.id != info["user_id"] or getattr(user, "enabled", None) is not True:
            raise AuthorityRejected("Keystone caller is not enabled")
        system_admin = not info["credential_restricted"] and _is_system_admin(info["user_id"], client)
        _require_enabled_identity_domain(client, user)
        project_id = target_project_id or info["connection_project_id"]
        if project_id != info["connection_project_id"] and not system_admin:
            raise AuthorityRejected("Target project selection requires current system administration")
        if not project_id:
            if not system_admin:
                raise AuthorityRejected("Projectless credentials require current system administration")
            roles = []
        else:
            project = client.projects.get(project_id)
            if project.id != project_id or getattr(project, "enabled", None) is not True:
                raise AuthorityRejected("Keystone target project is not enabled")
            _require_enabled_identity_domain(client, project)
            roles = _current_project_roles(info["user_id"], project_id, client)
            if info["credential_restricted"]:
                roles = sorted(set(roles) & set(info["token_roles"]))
            if not system_admin and not roles:
                raise AuthorityRejected("Current project role bindings are required")
    except (AuthorityRejected, NotFound):
        raise AuthorityRejected("Keystone caller or target authority was rejected") from None
    except Exception as exc:
        raise AuthorityUnavailable("Keystone authority unavailable") from exc
    finally:
        if client is not None:
            client.session.session.close()
    return {**info, "project_id": project_id, "roles": roles, "is_system_admin": system_admin}


async def require_token(
    request: Request,
    x_auth_token: str | None = Security(keystone_token_header),
    x_project_id: str | None = Header(default=None, alias="X-Project-Id"),
    x_target_project_id: str | None = Header(default=None, alias="X-Target-Project-Id"),
) -> dict:
    if not x_auth_token:
        raise HTTPException(status_code=401, detail="X-Auth-Token header is required")
    try:
        info = await asyncio.to_thread(validate_token, x_auth_token)
    except (Forbidden, Unauthorized, NotFound):
        raise HTTPException(status_code=401, detail="Invalid or expired Keystone token") from None
    except Exception as exc:
        _logger.warning("Keystone token validation unavailable error_type=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Keystone token validation is temporarily unavailable") from None
    if x_project_id is not None and info["connection_project_id"] != x_project_id:
        raise HTTPException(status_code=403, detail="Token project does not match X-Project-Id")
    try:
        info = await asyncio.to_thread(resolve_authority, info, x_target_project_id or "")
    except AuthorityRejected:
        _logger.warning("Keystone caller, target or role graph rejected for Waygate authorization")
        raise HTTPException(status_code=403, detail="Waygate caller, target or role graph is not authorized") from None
    except AuthorityUnavailable:
        _logger.warning("Keystone authority lookup unavailable")
        raise HTTPException(status_code=503, detail="Waygate authorization is temporarily unavailable") from None
    request.state.token_info = info
    return info




_SERVICE_ROLES = frozenset({"waygate_reader", "waygate_user", "waygate_editor", "waygate_admin", *policy.CAPABILITY_ACTIONS})
_PLATFORM_ROLE_NAMES = frozenset({"admin", "manager"})


def _role_catalog(client):
    """Resolve current, unique global role identities without service implications."""
    catalog = _identity_collection(client, "/roles", "roles")
    rows: dict[str, dict] = {}
    names: dict[str, list[str]] = {}
    for role in catalog:
        role_id, name = role.get("id"), role.get("name")
        if not isinstance(role_id, str) or not role_id or not isinstance(name, str) or not name or role_id in rows:
            raise ValueError("Malformed Keystone role catalog")
        rows[role_id] = role
        # oslo.policy RoleCheck is case-insensitive: distinct native IDs must not
        # collapse to the same policy authority under case normalization.
        names.setdefault(name.casefold(), []).append(role_id)
    return rows, names


def _current_role_graph(client, catalog=None, *, project: bool = False):
    """Expand current native role IDs; project implications do not establish system scope."""
    rows, names = catalog if catalog is not None else _role_catalog(client)
    graph = {role_id: set() for role_id in rows}
    for data in _identity_collection(client, "/role_inferences", "role_inferences"):
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
        if role_id not in rows:
            raise AuthorityRejected("Assigned role is not a global Keystone authority")
        role = rows[role_id]
        if role.get("domain_id") or len(names[role["name"].casefold()]) != 1:
            raise AuthorityRejected("Ambiguous or domain-specific Keystone authority")
        if role_id in visiting:
            raise AuthorityRejected("Cyclic Keystone role graph")
        result = {role_id}
        for child in graph[role_id]:
            result.update(closure(child, visiting | {role_id}))
        if not project and role["name"] in _SERVICE_ROLES and any(
            rows[child]["name"].casefold() in _PLATFORM_ROLE_NAMES for child in result
        ):
            raise AuthorityRejected("Service roles cannot imply system administration")
        return result

    return rows, closure


def _current_project_roles(user_id: str, project_id: str, client) -> list[str]:
    """Use fresh effective project bindings, including Keystone's canonical role graph."""
    if not user_id or not project_id:
        return []
    rows, closure = _current_role_graph(client, project=True)
    assigned_ids: set[str] = set()
    query = urlencode({"user.id": user_id, "scope.project.id": project_id, "effective": True})
    for data in _identity_collection(client, "/role_assignments?" + query, "role_assignments"):
        if data.get("scope", {}).get("project", {}).get("id") != project_id:
            raise ValueError("Unexpected Keystone assignment scope")
        if data.get("user", {}).get("id") != user_id:
            raise ValueError("Unexpected Keystone assignment subject")
        role_id = data.get("role", {}).get("id")
        if role_id not in rows:
            raise AuthorityRejected("Assigned role is not a global Keystone authority")
        assigned_ids.add(role_id)
    effective_ids = set()
    for role_id in assigned_ids:
        effective_ids.update(closure(role_id))
    return sorted(rows[role_id]["name"] for role_id in effective_ids)


@lru_cache
def require_action(action: str):
    def dependency(token_info: dict = Depends(require_token)) -> dict:
        if action not in policy.SYSTEM_ACTIONS and not token_info.get("project_id"):
            raise HTTPException(status_code=400, detail="X-Target-Project-Id is required for project resources")
        return policy.enforce(token_info, action)

    return dependency


def require_clients_update(token_info: dict = Depends(require_token)) -> dict:
    if not token_info.get("project_id"):
        raise HTTPException(status_code=400, detail="X-Target-Project-Id is required for project resources")
    if not (policy.allows(token_info, "waygate:client:update") or policy.allows(token_info, "waygate:client:set-enabled")):
        raise HTTPException(status_code=403, detail="Waygate client update is not authorized")
    return token_info


def _validate_client_owner(project_id: str, owner_user_id: str) -> bool:
    client = _get_admin_ks_client()
    try:
        user = client.users.get(owner_user_id)
        if user.id != owner_user_id or getattr(user, "enabled", None) is not True:
            return False
        # Owners can use their profile under current native or verified system authority.
        roles = set(_current_project_roles(owner_user_id, project_id, client))
        if roles.intersection({"member", "manager", "admin"}):
            return True
        if _is_system_admin(owner_user_id, client):
            _require_enabled_identity_domain(client, user)
            return True
        return False
    except NotFound:
        return False
    finally:
        client.session.session.close()


async def validate_client_owner(project_id: str, owner_user_id: str | None) -> None:
    """An assignment requires an enabled current project member or verified system admin."""
    if owner_user_id is None:
        return
    try:
        valid = await asyncio.to_thread(_validate_client_owner, project_id, owner_user_id)
    except AuthorityRejected:
        raise HTTPException(status_code=403, detail="Waygate role graph is not authorized") from None
    except Exception:
        raise HTTPException(status_code=503, detail="Client owner membership could not be verified") from None
    if not valid:
        raise HTTPException(status_code=422, detail="Client owner must be an enabled project member or system admin")


