"""Waygate-owned OpenStack resource policies."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from waygate.db import get_session_factory, is_db_available
from waygate.models.orm import ResourcePolicy


class ResourcePolicyValidationError(ValueError):
    pass


class ResourcePolicyStorageUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicySpec:
    key: str
    resource_kind: str
    title: str
    help_text: str
    external_only: bool = False
    shared_only: bool = False
    group: str = "Waygate"
    execution_scope: str = "tenant"
    dependency: str | None = None
    required_when: str | None = None


_SPECS = (
    PolicySpec(
        "waygate.provider_network",
        "network",
        "Waygate provider network",
        "Target-tenant-visible shared provider network.",
        shared_only=True,
    ),
    PolicySpec("waygate.image", "image", "Waygate image", "Target-tenant-visible public image."),
    PolicySpec("waygate.flavor", "flavor", "Waygate flavor", "Target-tenant-visible public flavor."),
    PolicySpec(
        "waygate.floating_network",
        "network",
        "Waygate floating network",
        "Optional external network for Waygate endpoints.",
        external_only=True,
    ),
)
_SPECS_BY_KEY = {spec.key: spec for spec in _SPECS}


def get_spec(key: str) -> PolicySpec:
    try:
        return _SPECS_BY_KEY[key]
    except KeyError as exc:
        raise ResourcePolicyValidationError("unknown resource policy") from exc


def list_specs() -> list[PolicySpec]:
    return list(_SPECS)


def _require_db():
    factory = get_session_factory()
    if not is_db_available() or factory is None:
        raise ResourcePolicyStorageUnavailable("resource policy storage is unavailable")
    return factory


def _public(row: ResourcePolicy | None, spec: PolicySpec) -> dict[str, Any]:
    resource_id = row.resource_id if row else None
    return {
        "key": spec.key,
        "resource_kind": spec.resource_kind,
        "title": spec.title,
        "group": spec.group,
        "help_text": spec.help_text,
        "execution_scope": spec.execution_scope,
        "dependency": spec.dependency,
        "required_when": spec.required_when,
        "external_only": spec.external_only,
        "shared_only": spec.shared_only,
        "resource_id": resource_id,
        "resource_name": row.resource_name if row else None,
        "constraints": row.constraints if row else None,
        "updated_by_user_id": row.updated_by_user_id if row else None,
        "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
        "state": "configured" if resource_id else "missing",
    }


def _option(resource_id: object, name: object, **extra: Any) -> dict[str, Any]:
    return {"id": str(resource_id), "name": str(name or resource_id), **extra}


def _is_tenant_network(network: object) -> bool:
    return bool(getattr(network, "is_shared", False) or getattr(network, "is_router_external", False))


def _discover_sync(conn, spec: PolicySpec) -> list[dict[str, Any]]:
    if spec.resource_kind == "image":
        return [
            _option(image.id, image.name, status=getattr(image, "status", None))
            for image in conn.image.images()
            if getattr(image, "visibility", None) in {"public", "community"}
        ]
    if spec.resource_kind == "flavor":
        return [
            _option(flavor.id, flavor.name, vcpus=getattr(flavor, "vcpus", None), ram=getattr(flavor, "ram", None))
            for flavor in conn.compute.flavors()
            if bool(getattr(flavor, "is_public", False))
        ]
    if spec.resource_kind == "network":
        options = [
            _option(
                network.id,
                network.name,
                is_external=bool(getattr(network, "is_router_external", False)),
                is_shared=bool(getattr(network, "is_shared", False)),
            )
            for network in conn.network.networks()
            if _is_tenant_network(network)
        ]
        return [
            option
            for option in options
            if (not spec.external_only or option["is_external"]) and (not spec.shared_only or option["is_shared"])
        ]
    raise AssertionError(f"unsupported resource kind: {spec.resource_kind}")


async def discover_options(conn, key: str) -> list[dict[str, Any]]:
    return await asyncio.to_thread(_discover_sync, conn, get_spec(key))


def _validate_existing_sync(conn, spec: PolicySpec, resource_id: str) -> dict[str, Any]:
    if spec.resource_kind == "image":
        image = conn.image.get_image(resource_id)
        if image is None or getattr(image, "visibility", None) not in {"public", "community"}:
            raise ResourcePolicyValidationError("selected image is unavailable in the execution scope")
        return _option(image.id, image.name)
    if spec.resource_kind == "flavor":
        flavor = conn.compute.get_flavor(resource_id)
        if flavor is None or not bool(getattr(flavor, "is_public", False)):
            raise ResourcePolicyValidationError("selected flavor is unavailable in the execution scope")
        return _option(flavor.id, flavor.name)
    if spec.resource_kind == "network":
        network = conn.network.get_network(resource_id)
        if (
            network is None
            or not _is_tenant_network(network)
            or (spec.external_only and not bool(getattr(network, "is_router_external", False)))
            or (spec.shared_only and not bool(getattr(network, "is_shared", False)))
        ):
            raise ResourcePolicyValidationError("selected network is unavailable in the execution scope")
        return _option(network.id, network.name)
    raise AssertionError(f"unsupported resource kind: {spec.resource_kind}")


async def validate_existing_selection(conn, key: str, resource_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(_validate_existing_sync, conn, get_spec(key), resource_id)


async def validate_selection(conn, key: str, resource_id: str | None) -> dict[str, Any] | None:
    if resource_id is None or not resource_id.strip():
        return None
    return await validate_existing_selection(conn, key, resource_id.strip())


async def list_policies() -> list[dict[str, Any]]:
    factory = _require_db()
    async with factory() as session:
        rows = (await session.execute(select(ResourcePolicy).where(ResourcePolicy.policy_key.in_(_SPECS_BY_KEY)))).scalars().all()
    by_key = {row.policy_key: row for row in rows}
    return [_public(by_key.get(spec.key), spec) for spec in _SPECS]


async def inspect_policies(conn) -> list[dict[str, Any]]:
    policies = await list_policies()
    for policy in policies:
        if policy["state"] == "missing":
            continue
        try:
            selected = await validate_existing_selection(conn, policy["key"], policy["resource_id"])
            policy["resolved_name"] = selected["name"]
        except ResourcePolicyValidationError:
            policy["state"] = "stale"
        except Exception:
            policy["state"] = "unavailable"
    return policies


async def get_policy_snapshot(keys: tuple[str, ...]) -> dict[str, dict[str, str] | None]:
    for key in keys:
        get_spec(key)
    factory = _require_db()
    async with factory() as session:
        rows = (
            await session.execute(select(ResourcePolicy).where(ResourcePolicy.policy_key.in_(keys)))
        ).scalars().all()
    by_key = {row.policy_key: row for row in rows}
    return {
        key: (
            {"id": row.resource_id, "name": row.resource_name or row.resource_id}
            if (row := by_key.get(key)) and row.resource_id
            else None
        )
        for key in keys
    }


async def set_policy(*, conn, key: str, resource_id: str | None, updated_by_user_id: str) -> dict[str, Any]:
    spec = get_spec(key)
    selected = await validate_selection(conn, key, resource_id)
    factory = _require_db()
    async with factory() as session, session.begin():
        row = await session.get(ResourcePolicy, key, with_for_update=True)
        if row is None:
            row = ResourcePolicy(policy_key=key, resource_kind=spec.resource_kind)
            session.add(row)
        row.resource_id = selected["id"] if selected else None
        row.resource_name = selected["name"] if selected else None
        row.constraints = {
            "external_only": spec.external_only,
            "shared_only": spec.shared_only,
            "execution_scope": spec.execution_scope,
        }
        row.updated_by_user_id = updated_by_user_id
        await session.flush()
        return _public(row, spec)


async def resolve_policy_snapshot(*, conn, keys: tuple[str, ...]) -> dict[str, dict[str, str]]:
    stored = await get_policy_snapshot(keys)
    missing = [key for key, selected in stored.items() if selected is None]
    if missing:
        raise ResourcePolicyValidationError(f"required resource policies are not configured: {', '.join(missing)}")
    resolved = {}
    for key in keys:
        selected = await validate_existing_selection(conn, key, stored[key]["id"])
        resolved[key] = {"id": selected["id"], "name": selected["name"]}
    return resolved
