"""Administrator-managed Waygate resource policies."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import suppress

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from waygate.auth import require_admin, require_token
from waygate.config import get_settings
from waygate.services import resource_policies

router = APIRouter()


class ResourcePolicyUpdate(BaseModel):
    resource_id: str | None = Field(default=None, max_length=128)


def _admin_connection():
    import openstack

    settings = get_settings()
    return openstack.connect(
        load_envvars=False,
        load_yaml_config=False,
        auth_url=settings.os_auth_url,
        auth_type="password",
        username=settings.os_username,
        password=settings.os_password,
        project_name=settings.os_project_name,
        user_domain_name=settings.os_user_domain_name,
        project_domain_name=settings.os_project_domain_name,
        region_name=settings.os_region_name,
        interface=settings.os_interface,
        api_timeout=30,
        verify=settings.ssl_verify,
    )


async def get_admin_os_conn() -> AsyncIterator:
    try:
        connection = await asyncio.to_thread(_admin_connection)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="관리자 OpenStack 연결을 만들 수 없습니다") from exc
    try:
        yield connection
    finally:
        with suppress(Exception):
            await asyncio.to_thread(connection.close)


@router.get("/resource-policies", dependencies=[Depends(require_admin)])
async def list_resource_policies(conn=Depends(get_admin_os_conn)):
    try:
        return await resource_policies.inspect_policies(conn)
    except resource_policies.ResourcePolicyStorageUnavailable as exc:
        raise HTTPException(status_code=503, detail="리소스 정책 저장소를 사용할 수 없습니다") from exc


@router.get("/resource-policies/catalog/{policy_key}", dependencies=[Depends(require_admin)])
async def discover_resource_policy_options(policy_key: str, conn=Depends(get_admin_os_conn)):
    try:
        spec = resource_policies.get_spec(policy_key)
        return {
            "key": spec.key,
            "resource_kind": spec.resource_kind,
            "group": spec.group,
            "execution_scope": spec.execution_scope,
            "dependency": spec.dependency,
            "constraints": {"external_only": spec.external_only, "shared_only": spec.shared_only},
            "options": await resource_policies.discover_options(conn, policy_key),
        }
    except resource_policies.ResourcePolicyValidationError as exc:
        raise HTTPException(status_code=404, detail="알 수 없는 리소스 정책입니다") from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="OpenStack 리소스 목록을 조회할 수 없습니다") from exc


@router.put("/resource-policies/{policy_key}", dependencies=[Depends(require_admin)])
async def update_resource_policy(
    policy_key: str,
    body: ResourcePolicyUpdate,
    token_info: dict = Depends(require_token),
    conn=Depends(get_admin_os_conn),
):
    try:
        return await resource_policies.set_policy(
            conn=conn,
            key=policy_key,
            resource_id=body.resource_id,
            updated_by_user_id=str(token_info.get("user_id") or ""),
        )
    except resource_policies.ResourcePolicyValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except resource_policies.ResourcePolicyStorageUnavailable as exc:
        raise HTTPException(status_code=503, detail="리소스 정책 저장소를 사용할 수 없습니다") from exc
