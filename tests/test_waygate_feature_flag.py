"""Waygate standalone discovery and health contracts."""

import pytest
from httpx import ASGITransport, AsyncClient

from waygate.main import app

pytestmark = pytest.mark.asyncio


async def test_root_and_version_discovery_are_openstack_compatible():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://waygate.example") as client:
        root = await client.get("/")
        version = await client.get("/v1/")

    expected = {
        "id": "v1.0",
        "status": "CURRENT",
        "min_version": "1.0",
        "version": "1.0",
        "links": [{"rel": "self", "href": "https://waygate.example/v1/"}],
    }
    assert root.status_code == 200
    assert root.json() == {"versions": [expected]}
    assert version.status_code == 200
    assert version.json() == {"version": expected}


async def test_health_is_unauthenticated():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_standalone_routes_are_mounted_under_v1():
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/v1/servers" in paths
    assert "/v1/servers/{server_id}/agent/register" in paths
    assert "/v1/admin/resource-policies" in paths


async def test_tenant_project_admin_cannot_update_global_resource_policy():
    from waygate.auth import require_token

    async def tenant_admin():
        return {
            "project_id": "tenant-project",
            "user_id": "tenant-admin",
            "username": "alice",
            "roles": ["admin"],
            "is_system_admin": False,
        }

    app.dependency_overrides[require_token] = tenant_admin
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.put(
                "/v1/admin/resource-policies/waygate.image",
                json={"resource_id": "image-1"},
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
