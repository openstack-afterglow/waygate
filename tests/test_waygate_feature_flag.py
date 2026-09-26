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


@pytest.mark.parametrize(
    ("peer", "scheme"),
    [("127.0.0.1", "https"), ("198.51.100.24", "http")],
)
async def test_discovery_accepts_forwarded_scheme_only_from_trusted_proxy(peer, scheme):
    transport = ASGITransport(app=app, client=(peer, 12345))
    async with AsyncClient(transport=transport, base_url="http://waygate.example") as client:
        headers = {"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7"}
        root = await client.get("/", headers=headers)
        version = await client.get("/v1/", headers=headers)

    expected = [{"rel": "self", "href": f"{scheme}://waygate.example/v1/"}]
    assert root.json()["versions"][0]["links"] == expected
    assert version.json()["version"]["links"] == expected


async def test_forwarded_chain_cannot_change_rate_limit_identity():
    transport = ASGITransport(app=app, client=("127.0.0.1", 12345))
    async with AsyncClient(transport=transport, base_url="http://waygate.example") as client:
        for attempt in range(31):
            response = await client.post(
                "/v1/servers/unknown/agent/register",
                headers={"X-Forwarded-For": f"203.0.113.{attempt + 1}, 198.51.100.7"},
                json={"public_key": "A" * 43 + "="},
            )
            assert response.status_code == (401 if attempt < 30 else 429)

        other_client = await client.post(
            "/v1/servers/unknown/agent/register",
            headers={"X-Forwarded-For": "198.51.100.8"},
            json={"public_key": "A" * 43 + "="},
        )
    assert other_client.status_code == 401


async def test_health_is_unauthenticated():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


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
