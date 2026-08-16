"""OpenAPI schema, security, discovery, health, and response model tests for Waygate."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from waygate.main import app


@pytest.fixture
async def api_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


def test_openapi_security_schemes():
    schema = app.openapi()
    components = schema.get("components", {})
    security_schemes = components.get("securitySchemes", {})

    assert "KeystoneToken" in security_schemes
    keystone_scheme = security_schemes["KeystoneToken"]
    assert keystone_scheme["type"] == "apiKey"
    assert keystone_scheme["name"] == "X-Auth-Token"
    assert keystone_scheme["in"] == "header"


def test_openapi_unique_operation_ids():
    schema = app.openapi()
    operation_ids = []

    for path, methods in schema.get("paths", {}).items():
        for method, spec in methods.items():
            if isinstance(spec, dict) and "operationId" in spec:
                operation_ids.append(spec["operationId"])

    assert len(operation_ids) > 0
    assert len(operation_ids) == len(set(operation_ids)), "Duplicate operation_ids found in OpenAPI schema"


def test_openapi_server_delete_response_schema():
    schema = app.openapi()
    delete_spec = schema["paths"]["/v1/servers/{server_id}"]["delete"]
    responses = delete_spec["responses"]

    assert "202" in responses
    resp_202 = responses["202"]
    schema_ref = resp_202["content"]["application/json"]["schema"]

    # Resolve schema reference or inline schema
    if "$ref" in schema_ref:
        model_name = schema_ref["$ref"].split("/")[-1]
        model_schema = schema["components"]["schemas"][model_name]
    else:
        model_schema = schema_ref

    assert "WaygateServerDeleteResponse" in schema["components"]["schemas"]
    properties = model_schema.get("properties", {})
    assert "ok" in properties
    assert "status" in properties


def test_openapi_status_enums():
    schema = app.openapi()
    schemas = schema["components"]["schemas"]

    server_info = schemas["WaygateServerInfo"]
    status_prop = server_info["properties"]["status"]
    if "$ref" in status_prop:
        enum_name = status_prop["$ref"].split("/")[-1]
        enum_schema = schemas[enum_name]
        enum_values = enum_schema.get("enum")
    else:
        enum_values = status_prop.get("enum")

    assert enum_values is not None
    assert set(enum_values) == {"CREATING", "PROVISIONING", "ACTIVE", "DELETING", "DELETED", "ERROR"}


@pytest.mark.asyncio
async def test_typed_discovery_root(api_client):
    resp = await api_client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert "versions" in body
    assert len(body["versions"]) == 1
    assert body["versions"][0]["id"] == "v1.0"
    assert body["versions"][0]["status"] == "CURRENT"


@pytest.mark.asyncio
async def test_typed_discovery_v1(api_client):
    resp = await api_client.get("/v1/")
    assert resp.status_code == 200
    body = resp.json()
    assert "version" in body
    assert body["version"]["id"] == "v1.0"
    assert body["version"]["status"] == "CURRENT"


@pytest.mark.asyncio
async def test_typed_health(api_client):
    resp = await api_client.get("/v1/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
