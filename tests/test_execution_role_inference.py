"""Installed Keystone/OpenStack SDK HTTP regressions for native Trust role inference."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
import test_execution_delegation as fixture

from waygate.models.orm import WaygateExecutionGrant, WaygateJob, WaygateServer
from waygate.services import execution, waygate_jobs

pytestmark = pytest.mark.asyncio
PROJECT = "project-a"
MEMBER_ROLES = {"member", "reader", "project_member", "project_reader"}
native = fixture.native
synthetic_cloud = fixture.synthetic_cloud


def member_graph(cloud, monkeypatch):
    names = (*fixture.ROLE_NAMES, "project_member", "project_reader", "audit")
    monkeypatch.setattr(fixture, "ROLE_NAMES", tuple(dict.fromkeys((*names, "manager"))))
    graph = getattr(cloud, "implies", fixture.IMPLIES)
    monkeypatch.setitem(graph, "member", ["reader", "project_member"])
    monkeypatch.setitem(graph, "project_member", ["project_reader"])
    monkeypatch.setitem(graph, "project_reader", ["reader"])
    return graph


def original_headers(cloud, *, roles=None, project=PROJECT, methods=None):
    token = cloud.issue(methods or ["password"], "user-a", project,
                        roles if roles is not None else cloud.effective("user-a", project))
    return {"X-Auth-Token": token, "X-Project-Id": project}


@pytest.mark.parametrize("methods", [["password"], ["openid"]])
async def test_native_member_implied_project_roles_create_and_worker(native, monkeypatch, methods):
    cloud = native.cloud
    member_graph(cloud, monkeypatch)
    headers = original_headers(cloud, methods=methods)
    response = await native.client.post("/v1/servers", json={"name": "native-member"}, headers=headers)
    assert response.status_code == 201, response.text
    [trust] = cloud.trusts.values()
    assert trust["roles"] == ["member"]
    assert (trust["trustor_user_id"], trust["trustee_user_id"], trust["project_id"]) == (
        "user-a", fixture.SERVICE_USER, PROJECT,
    )
    assert await waygate_jobs.process_one_job() is True
    assert (await fixture._rows(WaygateServer, id=response.json()["id"]))[0].status == "PROVISIONING"
    assert cloud.cloud_requests and all(record["roles"] == MEMBER_ROLES for _, _, record in cloud.cloud_requests)
    assert all(document["auth"]["identity"]["methods"] == ["password"] for document in cloud.auth_requests)
    assert {token for token, record in cloud.tokens.items()
            if record["user"] == "user-a" and record["trust"] is None} == {headers["X-Auth-Token"]}
    assert cloud.validation_requests[0][0] == headers["X-Auth-Token"]


async def test_native_separately_assigned_admin_is_not_delegated(native, monkeypatch):
    member_graph(native.cloud, monkeypatch)
    native.cloud.assignments["user-a", PROJECT] = {"member", "admin"}
    server_id = await fixture._create(native)
    [trust] = native.cloud.trusts.values()
    assert trust["roles"] == ["member"]
    assert await waygate_jobs.process_one_job() is True
    assert (await fixture._rows(WaygateJob, server_id=server_id))[0].status == "completed"
    assert all(record["roles"] == MEMBER_ROLES for _, _, record in native.cloud.cloud_requests)


@pytest.mark.parametrize("fault", [
    "extra-role", "foreign-role-id", "swapped-role-names", "foreign-project", "foreign-user",
    "foreign-trustor", "foreign-trustee", "foreign-trust", "expired",
])
async def test_native_trust_token_cannot_exceed_exact_current_role_ids_or_identity(native, monkeypatch, fault):
    cloud = native.cloud
    member_graph(cloud, monkeypatch)
    body = cloud.token_body

    def corrupt(token):
        result = body(token)
        data = result["token"]
        if "OS-TRUST:trust" not in data:
            return result
        if fault == "extra-role":
            data["roles"].append({"id": "role-audit", "name": "audit"})
        elif fault == "foreign-role-id":
            data["roles"][0]["id"] = "foreign-member-id"
        elif fault == "swapped-role-names":
            data["roles"][0]["name"], data["roles"][1]["name"] = data["roles"][1]["name"], data["roles"][0]["name"]
        elif fault in {"foreign-project", "foreign-user"}:
            data[fault.removeprefix("foreign-")]["id"] = "foreign-identity"
        elif fault in {"foreign-trustor", "foreign-trustee"}:
            data["OS-TRUST:trust"][fault.removeprefix("foreign-") + "_user"]["id"] = "foreign-identity"
        elif fault == "foreign-trust":
            data["OS-TRUST:trust"]["id"] = "foreign-trust"
        else:
            data["expires_at"] = fixture._iso(datetime.now(UTC) - timedelta(hours=1))
        return result

    monkeypatch.setattr(cloud, "token_body", corrupt)
    response = await native.client.post("/v1/servers", json={"name": "deny"}, headers=original_headers(cloud))
    assert response.status_code == 403, response.text
    assert cloud.cloud_requests == [] and cloud.servers == cloud.ports == {}
    assert await fixture._rows(WaygateServer) == [] and await fixture._rows(WaygateJob) == []
    assert all(trust["deleted"] for trust in cloud.trusts.values())


@pytest.mark.parametrize("issued_roles", [{"reader"}, {"member", "reader"}])
async def test_native_original_token_is_not_reissued_to_acquire_new_authority(native, monkeypatch, issued_roles):
    cloud = native.cloud
    member_graph(cloud, monkeypatch)
    response = await native.client.post("/v1/servers", json={"name": "deny"},
                                       headers=original_headers(cloud, roles=issued_roles))
    assert response.status_code == 403, response.text
    assert cloud.trusts == {} and cloud.cloud_requests == []
    assert all(document["auth"]["identity"]["methods"] == ["password"] for document in cloud.auth_requests)


@pytest.mark.parametrize("change", ["edge-removed", "membership-revoked"])
async def test_native_cached_trust_is_rechecked_before_next_provider_send(native, monkeypatch, change):
    cloud = native.cloud
    graph = member_graph(cloud, monkeypatch)
    server_id = await fixture._create(native)
    [row] = await fixture._rows(WaygateExecutionGrant)
    grant = await execution.load_grant(row.id, PROJECT, server_id, "user-a", "provision")
    connection = await asyncio.to_thread(execution._open_connection, grant)
    try:
        await asyncio.to_thread(connection.compute.get_flavor, fixture.FLAVOR)
        before = len(cloud.cloud_requests)
        if change == "edge-removed":
            monkeypatch.setitem(graph, "member", ["reader"])
        else:
            cloud.assignments["user-a", PROJECT] = {"reader"}
        with pytest.raises(execution.ExecutionDenied):
            await asyncio.to_thread(connection.compute.get_flavor, fixture.FLAVOR)
        assert cloud.cloud_requests[before:] == []
    finally:
        await asyncio.to_thread(execution._close_connection, connection)


@pytest.mark.parametrize("higher_role", ["manager", "Manager", "ADMIN"])
async def test_native_member_cannot_gain_higher_core_role_through_inference(native, monkeypatch, higher_role):
    graph = member_graph(native.cloud, monkeypatch)
    # Unique mixed-case names still match oslo.policy's case-insensitive role checks.
    names = tuple(name for name in fixture.ROLE_NAMES if name.casefold() != higher_role.casefold())
    monkeypatch.setattr(fixture, "ROLE_NAMES", (*names, higher_role))
    if higher_role == "ADMIN":
        monkeypatch.delitem(graph, "admin", raising=False)
    monkeypatch.setitem(graph, "member", ["reader", "project_member", higher_role])
    response = await native.client.post("/v1/servers", json={"name": "deny"}, headers=original_headers(native.cloud))
    assert response.status_code == 403, response.text
    assert native.cloud.trusts == {} and native.cloud.cloud_requests == []


async def test_native_foreign_original_scope_is_not_rescoped_for_delegation(native, monkeypatch):
    cloud = native.cloud
    member_graph(cloud, monkeypatch)
    cloud.projects["foreign-project"] = True
    cloud.assignments["user-a", "foreign-project"] = {"member"}
    headers = original_headers(cloud, project="foreign-project")
    headers["X-Project-Id"] = PROJECT
    response = await native.client.post("/v1/servers", json={"name": "deny"}, headers=headers)
    assert response.status_code == 403, response.text
    assert cloud.trusts == {} and cloud.cloud_requests == []


@pytest.mark.parametrize("auth_url", ["versioned", "unversioned"])
async def test_native_24h_trust_token_executes_with_independent_two_hour_grant(native, auth_url):
    cloud = native.cloud
    # Actual deployed Keystone2025.2 uses [token] expiration=86400. Its Trust
    # token is not expiry-clamped; the operation still ends at its own deadline.
    cloud.token_lifetime = timedelta(hours=24)
    fixture.get_settings().os_auth_url = cloud.base + ("/v3" if auth_url == "versioned" else "")
    server_id = await fixture._create(native)
    [row] = await fixture._rows(WaygateExecutionGrant)
    grant = await execution.load_grant(row.id, PROJECT, server_id, "user-a", "provision")
    trust_tokens = [record for record in cloud.tokens.values() if record["trust"] is not None]
    assert trust_tokens and all(record["expires"] > grant.expires_at for record in trust_tokens)
    assert await waygate_jobs.process_one_job() is True
    assert (await fixture._rows(WaygateJob, server_id=server_id))[0].status == "completed"
    assert all(record["roles"] == {"member", "reader"} for _, _, record in cloud.cloud_requests)


@pytest.mark.parametrize("change", ["grant-expired", "trust-revoked", "token-expired"])
async def test_native_long_token_cannot_outlive_operation_or_revocation(native, monkeypatch, change):
    from dataclasses import replace

    cloud = native.cloud
    cloud.token_lifetime = timedelta(hours=24)
    server_id = await fixture._create(native)
    [row] = await fixture._rows(WaygateExecutionGrant)
    grant = await execution.load_grant(row.id, PROJECT, server_id, "user-a", "provision")
    connection = await asyncio.to_thread(execution._open_connection, grant)
    try:
        await asyncio.to_thread(connection.compute.get_flavor, fixture.FLAVOR)
        before = len(cloud.cloud_requests)
        if change == "grant-expired":
            expired = replace(grant, expires_at=datetime.now(UTC) - timedelta(seconds=1))
            monkeypatch.setattr(connection.session, "grant", expired)
        elif change == "trust-revoked":
            cloud.trusts[grant.trust_id]["deleted"] = True
        else:
            body = cloud.token_body

            def expired_response(token):
                result = body(token)
                if "OS-TRUST:trust" in result["token"]:
                    result["token"]["expires_at"] = fixture._iso(datetime.now(UTC) - timedelta(seconds=1))
                return result

            monkeypatch.setattr(cloud, "token_body", expired_response)
            from keystoneauth1 import access as ks_access

            connection.session.auth.auth_ref = ks_access.create(
                body=expired_response(connection.session.auth.auth_ref.auth_token),
            )
        with pytest.raises(execution.ExecutionDenied):
            await asyncio.to_thread(connection.compute.get_flavor, fixture.FLAVOR)
        assert cloud.cloud_requests[before:] == []
    finally:
        await asyncio.to_thread(execution._close_connection, connection)


@pytest.mark.parametrize("binding", ["direct", "group"])
async def test_native_observed_project_role_graph_delegates_only_member(native, monkeypatch, binding):
    cloud = native.cloud
    graph = getattr(cloud, "implies", fixture.IMPLIES)
    names = (*fixture.ROLE_NAMES, "manager", "creator", "project_admin", "project_member", "project_reader")
    monkeypatch.setattr(fixture, "ROLE_NAMES", tuple(dict.fromkeys(names)))
    for prior, children in {
        "admin": ["manager", "creator"], "manager": ["member", "project_admin"],
        "member": ["reader"], "project_admin": ["project_member"],
        "project_member": ["member", "project_reader"], "project_reader": ["reader"],
    }.items():
        monkeypatch.setitem(graph, prior, children)
    cloud.token_lifetime = timedelta(hours=24)
    cloud.assignments["user-a", PROJECT] = {"project_member"} if binding == "direct" else set()
    if binding == "group":
        cloud.user_groups["user-a"] = {"project-members"}
        cloud.project_group_assignments["project-members", PROJECT] = {"project_member"}
    headers = original_headers(cloud)
    assert cloud.tokens[headers["X-Auth-Token"]]["roles"] == {"project_member", "project_reader", "member", "reader"}
    response = await native.client.post("/v1/servers", json={"name": "current-native-graph"}, headers=headers)
    assert response.status_code == 201, response.text
    [trust] = cloud.trusts.values()
    assert trust["roles"] == ["member"]
    assert await waygate_jobs.process_one_job() is True
    assert all(record["roles"] == {"member", "reader"} for _, _, record in cloud.cloud_requests)
