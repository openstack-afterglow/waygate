"""Exact native grades, persistent ownership and real Keystone-token HTTP regression definitions.

The application is the registered main.app, with its real lifespan and SQL store.
Only cloud discovery/admin directory data and Redis are synthetic: Keystone token
validation itself talks HTTP to a local v3 endpoint, with no dependency override.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from waygate import auth, db
from waygate.config import Settings
from waygate.main import app
from waygate.models.orm import WaygateClient, WaygateServer
from waygate.services import k3s_crypto, waygate_agent_auth, waygate_db, waygate_keys

CAPABILITIES = (
    "waygate-inventory_reader",
    "waygate-connect_user",
    "waygate-clients_editor",
    "waygate-gateways_editor",
    "waygate-clients_admin",
    "waygate-gateways_admin",
    "waygate-routing_admin",
)
PARENTS = {
    "waygate_reader": CAPABILITIES[:1],
    "waygate_user": CAPABILITIES[:2],
    "waygate_editor": CAPABILITIES[:4],
    "waygate_admin": CAPABILITIES,
}
SERVER = "/v1/servers/server-a"
CLIENT = SERVER + "/clients/own"
NETWORK_ID = "11111111-2222-3333-4444-555555555555"
SECRET_REASON = "provider-error-password=synthetic-secret-sentinel"


def _assignment(document):
    return SimpleNamespace(to_dict=lambda: document)


def _project_assignment(user_id, project_id):
    return _assignment({"user": {"id": user_id}, "scope": {"project": {"id": project_id}}})


@pytest.mark.parametrize("parent,expected", PARENTS.items())
@pytest.mark.parametrize("base", ["member", "reader", None])
def test_current_effective_parent_descendants_require_native_base(parent, expected, base):
    token = {"roles": ([base] if base else []) + [parent, *expected], "is_system_admin": False}
    for capability in CAPABILITIES:
        authorized = capability in expected and (
            base == "member" or (base == "reader" and capability == CAPABILITIES[0])
        )
        assert auth.has_capability(token, capability) is authorized


@pytest.mark.parametrize("leaf", CAPABILITIES)
def test_exact_leaf_does_not_imply_other_leaves_or_parents(leaf):
    token = {"roles": ["member", leaf], "is_system_admin": False}
    assert [cap for cap in CAPABILITIES if auth.has_capability(token, cap)] == [leaf]
    for parent in PARENTS:
        assert auth.has_capability(token, parent) is False


@pytest.mark.parametrize("roles", [
    [], ["member"], ["reader"], ["admin"], ["manager"], ["member", "admin"],
    ["member", "manager"], ["member", "waygate-admin"], ["member", "waygate_admin_extra"],
    ["member", "admin", "waygate_admin"], ["member", "manager", "waygate_admin"],
])
def test_plain_platform_and_lookalike_roles_never_grant_service_authority(roles):
    assert not any(auth.has_capability({"roles": roles, "is_system_admin": False}, cap) for cap in CAPABILITIES)


@pytest.mark.parametrize("roles,allowed", [
    (["member", "waygate-clients_admin"], False),
    (["member", "waygate-routing_admin"], False),
    (["member", "waygate-clients_admin", "waygate-routing_admin"], True),
    (["member", "waygate_admin"], False),
])
def test_credential_bundle_requires_both_exact_capabilities(roles, allowed):
    token = {"roles": roles, "is_system_admin": False}
    if allowed:
        assert auth.require_credentials_admin(token) is token
    else:
        with pytest.raises(HTTPException) as error:
            auth.require_credentials_admin(token)
        assert error.value.status_code == 403


@pytest.mark.parametrize("flag", [False, None, 1, "true"])
def test_global_admin_requires_verified_boolean(flag):
    with pytest.raises(HTTPException) as error:
        auth.require_admin({"roles": ["member", "waygate_admin", "admin"], "is_system_admin": flag})
    assert error.value.status_code == 403


def test_verified_system_admin_has_tenant_and_global_authority():
    token = {"roles": ["admin"], "is_system_admin": True}
    assert auth.require_admin(token) is token
    assert all(auth.has_capability(token, cap) for cap in CAPABILITIES)


@pytest.mark.parametrize("document,expected", [
    ({"scope": {"system": {"all": True}}, "role": {"id": "admin-id"}, "user": {"id": "user-a"}}, True),
    ({"scope": {"project": {"id": "project-a"}}, "role": {"id": "admin-id"}, "user": {"id": "user-a"}}, False),
    ({"scope": {"system": {"all": True}}, "role": {"id": "other"}, "user": {"id": "user-a"}}, False),
    ({"scope": {"system": {"all": True}}, "role": {"id": "admin-id"}, "user": {"id": "other"}}, False),
    ({"scope": {"system": {"all": "true"}}, "role": {"id": "admin-id"}, "user": {"id": "user-a"}}, False),
    ({}, False),
])
def test_system_admin_requires_exact_effective_system_assignment(monkeypatch, document, expected):
    client = MagicMock()
    client.roles.list.return_value = [SimpleNamespace(name="admin", id="admin-id", domain_id=None)]
    client.role_assignments.list.return_value = [_assignment(document)]
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    assert auth._is_system_admin("user-a") is expected
    client.role_assignments.list.assert_called_once_with(user="user-a", role="admin-id", system="all", effective=True)


@pytest.mark.parametrize("roles", [
    [], [SimpleNamespace(name="admin", id="domain-admin", domain_id="domain-a")],
    [SimpleNamespace(name="admin", id="one", domain_id=None), SimpleNamespace(name="admin", id="two", domain_id=None)],
    [SimpleNamespace(name="manager", id="manager-id", domain_id=None)],
])
def test_system_admin_role_resolution_rejects_ambiguous_or_domain_roles(monkeypatch, roles):
    client = MagicMock()
    client.roles.list.return_value = roles
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    assert auth._is_system_admin("user-a") is False
    client.role_assignments.list.assert_not_called()


def _owner_directory(enabled=True, roles=("member",), project="project-a", identity="user-a"):
    names = {"member", "reader", "admin", "manager"}
    client = MagicMock()
    client.users.get.return_value = SimpleNamespace(id=identity, enabled=enabled)
    client.roles.list.return_value = [
        SimpleNamespace(to_dict=lambda name=name: {"id": "role-" + name, "name": name}) for name in sorted(names)
    ]
    client.inference_rules.list_inference_roles.return_value = []
    client.role_assignments.list.side_effect = lambda **kwargs: [
        _assignment({"user": {"id": kwargs["user"]}, "scope": {"project": {"id": kwargs["project"]}},
                     "role": {"id": "role-" + role}})
        for role in roles
    ] if kwargs["project"] == project else []
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled,roles,project,expected", [
    (True, ("member",), "project-a", True),
    (False, ("member",), "project-a", False),
    (None, ("member",), "project-a", False),
    (1, ("member",), "project-a", False),
    (True, ("reader",), "project-a", False),
    (True, ("member", "admin"), "project-a", False),
    (True, ("member",), "project-b", False),
])
async def test_owner_requires_enabled_effective_native_member(monkeypatch, enabled, roles, project, expected):
    client = _owner_directory(enabled=enabled, roles=roles, project=project)
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    if expected:
        await auth.validate_client_owner("project-a", "user-a")
    else:
        with pytest.raises(HTTPException) as error:
            await auth.validate_client_owner("project-a", "user-a")
        assert error.value.status_code == 422
    if enabled is True:
        client.role_assignments.list.assert_called_once_with(user="user-a", project="project-a", effective=True)
    else:
        client.role_assignments.list.assert_not_called()


@pytest.mark.asyncio
async def test_owner_unknown_wrong_identity_and_unavailable_directory_fail_closed(monkeypatch):
    from keystoneauth1.exceptions.http import NotFound

    client = _owner_directory(identity="other")
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    with pytest.raises(HTTPException) as error:
        await auth.validate_client_owner("project-a", "user-a")
    assert error.value.status_code == 422
    client.role_assignments.list.assert_not_called()
    client.users.get.side_effect = NotFound()
    with pytest.raises(HTTPException) as error:
        await auth.validate_client_owner("project-a", "user-a")
    assert error.value.status_code == 422
    client.users.get.side_effect = RuntimeError("directory unavailable")
    with pytest.raises(HTTPException) as error:
        await auth.validate_client_owner("project-a", "user-a")
    assert error.value.status_code == 503
    client.users.get.reset_mock()
    await auth.validate_client_owner("project-a", None)
    client.users.get.assert_not_called()


@pytest.fixture
def synthetic_keystone():
    """A real local v3 HTTP issuer used by keystoneauth1.identity.v3.Token."""
    tokens = {}
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def send_document(self, status, document, subject=None):
            body = json.dumps(document).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if subject:
                self.send_header("X-Subject-Token", subject)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.send_document(200, {"version": {
                "id": "v3.13", "status": "stable", "updated": "2026-01-01T00:00:00Z",
                "links": [{"rel": "self", "href": issuer.auth_url + "/"}],
                "media-types": [{"base": "application/json", "type": "application/vnd.openstack.identity-v3+json"}],
            }})

        def do_POST(self):
            document = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            credential = document["auth"]["identity"]["token"]["id"]
            requests.append(document)
            identity = tokens.get(credential)
            if self.path.rstrip("/") != "/v3/auth/tokens" or identity is None:
                self.send_document(401, {"error": {"message": "Invalid synthetic token", "code": 401}})
                return
            self.send_document(201, {"token": {
                "methods": ["token"], "expires_at": "2099-01-01T00:00:00Z",
                "issued_at": "2026-01-01T00:00:00Z", "audit_ids": ["synthetic-audit"],
                "user": {"id": identity["user_id"], "name": identity["user_id"],
                         "domain": {"id": "default", "name": "Default"}},
                "project": {"id": identity["project_id"], "name": identity["project_id"],
                            "domain": {"id": "default", "name": "Default"}},
                "roles": [{"id": "role-" + role, "name": role} for role in identity["roles"]],
                "catalog": [],
            }}, subject="reissued-" + credential)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    issuer = SimpleNamespace(auth_url=f"http://127.0.0.1:{server.server_port}/v3", tokens=tokens, requests=requests)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield issuer
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.fixture
async def native_http(tmp_path, monkeypatch, synthetic_keystone):
    """Persistent SQL, main application startup, real token validation and owner checks."""
    import waygate.main as main

    database_path = tmp_path / "native-grades.sqlite"
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{database_path}", os_auth_url=synthetic_keystone.auth_url,
        waygate_callback_base_url="https://callbacks.example.test", waygate_encryption_key="a" * 64,
    )
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(db, "_engine", None)
    monkeypatch.setattr(db, "_session_factory", None)
    directory = MagicMock()
    enabled = {"user-a": True, "user-b": True, "disabled-user": False}
    memberships = {"user-a": "project-a", "user-b": "project-a", "disabled-user": "project-a"}
    current_roles = {}
    role_names = set(CAPABILITIES) | set(PARENTS) | {"member", "reader", "admin", "manager"}
    graph = {parent: list(leaves) for parent, leaves in PARENTS.items()}

    def role_record(name):
        role_id = "admin-id" if name == "admin" else "role-" + name
        return SimpleNamespace(id=role_id, name=name, domain_id=None,
                               to_dict=lambda: {"id": role_id, "name": name})

    directory.roles.list.side_effect = lambda **kwargs: [
        role_record(name) for name in sorted(role_names) if not kwargs.get("name") or name == kwargs["name"]
    ]
    directory.inference_rules.list_inference_roles.side_effect = lambda: [
        {"prior_role": {"id": "role-" + parent}, "implies": [{"id": "role-" + leaf} for leaf in leaves]}
        for parent, leaves in graph.items()
    ]
    directory.users.get.side_effect = lambda user_id: SimpleNamespace(id=user_id, enabled=enabled.get(user_id, False))

    def assignments(**kwargs):
        if "system" in kwargs:
            return []
        project_id = kwargs["project"]
        if memberships.get(kwargs["user"]) != project_id:
            return []
        roles = current_roles.get((kwargs["user"], project_id), ["member"])
        return [_assignment({
            "user": {"id": kwargs["user"]}, "scope": {"project": {"id": project_id}},
            "role": {"id": role_record(role).id},
        }) for role in roles]

    directory.role_assignments.list.side_effect = assignments
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: directory)
    # Never override require_token or the capability dependencies.
    monkeypatch.setattr(app, "dependency_overrides", {})
    schema_engine = create_async_engine(settings.database_url)
    try:
        async with schema_engine.begin() as connection:
            await connection.run_sync(db.Base.metadata.create_all)
    finally:
        await schema_engine.dispose()

    async with app.router.lifespan_context(app):
        private_key, public_key = waygate_keys.generate_keypair()
        psk = waygate_keys.generate_preshared_key()
        async with db.get_session_factory()() as session:
            session.add_all([
                WaygateServer(id="server-a", project_id="project-a", name="gateway-a", status="ACTIVE",
                              status_reason=SECRET_REASON, endpoint_ip="203.0.113.10", server_public_key=public_key,
                              resource_policy_snapshot={"secret": "snapshot-secret-sentinel"}),
                WaygateServer(id="server-b", project_id="project-b", name="gateway-b", status="ACTIVE",
                              endpoint_ip="203.0.113.20", server_public_key=public_key),
                WaygateServer(id="import-target", project_id="project-a", name="import-target", status="ACTIVE",
                              endpoint_ip="203.0.113.30", server_public_key=public_key),
            ])
            await session.flush()
            for client_id, owner, active, ip in [
                ("own", "user-a", True, "10.8.0.2"), ("other", "user-b", True, "10.8.0.3"),
                ("legacy", None, True, "10.8.0.4"), ("disabled", "user-a", False, "10.8.0.5"),
            ]:
                session.add(WaygateClient(
                    id=client_id, server_id="server-a", project_id="project-a", name=client_id,
                    owner_user_id=owner, enabled=active, public_key=public_key, tunnel_ip=ip,
                    private_key_encrypted=k3s_crypto.encrypt_wg_client_key(private_key),
                    preshared_key_encrypted=k3s_crypto.encrypt_wg_client_key(psk), allowed_ips=["10.8.0.0/24"],
                ))
            await session.commit()
        agent_token = await waygate_agent_auth.issue_report_token("server-a")

        def headers(roles, user_id="user-a", project_id="project-a"):
            credential = f"native-{len(synthetic_keystone.tokens)}"
            synthetic_keystone.tokens[credential] = {"roles": roles, "user_id": user_id, "project_id": project_id}
            role_names.update(roles)
            current_roles[user_id, project_id] = list(roles)
            memberships[user_id] = project_id
            return {"X-Auth-Token": credential}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://native.test") as client:
            yield SimpleNamespace(
                client=client, headers=headers, keystone=synthetic_keystone, directory=directory,
                enabled=enabled, memberships=memberships, path=database_path, settings=settings,
                private_key=private_key, psk=psk, agent_token=agent_token,
                current_roles=current_roles, graph=graph, role_names=role_names,
            )


@pytest.fixture
def delegated(monkeypatch):
    """Grade checks stop at the Keystone Trust boundary covered natively in test_execution_delegation."""
    from dataclasses import replace

    from waygate.services import execution

    conn = MagicMock()
    purposes = []

    def create_trust(_token, grant):
        purposes.append(grant.purpose)
        return replace(grant, trust_id="trust-" + grant.id, trustee_user_id="waygate-service", role_id="role-member")

    monkeypatch.setattr(execution, "_create_trust", create_trust)
    monkeypatch.setattr(execution, "_open_connection", lambda _grant: conn)
    monkeypatch.setattr(execution, "_close_connection", lambda _conn: None)
    monkeypatch.setattr(execution, "_revoke_trust", lambda *_args: None)
    return SimpleNamespace(conn=conn, purposes=purposes)


@pytest.mark.asyncio
@pytest.mark.parametrize("roles", [
    ["member"], ["reader"], ["admin"], ["manager"], ["waygate_admin"],
    ["reader", "waygate-clients_editor"], ["member", "admin", "waygate_admin"],
    ["member", "manager", "waygate_admin"],
])
async def test_registered_routes_deny_plain_service_only_and_raw_platform_roles(native_http, roles):
    headers = native_http.headers(roles)
    for method, path, body in [
        ("GET", "/v1/servers", None), ("GET", CLIENT + "/config", None),
        ("POST", "/v1/servers", {"name": "gateway"}),
        ("POST", SERVER + "/clients", {"name": "client"}),
        ("PATCH", CLIENT, {"name": "renamed"}), ("PATCH", SERVER, {"dns": "9.9.9.9"}),
    ]:
        response = await native_http.client.request(method, path, json=body, headers=headers)
        assert response.status_code == 403
        assert native_http.keystone.requests[-1]["auth"]["identity"]["methods"] == ["token"]


@pytest.mark.asyncio
@pytest.mark.parametrize("roles", [["reader", "waygate_reader"], ["member", "waygate-inventory_reader"]])
async def test_reader_metadata_excludes_credentials_and_provider_reason(native_http, roles):
    headers = native_http.headers(roles)
    for path in ("/v1/servers", SERVER, SERVER + "/clients", SERVER + "/networks"):
        response = await native_http.client.get(path, headers=headers)
        assert response.status_code == 200
        serialized = response.text
        for secret in (native_http.private_key, native_http.psk, native_http.agent_token,
                       SECRET_REASON, "snapshot-secret-sentinel"):
            assert secret not in serialized
        for forbidden in ("private_key", "preshared_key_encrypted", "agent_token_encrypted", "tunnel_conf",
                          "resource_policy_snapshot", "bootstrap_token"):
            assert forbidden not in serialized
    denied = await native_http.client.get(CLIENT + "/config", headers=headers)
    assert denied.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["waygate_user", "waygate-connect_user"])
async def test_connect_downloads_only_assigned_enabled_own_profile_before_decryption(native_http, monkeypatch, role):
    headers = native_http.headers(["member", role])
    response = await native_http.client.get(CLIENT + "/config", headers=headers)
    assert response.status_code == 200
    assert "PrivateKey = " + native_http.private_key in response.text
    assert "PresharedKey = " + native_http.psk in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "attachment;" in response.headers["content-disposition"]
    decrypt = MagicMock(side_effect=AssertionError("unauthorized profile must not decrypt"))
    monkeypatch.setattr(k3s_crypto, "decrypt_wg_client_key", decrypt)
    for client_id in ("other", "legacy", "disabled"):
        response = await native_http.client.get(SERVER + f"/clients/{client_id}/config", headers=headers)
        assert response.status_code == 403
    decrypt.assert_not_called()
    assert (await native_http.client.patch(CLIENT, json={"name": "renamed"}, headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["waygate_admin", "waygate-clients_editor", "waygate-clients_admin"])
async def test_service_administration_never_downloads_foreign_or_unassigned_private_profiles(native_http, monkeypatch, role):
    headers = native_http.headers(["member", role])
    decrypt = MagicMock(side_effect=AssertionError("foreign private profile must not decrypt"))
    monkeypatch.setattr(k3s_crypto, "decrypt_wg_client_key", decrypt)
    for client_id in ("other", "legacy"):
        response = await native_http.client.get(SERVER + f"/clients/{client_id}/config", headers=headers)
        assert response.status_code == 403
    decrypt.assert_not_called()


@pytest.mark.asyncio
async def test_verified_system_admin_never_downloads_another_members_profile(native_http):
    native_http.directory.role_assignments.list.side_effect = lambda **kwargs: [_assignment({
        "scope": {"system": {"all": True}}, "role": {"id": "admin-id"}, "user": {"id": "system-user"},
    })] if "system" in kwargs else []
    headers = native_http.headers(["admin"], user_id="system-user")
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_create_for_another_or_unassigned_owner_returns_no_private_profile(native_http):
    headers = native_http.headers(["member", "waygate_admin"])
    for owner in ("user-b", None):
        created = await native_http.client.post(
            SERVER + "/clients", json={"name": f"for-{owner or 'nobody'}", "owner_user_id": owner}, headers=headers,
        )
        assert created.status_code == 201
        assert created.json()["tunnel_conf"] is None
        assert "PrivateKey" not in created.text and "PresharedKey" not in created.text


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["waygate_editor", "waygate-clients_editor"])
async def test_editor_creates_updates_and_persists_default_and_explicit_owner(native_http, role):
    headers = native_http.headers(["member", role])
    created = await native_http.client.post(SERVER + "/clients", json={"name": "new-client"}, headers=headers)
    assert created.status_code == 201
    assert created.headers["cache-control"] == "no-store"
    assert created.json()["owner_user_id"] == "user-a"
    async with db.get_session_factory()() as session:
        record = await session.get(WaygateClient, created.json()["id"])
        stored_private = k3s_crypto.decrypt_wg_client_key(record.private_key_encrypted)
        assert stored_private not in record.private_key_encrypted
        if role == "waygate_editor":
            assert "PrivateKey = " + stored_private in created.json()["tunnel_conf"]
        else:
            assert created.json()["tunnel_conf"] is None
    native_http.directory.role_assignments.list.assert_any_call(user="user-a", project="project-a", effective=True)
    unassigned = await native_http.client.post(
        SERVER + "/clients", json={"name": "unassigned-new", "owner_user_id": None}, headers=headers,
    )
    assert unassigned.status_code == 201
    assert (unassigned.json()["owner_user_id"], unassigned.json()["tunnel_conf"]) == (None, None)
    client_id = unassigned.json()["id"]
    assigned = await native_http.client.patch(
        SERVER + f"/clients/{client_id}", json={"name": "renamed", "owner_user_id": "user-b"}, headers=headers,
    )
    assert assigned.status_code == 200 and assigned.json()["owner_user_id"] == "user-b"
    assert "tunnel_conf" not in assigned.json()
    # A known owner cannot be transferred (to the editor) or cleared.
    transfer = await native_http.client.patch(
        SERVER + f"/clients/{client_id}", json={"owner_user_id": "user-a"}, headers=headers,
    )
    assert transfer.status_code == 409
    cleared = await native_http.client.patch(SERVER + f"/clients/{client_id}", json={"owner_user_id": None}, headers=headers)
    assert cleared.status_code == 422
    assert (await native_http.client.patch(
        SERVER + f"/clients/{client_id}", json={"enabled": True}, headers=headers,
    )).status_code == 403
    assert native_http.path.is_file()
    # Reopen an independent connection: this is durable assignment, not a fake in-memory store.
    reopened = create_async_engine(native_http.settings.database_url)
    try:
        async with reopened.connect() as connection:
            assert (await connection.execute(
                select(WaygateClient.name, WaygateClient.owner_user_id).where(WaygateClient.id == client_id)
            )).one() == ("renamed", "user-b")
    finally:
        await reopened.dispose()
    # Also dispose the application's pool and reconnect without rebuilding its schema.
    await db.close_db()
    db.init_db(native_http.settings.database_url)
    assert (await waygate_db.get_client("server-a", "project-a", client_id))["owner_user_id"] == "user-b"
    user_headers = native_http.headers(["member", "waygate_user"], user_id="user-b")
    assert (await native_http.client.get(SERVER + f"/clients/{client_id}/config", headers=user_headers)).status_code == 200
    creator_headers = native_http.headers(["member", "waygate_user"])
    assert (await native_http.client.get(SERVER + f"/clients/{client_id}/config", headers=creator_headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("owner", ["disabled-user", "unknown-user", "foreign-user", "removed-user"])
async def test_create_and_patch_reject_invalid_owner_without_persisting(native_http, owner):
    native_http.enabled.update({"foreign-user": True, "removed-user": True})
    native_http.memberships["foreign-user"] = "project-b"
    headers = native_http.headers(["member", "waygate_editor"])
    before = await waygate_db.list_clients("server-a", "project-a")
    created = await native_http.client.post(
        SERVER + "/clients", json={"name": "invalid-owner", "owner_user_id": owner}, headers=headers,
    )
    assert created.status_code == 422
    updated = await native_http.client.patch(CLIENT, json={"owner_user_id": owner}, headers=headers)
    assert updated.status_code == 422
    assert (await waygate_db.get_client("server-a", "project-a", "own"))["owner_user_id"] == "user-a"
    assert len(await waygate_db.list_clients("server-a", "project-a")) == len(before)


@pytest.mark.asyncio
async def test_owner_directory_failure_on_create_and_patch_fails_closed(native_http):
    headers = native_http.headers(["member", "waygate_editor"])
    native_http.directory.users.get.side_effect = RuntimeError("synthetic directory offline")
    assert (await native_http.client.patch(CLIENT, json={"owner_user_id": "user-b"}, headers=headers)).status_code == 503
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "new"}, headers=headers)).status_code == 503
    assert (await waygate_db.get_client("server-a", "project-a", "own"))["owner_user_id"] == "user-a"


PRIVILEGED_ACTIONS = [
    ("PATCH", "/clients/own", {"enabled": False}),
    ("DELETE", "/clients/own", None),
    ("DELETE", "", None),
    ("POST", "/agent-token/rotate", None),
    ("POST", "/networks", {"network_id": NETWORK_ID}),
    ("DELETE", "/networks/1", None),
    ("POST", "/export", {"passphrase": "synthetic-passphrase"}),
    ("POST", "/import", {"passphrase": "synthetic-passphrase", "bundle": {"version": 1, "clients": []}}),
    ("PATCH", "/clients/disabled", {"enabled": True}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,suffix,body", PRIVILEGED_ACTIONS)
async def test_editor_denied_revocation_deletion_rotation_routing_and_bundles(native_http, method, suffix, body):
    response = await native_http.client.request(
        method, SERVER + suffix, json=body, headers=native_http.headers(["member", "waygate_editor"]),
    )
    assert response.status_code == 403
    assert (await waygate_db.get_client("server-a", "project-a", "own"))["enabled"] is True
    assert (await waygate_db.get_server("project-a", "server-a"))["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_gateway_editor_creates_and_updates_without_cloud_provisioning(native_http, monkeypatch, delegated):
    from waygate.services import resource_policies

    snapshot = {key: {"id": key + "-id"} for key in ("waygate.flavor", "waygate.image", "waygate.provider_network")}
    resolve = AsyncMock(return_value=snapshot)
    monkeypatch.setattr(resource_policies, "resolve_policy_snapshot", resolve)
    monkeypatch.setattr(resource_policies, "get_policy_snapshot", AsyncMock(return_value={"waygate.floating_network": None}))
    headers = native_http.headers(["member", "waygate-gateways_editor"])
    response = await native_http.client.post("/v1/servers", json={"name": "new-gateway"}, headers=headers)
    assert response.status_code == 201
    assert response.json()["status"] == "CREATING"
    assert (await waygate_db.get_server("project-a", response.json()["id"]))["name"] == "new-gateway"
    assert delegated.purposes == ["provision"] and resolve.await_args.kwargs["conn"] is delegated.conn
    updated = await native_http.client.patch(SERVER, json={"dns": "9.9.9.9", "persistent_keepalive": 0}, headers=headers)
    assert updated.status_code == 200
    assert (updated.json()["dns"], updated.json()["persistent_keepalive"]) == ("9.9.9.9", 0)
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "wrong-leaf"}, headers=headers)).status_code == 403
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("method,suffix,body", PRIVILEGED_ACTIONS + [
    ("GET", "", None), ("PATCH", "", {"dns": "9.9.9.9"}),
    ("GET", "/clients", None), ("GET", "/clients/own/config", None),
    ("POST", "/clients", {"name": "foreign"}), ("PATCH", "/clients/own", {"owner_user_id": "user-a"}),
    ("GET", "/networks", None),
])
async def test_service_admin_remains_project_bound_for_every_resource_route(native_http, method, suffix, body):
    headers = native_http.headers(["member", "waygate_admin"], project_id="project-b")
    response = await native_http.client.request(method, SERVER + suffix, json=body, headers=headers)
    assert response.status_code == 404
    assert (await waygate_db.get_client("server-a", "project-a", "own"))["owner_user_id"] == "user-a"
    assert (await waygate_db.get_client("server-a", "project-a", "own"))["enabled"] is True
    assert (await waygate_db.get_server("project-a", "server-a"))["status"] == "ACTIVE"


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", [
    ("GET", "/v1/admin/resource-policies", None),
    ("GET", "/v1/admin/resource-policies/catalog/waygate.image", None),
    ("PUT", "/v1/admin/resource-policies/waygate.image", {"resource_id": "image-a"}),
])
async def test_service_admin_cannot_access_global_policies(native_http, method, path, body):
    response = await native_http.client.request(
        method, path, json=body, headers=native_http.headers(["member", "waygate_admin"]),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_service_admin_revokes_and_rotates_but_does_not_leak_credentials(native_http):
    headers = native_http.headers(["member", "waygate_admin"])
    disabled = await native_http.client.patch(CLIENT, json={"enabled": False}, headers=headers)
    assert disabled.status_code == 200 and disabled.json()["enabled"] is False
    deleted = await native_http.client.delete(SERVER + "/clients/other", headers=headers)
    assert deleted.status_code == 204
    assert await waygate_db.get_client("server-a", "project-a", "other") is None
    rotated = await native_http.client.post(SERVER + "/agent-token/rotate", headers=headers)
    assert rotated.status_code == 202
    assert rotated.json()["agent_token_rotation_pending"] is True
    assert native_http.agent_token not in rotated.text
    assert "agent_token_next_encrypted" not in rotated.text


@pytest.mark.asyncio
async def test_legacy_and_imported_owners_remain_unassigned(native_http):
    headers = native_http.headers(["member", "waygate_admin"])
    exported = await native_http.client.post(SERVER + "/export", json={"passphrase": "synthetic-passphrase"}, headers=headers)
    assert exported.status_code == 200
    bundle = exported.json()
    assert all("owner_user_id" not in entry for entry in bundle["clients"])
    # An external bundle must not confer ownership, even if a caller adds a user ID.
    for entry in bundle["clients"]:
        entry["owner_user_id"] = "user-a"
    imported = await native_http.client.post(
        "/v1/servers/import-target/import", json={"passphrase": "synthetic-passphrase", "bundle": bundle}, headers=headers,
    )
    assert imported.status_code == 200 and imported.json()["imported"] > 0
    clients = await waygate_db.list_clients("import-target", "project-a")
    assert clients and all(client["owner_user_id"] is None for client in clients)
    user_headers = native_http.headers(["member", "waygate_user"])
    for client in clients:
        response = await native_http.client.get(
            f"/v1/servers/import-target/clients/{client['id']}/config", headers=user_headers,
        )
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_real_token_validation_rechecks_roles_rejects_spoofed_headers_and_invalid_tokens(native_http):
    headers = native_http.headers(["member", "waygate_reader"])
    assert (await native_http.client.get("/v1/servers", headers=headers)).status_code == 200
    native_http.current_roles["user-a", "project-a"] = ["member"]
    headers["X-Roles"] = "member,waygate_admin"
    headers["X-User-Id"] = "user-b"
    assert (await native_http.client.get("/v1/servers", headers=headers)).status_code == 403
    assert len(native_http.keystone.requests) == 2
    assert (await native_http.client.get("/v1/servers", headers={"X-Auth-Token": "unknown"})).status_code == 401
    assert (await native_http.client.get("/v1/servers")).status_code == 401
    mismatch = native_http.headers(["member", "waygate_admin"])
    mismatch["X-Project-Id"] = "project-b"
    assert (await native_http.client.get("/v1/servers", headers=mismatch)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("method,suffix,body", [
    ("GET", "/desired-state", None),
    ("POST", "/register", {"public_key": "A" * 43 + "="}),
    ("POST", "/status", {"peers": []}),
])
async def test_machine_callbacks_retain_server_bound_durable_bearer_authority(native_http, method, suffix, body):
    path = SERVER + "/agent" + suffix
    tenant_headers = native_http.headers(["member", "waygate_admin"])
    assert (await native_http.client.request(method, path, json=body, headers=tenant_headers)).status_code == 401
    tenant_headers["Authorization"] = "Bearer " + tenant_headers["X-Auth-Token"]
    assert (await native_http.client.request(method, path, json=body, headers=tenant_headers)).status_code == 401
    machine_headers = {"Authorization": "Bearer " + native_http.agent_token}
    response = await native_http.client.request(method, path, json=body, headers=machine_headers)
    assert response.status_code == (200 if method == "GET" else 204)
    foreign = await native_http.client.request(method, "/v1/servers/server-b/agent" + suffix, json=body, headers=machine_headers)
    assert foreign.status_code == 401
    # Machine credentials cannot stand in for a tenant Keystone token.
    assert (await native_http.client.get("/v1/servers", headers=machine_headers)).status_code == 401
    assert (await native_http.client.get("/v1/servers", headers={"X-Auth-Token": native_http.agent_token})).status_code == 401
    if method == "GET":
        assert native_http.psk in response.text
        assert native_http.private_key not in response.text


@pytest.mark.asyncio
async def test_clients_admin_leaf_can_revoke_reenable_delete_but_cannot_edit_or_create(native_http):
    headers = native_http.headers(["member", "waygate-clients_admin"])
    revoked = await native_http.client.patch(CLIENT, json={"enabled": False}, headers=headers)
    assert revoked.status_code == 200 and revoked.json()["enabled"] is False
    restored = await native_http.client.patch(CLIENT, json={"enabled": True}, headers=headers)
    assert restored.status_code == 200 and restored.json()["enabled"] is True
    for body in ({"name": "renamed"}, {"owner_user_id": "user-b"}, {"enabled": False, "name": "renamed"}):
        assert (await native_http.client.patch(CLIENT, json=body, headers=headers)).status_code == 403
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "new"}, headers=headers)).status_code == 403
    assert (await native_http.client.post(SERVER + "/export", json={"passphrase": "synthetic-passphrase"}, headers=headers)).status_code == 403
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 204
    assert await waygate_db.get_client("server-a", "project-a", "own") is None


@pytest.mark.asyncio
async def test_combined_editor_and_admin_leaves_allow_atomic_edit_and_revoke(native_http):
    headers = native_http.headers(["member", "waygate-clients_editor", "waygate-clients_admin"])
    response = await native_http.client.patch(CLIENT, json={"name": "renamed", "enabled": False}, headers=headers)
    assert response.status_code == 200
    assert (response.json()["name"], response.json()["enabled"]) == ("renamed", False)


@pytest.mark.asyncio
async def test_gateway_admin_leaf_rotates_deletes_but_cannot_edit_or_create(native_http, delegated):
    headers = native_http.headers(["member", "waygate-gateways_admin"])
    assert (await native_http.client.post(SERVER + "/agent-token/rotate", headers=headers)).status_code == 202
    assert (await native_http.client.patch(SERVER, json={"dns": "9.9.9.9"}, headers=headers)).status_code == 403
    assert (await native_http.client.post("/v1/servers", json={"name": "new"}, headers=headers)).status_code == 403
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    deleted = await native_http.client.delete(SERVER, headers=headers)
    assert deleted.status_code == 202 and deleted.json()["status"] == "DELETING"
    assert (await waygate_db.get_server("project-a", "server-a"))["status"] == "DELETING"
    assert delegated.purposes == ["delete"]


@pytest.mark.asyncio
async def test_routing_leaf_attaches_detaches_but_has_no_inventory_or_bundle_authority(native_http, monkeypatch, delegated):
    from waygate.services import waygate_network

    attach = AsyncMock(return_value={
        "id": 1, "server_id": "server-a", "project_id": "project-a", "network_id": NETWORK_ID,
        "nat_mode": "snat", "status": "ACTIVE",
    })
    detach = AsyncMock()
    monkeypatch.setattr(waygate_network, "attach_network", attach)
    monkeypatch.setattr(waygate_network, "detach_network", detach)
    headers = native_http.headers(["member", "waygate-routing_admin"])
    assert (await native_http.client.post(SERVER + "/networks", json={"network_id": NETWORK_ID}, headers=headers)).status_code == 201
    assert (await native_http.client.delete(SERVER + "/networks/1", headers=headers)).status_code == 204
    assert attach.await_args.args[0] == "project-a" and attach.await_args.args[1]["id"] == "server-a"
    assert detach.await_args.args[0] == "project-a" and detach.await_args.args[2] == 1
    assert delegated.purposes == ["attach", "detach"]
    assert attach.await_args.kwargs["conn"] is detach.await_args.kwargs["conn"] is delegated.conn
    assert (await native_http.client.get(SERVER + "/networks", headers=headers)).status_code == 403
    assert (await native_http.client.post(SERVER + "/export", json={"passphrase": "synthetic-passphrase"}, headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_verified_system_admin_http_global_access_still_respects_project_ownership(native_http, monkeypatch):
    native_http.directory.role_assignments.list.side_effect = lambda **kwargs: [_assignment({
        "scope": {"system": {"all": True}}, "role": {"id": "admin-id"}, "user": {"id": "system-user"},
    })] if "system" in kwargs else []
    headers = native_http.headers(["admin"], user_id="system-user", project_id="project-b")
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 404
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 404
    assert (await native_http.client.delete(SERVER, headers=headers)).status_code == 404
    from waygate.api import resource_policies as policy_api

    conn = MagicMock()
    inspect = AsyncMock(return_value=[{"key": "waygate.image", "resource_id": "image-a"}])
    monkeypatch.setattr(policy_api, "_admin_connection", lambda: conn)
    monkeypatch.setattr(policy_api.resource_policies, "inspect_policies", inspect)
    response = await native_http.client.get("/v1/admin/resource-policies", headers=headers)
    assert response.status_code == 200
    inspect.assert_awaited_once_with(conn)
    conn.close.assert_called_once()


@pytest.mark.asyncio
async def test_default_owner_requires_current_creator_membership(native_http):
    headers = native_http.headers(["member", "waygate_editor"])
    native_http.memberships.pop("user-a")
    response = await native_http.client.post(
        SERVER + "/clients", json={"name": "removed-creator"}, headers=headers,
    )
    assert response.status_code == 403
    assert not any(client["name"] == "removed-creator" for client in await waygate_db.list_clients("server-a", "project-a"))


@pytest.mark.asyncio
async def test_unscoped_keystone_identity_is_rejected(native_http):
    headers = native_http.headers(["member", "waygate_admin"], project_id="")
    assert (await native_http.client.get("/v1/servers", headers=headers)).status_code == 401


@pytest.mark.asyncio
async def test_machine_auth_remains_db_authoritative_after_tenant_grade_change(native_http):
    headers = native_http.headers(["member", "waygate_admin"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    native_http.current_roles["user-a", "project-a"] = ["member"]
    machine = {"Authorization": "Bearer " + native_http.agent_token}
    path = SERVER + "/agent/desired-state"
    assert (await native_http.client.get(path, headers=machine)).status_code == 200
    await waygate_agent_auth.revoke_report_token_by_server("server-a")
    assert (await native_http.client.get(path, headers=machine)).status_code == 401
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_reader_base_with_admin_entitlement_only_grants_inventory(native_http):
    headers = native_http.headers(["reader", "waygate_admin"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    for method, path, body in [
        ("GET", CLIENT + "/config", None),
        ("POST", SERVER + "/clients", {"name": "new"}),
        ("PATCH", CLIENT, {"enabled": False}), ("DELETE", CLIENT, None),
        ("POST", SERVER + "/agent-token/rotate", None),
    ]:
        assert (await native_http.client.request(method, path, json=body, headers=headers)).status_code == 403


@pytest.mark.parametrize("failure", ["role-resolution", "assignment-read"])
def test_system_admin_directory_errors_fail_closed(monkeypatch, failure):
    client = MagicMock()
    client.roles.list.return_value = [SimpleNamespace(name="admin", id="admin-id", domain_id=None)]
    if failure == "role-resolution":
        client.roles.list.side_effect = RuntimeError("directory unavailable")
    else:
        client.role_assignments.list.side_effect = RuntimeError("directory unavailable")
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    assert auth._is_system_admin("user-a") is False


@pytest.mark.asyncio
async def test_owner_assignment_rechecks_membership_and_enabled_state_on_each_patch(native_http):
    headers = native_http.headers(["member", "waygate_editor"])
    legacy = SERVER + "/clients/legacy"
    native_http.memberships.pop("user-b")
    assert (await native_http.client.patch(legacy, json={"owner_user_id": "user-b"}, headers=headers)).status_code == 422
    native_http.memberships["user-b"] = "project-a"
    native_http.enabled["user-b"] = False
    assert (await native_http.client.patch(legacy, json={"owner_user_id": "user-b"}, headers=headers)).status_code == 422
    native_http.current_roles["user-b", "project-a"] = ["reader"]
    native_http.enabled["user-b"] = True
    assert (await native_http.client.patch(legacy, json={"owner_user_id": "user-b"}, headers=headers)).status_code == 422
    assert (await waygate_db.get_client("server-a", "project-a", "legacy"))["owner_user_id"] is None
    native_http.current_roles["user-b", "project-a"] = ["member"]
    assert (await native_http.client.patch(legacy, json={"owner_user_id": "user-b"}, headers=headers)).status_code == 200
    assert (await waygate_db.get_client("server-a", "project-a", "legacy"))["owner_user_id"] == "user-b"


@pytest.mark.parametrize("parent", PARENTS)
def test_parent_label_alone_never_restores_missing_graph_edges(parent):
    assert not any(auth.has_capability({"roles": ["member", parent]}, cap) for cap in CAPABILITIES)


@pytest.mark.asyncio
async def test_current_graph_removal_denies_old_token_without_changing_its_parent(native_http):
    headers = native_http.headers(["member", "waygate_admin"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    native_http.graph["waygate_admin"] = []
    assert native_http.keystone.tokens[headers["X-Auth-Token"]]["roles"] == ["member", "waygate_admin"]
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 403
    native_http.graph["waygate_admin"] = ["waygate-inventory_reader"]
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["catalog", "inferences", "assignments"])
async def test_current_authority_lookup_failure_never_uses_token_bundle(native_http, failure):
    headers = native_http.headers(["member", "waygate_admin"])
    target = {
        "catalog": native_http.directory.roles.list,
        "inferences": native_http.directory.inference_rules.list_inference_roles,
        "assignments": native_http.directory.role_assignments.list,
    }[failure]
    target.side_effect = RuntimeError("synthetic authority unavailable")
    response = await native_http.client.get(SERVER, headers=headers)
    # Provider outage is not session expiry: 503, never 401 and never a token-claim fallback.
    assert response.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["unknown", "cycle", "unsafe", "domain", "ambiguous"])
async def test_invalid_current_graph_fails_closed(native_http, kind):
    headers = native_http.headers(["member", "waygate_admin"])
    if kind == "unknown":
        native_http.graph["waygate_admin"] = ["unregistered-leaf"]
    elif kind == "cycle":
        native_http.graph["waygate_admin"] = ["waygate_admin"]
    elif kind == "unsafe":
        native_http.graph["waygate_admin"] = ["member"]
    else:
        original = native_http.directory.roles.list.side_effect

        def catalog(**kwargs):
            records = original(**kwargs)
            if not kwargs:
                role = {"id": "role-waygate_admin", "name": "waygate_admin", "domain_id": "domain-a"}
                if kind == "ambiguous":
                    role = {"id": "duplicate-id", "name": "waygate_admin"}
                    records.append(_assignment(role))
                else:
                    records = [_assignment(role) if record.id == role["id"] else record for record in records]
            return records

        native_http.directory.roles.list.side_effect = catalog
    response = await native_http.client.get(SERVER, headers=headers)
    assert response.status_code == (503 if kind == "unknown" else 403)


@pytest.mark.asyncio
async def test_current_graph_transitive_parent_edges_are_resolved(native_http):
    native_http.graph["waygate_admin"] = ["waygate_editor"]
    native_http.graph["waygate_editor"] = ["waygate_user"]
    native_http.graph["waygate_user"] = ["waygate_reader"]
    headers = native_http.headers(["member", "waygate_admin"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("prior", ["waygate_reader", "waygate_user", "waygate-inventory_reader", "waygate-connect_user"])
async def test_lower_service_grade_cannot_reach_privileged_leaf(native_http, prior):
    native_http.graph[prior] = ["waygate-clients_admin"]
    headers = native_http.headers(["member", prior])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_nonreader_leaf_can_use_current_inventory_dependency_without_broadening_write_authority(native_http):
    native_http.graph["waygate-connect_user"] = ["waygate_reader"]
    headers = native_http.headers(["member", "waygate-connect_user"])
    assert (await native_http.client.get(SERVER + "/clients", headers=headers)).status_code == 200
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 200
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_admin_export_skips_foreign_owned_keys_before_decryption(native_http, monkeypatch):
    headers = native_http.headers(["member", "waygate_admin"])
    original = k3s_crypto.decrypt_wg_client_key
    foreign = await waygate_db.get_client("server-a", "project-a", "other")
    calls = []

    def decrypt(ciphertext):
        calls.append(ciphertext)
        return original(ciphertext)

    monkeypatch.setattr(k3s_crypto, "decrypt_wg_client_key", decrypt)
    response = await native_http.client.post(
        SERVER + "/export", json={"passphrase": "synthetic-passphrase"}, headers=headers,
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert {entry["name"] for entry in response.json()["clients"]} == {"own", "legacy", "disabled"}
    assert foreign["private_key_encrypted"] not in calls
    assert foreign["preshared_key_encrypted"] not in calls
    assert response.json()["export_scope"] == "caller_owned_and_unassigned_profiles"
    assert response.json()["excluded_assigned_client_count"] == 1
    assert response.json()["excluded_assigned_client_ids"] == ["other"]


@pytest.mark.asyncio
async def test_editor_leaf_without_connect_never_receives_issued_private_profile(native_http, monkeypatch):
    from waygate.api import clients as client_api

    headers = native_http.headers(["member", "waygate-clients_editor", "waygate-inventory_reader"])
    render = MagicMock(side_effect=AssertionError("editor-only cannot render a usable profile"))
    decrypt = MagicMock(side_effect=AssertionError("editor-only cannot decrypt a profile"))
    monkeypatch.setattr(client_api.waygate_config, "render_client_conf", render)
    monkeypatch.setattr(k3s_crypto, "decrypt_wg_client_key", decrypt)
    response = await native_http.client.post(SERVER + "/clients", json={"name": "editor-owned"}, headers=headers)
    assert response.status_code == 201
    assert response.json()["owner_user_id"] == "user-a"
    assert response.json()["tunnel_conf"] is None
    assert "PrivateKey" not in response.text and "PresharedKey" not in response.text
    assert (await native_http.client.get(
        SERVER + f"/clients/{response.json()['id']}/config", headers=headers,
    )).status_code == 403
    render.assert_not_called()
    decrypt.assert_not_called()


@pytest.mark.asyncio
async def test_editor_parent_loses_issuance_authority_when_current_connect_edge_is_removed(native_http):
    native_http.graph["waygate_editor"].remove("waygate-connect_user")
    headers = native_http.headers(["member", "waygate_editor"])
    response = await native_http.client.post(SERVER + "/clients", json={"name": "missing-connect"}, headers=headers)
    assert response.status_code == 201
    assert response.json()["tunnel_conf"] is None


@pytest.mark.asyncio
async def test_unrelated_domain_inference_does_not_disable_global_project_authority(native_http):
    native_http.graph["domain-specific-parent"] = ["waygate-inventory_reader"]
    headers = native_http.headers(["member", "waygate_reader"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200


@pytest.mark.asyncio
async def test_assigned_domain_role_absent_from_global_catalog_denies_only_that_subject(native_http):
    headers = native_http.headers(["member", "waygate-inventory_reader"])
    native_http.current_roles["user-a", "project-a"].append("domain-specific-role")
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    other = native_http.headers(["member", "waygate-inventory_reader"], user_id="user-b")
    assert (await native_http.client.get(SERVER, headers=other)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("architecture", ["arm64", "amd64"])
@pytest.mark.skipif(os.environ.get("WAYGATE_NATIVE_CONTAINER_SMOKE") != "1", reason="Opt-in disposable Docker/MariaDB smoke")
async def test_native_built_images_and_mariadb_upgrade(architecture, monkeypatch):
    from native_container_smoke import run_container_smoke

    await run_container_smoke(architecture, PARENTS, CAPABILITIES, monkeypatch)
