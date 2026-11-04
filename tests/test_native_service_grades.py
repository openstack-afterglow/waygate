"""Standard project roles, persistent ownership and real Keystone-token HTTP regression definitions.

The application is the registered main.app, with its real lifespan and SQL store.
Only cloud discovery/admin directory data and Redis are synthetic: Keystone token
validation itself talks HTTP to a local v3 endpoint, with no dependency override.
System authority uses current raw user/group grants and a shared global role-ID DAG;
effective=True system queries return [] even when raw administrator grants exist.
All authority fixtures expose explicit complete native GET envelopes; SDK mock state
is fixture-internal mutation/failure input only. Incomplete collections are unavailable,
never positive authority or confirmed absence, including apparently empty raw grants.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

import pytest
import requests as http_requests
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from waygate import auth, db, policy
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
PROJECT_ROLES = {
    "reader": CAPABILITIES[:1],
    "member": CAPABILITIES,
    "manager": CAPABILITIES,
    "admin": CAPABILITIES,
}
LEGACY_ROLES = ("waygate_reader", "waygate_user", "waygate_editor", "waygate_admin", *CAPABILITIES)
SERVER = "/v1/servers/server-a"
CLIENT = SERVER + "/clients/own"
NETWORK_ID = "11111111-2222-3333-4444-555555555555"
SECRET_REASON = "provider-error-password=synthetic-secret-sentinel"


def _assignment(document):
    return SimpleNamespace(to_dict=lambda: document)


def _install_native_collections(client):
    """Keep injectable SDK state fixture-local; auth sees complete native GET envelopes only."""
    def get(path):
        parsed = urlsplit(path)
        query = parse_qs(parsed.query, strict_parsing=True)
        if parsed.path == "/roles":
            assert not query
            key = "roles"
            rows = [role.to_dict() for role in client.roles.list()]
        elif parsed.path == "/role_inferences":
            assert not query
            key = "role_inferences"
            rows = client.inference_rules.list_inference_roles()
        elif parsed.path.startswith("/users/") and parsed.path.endswith("/groups"):
            assert not query
            user_id = unquote(parsed.path[len("/users/"):-len("/groups")])
            key = "groups"
            rows = [{"id": group.id} for group in client.groups.list(user=user_id)]
        elif parsed.path == "/role_assignments":
            key = "role_assignments"
            if "scope.system" in query:
                principal = "user" if "user.id" in query else "group"
                expected_keys = {principal + ".id", "scope.system"}
                if "effective" in query:
                    expected_keys.add("effective")
                assert set(query) == expected_keys and query["scope.system"] == ["all"]
                kwargs = {principal: query[principal + ".id"][0], "system": "all"}
                if "effective" in query:
                    assert query["effective"] == ["True"]
                    kwargs["effective"] = True
            else:
                assert set(query) == {"user.id", "scope.project.id", "effective"}
                assert query["effective"] == ["True"]
                kwargs = {"user": query["user.id"][0], "project": query["scope.project.id"][0], "effective": True}
            assert all(len(values) == 1 for values in query.values())
            rows = [assignment.to_dict() for assignment in client.role_assignments.list(**kwargs)]
        else:
            raise AssertionError(f"Unexpected native directory GET: {path}")
        return None, {key: rows, "links": {"next": None}, "truncated": False}

    client.get.side_effect = get


INCOMPLETE_ENVELOPES = (
    "next", "false-next", "empty-next", "zero-next", "null-links", "list-links", "string-links",
    "missing-collection", "null-collection", "dict-collection", "string-collection",
    "null-row", "list-row", "string-row", "truncated", "zero-truncated", "string-truncated",
    "list-envelope", "null-envelope",
)


SYSTEM_COLLECTIONS = (
    ("/roles", "roles"), ("/role_inferences", "role_inferences"),
    ("/role_assignments?user.id=user-a&scope.system=all", "role_assignments"),
    ("/users/user-a/groups", "groups"),
    ("/role_assignments?group.id=group-a&scope.system=all", "role_assignments"),
)


def _incomplete_envelope(payload, key, defect):
    """Retain plausible authority rows alongside malformed native envelope metadata."""
    payload = dict(payload)
    if defect.endswith("-next") or defect == "next":
        payload["links"] = {"next": {
            "next": "/next-page", "false-next": False, "empty-next": "", "zero-next": 0,
        }[defect]}
    elif defect.endswith("-links"):
        payload["links"] = {"null-links": None, "list-links": [], "string-links": "invalid"}[defect]
    elif defect == "missing-collection":
        del payload[key]
    elif defect.endswith("-collection"):
        payload[key] = {"null-collection": None, "dict-collection": {}, "string-collection": "invalid"}[defect]
    elif defect.endswith("-row"):
        payload[key] = [*payload[key], {"null-row": None, "list-row": [], "string-row": "invalid"}[defect]]
    elif defect.endswith("truncated"):
        payload["truncated"] = {"truncated": True, "zero-truncated": 0, "string-truncated": "false"}[defect]
    elif defect == "list-envelope":
        return [payload]
    elif defect == "null-envelope":
        return None
    else:
        raise AssertionError(f"Unknown envelope defect: {defect}")
    return payload


def _corrupt_native_collection(client, path, key, defect):
    original = client.get.side_effect

    def get(request_path):
        response, payload = original(request_path)
        if request_path == path:
            payload = _incomplete_envelope(payload, key, defect)
        return response, payload

    client.get.side_effect = get


@pytest.mark.parametrize("role,expected", PROJECT_ROLES.items())
def test_standard_project_roles_project_internal_capability_labels(role, expected):
    token = {"project_id": "project-a", "roles": [role], "is_system_admin": False}
    assert set(policy.capabilities(token)["capabilities"]) == set(expected)


@pytest.mark.parametrize("legacy", LEGACY_ROLES)
def test_legacy_service_roles_are_not_default_assignable_authority(legacy):
    token = {"project_id": "project-a", "roles": [legacy], "is_system_admin": False}
    assert policy.capabilities(token)["capabilities"] == []
    assert not policy.allows(token, "waygate:unregistered:action")


@pytest.mark.parametrize("roles", [
    [], ["project_owner"], ["project_admin"], ["project_member"],
    ["waygate-admin"], ["waygate_admin_extra"], ["drover_admin"],
])
def test_alias_foreign_service_and_lookalike_roles_have_no_default_service_authority(roles):
    assert policy.capabilities({"project_id": "project-a", "roles": roles})["capabilities"] == []


@pytest.mark.parametrize("flag", [False, None, 1, "true"])
def test_global_admin_requires_verified_boolean(flag):
    assert not policy.allows({"roles": ["admin", "waygate_admin"], "is_system_admin": flag}, "waygate:resource-policy:list")


def test_verified_system_admin_has_selected_tenant_and_global_policy_authority():
    token = {"project_id": "project-a", "roles": [], "is_system_admin": True}
    assert set(policy.capabilities(token)["capabilities"]) == set(CAPABILITIES)
    assert policy.allows(token, "waygate:resource-policy:list")


def test_project_admin_is_not_system_admin():
    token = {"project_id": "project-a", "roles": ["admin"]}
    assert set(policy.capabilities(token)["capabilities"]) == set(CAPABILITIES)
    assert not policy.allows(token, "waygate:resource-policy:list")


def _system_directory(*, user_grants=(), groups=(), group_grants=None, roles=None, inferences=()):
    """Model raw grants: Keystone effective system listings deliberately return nothing."""
    client = MagicMock()
    client.groups.list.return_value = [SimpleNamespace(id=group_id) for group_id in groups]
    client.roles.list.return_value = [
        _assignment(role) for role in (roles if roles is not None else [
            {"id": "admin-id", "name": "admin"}, {"id": "manager-id", "name": "manager"},
        ])
    ]
    client.inference_rules.list_inference_roles.return_value = list(inferences)

    def assignments(**kwargs):
        if kwargs.get("effective") is True:
            return []
        if "user" in kwargs:
            documents = user_grants
        else:
            documents = (group_grants or {}).get(kwargs["group"], ())
        return [_assignment(document) for document in documents]

    client.role_assignments.list.side_effect = assignments
    _install_native_collections(client)
    return client


@pytest.mark.parametrize("principal", ["user", "group"])
@pytest.mark.parametrize("scope,subject,role_id,mixed_principal,expected", [
    ({"system": {"all": True}}, "exact", "admin-id", False, True),
    ({"project": {"id": "project-a"}}, "exact", "admin-id", False, False),
    ({"domain": {"id": "domain-a"}}, "exact", "admin-id", False, False),
    ({"system": {"all": True}, "project": {"id": "project-a"}}, "exact", "admin-id", False, False),
    ({"system": {"all": True}, "domain": {"id": "domain-a"}}, "exact", "admin-id", False, False),
    ({"system": {"all": True}}, "exact", "manager-id", False, False),
    ({"system": {"all": True}}, "foreign", "admin-id", False, False),
    ({"system": {"all": "true"}}, "exact", "admin-id", False, False),
    ({"system": {"all": 1}}, "exact", "admin-id", False, False),
    ({"system": {"all": True, "id": "extra"}}, "exact", "admin-id", False, False),
    ({"system": {"all": True}}, "exact", "admin-id", True, False),
    ({}, "exact", "admin-id", False, False),
])
def test_system_admin_requires_exact_raw_system_assignment(
    monkeypatch, principal, scope, subject, role_id, mixed_principal, expected,
):
    principal_id = "user-a" if principal == "user" else "group-a"
    document = {"scope": scope, "role": {"id": role_id},
                principal: {"id": principal_id if subject == "exact" else "foreign"}}
    if mixed_principal:
        document["group" if principal == "user" else "user"] = {"id": "other"}
    client = _system_directory(
        user_grants=[document] if principal == "user" else [], groups=["group-a"],
        group_grants={"group-a": [document]} if principal == "group" else {},
    )
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    assert auth._is_system_admin("user-a") is expected
    paths = [call.args[0] for call in client.get.call_args_list]
    assert paths[:3] == [
        "/role_assignments?user.id=user-a&scope.system=all", "/users/user-a/groups",
        "/role_assignments?group.id=group-a&scope.system=all",
    ]
    if expected:
        assert paths[3:] == ["/roles", "/role_inferences"]


@pytest.mark.parametrize("roles", [
    [], [{"name": "admin", "id": "domain-admin", "domain_id": "domain-a"}],
    [{"name": "admin", "id": "admin-id"}, {"name": "admin", "id": "duplicate-id"}],
    [{"name": "admin", "id": "admin-id"}, {"name": "Admin", "id": "case-duplicate-id"}],
    [{"name": "Admin", "id": "admin-id"}],
    [{"name": "ADMIN", "id": "admin-id"}],
    [{"name": "manager", "id": "admin-id"}],
])
def test_system_admin_role_resolution_rejects_ambiguous_or_domain_roles(monkeypatch, roles):
    client = _system_directory(roles=roles, user_grants=[{
        "user": {"id": "user-a"}, "scope": {"system": {"all": True}}, "role": {"id": "admin-id"},
    }])
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    assert auth._is_system_admin("user-a") is False
    assert [call.args[0] for call in client.get.call_args_list] == [
        "/role_assignments?user.id=user-a&scope.system=all", "/users/user-a/groups",
        "/roles", "/role_inferences",
    ]


@pytest.mark.parametrize("principal", ["user", "group"])
def test_system_admin_expands_global_role_id_dag_from_raw_grants(monkeypatch, principal):
    document = {principal: {"id": "user-a" if principal == "user" else "group-a"},
                "scope": {"system": {"all": True}}, "role": {"id": "root-id"}}
    client = _system_directory(
        user_grants=[document] if principal == "user" else [], groups=["group-a"],
        group_grants={"group-a": [document]} if principal == "group" else {},
        roles=[{"id": role_id, "name": name} for role_id, name in [
            ("admin-id", "admin"), ("root-id", "operator"), ("left-id", "left"), ("right-id", "right"),
        ]],
        inferences=[
            {"prior_role": {"id": "root-id"}, "implies": [{"id": "left-id"}, {"id": "right-id"}]},
            {"prior_role": {"id": "left-id"}, "implies": [{"id": "admin-id"}]},
            {"prior_role": {"id": "right-id"}, "implies": [{"id": "admin-id"}]},
        ],
    )
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    assert client.get("/role_assignments?user.id=user-a&scope.system=all&effective=True")[1] == {
        "role_assignments": [], "links": {"next": None}, "truncated": False,
    }
    client.get.reset_mock()
    assert auth._is_system_admin("user-a") is True
    assert [call.args[0] for call in client.get.call_args_list] == [
        "/role_assignments?user.id=user-a&scope.system=all", "/users/user-a/groups",
        "/role_assignments?group.id=group-a&scope.system=all", "/roles", "/role_inferences",
    ]


@pytest.mark.parametrize("kind", ["unknown-role", "domain-role", "cycle", "unsafe", "ambiguous-role"])
def test_system_admin_invalid_raw_role_graph_is_rejected_not_unavailable(monkeypatch, kind):
    roles = [{"id": "admin-id", "name": "admin"}, {"id": "seed-id", "name": "operator"}]
    seed_id = "seed-id"
    inferences = [{"prior_role": {"id": seed_id}, "implies": [{"id": "admin-id"}]}]
    if kind == "unknown-role":
        seed_id = "missing-id"
    elif kind == "domain-role":
        roles[1]["domain_id"] = "domain-a"
    elif kind == "cycle":
        inferences.append({"prior_role": {"id": "admin-id"}, "implies": [{"id": seed_id}]})
    elif kind == "unsafe":
        roles[1]["name"] = "waygate_admin"
    else:
        roles.append({"id": "duplicate-id", "name": "operator"})
    client = _system_directory(roles=roles, inferences=inferences, user_grants=[{
        "user": {"id": "user-a"}, "scope": {"system": {"all": True}}, "role": {"id": seed_id},
    }])
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    with pytest.raises(auth.AuthorityRejected):
        auth._is_system_admin("user-a")


def test_system_admin_without_exact_raw_seeds_skips_role_resolution(monkeypatch):
    client = _system_directory()
    client.roles.list.side_effect = RuntimeError("catalog must not be read without a raw grant")
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    assert auth._is_system_admin("user-a") is False
    assert [call.args[0] for call in client.get.call_args_list] == [
        "/role_assignments?user.id=user-a&scope.system=all", "/users/user-a/groups",
    ]


@pytest.mark.parametrize("principal", ["user", "group"])
@pytest.mark.parametrize("path,key", SYSTEM_COLLECTIONS)
@pytest.mark.parametrize("defect", INCOMPLETE_ENVELOPES)
def test_system_admin_incomplete_collection_never_confirms_potential_admin(principal, path, key, defect):
    grant = {principal: {"id": "user-a" if principal == "user" else "group-a"},
             "scope": {"system": {"all": True}}, "role": {"id": "operator-id"}}
    client = _system_directory(
        user_grants=[grant] if principal == "user" else [], groups=["group-a"],
        group_grants={"group-a": [grant]} if principal == "group" else {},
        roles=[{"id": "admin-id", "name": "admin"}, {"id": "operator-id", "name": "operator"}],
        inferences=[{"prior_role": {"id": "operator-id"}, "implies": [{"id": "admin-id"}]}],
    )
    assert auth._is_system_admin("user-a", client) is True
    client.get.reset_mock()
    _corrupt_native_collection(client, path, key, defect)
    with pytest.raises(auth.AuthorityUnavailable):
        auth._is_system_admin("user-a", client)
    client.get.assert_any_call(path)


@pytest.mark.parametrize("path,key", SYSTEM_COLLECTIONS[2:])
@pytest.mark.parametrize("defect", INCOMPLETE_ENVELOPES)
def test_system_admin_incomplete_empty_collection_never_confirms_absence(path, key, defect):
    client = _system_directory(groups=["group-a"])
    assert auth._is_system_admin("user-a", client) is False
    client.get.reset_mock()
    _corrupt_native_collection(client, path, key, defect)
    with pytest.raises(auth.AuthorityUnavailable):
        auth._is_system_admin("user-a", client)
    client.get.assert_any_call(path)


@pytest.mark.parametrize("links", ["absent", "empty", "null-next"])
@pytest.mark.parametrize("truncated", ["absent", None, False])
def test_system_admin_complete_envelope_optional_metadata_is_accepted(links, truncated):
    client = _system_directory(user_grants=[{
        "user": {"id": "user-a"}, "scope": {"system": {"all": True}}, "role": {"id": "admin-id"},
    }])
    original = client.get.side_effect

    def get(path):
        response, payload = original(path)
        if links == "absent":
            del payload["links"]
        elif links == "empty":
            payload["links"] = {}
        if truncated == "absent":
            del payload["truncated"]
        else:
            payload["truncated"] = truncated
        return response, payload

    client.get.side_effect = get
    assert auth._is_system_admin("user-a", client) is True


def _owner_directory(enabled=True, roles=("member",), project="project-a", identity="user-a", system_admin=False):
    names = {"member", "reader", "admin", "manager"} | set(roles)
    client = MagicMock()
    client.users.get.return_value = SimpleNamespace(id=identity, enabled=enabled, domain_id="default")
    client.domains.get.return_value = SimpleNamespace(id="default", enabled=True)
    client.projects.get.side_effect = lambda project_id: SimpleNamespace(id=project_id, enabled=True, domain_id="default")
    client.groups.list.return_value = []
    client.roles.list.return_value = [
        SimpleNamespace(id="role-" + name, name=name, domain_id=None,
                        to_dict=lambda name=name: {"id": "role-" + name, "name": name}) for name in sorted(names)
    ]
    client.inference_rules.list_inference_roles.return_value = []

    def assignments(**kwargs):
        if "system" in kwargs:
            if kwargs.get("effective") is True:
                return []
            return [_assignment({"user": {"id": identity}, "scope": {"system": {"all": True}},
                                 "role": {"id": "role-admin"}})] if system_admin else []
        return [
            _assignment({"user": {"id": kwargs["user"]}, "scope": {"project": {"id": kwargs["project"]}},
                         "role": {"id": "role-" + role}})
            for role in roles
        ] if kwargs["project"] == project else []

    client.role_assignments.list.side_effect = assignments
    _install_native_collections(client)
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled,roles,project,expected", [
    (True, ("member",), "project-a", True),
    (False, ("member",), "project-a", False),
    (None, ("member",), "project-a", False),
    (1, ("member",), "project-a", False),
    (True, ("reader",), "project-a", False),
    (True, ("admin",), "project-a", True),
    (True, ("manager",), "project-a", True),
    (True, ("project_owner",), "project-a", False),
    (True, ("waygate_admin",), "project-a", False),
    (True, ("member",), "project-b", False),
])
async def test_owner_requires_enabled_effective_native_management_role(monkeypatch, enabled, roles, project, expected):
    client = _owner_directory(enabled=enabled, roles=roles, project=project)
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    if expected:
        await auth.validate_client_owner("project-a", "user-a")
    else:
        with pytest.raises(HTTPException) as error:
            await auth.validate_client_owner("project-a", "user-a")
        assert error.value.status_code == 422
    if enabled is True:
        client.get.assert_any_call("/role_assignments?user.id=user-a&scope.project.id=project-a&effective=True")
    else:
        client.get.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("alias", ["project_owner", "project_admin", "project_member"])
async def test_owner_alias_requires_current_native_graph_to_expose_standard_role(monkeypatch, alias):
    client = _owner_directory(roles=(alias,))
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    with pytest.raises(HTTPException) as error:
        await auth.validate_client_owner("project-a", "user-a")
    assert error.value.status_code == 422
    client.inference_rules.list_inference_roles.return_value = [
        {"prior_role": {"id": "role-" + alias}, "implies": [{"id": "role-member"}]},
    ]
    await auth.validate_client_owner("project-a", "user-a")
    client.inference_rules.list_inference_roles.return_value = []
    with pytest.raises(HTTPException) as error:
        await auth.validate_client_owner("project-a", "user-a")
    assert error.value.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled,system_admin,expected", [(True, True, 200), (True, False, 422), (False, True, 422)])
async def test_owner_without_target_membership_requires_enabled_current_system_admin(
    monkeypatch, enabled, system_admin, expected,
):
    client = _owner_directory(enabled=enabled, roles=(), project="project-b", system_admin=system_admin)
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    if expected == 200:
        await auth.validate_client_owner("project-a", "user-a")
    else:
        with pytest.raises(HTTPException) as error:
            await auth.validate_client_owner("project-a", "user-a")
        assert error.value.status_code == expected


@pytest.mark.asyncio
async def test_owner_system_assignment_outage_is_unavailable_not_invalid_owner(monkeypatch):
    client = _owner_directory(roles=())
    original = client.role_assignments.list.side_effect

    def assignments(**kwargs):
        if "system" in kwargs:
            raise RuntimeError("synthetic system directory offline")
        return original(**kwargs)

    client.role_assignments.list.side_effect = assignments
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    with pytest.raises(HTTPException) as error:
        await auth.validate_client_owner("project-a", "user-a")
    assert error.value.status_code == 503


@pytest.mark.asyncio
async def test_owner_unknown_wrong_identity_and_unavailable_directory_fail_closed(monkeypatch):
    from keystoneauth1.exceptions.http import NotFound

    client = _owner_directory(identity="other")
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    with pytest.raises(HTTPException) as error:
        await auth.validate_client_owner("project-a", "user-a")
    assert error.value.status_code == 422
    client.get.assert_not_called()
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


@pytest.mark.asyncio
@pytest.mark.parametrize("roles,path,key", [
    (roles, path, key)
    for roles in [("member",), ()]
    for path, key in [
        ("/roles", "roles"), ("/role_inferences", "role_inferences"),
        ("/role_assignments?user.id=user-a&scope.project.id=project-a&effective=True", "role_assignments"),
    ]
])
@pytest.mark.parametrize("defect", INCOMPLETE_ENVELOPES)
async def test_owner_incomplete_collection_is_unavailable_not_valid_or_absent(monkeypatch, roles, path, key, defect):
    client = _owner_directory(roles=roles, system_admin=True)
    _corrupt_native_collection(client, path, key, defect)
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    with pytest.raises(HTTPException) as error:
        await auth.validate_client_owner("project-a", "user-a")
    assert error.value.status_code == 503
    client.get.assert_any_call(path)


@pytest.fixture
def synthetic_keystone():
    """A real local v3 endpoint inspecting the unchanged original credential."""
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
            credential = self.headers.get("X-Subject-Token")
            requests.append({"method": "GET", "path": self.path, "subject_token": credential})
            if urlsplit(self.path).path.rstrip("/") != "/v3/auth/tokens":
                self.send_document(404, {"error": {"message": "Unknown synthetic endpoint", "code": 404}})
                return
            identity = tokens.get(credential)
            if identity is None:
                self.send_document(401, {"error": {"message": "Invalid synthetic token", "code": 401}})
                return
            token = {
                "methods": identity.get("methods", ["password"]), "expires_at": "2099-01-01T00:00:00Z",
                "issued_at": "2026-01-01T00:00:00Z", "audit_ids": ["synthetic-audit"],
                "user": {"id": identity["user_id"], "name": identity["user_id"],
                         "domain": {"id": "default", "name": "Default"}},
                "roles": [{"id": "role-" + role, "name": role} for role in identity["roles"]],
                "catalog": [],
            }
            if identity["project_id"]:
                token["project"] = {
                    "id": identity["project_id"], "name": identity["project_id"],
                    "domain": {"id": "default", "name": "Default"},
                }
            token.update(identity.get("token_data", {}))
            self.send_document(200, {"token": token}, subject=credential)

        def do_POST(self):
            document = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append({"method": "POST", "path": self.path, "document": document})
            self.send_document(405, {"error": {"message": "Token reissue is forbidden", "code": 405}})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    issuer = SimpleNamespace(auth_url=f"http://127.0.0.1:{server.server_port}/v3", tokens=tokens, requests=requests)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
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
    monkeypatch.setattr(policy, "get_settings", lambda: settings)
    monkeypatch.setattr(db, "_engine", None)
    monkeypatch.setattr(db, "_session_factory", None)
    directory = MagicMock()
    enabled = {"user-a": True, "user-b": True, "system-user": True, "disabled-user": False}
    projects = {"project-a": True, "project-b": True}
    domains = {"default": True, "requester-domain": True, "target-domain": True}
    system_admins = set()
    system_groups = {}
    system_group_grants = {}
    memberships = {"user-a": "project-a", "user-b": "project-a", "disabled-user": "project-a"}
    current_roles = {}
    role_names = set(LEGACY_ROLES) | set(PROJECT_ROLES) | {"project_owner", "project_admin", "project_member"}
    graph = {}  # Effective native assignments, never local alias expansion, provide project authority.

    def role_record(name):
        role_id = "admin-id" if name == "admin" else "role-" + name
        return SimpleNamespace(id=role_id, name=name, domain_id=None,
                               to_dict=lambda: {"id": role_id, "name": name})

    directory.roles.list.side_effect = lambda **kwargs: [
        role_record(name) for name in sorted(role_names) if not kwargs.get("name") or name == kwargs["name"]
    ]
    directory.groups.list.side_effect = lambda *, user: [
        SimpleNamespace(id=group_id) for group_id in sorted(system_groups.get(user, ()))
    ]
    directory.inference_rules.list_inference_roles.side_effect = lambda: [
        {"prior_role": {"id": role_record(parent).id}, "implies": [{"id": role_record(leaf).id} for leaf in leaves]}
        for parent, leaves in graph.items()
    ]
    directory.users.get.side_effect = lambda user_id: SimpleNamespace(
        id=user_id, enabled=enabled.get(user_id, False), domain_id="requester-domain" if user_id == "system-user" else "default",
    )
    directory.domains.get.side_effect = lambda domain_id: SimpleNamespace(id=domain_id, enabled=domains.get(domain_id, False))
    directory.projects.get.side_effect = lambda project_id: SimpleNamespace(
        id=project_id, enabled=projects.get(project_id, False), domain_id="target-domain" if project_id == "project-a" else "default",
    )

    def get_token_data(credential, include_catalog=True):
        from keystoneauth1.exceptions.http import Unauthorized

        response = http_requests.get(
            synthetic_keystone.auth_url + "/auth/tokens", headers={"X-Subject-Token": credential},
            params=None if include_catalog else {"nocatalog": ""}, timeout=5,
        )
        if response.status_code == 401:
            raise Unauthorized()
        response.raise_for_status()
        return response.json()

    directory.tokens.get_token_data.side_effect = get_token_data

    def assignments(**kwargs):
        if "system" in kwargs:
            # Keystone omits system assignments when effective=True, even for admins.
            if kwargs.get("effective") is True:
                return []
            if "group" in kwargs:
                return [_assignment({
                    "group": {"id": kwargs["group"]}, "scope": {"system": {"all": True}},
                    "role": {"id": role_record(role).id},
                }) for role in sorted(system_group_grants.get(kwargs["group"], ()))]
            return [_assignment({
                "user": {"id": kwargs["user"]}, "scope": {"system": {"all": True}},
                "role": {"id": "admin-id"},
            })] if kwargs["user"] in system_admins else []
        project_id = kwargs["project"]
        if memberships.get(kwargs["user"]) != project_id:
            return []
        roles = current_roles.get((kwargs["user"], project_id), ["member"])
        return [_assignment({
            "user": {"id": kwargs["user"]}, "scope": {"project": {"id": project_id}},
            "role": {"id": role_record(role).id},
        }) for role in roles]

    directory.role_assignments.list.side_effect = assignments
    _install_native_collections(directory)
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

        def headers(roles, user_id="user-a", project_id="project-a", *, methods=None, token_data=None):
            credential = f"native-{len(synthetic_keystone.tokens)}"
            synthetic_keystone.tokens[credential] = {
                "roles": roles, "user_id": user_id, "project_id": project_id,
                "methods": ["password"] if methods is None else methods, "token_data": token_data or {},
            }
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
                projects=projects, system_admins=system_admins, domains=domains,
                system_groups=system_groups, system_group_grants=system_group_grants,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["disabled", "removed", "outage", "wrong-domain", "missing-domain"])
@pytest.mark.parametrize("domain_subject", ["requester", "target"])
@pytest.mark.parametrize("principal", ["member", "system-admin"])
async def test_native_subject_domains_are_rechecked_before_project_actions(native_http, failure, domain_subject, principal):
    from keystoneauth1.exceptions.http import NotFound

    if principal == "system-admin":
        native_http.system_admins.add("system-user")
        headers = native_http.headers([], user_id="system-user", project_id="project-b")
        headers.update({"X-Project-Id": "project-b", "X-Target-Project-Id": "project-a"})
    else:
        headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    domain_id = ("requester-domain" if principal == "system-admin" else "default") if domain_subject == "requester" else "target-domain"
    original_domain_get = native_http.directory.domains.get.side_effect

    def changed_domain(requested):
        if requested != domain_id:
            return original_domain_get(requested)
        if failure == "removed":
            raise NotFound()
        if failure == "outage":
            raise RuntimeError("synthetic domain outage")
        return SimpleNamespace(id="other", enabled=True)
    if failure == "disabled":
        native_http.domains[domain_id] = False
    elif failure in {"removed", "outage", "wrong-domain"}:
        native_http.directory.domains.get.side_effect = changed_domain
    else:
        lookup = native_http.directory.users.get if domain_subject == "requester" else native_http.directory.projects.get
        lookup.side_effect = lambda identity: SimpleNamespace(id=identity, enabled=True)
    expected = 503 if failure == "outage" else 403
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == expected
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "must-not-create"}, headers=headers)).status_code == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("home_roles", [[], ["member"]], ids=["zero-home-roles", "home-member"])
async def test_header_pair_system_admin_without_target_membership_operates_as_requester(native_http, home_roles):
    native_http.system_admins.add("system-user")
    headers = native_http.headers(home_roles, user_id="system-user", project_id="project-b")
    headers.update({"X-Project-Id": "project-b", "X-Target-Project-Id": "project-a"})
    assert native_http.memberships["system-user"] == "project-b"
    assert ("system-user", "project-a") not in native_http.current_roles
    for path in ("/v1/servers", SERVER, SERVER + "/clients"):
        response = await native_http.client.get(path, headers=headers)
        assert response.status_code == 200
        assert native_http.private_key not in response.text and native_http.psk not in response.text
    listing = await native_http.client.get("/v1/servers", headers=headers)
    assert {server["id"] for server in listing.json()} == {"server-a", "import-target"}
    created = await native_http.client.post(SERVER + "/clients", json={"name": "admin-default"}, headers=headers)
    assert created.status_code == 201
    assert created.json()["owner_user_id"] == "system-user"
    assert "PrivateKey = " in created.json()["tunnel_conf"]
    client_path = SERVER + "/clients/" + created.json()["id"]
    assert (await native_http.client.get(client_path + "/config", headers=headers)).status_code == 200
    for client_id in ("own", "other", "legacy", "disabled"):
        assert (await native_http.client.get(SERVER + f"/clients/{client_id}/config", headers=headers)).status_code == 403
    exported = await native_http.client.post(
        SERVER + "/export", json={"passphrase": "synthetic-passphrase"}, headers=headers,
    )
    assert exported.status_code == 200
    assert {entry["name"] for entry in exported.json()["clients"]} == {"legacy", "admin-default"}
    assert exported.json()["export_scope"] == "caller_owned_and_unassigned_profiles"
    assert set(exported.json()["excluded_assigned_client_ids"]) == {"own", "other", "disabled"}
    updated = await native_http.client.patch(client_path, json={"name": "admin-renamed"}, headers=headers)
    assert updated.status_code == 200 and updated.json()["name"] == "admin-renamed"
    disabled = await native_http.client.patch(client_path, json={"enabled": False}, headers=headers)
    assert disabled.status_code == 200 and disabled.json()["enabled"] is False
    assert (await native_http.client.get(client_path + "/config", headers=headers)).status_code == 403
    assert (await native_http.client.delete(client_path, headers=headers)).status_code == 204
    assert await waygate_db.get_client("server-a", "project-a", created.json()["id"]) is None
    native_http.directory.get.assert_any_call("/role_assignments?user.id=system-user&scope.system=all")
    native_http.directory.get.assert_any_call("/users/system-user/groups")
    system_paths = [call.args[0] for call in native_http.directory.get.call_args_list if "scope.system=" in call.args[0]]
    assert system_paths and set(system_paths) == {"/role_assignments?user.id=system-user&scope.system=all"}
    native_http.directory.get.assert_any_call(
        "/role_assignments?user.id=system-user&scope.project.id=project-a&effective=True",
    )
    assert all(request["method"] == "GET" and request["subject_token"] == headers["X-Auth-Token"]
               for request in native_http.keystone.requests)


@pytest.mark.asyncio
async def test_native_system_effective_queries_are_empty_despite_raw_user_and_group_grants(native_http):
    native_http.system_admins.add("system-user")
    native_http.system_groups["system-user"] = {"operators"}
    native_http.system_group_grants["operators"] = {"admin"}
    for principal, identity in (("user", "system-user"), ("group", "operators")):
        path = "/role_assignments?" + urlencode({principal + ".id": identity, "scope.system": "all"})
        assert native_http.directory.get(path + "&effective=True")[1] == {
            "role_assignments": [], "links": {"next": None}, "truncated": False,
        }
        assert native_http.directory.get(path)[1] == {
            "role_assignments": [{
                principal: {"id": identity},
                "scope": {"system": {"all": True}}, "role": {"id": "admin-id"},
            }],
            "links": {"next": None}, "truncated": False,
        }


@pytest.mark.asyncio
@pytest.mark.parametrize("grant,revocation", [
    ("admin", "membership"), ("admin", "grant"),
    ("operator", "membership"), ("operator", "grant"), ("operator", "inference"),
])
async def test_group_system_admin_rechecks_raw_grants_membership_and_inference_without_reissue(
    native_http, grant, revocation,
):
    native_http.system_groups["system-user"] = {"operators"}
    native_http.system_group_grants["operators"] = {grant}
    native_http.role_names.update({"operator", "operator-middle"})
    native_http.graph["operator"] = ["operator-middle"]
    native_http.graph["operator-middle"] = ["admin"]
    headers = native_http.headers([], user_id="system-user", project_id="project-b")
    headers.update({"X-Project-Id": "project-b", "X-Target-Project-Id": "project-a"})
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    created = await native_http.client.post(SERVER + "/clients", json={"name": "group-admin"}, headers=headers)
    assert created.status_code == 201 and created.json()["owner_user_id"] == "system-user"
    assert created.json()["tunnel_conf"] is not None
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 403
    if revocation == "membership":
        native_http.system_groups["system-user"].clear()
    elif revocation == "grant":
        native_http.system_group_grants["operators"].clear()
    else:
        native_http.graph["operator-middle"].clear()
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "denied"}, headers=headers)).status_code == 403
    native_http.system_groups["system-user"] = {"operators"}
    native_http.system_group_grants["operators"] = {grant}
    native_http.graph["operator-middle"] = ["admin"]
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    assert native_http.keystone.tokens[headers["X-Auth-Token"]]["roles"] == []
    native_http.directory.get.assert_any_call("/users/system-user/groups")
    native_http.directory.get.assert_any_call("/role_assignments?group.id=operators&scope.system=all")
    native_http.directory.get.assert_any_call("/roles")
    assert {call.args[0] for call in native_http.directory.get.call_args_list if "scope.system=" in call.args[0]} == {
        "/role_assignments?user.id=system-user&scope.system=all",
        "/role_assignments?group.id=operators&scope.system=all",
    }
    assert all(request["method"] == "GET" and request["subject_token"] == headers["X-Auth-Token"]
               for request in native_http.keystone.requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", [
    "project", "domain", "mixed-project", "mixed-domain", "foreign-group", "mixed-principal",
    "domain-role", "ambiguous-admin", "case-admin", "unknown-role", "cycle", "unsafe",
])
async def test_invalid_raw_group_system_authority_never_promotes_original_admin_claim(native_http, kind):
    native_http.system_groups["system-user"] = {"operators"}
    native_http.system_group_grants["operators"] = {"admin"}
    headers = native_http.headers(["admin"], user_id="system-user", project_id="project-b")
    headers.update({"X-Project-Id": "project-b", "X-Target-Project-Id": "project-a"})
    original_assignments = native_http.directory.role_assignments.list.side_effect
    original_catalog = native_http.directory.roles.list.side_effect

    def assignments(**kwargs):
        records = original_assignments(**kwargs)
        if "system" not in kwargs or "group" not in kwargs:
            return records
        documents = [record.to_dict() for record in records]
        for document in documents:
            if kind in {"project", "domain"}:
                document["scope"] = {kind: {"id": kind + "-a"}}
            elif kind.startswith("mixed-") and kind != "mixed-principal":
                document["scope"][kind.removeprefix("mixed-")] = {"id": "other-scope"}
            elif kind == "foreign-group":
                document["group"]["id"] = "foreign-group"
            elif kind == "mixed-principal":
                document["user"] = {"id": "system-user"}
            elif kind == "unknown-role":
                document["role"]["id"] = "unregistered-id"
        return [_assignment(document) for document in documents]

    def catalog(**kwargs):
        records = original_catalog(**kwargs)
        if kind == "ambiguous-admin":
            records.append(_assignment({"id": "duplicate-id", "name": "Admin"}))
        elif kind in {"domain-role", "case-admin"}:
            replacement = {"id": "admin-id", "name": "admin"}
            if kind == "domain-role":
                replacement["domain_id"] = "domain-a"
                records.append(_assignment({"id": "global-admin-id", "name": "admin"}))
            else:
                replacement["name"] = "ADMIN"
            records = [_assignment(replacement) if record.to_dict()["id"] == "admin-id" else record
                       for record in records]
        return records

    if kind == "cycle":
        native_http.graph["admin"] = ["admin"]
    elif kind == "unsafe":
        native_http.system_group_grants["operators"] = {"waygate_admin"}
        native_http.graph["waygate_admin"] = ["admin"]
    native_http.directory.role_assignments.list.side_effect = assignments
    native_http.directory.roles.list.side_effect = catalog
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "denied"}, headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_same_scope_entitled_member_header_pair_retains_client_lifecycle(native_http):
    headers = native_http.headers(["member"])
    headers.update({"X-Project-Id": "project-a", "X-Target-Project-Id": "project-a"})
    for path in ("/v1/servers", SERVER, SERVER + "/clients"):
        assert (await native_http.client.get(path, headers=headers)).status_code == 200
    created = await native_http.client.post(SERVER + "/clients", json={"name": "member-default"}, headers=headers)
    assert created.status_code == 201 and created.json()["owner_user_id"] == "user-a"
    client_path = SERVER + "/clients/" + created.json()["id"]
    assert (await native_http.client.get(client_path + "/config", headers=headers)).status_code == 200
    assert (await native_http.client.get(SERVER + "/clients/other/config", headers=headers)).status_code == 403
    assert (await native_http.client.patch(client_path, json={"name": "member-renamed"}, headers=headers)).status_code == 200
    assert (await native_http.client.delete(client_path, headers=headers)).status_code == 204


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["user", "project", "domain"])
async def test_project_admin_header_pair_has_local_policy_but_never_system_or_foreign_authority(native_http, scope):
    headers = native_http.headers(["member", "admin"])
    headers.update({"X-Project-Id": "project-a", "X-Target-Project-Id": "project-a"})
    original = native_http.directory.role_assignments.list.side_effect

    def assignments(**kwargs):
        if "system" not in kwargs:
            return original(**kwargs)
        document = {"user": {"id": "user-a"}, "role": {"id": "admin-id"}}
        if scope != "user":
            document["scope"] = {scope: {"id": scope + "-a"}}
        return [_assignment(document)]

    native_http.directory.role_assignments.list.side_effect = assignments
    for method, path, body in [
        ("GET", "/v1/servers", None), ("GET", SERVER, None),
        ("PATCH", CLIENT, {"name": "project-admin"}),
    ]:
        assert (await native_http.client.request(method, path, json=body, headers=headers)).status_code == 200
    assert (await native_http.client.get("/v1/admin/resource-policies", headers=headers)).status_code == 403
    headers["X-Target-Project-Id"] = "project-b"
    assert (await native_http.client.get("/v1/servers", headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_system_admin_revocation_and_directory_outage_recheck_same_original_token(native_http):
    native_http.system_admins.add("system-user")
    headers = native_http.headers([], user_id="system-user", project_id="project-b")
    headers.update({"X-Project-Id": "project-b", "X-Target-Project-Id": "project-a"})
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    native_http.system_admins.clear()
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    native_http.system_admins.add("system-user")
    original = native_http.directory.role_assignments.list.side_effect

    def assignments(**kwargs):
        if "system" in kwargs:
            raise RuntimeError("synthetic system directory offline")
        return original(**kwargs)

    native_http.directory.role_assignments.list.side_effect = assignments
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 503
    assert (await native_http.client.patch(CLIENT, json={"name": "denied"}, headers=headers)).status_code == 503
    assert (await waygate_db.get_client("server-a", "project-a", "own"))["name"] == "own"


@pytest.mark.asyncio
@pytest.mark.parametrize("target,state", [
    ("project-a", False), ("project-a", None), ("project-a", 1), ("unknown-project", None),
])
async def test_system_admin_cannot_select_disabled_or_unknown_target(native_http, target, state):
    native_http.system_admins.add("system-user")
    headers = native_http.headers([], user_id="system-user", project_id="project-b")
    if target == "project-a":
        native_http.projects[target] = state
    headers.update({"X-Project-Id": "project-b", "X-Target-Project-Id": target})
    assert (await native_http.client.get("/v1/servers", headers=headers)).status_code == 403
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "denied"}, headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("subject", ["user", "project"])
@pytest.mark.parametrize("state", [False, None, 1, "unknown", "wrong-id", "outage"])
async def test_native_authority_requires_exact_enabled_directory_identity(native_http, subject, state):
    from keystoneauth1.exceptions.http import NotFound

    headers = native_http.headers(["member"])
    lookup = native_http.directory.users.get if subject == "user" else native_http.directory.projects.get
    if state == "unknown":
        lookup.side_effect = NotFound()
    elif state == "outage":
        lookup.side_effect = RuntimeError("synthetic directory offline")
    else:
        lookup.side_effect = None
        lookup.return_value = SimpleNamespace(
            id="other" if state == "wrong-id" else ("user-a" if subject == "user" else "project-a"),
            enabled=True if state == "wrong-id" else state,
        )
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == (503 if state == "outage" else 403)


@pytest.mark.asyncio
async def test_target_header_never_reinterprets_mismatching_original_connection_scope(native_http):
    native_http.system_admins.add("system-user")
    headers = native_http.headers([], user_id="system-user", project_id="project-b")
    headers.update({"X-Project-Id": "project-a", "X-Target-Project-Id": "project-a"})
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    native_http.directory.users.get.assert_not_called()
    native_http.directory.projects.get.assert_not_called()


UNRESTRICTED_CREDENTIALS = [
    pytest.param(["password"], {}, id="password"),
    pytest.param(["token"], {}, id="token"),
    pytest.param(["totp"], {}, id="totp"),
    pytest.param(["password", "totp"], {}, id="password-totp"),
    pytest.param(["mapped"], {}, id="mapped"),
    pytest.param(["external"], {}, id="external"),
    pytest.param(["openid"], {}, id="openid"),
    pytest.param(["password"], {"user": {
        "id": "user-a", "name": "user-a", "domain": {"id": "default", "name": "Default"},
        "OS-FEDERATION": {"identity_provider": {"id": "idp"}, "protocol": {"id": "saml2"}, "groups": []},
    }}, id="federated-identity"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("methods,token_data", UNRESTRICTED_CREDENTIALS)
async def test_human_original_token_uses_current_same_scope_roles_without_delegation_ceiling(
    native_http, methods, token_data,
):
    headers = native_http.headers(["reader"], methods=methods, token_data=token_data)
    headers.update({"X-Project-Id": "project-a", "X-Target-Project-Id": "project-a"})
    native_http.current_roles["user-a", "project-a"] = ["member"]
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 200
    created = await native_http.client.post(SERVER + "/clients", json={"name": "current-human-role"}, headers=headers)
    assert created.status_code == 201 and created.json()["owner_user_id"] == "user-a"
    client_path = SERVER + "/clients/" + created.json()["id"]
    assert (await native_http.client.delete(client_path, headers=headers)).status_code == 204
    native_http.current_roles["user-a", "project-a"] = ["reader"]
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 403
    assert native_http.keystone.tokens[headers["X-Auth-Token"]]["roles"] == ["reader"]
    assert all(request["method"] == "GET" and request["subject_token"] == headers["X-Auth-Token"]
               for request in native_http.keystone.requests)


RESTRICTED_CREDENTIALS = [
    pytest.param(["application_credential"], {"application_credential": {"id": "app-a"}}, id="application-credential"),
    pytest.param(["password"], {"OS-TRUST:trust": {"id": "trust-a", "trustor_user_id": "system-user",
                 "trustee_user_id": "trustee", "impersonation": True}}, id="trust"),
    pytest.param(["password"], {"application_credential": {"id": "app-a"}}, id="application-metadata"),
    pytest.param(["mapped"], {"application_credential": {"id": "app-a", "access_rules": []}},
                 id="mapped-application-metadata"),
    pytest.param(["oauth1"], {"OS-OAUTH1": {"consumer_id": "consumer", "access_token_id": "oauth-token"}}, id="oauth1"),
    pytest.param(["password"], {"oauth2_credential": {"id": "oauth2-a"}}, id="oauth2"),
    pytest.param(["openid"], {"application_credential": {"id": "app-a"}}, id="openid-delegated-metadata"),
    pytest.param(["openid", "unknown-method"], {}, id="openid-unknown-method"),
    pytest.param(["unknown-method"], {}, id="unknown-method"),
    pytest.param([], {}, id="missing-methods"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("methods,token_data", UNRESTRICTED_CREDENTIALS)
async def test_human_auth_methods_and_federation_retain_verified_system_target_authority(
    native_http, methods, token_data,
):
    native_http.system_admins.add("user-a")
    headers = native_http.headers([], user_id="user-a", project_id="project-b", methods=methods, token_data=token_data)
    headers.update({"X-Project-Id": "project-b", "X-Target-Project-Id": "project-a"})
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    created = await native_http.client.post(SERVER + "/clients", json={"name": "human-default"}, headers=headers)
    assert created.status_code == 201 and created.json()["owner_user_id"] == "user-a"
    client_path = SERVER + "/clients/" + created.json()["id"]
    assert (await native_http.client.get(client_path + "/config", headers=headers)).status_code == 200
    assert (await native_http.client.get(SERVER + "/clients/other/config", headers=headers)).status_code == 403
    assert (await native_http.client.delete(client_path, headers=headers)).status_code == 204


@pytest.mark.asyncio
@pytest.mark.parametrize("methods", [["application_credential"], ["password"], ["mapped"]])
async def test_application_access_rules_are_rejected_before_directory_or_api_actions(native_http, methods):
    headers = native_http.headers(["member", *CAPABILITIES], methods=methods, token_data={
        "application_credential": {"id": "app-a", "access_rules": [
            {"service": "waygate", "method": "GET", "path": "/v1/servers"},
        ]},
    })
    info = auth.validate_token(headers["X-Auth-Token"])
    assert info["credential_restricted"] is True
    assert info["credential_access_rules"] is True
    for method, path, body in [
        ("GET", "/v1/servers", None), ("GET", SERVER, None),
        ("POST", SERVER + "/clients", {"name": "denied-access-rule"}),
        ("PATCH", CLIENT, {"name": "denied-access-rule"}), ("DELETE", CLIENT, None),
    ]:
        assert (await native_http.client.request(method, path, json=body, headers=headers)).status_code == 403
    native_http.directory.users.get.assert_not_called()
    native_http.directory.projects.get.assert_not_called()
    native_http.directory.get.assert_not_called()
    assert (await waygate_db.get_client("server-a", "project-a", "own"))["name"] == "own"


@pytest.mark.asyncio
@pytest.mark.parametrize("methods,token_data", RESTRICTED_CREDENTIALS)
async def test_restricted_original_credential_never_inherits_system_override_or_target_switch(
    native_http, methods, token_data,
):
    native_http.system_admins.add("user-a")
    headers = native_http.headers(["admin"], user_id="user-a", project_id="project-b",
                                  methods=methods, token_data=token_data)
    headers["X-Project-Id"] = "project-b"
    assert (await native_http.client.get("/v1/servers", headers=headers)).status_code == 200
    assert (await native_http.client.get("/v1/admin/resource-policies", headers=headers)).status_code == 403
    headers["X-Target-Project-Id"] = "project-a"
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert all(request["method"] == "GET" for request in native_http.keystone.requests)
    assert not any("scope.system=" in call.args[0] for call in native_http.directory.get.call_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize("methods,token_data", RESTRICTED_CREDENTIALS)
async def test_restricted_role_ceiling_intersects_current_roles_without_reissue(native_http, methods, token_data):
    headers = native_http.headers(["reader"], methods=methods, token_data=token_data)
    native_http.current_roles["user-a", "project-a"] = ["reader", "member"]
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 403
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "denied"}, headers=headers)).status_code == 403
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 403
    native_http.current_roles["user-a", "project-a"] = ["member"]
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert all(request["method"] == "GET" and request["subject_token"] == headers["X-Auth-Token"]
               for request in native_http.keystone.requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("methods,token_data,restricted", [
    pytest.param(case.values[0], case.values[1], restricted, id=case.id)
    for restricted, cases in [(False, UNRESTRICTED_CREDENTIALS), (True, RESTRICTED_CREDENTIALS)]
    for case in cases
])
async def test_original_token_inspection_preserves_scope_methods_restrictions_and_never_reissues(
    native_http, methods, token_data, restricted,
):
    headers = native_http.headers(["reader"], project_id="project-b",
                                  methods=methods, token_data=token_data)
    credential = headers["X-Auth-Token"]
    original = native_http.directory.tokens.get_token_data(credential, include_catalog=False)
    assert original["token"]["methods"] == methods
    assert original["token"]["project"]["id"] == "project-b"
    assert all(original["token"][key] == value for key, value in token_data.items())
    info = auth.validate_token(credential)
    assert info["token"] == credential
    assert info["connection_project_id"] == info["project_id"] == "project-b"
    assert info["user_id"] == "user-a"
    assert info["token_roles"] == ["reader"]
    assert info["credential_restricted"] is restricted
    native_http.directory.tokens.get_token_data.assert_called_with(credential, include_catalog=False)
    assert native_http.keystone.requests == [
        {"method": "GET", "path": "/v3/auth/tokens?nocatalog=", "subject_token": credential},
        {"method": "GET", "path": "/v3/auth/tokens?nocatalog=", "subject_token": credential},
    ]



@pytest.mark.asyncio
@pytest.mark.parametrize("principal", ["user", "group"])
@pytest.mark.parametrize("path,key", SYSTEM_COLLECTIONS)
@pytest.mark.parametrize("defect", ["next", "truncated"])
async def test_system_admin_incomplete_collection_http_is_503_without_mutation(native_http, principal, path, key, defect):
    if principal == "user":
        native_http.system_admins.add("user-a")
    native_http.system_groups["user-a"] = {"group-a"}
    native_http.system_group_grants["group-a"] = {"admin"} if principal == "group" else set()
    headers = native_http.headers(["admin"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    _corrupt_native_collection(native_http.directory, path, key, defect)
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 503
    assert (await native_http.client.patch(CLIENT, json={"name": "must-not-change"}, headers=headers)).status_code == 503
    assert (await waygate_db.get_client("server-a", "project-a", "own"))["name"] == "own"
    native_http.directory.get.assert_any_call(path)


@pytest.mark.asyncio
@pytest.mark.parametrize("principal", ["user", "group", "none"])
@pytest.mark.parametrize("invalid_group", [
    pytest.param({}, id="missing-id"), pytest.param({"id": None}, id="null-id"),
    pytest.param({"id": ""}, id="empty-id"), pytest.param({"id": 1}, id="integer-id"),
    pytest.param({"id": False}, id="boolean-id"), pytest.param({"id": []}, id="list-id"),
    pytest.param({"id": {}}, id="dict-id"), pytest.param({"id": " "}, id="whitespace-id"),
    pytest.param({"id": " operators"}, id="leading-whitespace-id"),
    pytest.param({"id": "operators "}, id="trailing-whitespace-id"),
    pytest.param({"id": "operators"}, id="duplicate-id"),
])
async def test_system_admin_duplicate_or_invalid_native_group_identity_is_503(native_http, principal, invalid_group):
    if principal == "user":
        native_http.system_admins.add("user-a")
    native_http.system_groups["user-a"] = {"operators"}
    native_http.system_group_grants["operators"] = {"admin"} if principal == "group" else set()
    headers = native_http.headers(["admin"])
    original = native_http.directory.get.side_effect

    def get(path):
        response, payload = original(path)
        if path == "/users/user-a/groups":
            payload["groups"] = [{"id": "operators"}, invalid_group]
        return response, payload

    native_http.directory.get.side_effect = get
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 503
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 503
    assert await waygate_db.get_client("server-a", "project-a", "own") is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [
    "token-validation", "system-role", "system-groups", "system-group-grants", "system-inferences", "target-project",
])
async def test_system_admin_lookup_outages_never_fall_back_to_original_claims(native_http, failure):
    native_http.system_admins.add("system-user")
    native_http.system_groups["system-user"] = {"operators"}
    native_http.system_group_grants["operators"] = {"admin"}
    headers = native_http.headers(["admin"], user_id="system-user", project_id="project-b")
    headers.update({"X-Project-Id": "project-b", "X-Target-Project-Id": "project-a"})
    lookup = {
        "token-validation": native_http.directory.tokens.get_token_data,
        "system-role": native_http.directory.roles.list,
        "system-groups": native_http.directory.groups.list,
        "system-group-grants": native_http.directory.role_assignments.list,
        "system-inferences": native_http.directory.inference_rules.list_inference_roles,
        "target-project": native_http.directory.projects.get,
    }[failure]
    if failure == "system-group-grants":
        original = lookup.side_effect

        def assignments(**kwargs):
            if "system" in kwargs and "group" in kwargs:
                raise RuntimeError("synthetic group grants unavailable")
            return original(**kwargs)

        lookup.side_effect = assignments
    else:
        lookup.side_effect = RuntimeError("synthetic directory unavailable")
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 503
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 503
    assert (await waygate_db.get_client("server-a", "project-a", "own"))["enabled"] is True

@pytest.fixture
def delegated(monkeypatch):
    """Project-role checks stop at the Trust boundary covered natively in test_execution_delegation."""
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
    ["project_owner"], ["project_admin"], ["project_member"], ["drover_admin"],
    *[[role] for role in LEGACY_ROLES],
])
async def test_registered_routes_deny_alias_and_legacy_only_service_roles(native_http, roles):
    headers = native_http.headers(roles)
    for method, path, body in [
        ("GET", "/v1/servers", None), ("GET", CLIENT + "/config", None),
        ("POST", "/v1/servers", {"name": "gateway"}),
        ("POST", SERVER + "/clients", {"name": "client"}),
        ("PATCH", CLIENT, {"name": "renamed"}), ("PATCH", SERVER, {"dns": "9.9.9.9"}),
    ]:
        response = await native_http.client.request(method, path, json=body, headers=headers)
        assert response.status_code == 403
        assert native_http.keystone.requests[-1]["method"] == "GET"
        assert native_http.keystone.requests[-1]["subject_token"] == headers["X-Auth-Token"]


@pytest.mark.asyncio
@pytest.mark.parametrize("roles", [["reader"], ["reader", "waygate_admin"]])
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
@pytest.mark.parametrize("role", ["member", "manager", "admin"])
async def test_management_role_downloads_only_assigned_enabled_own_profile_before_decryption(native_http, monkeypatch, role):
    headers = native_http.headers([role])
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
    assert (await native_http.client.patch(CLIENT, json={"name": "renamed"}, headers=headers)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["member", "manager", "admin"])
async def test_management_role_never_downloads_foreign_or_unassigned_private_profiles(native_http, monkeypatch, role):
    headers = native_http.headers([role])
    decrypt = MagicMock(side_effect=AssertionError("foreign private profile must not decrypt"))
    monkeypatch.setattr(k3s_crypto, "decrypt_wg_client_key", decrypt)
    for client_id in ("other", "legacy"):
        response = await native_http.client.get(SERVER + f"/clients/{client_id}/config", headers=headers)
        assert response.status_code == 403
    decrypt.assert_not_called()


@pytest.mark.asyncio
async def test_verified_system_admin_never_downloads_another_members_profile(native_http):
    native_http.system_admins.add("system-user")
    headers = native_http.headers(["admin"], user_id="system-user")
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_create_for_another_or_unassigned_owner_returns_no_private_profile(native_http):
    headers = native_http.headers(["member"])
    for owner in ("user-b", None):
        created = await native_http.client.post(
            SERVER + "/clients", json={"name": f"for-{owner or 'nobody'}", "owner_user_id": owner}, headers=headers,
        )
        assert created.status_code == 201
        assert created.json()["tunnel_conf"] is None
        assert "PrivateKey" not in created.text and "PresharedKey" not in created.text


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["member", "manager", "admin"])
async def test_management_role_creates_updates_and_persists_default_and_explicit_owner(native_http, role):
    headers = native_http.headers([role])
    created = await native_http.client.post(SERVER + "/clients", json={"name": "new-client"}, headers=headers)
    assert created.status_code == 201
    assert created.headers["cache-control"] == "no-store"
    assert created.json()["owner_user_id"] == "user-a"
    async with db.get_session_factory()() as session:
        record = await session.get(WaygateClient, created.json()["id"])
        stored_private = k3s_crypto.decrypt_wg_client_key(record.private_key_encrypted)
        assert stored_private not in record.private_key_encrypted
        assert "PrivateKey = " + stored_private in created.json()["tunnel_conf"]
    native_http.directory.get.assert_any_call("/role_assignments?user.id=user-a&scope.project.id=project-a&effective=True")
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
    # A known owner cannot be transferred (to the creator) or cleared.
    transfer = await native_http.client.patch(
        SERVER + f"/clients/{client_id}", json={"owner_user_id": "user-a"}, headers=headers,
    )
    assert transfer.status_code == 409
    cleared = await native_http.client.patch(SERVER + f"/clients/{client_id}", json={"owner_user_id": None}, headers=headers)
    assert cleared.status_code == 422
    assert (await native_http.client.patch(
        SERVER + f"/clients/{client_id}", json={"enabled": True}, headers=headers,
    )).status_code == 200
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
    user_headers = native_http.headers(["member"], user_id="user-b")
    assert (await native_http.client.get(SERVER + f"/clients/{client_id}/config", headers=user_headers)).status_code == 200
    creator_headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER + f"/clients/{client_id}/config", headers=creator_headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("owner", ["disabled-user", "unknown-user", "foreign-user", "removed-user"])
async def test_create_and_patch_reject_invalid_owner_without_persisting(native_http, owner):
    native_http.enabled.update({"foreign-user": True, "removed-user": True})
    native_http.memberships["foreign-user"] = "project-b"
    headers = native_http.headers(["member"])
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
    headers = native_http.headers(["member"])
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
async def test_reader_denied_revocation_deletion_rotation_routing_and_bundles(native_http, method, suffix, body):
    response = await native_http.client.request(
        method, SERVER + suffix, json=body, headers=native_http.headers(["reader"]),
    )
    assert response.status_code == 403
    assert (await waygate_db.get_client("server-a", "project-a", "own"))["enabled"] is True
    assert (await waygate_db.get_server("project-a", "server-a"))["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_member_creates_and_updates_gateway_with_delegated_provider_connection(native_http, monkeypatch, delegated):
    from waygate.services import resource_policies

    snapshot = {key: {"id": key + "-id"} for key in ("waygate.flavor", "waygate.image", "waygate.provider_network")}
    resolve = AsyncMock(return_value=snapshot)
    monkeypatch.setattr(resource_policies, "resolve_policy_snapshot", resolve)
    monkeypatch.setattr(resource_policies, "get_policy_snapshot", AsyncMock(return_value={"waygate.floating_network": None}))
    headers = native_http.headers(["member"])
    response = await native_http.client.post("/v1/servers", json={"name": "new-gateway"}, headers=headers)
    assert response.status_code == 201
    assert response.json()["status"] == "CREATING"
    assert (await waygate_db.get_server("project-a", response.json()["id"]))["name"] == "new-gateway"
    assert delegated.purposes == ["provision"] and resolve.await_args.kwargs["conn"] is delegated.conn
    updated = await native_http.client.patch(SERVER, json={"dns": "9.9.9.9", "persistent_keepalive": 0}, headers=headers)
    assert updated.status_code == 200
    assert (updated.json()["dns"], updated.json()["persistent_keepalive"]) == ("9.9.9.9", 0)
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "member-client"}, headers=headers)).status_code == 201
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["manager", "admin"])
async def test_management_role_cloud_actions_do_not_require_implied_member(native_http, role, monkeypatch, delegated):
    from waygate.services import resource_policies

    headers = native_http.headers([role])
    snapshot = {key: {"id": key + "-id"} for key in ("waygate.flavor", "waygate.image", "waygate.provider_network")}
    monkeypatch.setattr(resource_policies, "resolve_policy_snapshot", AsyncMock(return_value=snapshot))
    monkeypatch.setattr(resource_policies, "get_policy_snapshot", AsyncMock(return_value={"waygate.floating_network": None}))
    created = await native_http.client.post("/v1/servers", json={"name": "native-core-role"}, headers=headers)
    assert created.status_code == 201
    assert delegated.purposes == ["provision"]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,suffix,body", PRIVILEGED_ACTIONS + [
    ("GET", "", None), ("PATCH", "", {"dns": "9.9.9.9"}),
    ("GET", "/clients", None), ("GET", "/clients/own/config", None),
    ("POST", "/clients", {"name": "foreign"}), ("PATCH", "/clients/own", {"owner_user_id": "user-a"}),
    ("GET", "/networks", None),
])
async def test_service_admin_remains_project_bound_for_every_resource_route(native_http, method, suffix, body):
    headers = native_http.headers(["member"], project_id="project-b")
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
@pytest.mark.parametrize("role", ["member", "manager", "admin"])
async def test_project_management_roles_cannot_access_global_policies(native_http, method, path, body, role):
    response = await native_http.client.request(
        method, path, json=body, headers=native_http.headers([role]),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_service_admin_revokes_and_rotates_but_does_not_leak_credentials(native_http):
    headers = native_http.headers(["member"])
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
    headers = native_http.headers(["member"])
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
    user_headers = native_http.headers(["member"])
    for client in clients:
        response = await native_http.client.get(
            f"/v1/servers/import-target/clients/{client['id']}/config", headers=user_headers,
        )
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_real_token_validation_rechecks_roles_rejects_spoofed_headers_and_invalid_tokens(native_http):
    headers = native_http.headers(["reader"])
    assert (await native_http.client.get("/v1/servers", headers=headers)).status_code == 200
    native_http.current_roles["user-a", "project-a"] = ["waygate_admin"]
    headers["X-Roles"] = "member,waygate_admin"
    headers["X-User-Id"] = "user-b"
    assert (await native_http.client.get("/v1/servers", headers=headers)).status_code == 403
    assert len(native_http.keystone.requests) == 2
    assert (await native_http.client.get("/v1/servers", headers={"X-Auth-Token": "unknown"})).status_code == 401
    assert (await native_http.client.get("/v1/servers")).status_code == 401
    mismatch = native_http.headers(["member"])
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
    tenant_headers = native_http.headers(["member"])
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
async def test_member_can_revoke_reenable_edit_create_export_and_delete(native_http):
    headers = native_http.headers(["member"])
    revoked = await native_http.client.patch(CLIENT, json={"enabled": False}, headers=headers)
    assert revoked.status_code == 200 and revoked.json()["enabled"] is False
    restored = await native_http.client.patch(CLIENT, json={"enabled": True}, headers=headers)
    assert restored.status_code == 200 and restored.json()["enabled"] is True
    for body in ({"name": "renamed"}, {"enabled": False, "name": "renamed"}):
        assert (await native_http.client.patch(CLIENT, json=body, headers=headers)).status_code == 200
    assert (await native_http.client.patch(CLIENT, json={"owner_user_id": "user-b"}, headers=headers)).status_code == 409
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "new"}, headers=headers)).status_code == 201
    assert (await native_http.client.post(SERVER + "/export", json={"passphrase": "synthetic-passphrase"}, headers=headers)).status_code == 200
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 204
    assert await waygate_db.get_client("server-a", "project-a", "own") is None


@pytest.mark.asyncio
async def test_member_allows_atomic_edit_and_revoke_without_service_leaves(native_http):
    headers = native_http.headers(["member"])
    response = await native_http.client.patch(CLIENT, json={"name": "renamed", "enabled": False}, headers=headers)
    assert response.status_code == 200
    assert (response.json()["name"], response.json()["enabled"]) == ("renamed", False)


@pytest.mark.asyncio
async def test_member_rotates_updates_and_deletes_gateway(native_http, delegated):
    headers = native_http.headers(["member"])
    assert (await native_http.client.post(SERVER + "/agent-token/rotate", headers=headers)).status_code == 202
    assert (await native_http.client.patch(SERVER, json={"dns": "9.9.9.9"}, headers=headers)).status_code == 200
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    deleted = await native_http.client.delete(SERVER, headers=headers)
    assert deleted.status_code == 202 and deleted.json()["status"] == "DELETING"
    assert (await waygate_db.get_server("project-a", "server-a"))["status"] == "DELETING"
    assert delegated.purposes == ["delete"]


@pytest.mark.asyncio
async def test_member_attaches_detaches_and_retains_inventory_and_bundle_authority(native_http, monkeypatch, delegated):
    from waygate.services import waygate_network

    attach = AsyncMock(return_value={
        "id": 1, "server_id": "server-a", "project_id": "project-a", "network_id": NETWORK_ID,
        "nat_mode": "snat", "status": "ACTIVE",
    })
    detach = AsyncMock()
    monkeypatch.setattr(waygate_network, "attach_network", attach)
    monkeypatch.setattr(waygate_network, "detach_network", detach)
    headers = native_http.headers(["member"])
    assert (await native_http.client.post(SERVER + "/networks", json={"network_id": NETWORK_ID}, headers=headers)).status_code == 201
    assert (await native_http.client.delete(SERVER + "/networks/1", headers=headers)).status_code == 204
    assert attach.await_args.args[0] == "project-a" and attach.await_args.args[1]["id"] == "server-a"
    assert detach.await_args.args[0] == "project-a" and detach.await_args.args[2] == 1
    assert delegated.purposes == ["attach", "detach"]
    assert attach.await_args.kwargs["conn"] is detach.await_args.kwargs["conn"] is delegated.conn
    assert (await native_http.client.get(SERVER + "/networks", headers=headers)).status_code == 200
    assert (await native_http.client.post(SERVER + "/export", json={"passphrase": "synthetic-passphrase"}, headers=headers)).status_code == 200


@pytest.mark.asyncio
async def test_verified_system_admin_http_global_access_still_respects_project_ownership(native_http, monkeypatch):
    native_http.system_admins.add("system-user")
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
    headers = native_http.headers(["member"])
    native_http.memberships.pop("user-a")
    response = await native_http.client.post(
        SERVER + "/clients", json={"name": "removed-creator"}, headers=headers,
    )
    assert response.status_code == 403
    assert not any(client["name"] == "removed-creator" for client in await waygate_db.list_clients("server-a", "project-a"))


@pytest.mark.asyncio
async def test_unscoped_nonadmin_keystone_identity_is_rejected(native_http):
    headers = native_http.headers(["member"], project_id="")
    assert (await native_http.client.get("/v1/servers", headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("original_project,token_data", [
    pytest.param("project-b", {}, id="original-project"),
    pytest.param("", {"system": {"all": True}}, id="original-system"),
    pytest.param("", {}, id="original-unscoped"),
])
@pytest.mark.parametrize("assert_original_scope", [False, True], ids=["omitted-caller-header", "exact-caller-header"])
async def test_verified_admin_original_scope_matrix_selects_target_without_membership(
    native_http, original_project, token_data, assert_original_scope,
):
    native_http.system_admins.add("system-user")
    headers = native_http.headers([], user_id="system-user", project_id=original_project, token_data=token_data)
    credential = headers["X-Auth-Token"]
    if assert_original_scope:
        headers["X-Project-Id"] = original_project
    headers["X-Target-Project-Id"] = "project-a"
    original = auth.validate_token(credential)
    assert original["token"] == credential
    assert original["connection_project_id"] == original_project
    assert original["credential_restricted"] is False
    for path in ("/v1/servers", SERVER, SERVER + "/clients"):
        assert (await native_http.client.get(path, headers=headers)).status_code == 200
    created = await native_http.client.post(SERVER + "/clients", json={"name": "scope-matrix-owner"}, headers=headers)
    assert created.status_code == 201 and created.json()["owner_user_id"] == "system-user"
    client_path = SERVER + "/clients/" + created.json()["id"]
    assert (await native_http.client.get(client_path + "/config", headers=headers)).status_code == 200
    assert (await native_http.client.patch(client_path, json={"name": "scope-matrix-updated"}, headers=headers)).status_code == 200
    assert (await native_http.client.delete(client_path, headers=headers)).status_code == 204
    assert ("system-user", "project-a") not in native_http.current_roles
    assert native_http.memberships["system-user"] != "project-a"
    assert all(request["method"] == "GET" and request["subject_token"] == credential
               for request in native_http.keystone.requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("token_data", [{"system": {"all": True}}, {}], ids=["system", "unscoped"])
async def test_projectless_verified_admin_global_routes_need_no_target_but_resource_routes_require_one(
    native_http, monkeypatch, token_data,
):
    from waygate.api import resource_policies as policy_api

    native_http.system_admins.add("system-user")
    headers = native_http.headers([], user_id="system-user", project_id="", token_data=token_data)
    headers["X-Project-Id"] = ""
    conn = MagicMock()
    inspect = AsyncMock(return_value=[])
    monkeypatch.setattr(policy_api, "_admin_connection", lambda: conn)
    monkeypatch.setattr(policy_api.resource_policies, "inspect_policies", inspect)
    assert (await native_http.client.get("/v1/admin/resource-policies", headers=headers)).status_code == 200
    inspect.assert_awaited_once_with(conn)
    for method, path, body in [
        ("GET", "/v1/servers", None), ("GET", SERVER, None), ("GET", CLIENT + "/config", None),
        ("POST", SERVER + "/clients", {"name": "missing-target"}),
        ("PATCH", CLIENT, {"name": "missing-target"}), ("DELETE", CLIENT, None),
    ]:
        assert (await native_http.client.request(method, path, json=body, headers=headers)).status_code == 400
    native_http.directory.projects.get.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("original_project,claimed_project,token_data", [
    pytest.param("project-b", "", {}, id="empty-header-does-not-match-project"),
    pytest.param("", "project-a", {}, id="unscoped-header-cannot-claim-target"),
    pytest.param("", "project-a", {"system": {"all": True}}, id="system-header-cannot-claim-target"),
])
async def test_original_scope_assertion_including_empty_header_must_match_exactly(
    native_http, original_project, claimed_project, token_data,
):
    native_http.system_admins.add("system-user")
    headers = native_http.headers([], user_id="system-user", project_id=original_project, token_data=token_data)
    headers.update({"X-Project-Id": claimed_project, "X-Target-Project-Id": "project-a"})
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    native_http.directory.users.get.assert_not_called()
    native_http.directory.projects.get.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("token_data", [{"system": {"all": True}}, {}], ids=["claimed-system", "unscoped"])
async def test_projectless_token_roles_and_scope_claims_never_substitute_current_system_assignment(native_http, token_data):
    headers = native_http.headers(["admin", "member", *CAPABILITIES], user_id="system-user",
                                  project_id="", token_data=token_data)
    headers["X-Project-Id"] = ""
    assert (await native_http.client.get("/v1/servers", headers=headers)).status_code == 403
    headers["X-Target-Project-Id"] = "project-a"
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.get("/v1/admin/resource-policies", headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("methods,token_data", RESTRICTED_CREDENTIALS)
async def test_projectless_delegated_credential_cannot_use_original_users_system_assignment(
    native_http, methods, token_data,
):
    native_http.system_admins.add("user-a")
    headers = native_http.headers(["admin", "member", *CAPABILITIES], user_id="user-a", project_id="",
                                  methods=methods, token_data={**token_data, "system": {"all": True}})
    headers.update({"X-Project-Id": "", "X-Target-Project-Id": "project-a"})
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "denied"}, headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_machine_auth_remains_db_authoritative_after_project_role_revocation(native_http):
    headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    native_http.current_roles["user-a", "project-a"] = ["waygate_admin"]
    machine = {"Authorization": "Bearer " + native_http.agent_token}
    path = SERVER + "/agent/desired-state"
    assert (await native_http.client.get(path, headers=machine)).status_code == 200
    await waygate_agent_auth.revoke_report_token_by_server("server-a")
    assert (await native_http.client.get(path, headers=machine)).status_code == 401
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_reader_with_legacy_grade_has_inventory_only_and_no_provider_or_profile_authority(native_http):
    headers = native_http.headers(["reader", "waygate_admin"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 403
    assert (await native_http.client.post(SERVER + "/clients", json={"name": "unassigned", "owner_user_id": None}, headers=headers)).status_code == 403
    assert (await native_http.client.patch(CLIENT, json={"enabled": False}, headers=headers)).status_code == 403
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 403
    assert (await native_http.client.post(SERVER + "/agent-token/rotate", headers=headers)).status_code == 403
    assert (await native_http.client.post("/v1/servers", json={"name": "provider-denied"}, headers=headers)).status_code == 403


@pytest.mark.parametrize("failure", ["role-resolution", "assignment-read", "group-membership", "group-grants", "inferences"])
def test_system_admin_directory_errors_fail_closed(monkeypatch, failure):
    client = _system_directory(groups=["group-a"], user_grants=[{
        "user": {"id": "user-a"}, "scope": {"system": {"all": True}}, "role": {"id": "admin-id"},
    }])
    lookup = {
        "role-resolution": client.roles.list,
        "assignment-read": client.role_assignments.list,
        "group-membership": client.groups.list,
        "group-grants": client.role_assignments.list,
        "inferences": client.inference_rules.list_inference_roles,
    }[failure]
    if failure == "group-grants":
        original = lookup.side_effect

        def assignments(**kwargs):
            if "group" in kwargs:
                raise RuntimeError("group directory unavailable")
            return original(**kwargs)

        lookup.side_effect = assignments
    else:
        lookup.side_effect = RuntimeError("directory unavailable")
    monkeypatch.setattr(auth, "_get_admin_ks_client", lambda: client)
    with pytest.raises(auth.AuthorityUnavailable):
        auth._is_system_admin("user-a")


@pytest.mark.asyncio
async def test_owner_assignment_rechecks_membership_and_enabled_state_on_each_patch(native_http):
    headers = native_http.headers(["member"])
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


@pytest.mark.asyncio
@pytest.mark.parametrize("grade,expected", PROJECT_ROLES.items())
async def test_standard_role_native_capabilities_without_service_edges(native_http, grade, expected):
    headers = native_http.headers([grade])
    assert native_http.graph == {}
    response = await native_http.client.get("/v1/policy/capabilities", headers=headers)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["service"] == "waygate"
    assert response.json()["capabilities"] == sorted(expected)
    assert response.json()["actions"] == sorted(response.json()["actions"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    changed = await native_http.client.patch(SERVER, json={"dns": "9.9.9.9"}, headers=headers)
    assert changed.status_code == (200 if grade in {"member", "manager", "admin"} else 403)
    assert (await native_http.client.get("/v1/admin/resource-policies", headers=headers)).status_code == 403
    assert native_http.keystone.tokens[headers["X-Auth-Token"]]["roles"] == [grade]
    native_http.current_roles["user-a", "project-a"] = ["waygate_admin"]
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).json()["capabilities"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("path,key", [
    ("/roles", "roles"), ("/role_inferences", "role_inferences"),
    ("/role_assignments?user.id=user-a&scope.project.id=project-a&effective=True", "role_assignments"),
])
@pytest.mark.parametrize("defect", INCOMPLETE_ENVELOPES)
async def test_project_incomplete_collection_never_uses_original_role_bundle(native_http, path, key, defect):
    headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    _corrupt_native_collection(native_http.directory, path, key, defect)
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 503
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 503
    assert await waygate_db.get_client("server-a", "project-a", "own") is not None
    native_http.directory.get.assert_any_call(path)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["catalog", "assignments", "inferences"])
async def test_current_authority_lookup_failure_never_uses_token_bundle(native_http, failure):
    headers = native_http.headers(["member"])
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
@pytest.mark.parametrize("kind", ["domain", "ambiguous"])
async def test_invalid_current_global_binding_fails_closed(native_http, kind):
    headers = native_http.headers(["member"])
    if kind in {"domain", "ambiguous"}:
        original = native_http.directory.roles.list.side_effect

        def catalog(**kwargs):
            records = original(**kwargs)
            if not kwargs:
                role = {"id": "role-member", "name": "member", "domain_id": "domain-a"}
                if kind == "ambiguous":
                    role = {"id": "duplicate-id", "name": "member"}
                    records.append(_assignment(role))
                else:
                    records = [_assignment(role) if record.id == role["id"] else record for record in records]
            return records

        native_http.directory.roles.list.side_effect = catalog
    response = await native_http.client.get(SERVER, headers=headers)
    assert response.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("alias", ["project_owner", "project_admin", "project_member", "custom_operator"])
async def test_project_alias_requires_current_native_graph_to_expose_standard_member(native_http, alias):
    headers = native_http.headers([alias])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    native_http.graph[alias] = ["member"]
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 200
    assert auth._current_project_roles("user-a", "project-a", native_http.directory) == sorted([alias, "member"])
    native_http.graph.clear()
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("prior", LEGACY_ROLES)
async def test_legacy_service_graph_without_standard_role_does_not_grant_project_authority(native_http, prior):
    native_http.graph[prior] = ["waygate-clients_admin"] if prior != "waygate-clients_admin" else []
    headers = native_http.headers([prior])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("prior", LEGACY_ROLES)
async def test_current_native_member_inference_is_authority_even_from_legacy_grant(native_http, prior):
    native_http.graph[prior] = ["member"]
    headers = native_http.headers([prior])
    assert (await native_http.client.get(SERVER + "/clients", headers=headers)).status_code == 200
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 200
    assert (await native_http.client.delete(CLIENT, headers=headers)).status_code == 204


@pytest.mark.asyncio
async def test_admin_export_skips_foreign_owned_keys_before_decryption(native_http, monkeypatch):
    headers = native_http.headers(["member"])
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
async def test_reader_with_legacy_leaves_never_issues_or_receives_private_profile(native_http, monkeypatch):
    from waygate.api import clients as client_api

    headers = native_http.headers(["reader", "waygate-clients_editor", "waygate-inventory_reader"])
    render = MagicMock(side_effect=AssertionError("reader cannot render a usable profile"))
    decrypt = MagicMock(side_effect=AssertionError("reader cannot decrypt a profile"))
    monkeypatch.setattr(client_api.waygate_config, "render_client_conf", render)
    monkeypatch.setattr(k3s_crypto, "decrypt_wg_client_key", decrypt)
    response = await native_http.client.post(SERVER + "/clients", json={"name": "reader-denied"}, headers=headers)
    assert response.status_code == 403
    assert "PrivateKey" not in response.text and "PresharedKey" not in response.text
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 403
    assert not any(client["name"] == "reader-denied" for client in await waygate_db.list_clients("server-a", "project-a"))
    render.assert_not_called()
    decrypt.assert_not_called()


@pytest.mark.asyncio
async def test_member_retains_issuance_authority_without_service_inference(native_http):
    headers = native_http.headers(["member"])
    assert native_http.graph == {}
    response = await native_http.client.post(SERVER + "/clients", json={"name": "local-connect"}, headers=headers)
    assert response.status_code == 201
    assert response.json()["tunnel_conf"]


@pytest.mark.asyncio
async def test_unrelated_domain_inference_does_not_disable_global_project_authority(native_http):
    native_http.graph["domain-specific-parent"] = ["waygate-inventory_reader"]
    headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200


@pytest.mark.asyncio
async def test_assigned_domain_role_absent_from_global_catalog_denies_only_that_subject(native_http):
    headers = native_http.headers(["member"])
    native_http.current_roles["user-a", "project-a"].append("domain-specific-role")
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    other = native_http.headers(["member"], user_id="user-b")
    assert (await native_http.client.get(SERVER, headers=other)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("architecture", ["arm64", "amd64"])
@pytest.mark.skipif(os.environ.get("WAYGATE_NATIVE_CONTAINER_SMOKE") != "1", reason="Opt-in disposable Docker/MariaDB smoke")
async def test_native_built_images_and_mariadb_upgrade(architecture, monkeypatch):
    from native_container_smoke import run_container_smoke

    await run_container_smoke(architecture, PROJECT_ROLES, CAPABILITIES, monkeypatch)


@pytest.fixture
def operator_policy(native_http, tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("{}\n")
    native_http.settings.oslo_policy_file = str(path)

    def replace(rules):
        timestamp = path.stat().st_mtime + 5
        replacement = path.with_suffix(".next")
        replacement.write_text(json.dumps(rules) + "\n")
        os.utime(replacement, (timestamp, timestamp))
        replacement.replace(path)

    return path, replace


@pytest.mark.asyncio
async def test_operator_yaml_deny_grant_reload_changes_native_api_and_capabilities(native_http, operator_policy):
    _, replace = operator_policy
    headers = native_http.headers(["member"])
    assert (await native_http.client.patch(SERVER, json={"dns": "9.9.9.9"}, headers=headers)).status_code == 200
    replace({"waygate:server:update": "!"})
    assert (await native_http.client.patch(SERVER, json={"dns": "1.1.1.1"}, headers=headers)).status_code == 403
    catalog = (await native_http.client.get("/v1/policy/capabilities", headers=headers)).json()
    assert "waygate:server:update" not in catalog["actions"]
    assert "waygate:server:create" in catalog["actions"]
    # UI labels summarize any allowed action; they are not a second API gate.
    assert "waygate-gateways_editor" in catalog["capabilities"]
    headers = native_http.headers(["member", "custom_operator"])
    replace({action: "!" for action in policy.ACTION_NAMES} | {
        "waygate:server:update": "role:custom_operator", "waygate:server:get": "role:custom_operator",
    })
    assert (await native_http.client.patch(SERVER, json={"dns": "1.1.1.1"}, headers=headers)).status_code == 200
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    catalog = (await native_http.client.get("/v1/policy/capabilities", headers=headers)).json()
    assert catalog["actions"] == ["waygate:server:get", "waygate:server:update"]
    assert catalog["capabilities"] == ["waygate-gateways_editor", "waygate-inventory_reader"]
    replace({action: "!" for action in policy.ACTION_NAMES})
    assert (await native_http.client.patch(SERVER, json={"dns": "9.9.9.9"}, headers=headers)).status_code == 403
    assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).json()["capabilities"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("roles", [["reader"], ["custom_operator"], *[[role] for role in LEGACY_ROLES]])
async def test_permissive_operator_policy_cannot_raise_native_core_role_floor(native_http, operator_policy, roles, monkeypatch):
    _, replace = operator_policy
    replace({action: "@" for action in policy.ACTION_NAMES})
    headers = native_http.headers(roles)
    decrypt = MagicMock(side_effect=AssertionError("native reader/legacy ceiling must precede decryption"))
    monkeypatch.setattr(k3s_crypto, "decrypt_wg_client_key", decrypt)
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == (200 if "reader" in roles else 403)
    for method, path, body in [
        ("GET", CLIENT + "/config", None),
        ("POST", SERVER + "/clients", {"name": "core-floor-denied"}),
        ("PATCH", CLIENT, {"name": "core-floor-denied"}),
        ("PATCH", CLIENT, {"enabled": False}),
        ("DELETE", CLIENT, None),
        ("PATCH", SERVER, {"dns": "9.9.9.9"}),
        ("POST", SERVER + "/agent-token/rotate", None),
        ("POST", SERVER + "/export", {"passphrase": "synthetic-passphrase"}),
        ("POST", "/v1/servers", {"name": "core-floor-denied"}),
    ]:
        assert (await native_http.client.request(method, path, json=body, headers=headers)).status_code == 403
    catalog = (await native_http.client.get("/v1/policy/capabilities", headers=headers)).json()
    assert catalog["capabilities"] == (["waygate-inventory_reader"] if "reader" in roles else [])
    decrypt.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("methods,token_data", RESTRICTED_CREDENTIALS)
async def test_delegated_and_unknown_methods_cannot_cross_native_provider_ceiling(native_http, delegated, methods, token_data):
    headers = native_http.headers(["member"], methods=methods, token_data=token_data)
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    for method, path, body in [
        ("POST", "/v1/servers", {"name": "restricted-provider"}),
        ("DELETE", SERVER, None),
        ("POST", SERVER + "/networks", {"network_id": NETWORK_ID}),
        ("DELETE", SERVER + "/networks/1", None),
    ]:
        assert (await native_http.client.request(method, path, json=body, headers=headers)).status_code == 403
    assert delegated.purposes == []


@pytest.mark.asyncio
async def test_permissive_yaml_preserves_foreign_project_private_owner_system_and_agent_boundaries(native_http, operator_policy):
    _, replace = operator_policy
    replace({action: "@" for action in policy.ACTION_NAMES})
    headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    assert (await native_http.client.get("/v1/servers/server-b", headers=headers)).status_code == 404
    assert (await native_http.client.patch("/v1/servers/server-b", json={"dns": "9.9.9.9"}, headers=headers)).status_code == 404
    for profile in ("other", "legacy", "disabled"):
        assert (await native_http.client.get(SERVER + f"/clients/{profile}/config", headers=headers)).status_code == 403
    assert (await native_http.client.get(CLIENT + "/config", headers=headers)).status_code == 200
    assert (await native_http.client.get("/v1/admin/resource-policies", headers=headers)).status_code == 403
    assert (await native_http.client.get(SERVER + "/agent/desired-state", headers=headers)).status_code == 401
    catalog = (await native_http.client.get("/v1/policy/capabilities", headers=headers)).json()
    assert not set(catalog["actions"]) & policy.SYSTEM_ACTIONS
    headers["X-Target-Project-Id"] = "project-b"
    assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_rules", [
    "false", "0", "[broken", "- not-a-policy-map",
    '{"waygate:server:get": {"bad": "type"}}',
    '{"waygate:server:get": "rule:missing"}',
    '{"waygate:server:get": "not rule:missing"}',
    '{"waygate:server:get": "not rule:cycle", "cycle": "not rule:waygate:server:get"}',
    '{"waygate:server:get": "role:member and not (rule:missing or role:reader)"}',
])
async def test_bad_operator_policy_never_falls_back_to_allowing_defaults(native_http, operator_policy, bad_rules):
    path, _ = operator_policy
    path.write_text(bad_rules)
    headers = native_http.headers(["member"])
    for _ in range(2):
        assert (await native_http.client.get(SERVER, headers=headers)).status_code in {403, 503}
        catalog = await native_http.client.get("/v1/policy/capabilities", headers=headers)
        if catalog.status_code == 200:
            assert "waygate:server:get" not in catalog.json()["actions"]
        else:
            assert catalog.status_code == 503


@pytest.mark.asyncio
async def test_unknown_actions_and_missing_configured_policy_fail_closed(native_http, operator_policy):
    path, _ = operator_policy
    assert not policy.allows({"project_id": "project-a", "is_system_admin": True}, "waygate:unknown")
    path.unlink()
    headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 503
    assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).status_code == 503

@pytest.mark.asyncio
async def test_missing_configured_policy_directory_fails_closed(native_http, tmp_path):
    native_http.settings.oslo_policy_dirs = [str(tmp_path / "missing-policy.d")]
    headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 503
    assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).status_code == 503



@pytest.mark.asyncio
async def test_policy_directories_reload_and_authenticated_empty_discovery(native_http, operator_policy, tmp_path):
    directory = tmp_path / "policy.d"
    directory.mkdir()
    native_http.settings.oslo_policy_dirs = [str(directory)]
    _, replace = operator_policy
    replace({action: "!" for action in policy.ACTION_NAMES})
    rules = directory / "override.yaml"
    rules.write_text(json.dumps({"waygate:server:get": "role:custom_operator"}))
    headers = native_http.headers(["reader", "custom_operator"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    timestamp = rules.stat().st_mtime + 5
    rules.write_text(json.dumps({"waygate:server:get": "!"}))
    os.utime(rules, (timestamp, timestamp))
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).json() == {
        "service": "waygate", "actions": [], "capabilities": [],
    }
    assert (await native_http.client.get("/v1/policy/capabilities")).status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", [
    ("GET", "/v1/servers", None), ("GET", SERVER, None),
    ("POST", "/v1/servers", {"name": "denied"}), ("PATCH", SERVER, {"dns": "9.9.9.9"}),
    ("DELETE", SERVER, None), ("POST", SERVER + "/agent-token/rotate", None),
    ("GET", SERVER + "/clients", None), ("POST", SERVER + "/clients", {"name": "denied"}),
    ("PATCH", CLIENT, {"name": "denied"}), ("PATCH", CLIENT, {"enabled": False}),
    ("DELETE", CLIENT, None), ("GET", CLIENT + "/config", None),
    ("GET", SERVER + "/networks", None), ("POST", SERVER + "/networks", {"network_id": NETWORK_ID}),
    ("DELETE", SERVER + "/networks/1", None),
    ("POST", SERVER + "/export", {"passphrase": "synthetic-passphrase"}),
    ("POST", SERVER + "/import", {"passphrase": "synthetic-passphrase", "bundle": {}}),
    ("GET", "/v1/admin/resource-policies", None),
    ("GET", "/v1/admin/resource-policies/catalog/waygate.image", None),
    ("PUT", "/v1/admin/resource-policies/waygate.image", {"resource_id": None}),
])
async def test_each_native_action_obeys_operator_deny_even_for_verified_system_admin(native_http, operator_policy, method, path, body):
    _, replace = operator_policy
    replace({action: "!" for action in policy.ACTION_NAMES})
    native_http.system_admins.add("user-a")
    headers = native_http.headers(["admin"])
    response = await native_http.client.request(method, path, headers=headers, json=body)
    assert response.status_code == 403
    assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).json()["actions"] == []


@pytest.mark.asyncio
async def test_permissive_policy_cannot_restore_revoked_native_project_binding(native_http, operator_policy):
    _, replace = operator_policy
    replace({action: "@" for action in policy.ACTION_NAMES})
    headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    native_http.current_roles["user-a", "project-a"] = []
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_project_admin_with_native_membership_can_create_only_its_assigned_profile(native_http):
    headers = native_http.headers(["member", "admin"])
    created = await native_http.client.post(SERVER + "/clients", json={"name": "project-admin-owned"}, headers=headers)
    assert created.status_code == 201
    assert created.json()["owner_user_id"] == "user-a" and created.json()["tunnel_conf"]
    assert (await native_http.client.get(SERVER + "/clients/other/config", headers=headers)).status_code == 403
    assert (await native_http.client.get("/v1/admin/resource-policies", headers=headers)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("assigned", ["member", "Member"])
async def test_case_colliding_native_role_ids_reject_before_actual_policy_engine(native_http, assigned):
    # Real oslo.policy folds RoleCheck names; native identity uniqueness must use
    # that comparison boundary instead of treating spelling variants as safe IDs.
    assert policy.allows({"project_id": "project-a", "roles": ["member", "Member"]}, "waygate:server:update")
    headers = native_http.headers(["member", assigned])
    native_http.role_names.update({"member", "Member"})
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    assert (await native_http.client.patch(SERVER, json={"dns": "9.9.9.9"}, headers=headers)).status_code == 403
    assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).status_code == 403
    native_http.current_roles["user-a", "project-a"] = ["member"]
    native_http.role_names.remove("Member")
    assert (await native_http.client.patch(SERVER, json={"dns": "9.9.9.9"}, headers=headers)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [
    {"waygate:server:get": None}, {"waygate:server:get": False}, {"waygate:server:get": []},
    {"waygate:server:get": 0}, {"waygate:server:get": {}}, {"": "@"}, {"   ": "@"},
])
async def test_typed_policy_document_errors_are_unavailable_and_corrected_file_recovers(native_http, operator_policy, invalid):
    _, replace = operator_policy
    headers = native_http.headers(["member"])
    replace(invalid)
    for _ in range(2):
        assert (await native_http.client.get(SERVER, headers=headers)).status_code == 503
        assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).status_code == 503
    replace({"waygate:server:get": "!"})
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    replace({"waygate:server:get": "@"})
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("expression,expected", [("@", 200), ("!", 403), ("", 200)])
async def test_standard_string_policy_checks_preserve_oslo_semantics(native_http, operator_policy, expression, expected):
    _, replace = operator_policy
    replace({"waygate:server:get": expression})
    headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == expected
    catalog = (await native_http.client.get("/v1/policy/capabilities", headers=headers)).json()
    assert ("waygate:server:get" in catalog["actions"]) is (expected == 200)


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["main", "policy.d"])
@pytest.mark.parametrize("expression", ["not malformed", "not (malformed)", "role:member or malformed"])
async def test_malformed_native_parser_clause_never_turns_not_or_into_allow(native_http, operator_policy, tmp_path, location, expression):
    main, replace = operator_policy
    headers = native_http.headers(["member"])
    if location == "main":
        replace({"waygate:server:get": expression})
        path = main
    else:
        directory = tmp_path / "policy.d"
        directory.mkdir()
        native_http.settings.oslo_policy_dirs = [str(directory)]
        path = directory / "override.yaml"
        path.write_text(json.dumps({"waygate:server:get": expression}))
    for _ in range(2):
        assert (await native_http.client.get(SERVER, headers=headers)).status_code == 503
        assert (await native_http.client.get("/v1/policy/capabilities", headers=headers)).status_code == 503
    stamp = path.stat().st_mtime + 5
    path.write_text(json.dumps({"waygate:server:get": "!"}))
    os.utime(path, (stamp, stamp))
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 403
    path.write_text(json.dumps({"waygate:server:get": "@"}))
    os.utime(path, (stamp + 5, stamp + 5))
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200


@pytest.mark.asyncio
async def test_native_parser_error_rejection_is_independent_of_logger_configuration(native_http, operator_policy, monkeypatch):
    from oslo_policy import _parser

    original = _parser.LOG
    monkeypatch.setattr(original, "disabled", True)
    _, replace = operator_policy
    replace({"waygate:server:get": "not malformed"})
    headers = native_http.headers(["member"])
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 503
    assert _parser.LOG is original
    replace({"waygate:server:get": "@"})
    assert (await native_http.client.get(SERVER, headers=headers)).status_code == 200
    assert _parser.LOG is original
