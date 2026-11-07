"""Per-attachment client routes, shared/external attach and expected-client flavor tiers."""

from __future__ import annotations

import contextlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from waygate import policy
from waygate.api import servers as server_api
from waygate.auth import require_token
from waygate.db import Base
from waygate.main import app
from waygate.models.orm import WaygateNetworkAttachment, WaygateServer
from waygate.models.schemas import (
    WaygateNetworkAttachCreateRequest,
    WaygateNetworkAttachmentUpdateRequest,
    WaygateServerCreateRequest,
)
from waygate.services import network as waygate_network
from waygate.services import waygate_config, waygate_db
from waygate.services.network import WaygateNetworkError

NETWORK_ID = "11111111-2222-3333-4444-555555555555"
PROJECT = "project-1"


def _server(**overrides) -> dict:
    return {
        "id": "server-1",
        "project_id": PROJECT,
        "name": "gw",
        "status": "ACTIVE",
        "server_vm_id": "vm-1",
        "tunnel_cidr": "10.8.0.0/24",
        "listen_port": 51820,
        "endpoint_ip": "203.0.113.10",
        "server_public_key": "A" * 43 + "=",
    } | overrides


# ---------------------------------------------------------------------------
# validation matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("model", [WaygateNetworkAttachCreateRequest, WaygateNetworkAttachmentUpdateRequest])
@pytest.mark.parametrize(
    "raw,expected",
    [
        ([], []),
        (["192.168.10.0/24"], ["192.168.10.0/24"]),
        (["192.168.10.5/24"], ["192.168.10.0/24"]),
        ([" 10.20.0.0/16 "], ["10.20.0.0/16"]),
        (["10.20.0.1"], ["10.20.0.1/32"]),
        (["2001:db8::1/64"], ["2001:db8::/64"]),
        (["192.168.10.0/24", "192.168.10.9/24", "172.16.0.0/12"], ["192.168.10.0/24", "172.16.0.0/12"]),
        ([f"10.{i}.0.0/16" for i in range(64)], [f"10.{i}.0.0/16" for i in range(64)]),
    ],
)
def test_allowed_ips_are_canonical_and_deduplicated(model, raw, expected):
    fields = {"network_id": NETWORK_ID} if model is WaygateNetworkAttachCreateRequest else {}
    assert model(**fields, allowed_ips=raw).allowed_ips == expected


@pytest.mark.parametrize("model", [WaygateNetworkAttachCreateRequest, WaygateNetworkAttachmentUpdateRequest])
@pytest.mark.parametrize(
    "raw",
    [
        ["0.0.0.0/0"],
        ["::/0"],
        ["192.168.1.1/0"],
        ["not-a-cidr"],
        ["10.0.0.0/33"],
        ["10.0.0.0/8; rm -rf /"],
        [42],
        None,
        [f"10.{i}.0.0/16" for i in range(65)],
    ],
)
def test_allowed_ips_rejects_default_routes_invalid_and_oversized(model, raw):
    fields = {"network_id": NETWORK_ID} if model is WaygateNetworkAttachCreateRequest else {}
    with pytest.raises(ValidationError):
        model(**fields, allowed_ips=raw)


def test_attach_defaults_to_no_routes_and_update_requires_explicit_list():
    assert WaygateNetworkAttachCreateRequest(network_id=NETWORK_ID).allowed_ips == []
    with pytest.raises(ValidationError):
        WaygateNetworkAttachmentUpdateRequest()
    with pytest.raises(ValidationError):
        WaygateNetworkAttachmentUpdateRequest(allowed_ips=[], cidr="10.0.0.0/24")


@pytest.mark.parametrize("route", ["10.8.0.0/24", "10.8.0.128/25", "10.0.0.0/8", "10.8.0.7/32"])
def test_routes_overlapping_tunnel_subnet_are_rejected(route):
    with pytest.raises(WaygateNetworkError) as exc:
        waygate_network.validate_attachment_routes([route], "10.8.0.0/24")
    assert exc.value.status_code == 422


def test_non_overlapping_ipv4_and_ipv6_routes_are_accepted():
    routes = ["10.9.0.0/24", "192.168.0.0/16", "2001:db8::/64"]
    assert waygate_network.validate_attachment_routes(routes, "10.8.0.0/24") == routes


# ---------------------------------------------------------------------------
# attach: shared/external provider networks vs foreign tenant networks
# ---------------------------------------------------------------------------


def _attach_conn(network) -> MagicMock:
    conn = MagicMock()
    conn.network.get_network.return_value = network
    conn.network.get_subnet.return_value = SimpleNamespace(
        network_id="net-1", cidr="192.168.9.0/24", id="sub-1", ip_version=4
    )
    return conn


def _attach_doubles(monkeypatch) -> AsyncMock:
    create = AsyncMock(side_effect=lambda _server, _project, data: {"id": 7, **data})
    monkeypatch.setattr(waygate_network.waygate_db, "list_attachments", AsyncMock(return_value=[]))
    monkeypatch.setattr(waygate_network.waygate_db, "create_attachment_record", create)
    monkeypatch.setattr(waygate_network.waygate_db, "update_attachment", AsyncMock())
    monkeypatch.setattr(waygate_network.neutron, "create_port", MagicMock(return_value={"id": "port-1"}))
    monkeypatch.setattr(waygate_network.nova, "attach_interface", MagicMock())
    return create


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "network",
    [
        SimpleNamespace(project_id=PROJECT, is_shared=False, is_router_external=False),
        SimpleNamespace(project_id="admin-project", is_shared=True, is_router_external=False),
        SimpleNamespace(project_id="admin-project", is_shared=False, is_router_external=True),
    ],
    ids=["owned", "shared-provider", "external-provider"],
)
async def test_owned_shared_and_external_networks_are_attachable(monkeypatch, network):
    create = _attach_doubles(monkeypatch)
    result = await waygate_network.attach_network(
        PROJECT, _server(), "net-1", "sub-1", "snat", conn=_attach_conn(network), allowed_ips=["192.168.9.0/24"]
    )
    assert result["status"] == "ACTIVE"
    assert result["cidr"] == "192.168.9.0/24"
    assert result["allowed_ips"] == ["192.168.9.0/24"]
    assert create.await_args.args[2]["allowed_ips"] == ["192.168.9.0/24"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "network",
    [
        None,
        SimpleNamespace(project_id="other-project", is_shared=False, is_router_external=False),
        SimpleNamespace(project_id="other-project"),
        SimpleNamespace(project_id=None, is_shared=False, is_router_external=False),
        # Truthy non-boolean SDK placeholders are not a sharing declaration.
        MagicMock(project_id="other-project"),
    ],
    ids=["missing", "foreign-tenant", "foreign-no-flags", "ownerless-unshared", "mock-flags"],
)
async def test_foreign_unshared_networks_remain_indistinguishable_404(monkeypatch, network):
    create = _attach_doubles(monkeypatch)
    with pytest.raises(WaygateNetworkError) as exc:
        await waygate_network.attach_network(PROJECT, _server(), "net-1", "sub-1", "snat", conn=_attach_conn(network))
    assert (exc.value.status_code, exc.value.detail) == (404, "네트워크를 찾을 수 없습니다")
    create.assert_not_awaited()


@pytest.mark.asyncio
async def test_attach_rejects_tunnel_overlap_before_any_cloud_call(monkeypatch):
    create = _attach_doubles(monkeypatch)
    conn = _attach_conn(SimpleNamespace(project_id=PROJECT))
    with pytest.raises(WaygateNetworkError) as exc:
        await waygate_network.attach_network(
            PROJECT, _server(), "net-1", "sub-1", "snat", conn=conn, allowed_ips=["10.8.0.0/16"]
        )
    assert exc.value.status_code == 422
    conn.network.get_network.assert_not_called()
    create.assert_not_awaited()


# ---------------------------------------------------------------------------
# durable store (real SQLAlchemy rows on SQLite)
# ---------------------------------------------------------------------------


class _SqlSession:
    def __init__(self, engine):
        self.session = Session(engine)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        self.session.close()

    async def execute(self, statement):
        return self.session.execute(statement)

    async def commit(self):
        self.session.commit()

    async def refresh(self, obj):
        self.session.refresh(obj)

    def add(self, obj):
        self.session.add(obj)


@pytest.fixture
def route_store(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all(
            [
                WaygateServer(id="server-1", project_id=PROJECT, name="gw", status="ACTIVE"),
                WaygateServer(id="server-2", project_id="project-2", name="other", status="ACTIVE"),
                WaygateNetworkAttachment(
                    id=1, server_id="server-1", project_id=PROJECT, network_id="net-a",
                    cidr="192.168.10.0/24", allowed_ips=["172.20.0.0/16", "192.168.10.0/24"], status="ACTIVE",
                ),
                # Row written by a pre-008 process: NULL keeps the legacy [cidr] route.
                WaygateNetworkAttachment(
                    id=2, server_id="server-1", project_id=PROJECT, network_id="net-b",
                    cidr="192.168.20.0/24", allowed_ips=None, status="ACTIVE",
                ),
                # Interface-only attachment: NAT continues, no client route is advertised.
                WaygateNetworkAttachment(
                    id=3, server_id="server-1", project_id=PROJECT, network_id="net-c",
                    cidr="192.168.30.0/24", allowed_ips=[], status="ACTIVE",
                ),
                WaygateNetworkAttachment(
                    id=4, server_id="server-1", project_id=PROJECT, network_id="net-d",
                    cidr="192.168.40.0/24", allowed_ips=["10.99.0.0/16"], status="ERROR",
                ),
                WaygateNetworkAttachment(
                    id=5, server_id="server-1", project_id=PROJECT, network_id="net-e",
                    cidr="192.168.50.0/24", allowed_ips=["172.20.0.0/16"], status="CREATING",
                ),
            ]
        )
        session.commit()
    monkeypatch.setattr(waygate_db, "get_session_factory", lambda: lambda: _SqlSession(engine))
    yield engine
    engine.dispose()


@pytest.mark.asyncio
async def test_client_routes_union_active_allowed_ips_while_nat_keeps_cidrs(route_store):
    assert await waygate_db.list_active_attachment_routes("server-1") == [
        "172.20.0.0/16", "192.168.10.0/24", "192.168.20.0/24",
    ]
    assert sorted(await waygate_db.list_active_attachment_cidrs("server-1")) == [
        "192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24",
    ]
    listed = {att["id"]: att["allowed_ips"] for att in await waygate_db.list_attachments("server-1", PROJECT)}
    assert listed[2] == ["192.168.20.0/24"] and listed[3] == []


@pytest.mark.asyncio
async def test_new_attachment_rows_store_explicit_routes(route_store):
    created = await waygate_db.create_attachment_record(
        "server-1", PROJECT, {"network_id": "net-f", "cidr": "192.168.60.0/24", "status": "CREATING"}
    )
    assert created["allowed_ips"] == []
    with Session(route_store) as session:
        assert session.get(WaygateNetworkAttachment, created["id"]).allowed_ips == []


@pytest.mark.asyncio
async def test_route_update_replaces_only_active_owned_attachment(route_store):
    updated = await waygate_db.update_attachment_routes("server-1", PROJECT, 3, ["10.30.0.0/16"])
    assert (updated["allowed_ips"], updated["cidr"], updated["status"]) == (["10.30.0.0/16"], "192.168.30.0/24", "ACTIVE")
    assert "10.30.0.0/16" in await waygate_db.list_active_attachment_routes("server-1")
    assert await waygate_db.update_attachment_routes("server-1", "project-2", 3, []) is None
    assert await waygate_db.update_attachment_routes("server-2", "project-2", 3, []) is None
    assert await waygate_db.update_attachment_routes("server-1", PROJECT, 99, []) is None
    for inactive in (4, 5):
        with pytest.raises(waygate_db.WaygateServerInactiveError):
            await waygate_db.update_attachment_routes("server-1", PROJECT, inactive, [])
    with Session(route_store) as session:
        session.get(WaygateServer, "server-1").status = "DELETING"
        session.commit()
    with pytest.raises(waygate_db.WaygateServerInactiveError):
        await waygate_db.update_attachment_routes("server-1", PROJECT, 1, [])
    with Session(route_store) as session:
        assert session.get(WaygateNetworkAttachment, 1).allowed_ips == ["172.20.0.0/16", "192.168.10.0/24"]


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def test_client_conf_uses_attachment_routes_not_nat_cidr():
    conf = waygate_config.render_client_conf(
        private_key="k",
        tunnel_ip="10.8.0.2",
        dns=None,
        server_public_key="pub",
        endpoint_ip="203.0.113.10",
        listen_port=51820,
        allowed_ips=["10.8.0.0/24"],
        attachment_routes=["172.20.0.0/16", "10.8.0.0/24"],
    )
    allowed = next(line for line in conf.splitlines() if line.startswith("AllowedIPs"))
    assert allowed == "AllowedIPs = 10.8.0.0/24, 172.20.0.0/16"


@pytest.fixture
async def api_client(monkeypatch):
    monkeypatch.setattr("waygate.api.attachments.is_db_available", lambda: True)
    monkeypatch.setattr("waygate.api.clients.is_db_available", lambda: True)
    previous = app.dependency_overrides.copy()
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            yield client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def _as(roles: list[str], *, project_id: str = PROJECT, user_id: str = "user-1", **extra) -> None:
    async def token():
        return {"project_id": project_id, "user_id": user_id, "username": "alice", "roles": roles,
                "is_system_admin": False, **extra}

    app.dependency_overrides[require_token] = token


@pytest.mark.asyncio
async def test_config_download_renders_attachment_routes_and_never_nat_cidr(api_client, monkeypatch):
    from waygate.api import clients as client_api

    _as(["member"])
    monkeypatch.setattr(client_api.waygate_db, "get_server", AsyncMock(return_value=_server()))
    monkeypatch.setattr(client_api.waygate_db, "get_client", AsyncMock(return_value={
        "id": "client-1", "name": "laptop", "owner_user_id": "user-1", "enabled": True, "tunnel_ip": "10.8.0.2",
        "allowed_ips": ["10.8.0.0/24"], "private_key_encrypted": "cipher", "preshared_key_encrypted": None,
        "dns": None, "mtu": None, "persistent_keepalive": 25,
    }))
    monkeypatch.setattr(client_api.waygate_db, "list_active_attachment_routes", AsyncMock(return_value=["172.20.0.0/16"]))
    nat = AsyncMock(side_effect=AssertionError("client config must not derive routes from NAT CIDRs"))
    monkeypatch.setattr(client_api.waygate_db, "list_active_attachment_cidrs", nat)
    monkeypatch.setattr(client_api.k3s_crypto, "decrypt_wg_client_key", lambda _cipher: "private-key")

    response = await api_client.get("/v1/servers/server-1/clients/client-1/config")

    assert response.status_code == 200
    assert "AllowedIPs = 10.8.0.0/24, 172.20.0.0/16\n" in response.text
    nat.assert_not_awaited()


# ---------------------------------------------------------------------------
# attach / PATCH API and authorization
# ---------------------------------------------------------------------------


def test_route_update_policy_is_registered_as_routing_project_action():
    rule = next(rule for rule in policy.list_rules() if rule.name == "waygate:network:update")
    assert rule.operations == [{"method": "PATCH", "path": "/v1/servers/{server_id}/networks/{attachment_id}"}]
    assert rule.scope_types == ["project"]
    assert rule.check_str == "system_admin:True or role:member or role:manager or role:admin"
    assert "waygate:network:update" in policy.CAPABILITY_ACTIONS["waygate-routing_admin"]
    assert "waygate:network:update" not in policy.CLOUD_ACTIONS
    sample = (Path(__file__).parents[1] / "waygate" / "policy.yaml.sample").read_text()
    assert f'"waygate:network:update": "{rule.check_str}"' in sample


@pytest.mark.asyncio
@pytest.mark.parametrize("roles", [["member"], ["manager"], ["admin"]])
async def test_route_update_succeeds_for_project_managers(api_client, monkeypatch, roles):
    from waygate.api import attachments as attachment_api

    _as(roles)
    monkeypatch.setattr(attachment_api.waygate_db, "get_server", AsyncMock(return_value=_server()))
    update = AsyncMock(return_value={
        "id": 3, "server_id": "server-1", "project_id": PROJECT, "network_id": NETWORK_ID, "cidr": "192.168.30.0/24",
        "allowed_ips": ["10.30.0.0/16"], "nat_mode": "snat", "status": "ACTIVE",
    })
    monkeypatch.setattr(waygate_network.waygate_db, "update_attachment_routes", update)

    response = await api_client.patch("/v1/servers/server-1/networks/3", json={"allowed_ips": ["10.30.0.9/16"]})

    assert response.status_code == 200
    assert response.json()["allowed_ips"] == ["10.30.0.0/16"]
    update.assert_awaited_once_with("server-1", PROJECT, 3, ["10.30.0.0/16"])


@pytest.mark.asyncio
@pytest.mark.parametrize("roles", [["reader"], [], ["waygate-routing_admin"]])
async def test_route_update_is_forbidden_without_project_management_role(api_client, monkeypatch, roles):
    from waygate.api import attachments as attachment_api

    _as(roles)
    get_server = AsyncMock(side_effect=AssertionError("authorization precedes lookup"))
    monkeypatch.setattr(attachment_api.waygate_db, "get_server", get_server)
    response = await api_client.patch("/v1/servers/server-1/networks/3", json={"allowed_ips": []})
    assert response.status_code == 403
    get_server.assert_not_awaited()


@pytest.mark.asyncio
async def test_route_update_status_mapping(api_client, monkeypatch):
    from waygate.api import attachments as attachment_api

    _as(["member"])
    monkeypatch.setattr(attachment_api.waygate_db, "get_server", AsyncMock(return_value=None))
    assert (await api_client.patch("/v1/servers/foreign/networks/3", json={"allowed_ips": []})).status_code == 404

    monkeypatch.setattr(attachment_api.waygate_db, "get_server", AsyncMock(return_value=_server()))
    update = AsyncMock(return_value=None)
    monkeypatch.setattr(waygate_network.waygate_db, "update_attachment_routes", update)
    assert (await api_client.patch("/v1/servers/server-1/networks/3", json={"allowed_ips": []})).status_code == 404

    update.side_effect = waygate_db.WaygateServerInactiveError("inactive")
    assert (await api_client.patch("/v1/servers/server-1/networks/3", json={"allowed_ips": []})).status_code == 409

    update.reset_mock(side_effect=True)
    for body in ({"allowed_ips": ["10.8.0.0/25"]}, {"allowed_ips": ["0.0.0.0/0"]}, {}, {"allowed_ips": [], "x": 1}):
        assert (await api_client.patch("/v1/servers/server-1/networks/3", json=body)).status_code == 422
    update.assert_not_awaited()


@pytest.mark.asyncio
async def test_attach_api_forwards_canonical_routes(api_client, monkeypatch):
    from waygate.api import attachments as attachment_api

    _as(["member"])
    monkeypatch.setattr(attachment_api.waygate_db, "get_server", AsyncMock(return_value=_server()))

    @contextlib.asynccontextmanager
    async def admitted(_token_info, _server_id, purpose):
        assert purpose == "attach"
        yield SimpleNamespace(id="grant-1"), "conn"

    attach = AsyncMock(return_value={
        "id": 7, "server_id": "server-1", "project_id": PROJECT, "network_id": NETWORK_ID, "cidr": "192.168.9.0/24",
        "allowed_ips": ["172.20.0.0/16"], "nat_mode": "snat", "status": "ACTIVE",
    })
    monkeypatch.setattr(attachment_api.execution, "admitted_operation", admitted)
    monkeypatch.setattr(attachment_api.waygate_network, "attach_network", attach)

    response = await api_client.post(
        "/v1/servers/server-1/networks", json={"network_id": NETWORK_ID, "allowed_ips": ["172.20.9.9/16", "172.20.0.0/16"]}
    )

    assert response.status_code == 201
    assert response.json()["allowed_ips"] == ["172.20.0.0/16"]
    assert attach.await_args.kwargs == {"conn": "conn", "allowed_ips": ["172.20.0.0/16"]}


# ---------------------------------------------------------------------------
# expected_clients flavor tiers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [0, 1001, -1, "10", 10.0, True])
def test_expected_clients_is_a_strict_bounded_integer(value):
    with pytest.raises(ValidationError):
        WaygateServerCreateRequest(name="gw", expected_clients=value)


@pytest.mark.parametrize("value,tier", [(None, None), (1, "small"), (50, "small"), (51, "large"), (1000, "large")])
def test_requested_flavor_tier_boundaries(value, tier):
    assert server_api.requested_flavor_tier(value) == tier


async def _create(monkeypatch, *, expected_clients, large_configured):
    calls = []
    resolved_keys = []

    async def resolve_policy_snapshot(*, conn, keys):
        resolved_keys.append(keys)
        catalog = {
            "waygate.provider_network": {"id": "network-1", "name": "provider"},
            "waygate.image": {"id": "image-1", "name": "image"},
            "waygate.flavor": {"id": "flavor-small", "name": "1c1g"},
            "waygate.flavor_large": {"id": "flavor-large", "name": "2c2g"},
        }
        return {key: catalog[key] for key in keys}

    async def get_policy_snapshot(keys):
        assert keys == ("waygate.floating_network", "waygate.flavor_large")
        return {
            "waygate.floating_network": None,
            "waygate.flavor_large": {"id": "flavor-large", "name": "2c2g"} if large_configured else None,
        }

    async def enqueue(project_id, server_id, data, **identity):
        calls.append(data)

    async def get_server(project_id, server_id):
        return {"id": server_id, "project_id": project_id, "name": "gw", "status": "CREATING", "listen_port": 51820,
                "tunnel_cidr": "10.8.0.0/24", "expected_clients": calls[0]["expected_clients"],
                "flavor_tier": calls[0]["flavor_tier"]}

    @contextlib.asynccontextmanager
    async def admitted(_token_info, _server_id, _purpose):
        yield SimpleNamespace(id="grant-1"), "conn"

    monkeypatch.setattr(server_api, "_require_db", lambda: None)
    monkeypatch.setattr(server_api, "get_settings", lambda: SimpleNamespace(
        waygate_default_listen_port=51820, waygate_default_tunnel_cidr="10.8.0.0/24",
        waygate_agent_install_mode="cloud-init",
    ))
    monkeypatch.setattr(server_api.execution, "admitted_operation", admitted)
    monkeypatch.setattr("waygate.services.resource_policies.resolve_policy_snapshot", resolve_policy_snapshot)
    monkeypatch.setattr("waygate.services.resource_policies.get_policy_snapshot", get_policy_snapshot)
    monkeypatch.setattr(server_api.waygate_jobs, "enqueue_provision_job", enqueue)
    monkeypatch.setattr(server_api.waygate_db, "get_server", get_server)
    monkeypatch.setattr(server_api.waygate_agent_auth, "get_status_result", AsyncMock(return_value=None))
    body = {"name": "gw"} | ({} if expected_clients is None else {"expected_clients": expected_clients})
    info = await server_api.create_waygate_server(
        WaygateServerCreateRequest(**body), {"project_id": PROJECT, "user_id": "user-1", "username": "alice"}
    )
    return calls[0], resolved_keys, info


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "expected_clients,large_configured,flavor_id,tier",
    [
        (None, True, "flavor-small", None),
        (None, False, "flavor-small", None),
        (10, True, "flavor-small", "small"),
        (50, True, "flavor-small", "small"),
        (51, True, "flavor-large", "large"),
        (51, False, "flavor-small", "small"),
        (1000, False, "flavor-small", "small"),
    ],
)
async def test_create_selects_flavor_tier_with_unconfigured_large_fallback(
    monkeypatch, expected_clients, large_configured, flavor_id, tier
):
    data, resolved_keys, info = await _create(
        monkeypatch, expected_clients=expected_clients, large_configured=large_configured
    )
    assert (data["flavor_id"], data["flavor_tier"], data["expected_clients"]) == (flavor_id, tier, expected_clients)
    assert (info.expected_clients, info.flavor_tier) == (expected_clients, tier)
    large_used = flavor_id == "flavor-large"
    # The large flavor is re-validated in the execution scope and pinned in the server snapshot only when applied.
    assert (("waygate.flavor_large",) in resolved_keys) is large_used
    assert ("waygate.flavor_large" in data["resource_policy_snapshot"]) is large_used
    assert data["resource_policy_snapshot"]["waygate.flavor"]["id"] == "flavor-small"


def test_large_flavor_policy_is_optional_admin_flavor_selection():
    from waygate.services import resource_policies

    spec = resource_policies.get_spec("waygate.flavor_large")
    assert (spec.resource_kind, spec.execution_scope, spec.required_when) == ("flavor", "tenant", None)
    assert [item.key for item in resource_policies.list_specs()] == [
        "waygate.provider_network", "waygate.image", "waygate.flavor", "waygate.flavor_large",
        "waygate.floating_network",
    ]


@pytest.mark.asyncio
async def test_server_store_round_trips_sizing_fields(route_store):
    with Session(route_store) as session:
        waygate_db.add_server_record(session, PROJECT, "server-3", {
            "name": "big", "flavor_id": "flavor-large", "expected_clients": 120, "flavor_tier": "large",
        })
        waygate_db.add_server_record(session, PROJECT, "server-4", {"name": "legacy"})
        session.commit()
    big = await waygate_db.get_server(PROJECT, "server-3")
    legacy = await waygate_db.get_server(PROJECT, "server-4")
    assert (big["expected_clients"], big["flavor_tier"], big["flavor_id"]) == (120, "large", "flavor-large")
    assert (legacy["expected_clients"], legacy["flavor_tier"]) == (None, None)
