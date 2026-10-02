from __future__ import annotations

import json

import pytest
import responses
from keystoneauth1 import exceptions, session, token_endpoint
from openstack.connection import Connection

from waygate_sdk import register


@pytest.fixture(params=["http://waygate.test", "http://waygate.test/v1"])
def transport(request):
    version = {
        "id": "v1.0", "status": "CURRENT", "min_version": "1.0", "version": "1.0",
        "links": [{"rel": "self", "href": "http://waygate.test/v1/"}],
    }
    # Discovery may start at either configured endpoint. The consumer operation
    # below must still match exactly one /v1/ prefix; unregistered URLs fail.
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        http.add(responses.GET, "http://waygate.test/", json={"versions": [version]})
        http.add(responses.GET, "http://waygate.test/v1", status=307,
                 headers={"Location": "http://waygate.test/v1/"})
        http.add(responses.GET, "http://waygate.test/v1/", json={"version": version})
        auth = token_endpoint.Token(endpoint=request.param, token="test-token")
        connection = Connection(
            session=session.Session(auth=auth),
            waygate_endpoint_override=request.param, waygate_api_version="1",
        )
        try:
            yield register(connection), http
        finally:
            connection.close()


@pytest.mark.parametrize(
    "method_name,args,kwargs,http_method,path,body",
    [
        ("servers", (), {}, "GET", "/v1/servers", None),
        ("get_server", ("server-1",), {}, "GET", "/v1/servers/server-1", None),
        ("create_server", (), {"name": "gateway-1"}, "POST", "/v1/servers", {"name": "gateway-1"}),
        (
            "update_server",
            ("server-1",),
            {"dns": "9.9.9.9", "persistent_keepalive": 15},
            "PATCH",
            "/v1/servers/server-1",
            {"dns": "9.9.9.9", "persistent_keepalive": 15},
        ),
        ("delete_server", ("server-1",), {}, "DELETE", "/v1/servers/server-1", None),
        (
            "rotate_agent_token",
            ("server/1",),
            {},
            "POST",
            "/v1/servers/server%2F1/agent-token/rotate",
            None,
        ),
        ("clients", ("server-1",), {}, "GET", "/v1/servers/server-1/clients", None),
        (
            "create_client",
            ("server-1",),
            {"name": "laptop"},
            "POST",
            "/v1/servers/server-1/clients",
            {"name": "laptop"},
        ),
        (
            "update_client",
            ("server-1", "client-1"),
            {"enabled": False},
            "PATCH",
            "/v1/servers/server-1/clients/client-1",
            {"enabled": False},
        ),
        (
            "delete_client",
            ("server-1", "client-1"),
            {},
            "DELETE",
            "/v1/servers/server-1/clients/client-1",
            None,
        ),
        (
            "networks",
            ("server-1",),
            {},
            "GET",
            "/v1/servers/server-1/networks",
            None,
        ),
        (
            "attach_network",
            ("server-1",),
            {"network_id": "network-1"},
            "POST",
            "/v1/servers/server-1/networks",
            {"network_id": "network-1"},
        ),
        (
            "detach_network",
            ("server-1", 7),
            {},
            "DELETE",
            "/v1/servers/server-1/networks/7",
            None,
        ),
        (
            "export_server",
            ("server-1",),
            {"passphrase": "correct horse battery staple"},
            "POST",
            "/v1/servers/server-1/export",
            {"passphrase": "correct horse battery staple"},
        ),
        (
            "import_server",
            ("server-1",),
            {"passphrase": "secret", "bundle": {"version": 1}},
            "POST",
            "/v1/servers/server-1/import",
            {"passphrase": "secret", "bundle": {"version": 1}},
        ),
        ("health", (), {}, "GET", "/v1/health", None),
        ("resource_policies", (), {}, "GET", "/v1/admin/resource-policies", None),
        (
            "resource_policy_catalog",
            ("waygate.image",),
            {},
            "GET",
            "/v1/admin/resource-policies/catalog/waygate.image",
            None,
        ),
        (
            "update_resource_policy",
            ("waygate.image",),
            {"resource_id": "img-123"},
            "PUT",
            "/v1/admin/resource-policies/waygate.image",
            {"resource_id": "img-123"},
        ),
    ],
)
def test_discovered_connection_routes_json_methods_once(transport, method_name, args, kwargs, http_method, path, body):
    proxy, http = transport
    status = 204 if http_method == "DELETE" else (202 if method_name == "rotate_agent_token" else 200)

    def respond(request):
        assert request.headers["X-Auth-Token"] == "test-token"
        if body is None:
            assert not request.body
        else:
            assert json.loads(request.body) == body
        return status, {"Content-Type": "application/json"}, "" if status == 204 else '{"id":"accepted-resource"}'

    http.add_callback(http_method, "http://waygate.test" + path, callback=respond)
    assert getattr(proxy, method_name)(*args, **kwargs) == (None if status == 204 else {"id": "accepted-resource"})


def test_update_server_preserves_null_and_zero_and_escapes_server_id(transport):
    proxy, http = transport
    server = {"id": "server/../../other"}

    def check_request(request):
        assert json.loads(request.body) == {"dns": None, "persistent_keepalive": 0}
        return 200, {"Content-Type": "application/json"}, json.dumps(server)

    http.add_callback(
        responses.PATCH, "http://waygate.test/v1/servers/server%2F..%2F..%2Fother",
        callback=check_request,
    )
    assert proxy.update_server(server["id"], dns=None, persistent_keepalive=0) == server


def test_update_server_propagates_conflict_response(transport):
    proxy, http = transport
    http.add(
        responses.PATCH, "http://waygate.test/v1/servers/server%2F1", status=409,
        json={"error": {"message": "server is not ACTIVE"}},
    )
    with pytest.raises(exceptions.http.Conflict):
        proxy.update_server("server/1", dns="1.1.1.1")


def test_client_config_download_uses_discovered_endpoint(transport):
    proxy, http = transport
    config = "[Interface]\nAddress = 10.8.0.2/32\n"
    http.add(
        responses.GET, "http://waygate.test/v1/servers/server-1/clients/client-1/config",
        body=config, content_type="text/plain",
    )
    assert proxy.client_config("server-1", "client-1") == config
