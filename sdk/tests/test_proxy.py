from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from waygate_sdk import register
from waygate_sdk.proxy import Proxy
from waygate_sdk.service import WaygateService


def _response(status_code=200, *, payload=None, text=""):
    content = text.encode() if text else (b"json" if payload is not None else b"")
    return SimpleNamespace(
        status_code=status_code,
        content=content,
        text=text,
        json=lambda: payload,
    )


@pytest.mark.parametrize(
    "method_name,args,kwargs,http_method,path,body",
    [
        ("servers", (), {}, "GET", "/v1/servers", None),
        ("get_server", ("server-1",), {}, "GET", "/v1/servers/server-1", None),
        ("create_server", (), {"name": "gateway-1"}, "POST", "/v1/servers", {"name": "gateway-1"}),
        ("delete_server", ("server-1",), {}, "DELETE", "/v1/servers/server-1", None),
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
    ],
)
def test_json_methods_issue_expected_request(method_name, args, kwargs, http_method, path, body):
    proxy = Proxy(session=MagicMock(), service_type="waygate")
    status = 204 if http_method == "DELETE" else 200
    response = _response(status, payload={"ok": True}) if status != 204 else _response(204)
    proxy.request = MagicMock(return_value=response)

    result = getattr(proxy, method_name)(*args, **kwargs)

    expected_kwargs = {"raise_exc": True}
    if body is not None:
        expected_kwargs["json"] = body
    proxy.request.assert_called_once_with(path, http_method, **expected_kwargs)
    assert result == ({"ok": True} if status != 204 else None)


def test_client_config_returns_wireguard_text():
    proxy = Proxy(session=MagicMock(), service_type="waygate")
    proxy.request = MagicMock(return_value=_response(200, text="[Interface]\nPrivateKey = secret\n"))

    result = proxy.client_config("server-1", "client-1")

    proxy.request.assert_called_once_with(
        "/v1/servers/server-1/clients/client-1/config",
        "GET",
        raise_exc=True,
    )
    assert result.startswith("[Interface]")


def test_identifiers_are_escaped_as_single_path_segments():
    proxy = Proxy(session=MagicMock(), service_type="waygate")
    proxy.request = MagicMock(return_value=_response(200, payload={"ok": True}))

    proxy.get_server("server/../../other")

    proxy.request.assert_called_once_with(
        "/v1/servers/server%2F..%2F..%2Fother",
        "GET",
        raise_exc=True,
    )


def test_service_description_constructs_with_required_service_type():
    description = WaygateService()
    assert description.service_type == "waygate"
    assert description.supported_versions == {"1": Proxy}


def test_register_enables_non_official_service_before_attaching_proxy():
    class Config:
        def __init__(self):
            self.enabled = set()

        def enable_service(self, service_type):
            self.enabled.add(service_type)

        def has_service(self, service_type):
            return service_type in self.enabled

    class Connection:
        def __init__(self):
            self.config = Config()
            self.waygate = None

        def add_service(self, service):
            assert self.config.has_service(service.service_type)
            self.waygate = Proxy(session=MagicMock(), service_type=service.service_type)

    connection = Connection()
    assert not hasattr(connection.config, "has_waygate")

    proxy = register(connection)

    assert isinstance(proxy, Proxy)
    assert connection.config.has_service("waygate")
