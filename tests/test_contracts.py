from ipaddress import IPv4Address, IPv4Network

import pytest
from pydantic import ValidationError

from afterglow_wg_agent.contracts import ClientCreate, ClientPatch, ClientPut


def test_create_normalizes_name_routes_and_dns() -> None:
    model = ClientCreate(name="  Alice  ", allowed_ips=[IPv4Network("0.0.0.0/0"), IPv4Network("0.0.0.0/0")], dns=[IPv4Address("1.1.1.1"), IPv4Address("1.1.1.1")])
    assert model.name == "Alice"
    assert model.allowed_ips == [IPv4Network("0.0.0.0/0")]
    assert model.dns == [IPv4Address("1.1.1.1")]


def test_patch_rejects_empty_and_null_fields() -> None:
    with pytest.raises(ValidationError):
        ClientPatch()
    with pytest.raises(ValidationError):
        ClientPatch(name=None)


def test_put_requires_every_mutable_field() -> None:
    with pytest.raises(ValidationError):
        ClientPut(name="Alice", allowed_ips=[IPv4Network("0.0.0.0/0")], dns=[])
