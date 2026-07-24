from pydantic import ValidationError
import pytest

from afterglow_wg_agent.settings import Settings


TOKEN = "t" * 32


def configured(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "wg_server_host": "172.16.53.135",
        "api_auth_token": TOKEN,
        "api_host": "127.0.0.1",
    }
    values.update(overrides)
    return Settings(**values)


def test_loopback_derived_url_is_never_unspecified() -> None:
    assert configured().public_base_url == "http://127.0.0.1:8080"


def test_insecure_non_loopback_derives_server_host() -> None:
    settings = configured(api_host="0.0.0.0", allow_insecure_http=True, api_allowed_cidrs="172.16.53.0/24")
    assert settings.public_base_url == "http://172.16.53.135:8080"


def test_non_loopback_requires_management_cidrs() -> None:
    with pytest.raises(ValidationError, match="API_ALLOWED_CIDRS"):
        configured(api_host="0.0.0.0", allow_insecure_http=True)


def test_non_loopback_http_origin_requires_opt_in() -> None:
    with pytest.raises(ValidationError, match="ALLOW_INSECURE_HTTP"):
        configured(api_public_base_url="http://example.test")


def test_explicit_insecure_http_origin_is_allowed_with_opt_in() -> None:
    assert configured(api_public_base_url="http://example.test", allow_insecure_http=True).public_base_url == "http://example.test"


def test_literal_ipv6_http_origin_is_rejected() -> None:
    with pytest.raises(ValidationError, match="IPv6 HTTP"):
        configured(api_public_base_url="http://[2001:db8::1]", allow_insecure_http=True)


def test_small_network_cannot_leave_only_one_client_address() -> None:
    with pytest.raises(ValidationError, match="at least two client"):
        configured(wg_server_net="10.8.0.0/30")
