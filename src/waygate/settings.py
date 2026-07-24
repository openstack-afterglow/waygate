"""Environment-backed settings and safe public URL derivation."""

from __future__ import annotations

import ipaddress
import re
from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Any
from urllib.parse import urlsplit, urlunsplit

from pydantic import AfterValidator, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_INTERFACE_RE = re.compile(r"[A-Za-z0-9_=+.-]{1,15}\Z")
_HOST_RE = re.compile(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


def _valid_name(value: str) -> str:
    if not _INTERFACE_RE.fullmatch(value):
        raise ValueError("must be a valid Linux interface name")
    return value


def _csv_networks(value: Any) -> list[IPv4Network]:
    if value in (None, ""):
        return []
    parts = value.split(",") if isinstance(value, str) else value
    if not isinstance(parts, list):
        raise ValueError("must be a comma-separated CIDR list")
    try:
        return [IPv4Network(str(part).strip(), strict=True) for part in parts if str(part).strip()]
    except ValueError as exc:
        raise ValueError("contains an invalid IPv4 CIDR") from exc


def _endpoint_host(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("must not be empty")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not _HOST_RE.fullmatch(value):
            raise ValueError("must be an IPv4 address, IPv6 address, or DNS name")
        return value.lower()


InterfaceName = Annotated[str, AfterValidator(_valid_name)]


class Settings(BaseSettings):
    """Only network/API settings are configurable; storage locations are not."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
        case_sensitive=False,
    )

    wg_interface: InterfaceName = "wg0"
    wg_port: int = Field(default=51820, ge=1, le=65535)
    wg_server_host: str
    wg_server_net: IPv4Network = IPv4Network("10.8.0.0/24")
    wg_default_dns: IPv4Address = IPv4Address("1.1.1.1")
    api_auth_token: SecretStr
    api_host: IPv4Address = IPv4Address("0.0.0.0")
    api_port: int = Field(default=8080, ge=1, le=65535)
    wg_persistent_keepalive: int = Field(default=25, ge=0, le=65535)
    wg_outbound_interface: InterfaceName | None = None
    api_public_base_url: str | None = None
    allow_insecure_http: bool = False
    api_allowed_cidrs: Annotated[list[IPv4Network], NoDecode] = Field(default_factory=list)
    api_docs_enabled: bool = False

    @field_validator("wg_server_host")
    @classmethod
    def validate_server_host(cls, value: str) -> str:
        return _endpoint_host(value)

    @field_validator("wg_server_net", mode="before")
    @classmethod
    def validate_server_net(cls, value: Any) -> IPv4Network:
        network = IPv4Network(value, strict=True)
        if network.prefixlen > 29 or network.num_addresses < 8:
            raise ValueError("must reserve server, network, broadcast, and at least two client hosts")
        return network

    @field_validator("api_allowed_cidrs", mode="before")
    @classmethod
    def parse_allowed_cidrs(cls, value: Any) -> list[IPv4Network]:
        return _csv_networks(value)

    @field_validator("api_auth_token")
    @classmethod
    def validate_auth_token(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("must be at least 32 characters")
        return value

    @field_validator("api_public_base_url")
    @classmethod
    def validate_public_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("must be an origin without path, query, fragment, or credentials")
        host = parsed.hostname
        if host is None:
            raise ValueError("must contain a host")
        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            if not _HOST_RE.fullmatch(host):
                raise ValueError("contains an invalid host")
            normalized_host = host.lower()
            literal_v6 = False
        else:
            normalized_host = str(host_ip)
            literal_v6 = host_ip.version == 6
        if parsed.scheme == "http" and literal_v6:
            raise ValueError("literal IPv6 HTTP public origins are not allowed")
        port = parsed.port
        netloc = normalized_host if ":" not in normalized_host else f"[{normalized_host}]"
        if port is not None:
            netloc = f"{netloc}:{port}"
        return urlunsplit((parsed.scheme, netloc, "", "", ""))

    @model_validator(mode="after")
    def validate_cross_field_policy(self) -> "Settings":
        if not self.api_host.is_loopback and not self.api_allowed_cidrs:
            raise ValueError("non-loopback API bind requires API_ALLOWED_CIDRS")
        if self.api_public_base_url is not None:
            public = urlsplit(self.api_public_base_url)
            host = public.hostname
            assert host is not None
            try:
                public_host_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                public_host_loopback = host.lower() == "localhost"
            if public.scheme == "http" and not (
                public_host_loopback and self.api_host.is_loopback
            ) and not self.allow_insecure_http:
                raise ValueError("non-loopback HTTP public origin requires ALLOW_INSECURE_HTTP=true")
        else:
            try:
                endpoint = ipaddress.ip_address(self.wg_server_host)
            except ValueError:
                endpoint = None
            if not self.api_host.is_loopback and (
                not self.allow_insecure_http or (endpoint is not None and endpoint.version == 6)
            ):
                raise ValueError("secure non-loopback binds and IPv6 endpoints require API_PUBLIC_BASE_URL=https://...")
        return self

    @property
    def server_address(self) -> IPv4Address:
        return IPv4Address(int(self.wg_server_net.network_address) + 1)

    @property
    def server_interface(self) -> str:
        return f"{self.server_address}/{self.wg_server_net.prefixlen}"

    @property
    def public_base_url(self) -> str:
        if self.api_public_base_url is not None:
            return self.api_public_base_url
        if self.api_host.is_loopback:
            return f"http://{self.api_host}:{self.api_port}"
        return f"http://{self.wg_server_host}:{self.api_port}"
