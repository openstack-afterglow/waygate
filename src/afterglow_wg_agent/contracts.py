"""Normative request/response models for the public HTTP contract."""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Literal
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _name(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 64 or any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError("name must be 1-64 non-control Unicode code points")
    return value


def _routes(value: list[IPv4Network]) -> list[IPv4Network]:
    if not 1 <= len(value) <= 16:
        raise ValueError("allowed_ips must contain 1-16 routes")
    return list(dict.fromkeys(value))


def _dns(value: list[IPv4Address]) -> list[IPv4Address]:
    if len(value) > 4:
        raise ValueError("dns must contain at most four entries")
    return list(dict.fromkeys(value))


class ClientCreate(StrictModel):
    name: str
    address: IPv4Address | None = None
    allowed_ips: list[IPv4Network] = Field(default_factory=lambda: [IPv4Network("0.0.0.0/0")])
    dns: list[IPv4Address] | None = None
    mtu: int = Field(default=1420, ge=1280, le=1500)
    persistent_keepalive: int = Field(default=25, ge=0, le=65535)

    @field_validator("name")
    @classmethod
    def name_valid(cls, value: str) -> str:
        return _name(value)

    @field_validator("allowed_ips")
    @classmethod
    def routes_valid(cls, value: list[IPv4Network]) -> list[IPv4Network]:
        return _routes(value)

    @field_validator("dns")
    @classmethod
    def dns_valid(cls, value: list[IPv4Address] | None) -> list[IPv4Address] | None:
        return None if value is None else _dns(value)


class ClientPut(StrictModel):
    name: str
    allowed_ips: list[IPv4Network]
    dns: list[IPv4Address]
    enabled: bool
    mtu: int = Field(ge=1280, le=1500)
    persistent_keepalive: int = Field(ge=0, le=65535)

    @field_validator("name")
    @classmethod
    def name_valid(cls, value: str) -> str:
        return _name(value)

    @field_validator("allowed_ips")
    @classmethod
    def routes_valid(cls, value: list[IPv4Network]) -> list[IPv4Network]:
        return _routes(value)

    @field_validator("dns")
    @classmethod
    def dns_valid(cls, value: list[IPv4Address]) -> list[IPv4Address]:
        return _dns(value)


class ClientPatch(StrictModel):
    name: str | None = None
    allowed_ips: list[IPv4Network] | None = None
    dns: list[IPv4Address] | None = None
    enabled: bool | None = None
    mtu: int | None = Field(default=None, ge=1280, le=1500)
    persistent_keepalive: int | None = Field(default=None, ge=0, le=65535)

    @field_validator("name")
    @classmethod
    def name_valid(cls, value: str | None) -> str | None:
        return None if value is None else _name(value)

    @field_validator("allowed_ips")
    @classmethod
    def routes_valid(cls, value: list[IPv4Network] | None) -> list[IPv4Network] | None:
        return None if value is None else _routes(value)

    @field_validator("dns")
    @classmethod
    def dns_valid(cls, value: list[IPv4Address] | None) -> list[IPv4Address] | None:
        return None if value is None else _dns(value)

    @model_validator(mode="after")
    def require_actual_change_fields(self) -> "ClientPatch":
        if not self.model_fields_set:
            raise ValueError("PATCH body must not be empty")
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("PATCH fields must not be null")
        return self


class ShareCreate(StrictModel):
    expires_in_seconds: int = Field(default=900, ge=60, le=86400)
    single_use: bool = True


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"


class ClientResponse(StrictModel):
    id: UUID
    name: str
    address: IPv4Address
    public_key: str
    allowed_ips: list[IPv4Network]
    dns: list[IPv4Address]
    enabled: bool
    mtu: int = Field(ge=1280, le=1500)
    persistent_keepalive: int = Field(ge=0, le=65535)
    connected: bool
    endpoint: str | None
    last_handshake_at: datetime | None
    transfer_rx_bytes: int = Field(ge=0)
    transfer_tx_bytes: int = Field(ge=0)
    created_at: datetime
    updated_at: datetime

    @field_serializer("last_handshake_at", "created_at", "updated_at")
    def serialize_time(self, value: datetime | None) -> str | None:
        return None if value is None else value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class ClientListResponse(StrictModel):
    clients: list[ClientResponse]


class TrafficPeerResponse(StrictModel):
    public_key: str
    transfer_rx_bytes: int = Field(ge=0)
    transfer_tx_bytes: int = Field(ge=0)
    rx_bytes_per_second: float | None = Field(default=None, ge=0)
    tx_bytes_per_second: float | None = Field(default=None, ge=0)


class TrafficResponse(StrictModel):
    peers: list[TrafficPeerResponse]


class StatusResponse(StrictModel):
    interface: str
    state: Literal["up", "down"]
    listen_port: int | None
    server_public_key: str
    server_address: IPv4Interface
    peer_count: int = Field(ge=0)
    enabled_peer_count: int = Field(ge=0)
    connected_peer_count: int = Field(ge=0)
    transfer_rx_bytes: int = Field(ge=0)
    transfer_tx_bytes: int = Field(ge=0)


class QrBase64Response(StrictModel):
    media_type: Literal["image/png"] = "image/png"
    data: str


class ShareResponse(StrictModel):
    url: AnyHttpUrl
    expires_at: datetime
    single_use: bool

    @field_serializer("expires_at")
    def serialize_time(self, value: datetime) -> str:
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class ErrorDetail(StrictModel):
    code: str
    message: str


class ErrorResponse(StrictModel):
    error: ErrorDetail


class AgentError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def error(status_code: int, code: str, message: str) -> AgentError:
    return AgentError(status_code, code, message)
