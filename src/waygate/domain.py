"""Immutable domain state and system-control protocols."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Protocol, Sequence
from uuid import UUID


@dataclass(frozen=True, slots=True)
class InstallationState:
    installation_id: UUID
    wg_interface: str
    wg_config_path: str
    server_network: IPv4Network
    server_address: IPv4Interface
    server_public_key: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class Client:
    id: UUID
    name: str
    address: IPv4Address
    public_key: str
    allowed_ips: tuple[IPv4Network, ...]
    dns: tuple[IPv4Address, ...]
    enabled: bool
    created_at: datetime
    updated_at: datetime
    mtu: int = 1420
    persistent_keepalive: int = 25


@dataclass(frozen=True, slots=True)
class ClientForwardPolicy:
    client_id: UUID
    source: IPv4Address
    destinations: tuple[IPv4Network, ...]


@dataclass(frozen=True, slots=True)
class KeyPair:
    private_key: str
    public_key: str


@dataclass(frozen=True, slots=True)
class PeerRuntime:
    public_key: str
    endpoint: str | None
    last_handshake_at: datetime | None
    transfer_rx_bytes: int
    transfer_tx_bytes: int
    allowed_ips: tuple[IPv4Network, ...]


@dataclass(frozen=True, slots=True)
class InterfaceSnapshot:
    exists: bool
    up: bool
    listen_port: int | None
    public_key: str | None
    addresses: tuple[IPv4Interface, ...]
    peers: tuple[PeerRuntime, ...]


class WireGuardControl(Protocol):
    def generate_keypair(self) -> KeyPair: ...
    def read_private_key(self, path: str) -> str | None: ...
    def snapshot(self, interface: str) -> InterfaceSnapshot: ...
    def apply_config(self, interface: str, config_path: str) -> None: ...
    def ensure_interface(self, interface: str, address: IPv4Interface) -> None: ...
    def remove_interface(self, interface: str) -> None: ...


class NetworkControl(Protocol):
    def validate_stage_chains(self, interface: str) -> None: ...
    def clear_stage_rules(self, interface: str) -> None: ...
    def stage_client(self, interface: str, address: str, client_id: str) -> None: ...
    def unstage_client(self, interface: str, address: str, client_id: str) -> None: ...
    def release_first_activation_forward_guard(self) -> None: ...
    def validate_topology(self, vpn_network: IPv4Network, interface: str) -> None: ...
    def reconcile(self, interface: str, vpn_network: IPv4Network, api_port: int, allowed_management: Sequence[IPv4Network], outbound_interface: str | None, client_policies: Sequence[ClientForwardPolicy]) -> None: ...
