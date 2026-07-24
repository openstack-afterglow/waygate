"""Application service with locked, staged desired-state transitions."""

from __future__ import annotations

import base64
import hashlib
import io
import re
import secrets
import shutil
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path
from threading import Lock

from fastapi.responses import JSONResponse, PlainTextResponse
from uuid import UUID, uuid4

import qrcode
from qrcode.image.pure import PyPNGImage

from .authority import AuthorityError, validate_config_identity
from .contracts import AgentError, ClientResponse, ShareResponse, StatusResponse, error
from .db import ClientDraft, Database, DatabaseBusy, InstanceLease
from .domain import Client, ClientForwardPolicy, InstallationState, InterfaceSnapshot, NetworkControl, PeerRuntime, WireGuardControl
from .paths import RuntimePaths, fsync_directory
from .traffic import PeerTrafficSampler
from .wireguard import install_config, render_config, write_private_key
from .settings import Settings


@dataclass(frozen=True, slots=True)
class PreparedHttp:
    response: object


class AgentService:
    def __init__(self, settings: Settings, paths: RuntimePaths, control: WireGuardControl | None = None, network: NetworkControl | None = None) -> None:
        self.settings = settings
        self.paths = paths
        self.control = control
        self.network = network
        self.database = Database(paths)
        self.lease = InstanceLease(paths.instance_lock)
        self.fatal_reconciliation = False
        self.traffic_sampler = PeerTrafficSampler()
        self._traffic_lock = Lock()

    def startup(self) -> None:
        self.lease.acquire()
        try:
            self.paths.ensure_private_directories()
            self._validate_runtime_names(set(), cleanup_orphans=False)
            self.database.migrate()
            with self.database.operation(exclusive=True) as connection:
                installation = self.database.installation(connection)
                if installation is None:
                    if self.control is None:
                        raise error(503, "wireguard_unavailable", "WireGuard unavailable")
                    server_key = self.paths.key_dir / "server.key"
                    config_path = self.paths.config_path(self.settings.wg_interface)
                    client_keys = list(self.paths.key_dir.glob("client-*.key"))
                    snapshot = self.control.snapshot(self.settings.wg_interface)
                    if server_key.exists() or config_path.exists() or snapshot.exists or client_keys:
                        if server_key.exists() and not config_path.exists() and not snapshot.exists and not client_keys:
                            server_key.unlink()
                            fsync_directory(server_key.parent)
                        else:
                            raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                    keypair = self.control.generate_keypair()
                    write_private_key(server_key, keypair.private_key)
                    installation = InstallationState(
                        installation_id=uuid4(), wg_interface=self.settings.wg_interface,
                        wg_config_path=str(config_path), server_network=self.settings.wg_server_net,
                        server_address=IPv4Interface(self.settings.server_interface),
                        server_public_key=keypair.public_key, created_at=datetime.now(UTC),
                    )
                    self.database.insert_installation(connection, installation)
                self.database.purge_expired_tokens(connection, datetime.now(UTC), limit=100)
                clients = tuple(self.database.list_clients(connection))
                self._validate_runtime_names({client.id for client in clients}, cleanup_orphans=True)
                for client in clients:
                    client_key = self._key_path(client.id)
                    if not client_key.is_file():
                        raise error(503, "client_key_missing", "Client key unavailable")
                    try:
                        private_key = client_key.read_text(encoding="ascii").strip()
                    except (OSError, UnicodeError) as exc:
                        raise error(503, "client_key_missing", "Client key unavailable") from exc
                    if not private_key:
                        raise error(503, "client_key_missing", "Client key unavailable")
                    derive = getattr(self.control, "public_key", None)
                    if callable(derive) and derive(private_key) != client.public_key:
                        raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                self.reconcile_desired(installation, clients, release_global_guard=True)
        except BaseException:
            self.lease.release()
            raise

    def shutdown(self) -> None:
        self.lease.release()

    @staticmethod
    def _is_uuid4_text(raw: str) -> bool:
        try:
            value = UUID(raw)
        except ValueError:
            return False
        return value.version == 4 and str(value) == raw

    def _validate_runtime_names(self, client_ids: set[UUID], *, cleanup_orphans: bool) -> None:
        client_pattern = re.compile(r"client-([0-9a-f-]{36})\.key\Z")
        tmp_pattern = re.compile(r"\.tmp-([0-9a-f-]{36})\Z")
        stage_pattern = re.compile(r"\.afterglow-stage-([0-9a-f-]{36})\Z")
        changed_keys = False
        for entry in self.paths.key_dir.iterdir():
            if entry.name == "server.key":
                if not entry.is_file() or entry.is_symlink() or entry.stat().st_mode & 0o777 != 0o600:
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                continue
            client_match = client_pattern.fullmatch(entry.name)
            if client_match:
                raw_id = client_match.group(1)
                if not self._is_uuid4_text(raw_id):
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                if UUID(raw_id) in client_ids:
                    if not entry.is_file() or entry.is_symlink() or entry.stat().st_mode & 0o777 != 0o600:
                        raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                    continue
                if cleanup_orphans and entry.is_file():
                    entry.unlink()
                    changed_keys = True
                elif entry.is_file() and not cleanup_orphans:
                    continue
                elif entry.is_file():
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                else:
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                continue
            tmp_match = tmp_pattern.fullmatch(entry.name)
            if tmp_match and self._is_uuid4_text(tmp_match.group(1)) and entry.is_file():
                entry.unlink()
                changed_keys = True
                continue
            raise error(503, "state_reconciliation_failed", "State reconciliation failed")
        if changed_keys:
            fsync_directory(self.paths.key_dir)
        changed_stages = False
        for entry in self.paths.wireguard_dir.iterdir():
            stage_match = stage_pattern.fullmatch(entry.name)
            if stage_match and self._is_uuid4_text(stage_match.group(1)) and entry.is_dir():
                shutil.rmtree(entry)
                changed_stages = True
                continue
            if entry.name.startswith(".afterglow-stage-"):
                raise error(503, "state_reconciliation_failed", "State reconciliation failed")
        if changed_stages:
            fsync_directory(self.paths.wireguard_dir)

    def _require_live(self) -> None:
        if self.fatal_reconciliation:
            raise error(503, "state_reconciliation_failed", "State reconciliation failed")

    def _key_path(self, client_id: UUID) -> Path:
        return self.paths.key_dir / f"client-{client_id}.key"

    def _validate_installation(self, installation: InstallationState) -> None:
        expected_path = self.paths.config_path(self.settings.wg_interface)
        if (
            installation.wg_interface != self.settings.wg_interface
            or Path(installation.wg_config_path) != expected_path
            or installation.server_network != self.settings.wg_server_net
            or installation.server_address != IPv4Interface(self.settings.server_interface)
        ):
            raise error(503, "state_reconciliation_failed", "State reconciliation failed")

    def _read_server_key(self, installation: InstallationState) -> str:
        path = self.paths.key_dir / "server.key"
        if not path.is_file():
            config_path = Path(installation.wg_config_path)
            if not config_path.is_file():
                raise error(503, "state_reconciliation_failed", "State reconciliation failed")
            try:
                private_key = next(
                    line.split("=", 1)[1].strip()
                    for line in config_path.read_text(encoding="ascii").splitlines()
                    if line.startswith("PrivateKey = ")
                )
            except (OSError, UnicodeError, StopIteration, IndexError) as exc:
                raise error(503, "state_reconciliation_failed", "State reconciliation failed") from exc
            derive = getattr(self.control, "public_key", None)
            if not callable(derive) or not private_key or derive(private_key) != installation.server_public_key:
                raise error(503, "state_reconciliation_failed", "State reconciliation failed")
            try:
                write_private_key(path, private_key)
            except OSError as exc:
                raise error(503, "state_reconciliation_failed", "State reconciliation failed") from exc
            return private_key
        try:
            private_key = path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise error(503, "state_reconciliation_failed", "State reconciliation failed") from exc
        if not private_key:
            raise error(503, "state_reconciliation_failed", "State reconciliation failed")
        derive = getattr(self.control, "public_key", None)
        if callable(derive) and derive(private_key) != installation.server_public_key:
            raise error(503, "state_reconciliation_failed", "State reconciliation failed")
        return private_key

    def _expected_peer_map(self, clients: tuple[Client, ...]) -> dict[str, set[str]]:
        return {client.public_key: {f"{client.address}/32"} for client in clients if client.enabled}

    def _verify_runtime(self, installation: InstallationState, clients: tuple[Client, ...], runtime: InterfaceSnapshot) -> None:
        actual = {peer.public_key: {str(route) for route in peer.allowed_ips} for peer in runtime.peers}
        if (not runtime.exists or not runtime.up or runtime.listen_port != self.settings.wg_port or runtime.public_key != installation.server_public_key or set(runtime.addresses) != {installation.server_address} or actual != self._expected_peer_map(clients)):
            self.fatal_reconciliation = True
            raise error(503, "state_reconciliation_failed", "State reconciliation failed")

    def reconcile_desired(self, installation: InstallationState, clients: tuple[Client, ...], *, release_global_guard: bool) -> InterfaceSnapshot:
        """Apply exactly the supplied in-memory desired state; never reopen SQLite."""
        self._require_live()
        if self.control is None:
            raise error(503, "wireguard_unavailable", "WireGuard unavailable")
        self._validate_installation(installation)
        config_path = Path(installation.wg_config_path)
        if config_path.exists():
            try:
                validate_config_identity(config_path, installation.installation_id)
            except AuthorityError as exc:
                raise error(503, "state_reconciliation_failed", "State reconciliation failed") from exc
        private_key = self._read_server_key(installation)
        policies = tuple(ClientForwardPolicy(client.id, client.address, client.allowed_ips) for client in clients if client.enabled)
        if self.network is not None:
            validate_topology = getattr(self.network, "validate_topology", None)
            if callable(validate_topology):
                validate_topology(installation.server_network, installation.wg_interface)
            validate_stages = getattr(self.network, "validate_stage_chains", None)
            if callable(validate_stages):
                validate_stages(installation.wg_interface)
            self.network.reconcile(installation.wg_interface, installation.server_network, self.settings.api_port, self.settings.api_allowed_cidrs, self.settings.wg_outbound_interface, policies)
        peers = [(client.public_key, IPv4Interface(f"{client.address}/32"), client.persistent_keepalive) for client in clients if client.enabled]
        install_config(config_path, render_config(installation_id=installation.installation_id, private_key=private_key, address=installation.server_address, port=self.settings.wg_port, clients=peers))
        self.control.ensure_interface(self.settings.wg_interface, installation.server_address)
        self.control.apply_config(self.settings.wg_interface, str(config_path))
        runtime = self.control.snapshot(self.settings.wg_interface)
        self._verify_runtime(installation, clients, runtime)
        if release_global_guard and self.network is not None:
            clear_stages = getattr(self.network, "clear_stage_rules", None)
            if callable(clear_stages):
                clear_stages(self.settings.wg_interface, {str(client.id) for client in clients})
            self.network.release_first_activation_forward_guard()
        return runtime

    def reconcile(self) -> None:
        self._require_live()
        try:
            with self.database.operation(exclusive=True) as connection:
                installation = self.database.installation(connection)
                clients = tuple(self.database.list_clients(connection))
                if installation is None:
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                self.reconcile_desired(installation, clients, release_global_guard=True)
        except DatabaseBusy as exc:
            raise error(503, "database_busy", "Database busy") from exc

    def _runtime(self) -> InterfaceSnapshot:
        if self.control is None:
            return InterfaceSnapshot(False, False, None, None, (), ())
        try:
            return self.control.snapshot(self.settings.wg_interface)
        except Exception as exc:
            raise error(503, "wireguard_unavailable", "WireGuard unavailable") from exc

    @staticmethod
    def _peer(client: Client, snapshot: InterfaceSnapshot) -> PeerRuntime | None:
        return next((peer for peer in snapshot.peers if peer.public_key == client.public_key), None)

    def response(self, client: Client, snapshot: InterfaceSnapshot | None = None) -> ClientResponse:
        snapshot = self._runtime() if snapshot is None else snapshot
        peer = self._peer(client, snapshot) if client.enabled and snapshot.exists else None
        connected = bool(peer and peer.last_handshake_at and datetime.now(UTC) - peer.last_handshake_at <= timedelta(seconds=180))
        return ClientResponse(id=client.id, name=client.name, address=client.address, public_key=client.public_key, allowed_ips=list(client.allowed_ips), dns=list(client.dns), enabled=client.enabled, mtu=client.mtu, persistent_keepalive=client.persistent_keepalive, connected=connected, endpoint=None if peer is None else peer.endpoint, last_handshake_at=None if peer is None else peer.last_handshake_at, transfer_rx_bytes=0 if peer is None else peer.transfer_rx_bytes, transfer_tx_bytes=0 if peer is None else peer.transfer_tx_bytes, created_at=client.created_at, updated_at=client.updated_at)

    def list_clients(self) -> list[ClientResponse]:
        self._require_live()
        try:
            with self.database.operation(exclusive=False) as connection:
                clients = self.database.list_clients(connection)
            snapshot = self._runtime()
            return [self.response(client, snapshot) for client in clients]
        except DatabaseBusy as exc:
            raise error(503, "database_busy", "Database busy") from exc

    def get_client(self, client_id: UUID) -> Client:
        self._require_live()
        try:
            with self.database.operation(exclusive=False) as connection:
                client = self.database.get_client(connection, client_id)
        except DatabaseBusy as exc:
            raise error(503, "database_busy", "Database busy") from exc
        if client is None:
            raise error(404, "client_not_found", "Client not found")
        return client

    def _stage(self, client: Client) -> None:
        if client.enabled and self.network is not None:
            self.network.stage_client(self.settings.wg_interface, str(client.address), str(client.id))

    def _unstage(self, client: Client) -> None:
        if client.enabled and self.network is not None:
            self.network.unstage_client(self.settings.wg_interface, str(client.address), str(client.id))

    def _compensate(self, installation: InstallationState, clients: tuple[Client, ...]) -> bool:
        try:
            self.reconcile_desired(installation, clients, release_global_guard=False)
            return True
        except BaseException:
            self.fatal_reconciliation = True
            return False

    def _commit_client(self, connection, operation: str, candidate: Client, current: Client | None) -> None:
        if operation == "create":
            self.database.insert_client(connection, ClientDraft(candidate.id, candidate.name, candidate.address, candidate.public_key, candidate.allowed_ips, candidate.dns, candidate.enabled, candidate.created_at, candidate.updated_at, candidate.mtu, candidate.persistent_keepalive))
        elif operation == "update":
            self.database.update_client(connection, candidate)
        else:
            if current is None or not self.database.delete_client(connection, current.id):
                raise error(404, "client_not_found", "Client not found")

    def create_client(self, *, name: str, address: IPv4Address | None, allowed_ips: list[IPv4Network], dns: list[IPv4Address], mtu: int = 1420, persistent_keepalive: int = 25) -> ClientResponse:
        self._require_live()
        if self.control is None:
            raise error(503, "wireguard_unavailable", "WireGuard unavailable")
        keypair = self.control.generate_keypair()
        client_id, now = uuid4(), datetime.now(UTC)
        key_path = self._key_path(client_id)
        committed = False
        try:
            with self.database.operation(exclusive=True) as connection:
                installation = self.database.installation(connection)
                old_clients = tuple(self.database.list_clients(connection))
                if installation is None:
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                if self.database.name_exists(connection, name):
                    raise error(409, "client_name_conflict", "Client name already exists")
                allocated = self.database.allocate_address(connection, self.settings.wg_server_net, address)
                candidate = Client(client_id, name, allocated, keypair.public_key, tuple(allowed_ips), tuple(dns), True, now, now, mtu, persistent_keepalive)
                self._profile_text(candidate, installation, keypair.private_key)
                key_path.write_text(keypair.private_key + "\n", encoding="ascii"); key_path.chmod(0o600); fsync_directory(key_path.parent)
                desired = old_clients + (candidate,)
                try:
                    self._stage(candidate)
                    runtime = self.reconcile_desired(installation, desired, release_global_guard=False)
                    response_model = self.response(candidate, runtime)
                    response = PreparedHttp(JSONResponse(response_model.model_dump(mode="json"), status_code=201, headers={"Cache-Control": "no-store"}))
                except BaseException as original_exc:
                    if not self._compensate(installation, old_clients):
                        raise original_exc
                    try:
                        self._unstage(candidate)
                    except BaseException as cleanup_exc:
                        self.fatal_reconciliation = True
                        raise error(503, "state_reconciliation_failed", "State reconciliation failed") from cleanup_exc
                    raise
                self._commit_client(connection, "create", candidate, None)
                connection.commit()
                committed = True
                try:
                    self._unstage(candidate)
                except BaseException:
                    self.fatal_reconciliation = True
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                return response
        except (KeyError, ValueError) as exc:
            key_path.unlink(missing_ok=True)
            raise error(409, "address_conflict", "Address already allocated") from exc
        except OverflowError as exc:
            key_path.unlink(missing_ok=True)
            raise error(409, "address_pool_exhausted", "Address pool exhausted") from exc
        except BaseException:
            if not committed:
                key_path.unlink(missing_ok=True)
            raise

    def update_client(self, client_id: UUID, *, name: str, allowed_ips: list[IPv4Network], dns: list[IPv4Address], enabled: bool, mtu: int, persistent_keepalive: int) -> ClientResponse:
        self._require_live()
        with self.database.operation(exclusive=True) as connection:
            installation = self.database.installation(connection)
            old_clients = tuple(self.database.list_clients(connection))
            current = self.database.get_client(connection, client_id)
            if installation is None:
                raise error(503, "state_reconciliation_failed", "State reconciliation failed")
            if current is None:
                raise error(404, "client_not_found", "Client not found")
            if self.database.name_exists(connection, name, exclude_id=client_id):
                raise error(409, "client_name_conflict", "Client name already exists")
            candidate = replace(current, name=name, allowed_ips=tuple(allowed_ips), dns=tuple(dns), enabled=enabled, mtu=mtu, persistent_keepalive=persistent_keepalive)
            if candidate != current:
                candidate = replace(candidate, updated_at=datetime.now(UTC))
            key_path = self._key_path(candidate.id)
            if not key_path.is_file():
                raise error(503, "client_key_missing", "Client key unavailable")
            try:
                private_key = key_path.read_text(encoding="ascii").strip()
            except (OSError, UnicodeError) as exc:
                raise error(503, "client_key_missing", "Client key unavailable") from exc
            if not private_key:
                raise error(503, "client_key_missing", "Client key unavailable")
            self._profile_text(candidate, installation, private_key)
            desired = tuple(candidate if client.id == client_id else client for client in old_clients)
            try:
                if current.enabled:
                    self._stage(current)
                elif candidate.enabled:
                    self._stage(candidate)
                runtime = self.reconcile_desired(installation, desired, release_global_guard=False)
                response_model = self.response(candidate, runtime)
                response = PreparedHttp(JSONResponse(response_model.model_dump(mode="json"), headers={"Cache-Control": "no-store"}))
            except BaseException as original_exc:
                if not self._compensate(installation, old_clients):
                    raise original_exc
                try:
                    if current.enabled: self._unstage(current)
                    elif candidate.enabled: self._unstage(candidate)
                except BaseException as cleanup_exc:
                    self.fatal_reconciliation = True
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed") from cleanup_exc
                raise
            self._commit_client(connection, "update", candidate, current)
            connection.commit()
            try:
                if current.enabled: self._unstage(current)
                elif candidate.enabled: self._unstage(candidate)
            except BaseException:
                self.fatal_reconciliation = True
                raise error(503, "state_reconciliation_failed", "State reconciliation failed")
            return response

    def delete_client(self, client_id: UUID) -> None:
        self._require_live()
        with self.database.operation(exclusive=True) as connection:
            installation = self.database.installation(connection)
            old_clients = tuple(self.database.list_clients(connection))
            current = self.database.get_client(connection, client_id)
            if installation is None:
                raise error(503, "state_reconciliation_failed", "State reconciliation failed")
            if current is None:
                raise error(404, "client_not_found", "Client not found")
            desired = tuple(client for client in old_clients if client.id != client_id)
            try:
                if current.enabled:
                    self._stage(current)
                self.reconcile_desired(installation, desired, release_global_guard=False)
            except BaseException as original_exc:
                if not self._compensate(installation, old_clients):
                    raise original_exc
                try:
                    if current.enabled: self._unstage(current)
                except BaseException as cleanup_exc:
                    self.fatal_reconciliation = True
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed") from cleanup_exc
                raise
            self._commit_client(connection, "delete", current, current)
            connection.commit()
            try:
                if current.enabled: self._unstage(current)
            except BaseException:
                self.fatal_reconciliation = True
                raise error(503, "state_reconciliation_failed", "State reconciliation failed")
            self._key_path(client_id).unlink(missing_ok=True)
            fsync_directory(self.paths.key_dir)

    def _profile_text(self, client: Client, installation: InstallationState, private_key: str) -> str:
        lines = ["[Interface]", f"PrivateKey = {private_key}", f"Address = {client.address}/32", f"MTU = {client.mtu}"]
        if client.dns: lines.append("DNS = " + ", ".join(map(str, client.dns)))
        endpoint_host = self.settings.wg_server_host
        endpoint = f"[{endpoint_host}]" if ":" in endpoint_host else endpoint_host
        lines += ["", "[Peer]", f"PublicKey = {installation.server_public_key}", f"Endpoint = {endpoint}:{self.settings.wg_port}", f"AllowedIPs = {', '.join(map(str, client.allowed_ips))}", f"PersistentKeepalive = {client.persistent_keepalive}"]
        profile = "\n".join(lines) + "\n"
        if len(profile.encode("utf-8")) > 2048: raise error(422, "client_profile_too_large", "Client profile too large")
        image = qrcode.make(profile, image_factory=PyPNGImage)
        buffer = io.BytesIO(); image.save(buffer)
        return profile

    def profile(self, client_id: UUID) -> str:
        self._require_live()
        try:
            with self.database.operation(exclusive=False) as connection:
                client = self.database.get_client(connection, client_id)
                if client is None:
                    raise error(404, "client_not_found", "Client not found")
                installation = self.database.installation(connection)
                if installation is None:
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                key_path = self._key_path(client.id)
                if not key_path.is_file():
                    raise error(503, "client_key_missing", "Client key unavailable")
                try:
                    private_key = key_path.read_text(encoding="ascii").strip()
                except (OSError, UnicodeError) as exc:
                    raise error(503, "client_key_missing", "Client key unavailable") from exc
                if not private_key:
                    raise error(503, "client_key_missing", "Client key unavailable")
                return self._profile_text(client, installation, private_key)
        except DatabaseBusy as exc:
            raise error(503, "database_busy", "Database busy") from exc

    def share(self, client_id: UUID, seconds: int, single_use: bool) -> PreparedHttp:
        self._require_live()
        token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        now = datetime.now(UTC)
        expiry = now + timedelta(seconds=seconds)
        try:
            with self.database.operation(exclusive=True) as connection:
                client = self.database.get_client(connection, client_id)
                if client is None:
                    raise error(404, "client_not_found", "Client not found")
                installation = self.database.installation(connection)
                if installation is None:
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                key_path = self._key_path(client.id)
                if not key_path.is_file():
                    raise error(503, "client_key_missing", "Client key unavailable")
                try:
                    private_key = key_path.read_text(encoding="ascii").strip()
                except (OSError, UnicodeError) as exc:
                    raise error(503, "client_key_missing", "Client key unavailable") from exc
                if not private_key:
                    raise error(503, "client_key_missing", "Client key unavailable")
                self._profile_text(client, installation, private_key)
                response_model = ShareResponse(url=f"{self.settings.public_base_url}/download/{token}", expires_at=expiry, single_use=single_use)
                response = PreparedHttp(JSONResponse(response_model.model_dump(mode="json"), status_code=201, headers={"Cache-Control": "no-store"}))
                self.database.create_share_token(connection, token_id=uuid4(), token_hash=hashlib.sha256(token.encode("ascii")).digest(), client_id=client_id, expires_at=expiry, single_use=single_use, created_at=now)
                return response
        except DatabaseBusy as exc:
            raise error(503, "database_busy", "Database busy") from exc

    def download_with_client(self, token: str) -> PreparedHttp:
        self._require_live()
        if len(token) != 43 or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for char in token):
            raise error(404, "download_not_found", "Download not found")
        try:
            with self.database.operation(exclusive=True) as connection:
                token_hash = hashlib.sha256(token.encode("ascii")).digest()
                now = datetime.now(UTC)
                client = self.database.peek_share_token(connection, token_hash, now)
                if client is None:
                    raise error(404, "download_not_found", "Download not found")
                installation = self.database.installation(connection)
                if installation is None:
                    raise error(503, "state_reconciliation_failed", "State reconciliation failed")
                key_path = self._key_path(client.id)
                if not key_path.is_file():
                    raise error(503, "client_key_missing", "Client key unavailable")
                try:
                    private_key = key_path.read_text(encoding="ascii").strip()
                except (OSError, UnicodeError) as exc:
                    raise error(503, "client_key_missing", "Client key unavailable") from exc
                if not private_key:
                    raise error(503, "client_key_missing", "Client key unavailable")
                profile = self._profile_text(client, installation, private_key)
                response = PreparedHttp(PlainTextResponse(profile, media_type="text/plain", headers={"Content-Disposition": f'attachment; filename="client-{client.id}.conf"', "Cache-Control": "no-store"}))
                if self.database.consume_share_token(connection, token_hash, now) is None:
                    raise error(404, "download_not_found", "Download not found")
                return response
        except DatabaseBusy as exc:
            raise error(503, "database_busy", "Database busy") from exc

    def download(self, token: str) -> object:
        return self.download_with_client(token).response

    def peer_traffic(self) -> list[dict[str, object]]:
        self._require_live()
        with self._traffic_lock:
            snapshot = self._runtime()
            return [{"public_key": peer.public_key, "transfer_rx_bytes": (reading := self.traffic_sampler.sample(peer)).transfer_rx_bytes, "transfer_tx_bytes": reading.transfer_tx_bytes, "rx_bytes_per_second": reading.rx_bytes_per_second, "tx_bytes_per_second": reading.tx_bytes_per_second} for peer in snapshot.peers]

    def status(self) -> StatusResponse:
        self._require_live()
        snapshot = self._runtime()
        try:
            with self.database.operation(exclusive=False) as connection:
                installation = self.database.installation(connection)
                clients = self.database.list_clients(connection)
        except DatabaseBusy as exc:
            raise error(503, "database_busy", "Database busy") from exc
        if installation is None:
            raise error(503, "state_reconciliation_failed", "State reconciliation failed")
        enabled_keys = {client.public_key for client in clients if client.enabled}
        active = [peer for peer in snapshot.peers if peer.public_key in enabled_keys]
        return StatusResponse(interface=self.settings.wg_interface, state="up" if snapshot.exists and snapshot.up else "down", listen_port=snapshot.listen_port if snapshot.exists and snapshot.up else None, server_public_key=installation.server_public_key, server_address=installation.server_address, peer_count=len(clients), enabled_peer_count=sum(client.enabled for client in clients), connected_peer_count=sum(peer.last_handshake_at is not None and datetime.now(UTC) - peer.last_handshake_at <= timedelta(seconds=180) for peer in active), transfer_rx_bytes=sum(peer.transfer_rx_bytes for peer in active), transfer_tx_bytes=sum(peer.transfer_tx_bytes for peer in active))

