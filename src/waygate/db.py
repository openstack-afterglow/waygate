"""SQLite persistence with the controller's mandatory lock ordering."""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path
from typing import Iterator
from uuid import UUID

from .domain import Client, InstallationState
from .paths import RuntimePaths


class DatabaseBusy(RuntimeError):
    pass


class InstanceAlreadyRunning(RuntimeError):
    pass


class FileLock:
    def __init__(self, path: Path, exclusive: bool, *, timeout: float = 5.0) -> None:
        self.path = path
        self.exclusive = exclusive
        self.timeout = timeout
        self.fd: int | None = None

    def __enter__(self) -> "FileLock":
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.fchmod(self.fd, 0o600)
        flag = fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fd, flag | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    self.fd = None
                    raise DatabaseBusy("database lock contention")
                time.sleep(0.05)

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


class InstanceLease:
    """Nonblocking, process-lifetime authority lease."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.fchmod(self.fd, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(self.fd)
            self.fd = None
            raise InstanceAlreadyRunning("instance_already_running") from exc

    def release(self) -> None:
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


@dataclass(frozen=True, slots=True)
class ClientDraft:
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


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _client_from_row(row: sqlite3.Row) -> Client:
    return Client(
        id=UUID(row["id"]),
        name=row["name"],
        address=IPv4Address(row["address"]),
        public_key=row["public_key"],
        allowed_ips=tuple(IPv4Network(item) for item in json.loads(row["allowed_ips_json"])),
        dns=tuple(IPv4Address(item) for item in json.loads(row["dns_json"])),
        enabled=bool(row["enabled"]),
        created_at=_parse_timestamp(row["created_at"]),
        updated_at=_parse_timestamp(row["updated_at"]),
        mtu=row["mtu"],
        persistent_keepalive=row["persistent_keepalive"],
    )


class Database:
    def __init__(self, paths: RuntimePaths) -> None:
        self.paths = paths

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.paths.database,
            timeout=5,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @contextmanager
    def operation(self, *, exclusive: bool) -> Iterator[sqlite3.Connection]:
        """Acquire operation flock before opening or transacting on SQLite."""
        with FileLock(self.paths.operation_lock, exclusive):
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE" if exclusive else "BEGIN")
                yield connection
                connection.commit()
            except sqlite3.OperationalError as exc:
                connection.rollback()
                if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                    raise DatabaseBusy("database_busy") from exc
                raise
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()

    def migrate(self) -> None:
        self.paths.ensure_private_directories()
        migrations = ((1, "001_initial.sql"), (2, "002_client_tunnel_controls.sql"))
        with FileLock(self.paths.operation_lock, exclusive=True):
            connection = self._connect()
            try:
                journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                if str(journal_mode).lower() != "wal":
                    raise RuntimeError("WAL journal mode unavailable")
                schema = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone()
                if schema is None:
                    version, filename = migrations[0]
                    connection.executescript(files("waygate.migrations").joinpath(filename).read_text(encoding="utf-8"))
                    connection.execute("INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)", (version, _timestamp(datetime.now(UTC))))
                elif connection.execute("SELECT 1 FROM schema_migrations WHERE version=1").fetchone() is None:
                    raise RuntimeError("database migration state is incomplete")
                if connection.execute("SELECT 1 FROM schema_migrations WHERE version > ?", (migrations[-1][0],)).fetchone() is not None:
                    raise RuntimeError("database migration version is newer than this agent")
                for version, filename in migrations[1:]:
                    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=?", (version,)).fetchone() is None:
                        connection.executescript(files("waygate.migrations").joinpath(filename).read_text(encoding="utf-8"))
                        connection.execute("INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)", (version, _timestamp(datetime.now(UTC))))
            finally:
                connection.close()

    def installation(self, connection: sqlite3.Connection) -> InstallationState | None:
        row = connection.execute("SELECT * FROM installation_state WHERE singleton=1").fetchone()
        if row is None:
            return None
        return InstallationState(
            installation_id=UUID(row["installation_id"]),
            wg_interface=row["wg_interface"],
            wg_config_path=row["wg_config_path"],
            server_network=IPv4Network(row["server_network"]),
            server_address=IPv4Interface(row["server_address"]),
            server_public_key=row["server_public_key"],
            created_at=_parse_timestamp(row["created_at"]),
        )

    def insert_installation(self, connection: sqlite3.Connection, state: InstallationState) -> None:
        connection.execute(
            """INSERT INTO installation_state(
                singleton, installation_id, wg_interface, wg_config_path, server_network,
                server_address, server_public_key, created_at
            ) VALUES(1, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(state.installation_id), state.wg_interface, state.wg_config_path,
                str(state.server_network), str(state.server_address), state.server_public_key,
                _timestamp(state.created_at),
            ),
        )

    def get_client(self, connection: sqlite3.Connection, client_id: UUID) -> Client | None:
        row = connection.execute("SELECT * FROM clients WHERE id=?", (str(client_id),)).fetchone()
        return None if row is None else _client_from_row(row)

    def list_clients(self, connection: sqlite3.Connection) -> list[Client]:
        return [_client_from_row(row) for row in connection.execute("SELECT * FROM clients ORDER BY created_at, id")]

    def name_exists(self, connection: sqlite3.Connection, name: str, *, exclude_id: UUID | None = None) -> bool:
        if exclude_id is None:
            row = connection.execute("SELECT 1 FROM clients WHERE name = ? COLLATE NOCASE LIMIT 1", (name,)).fetchone()
        else:
            row = connection.execute("SELECT 1 FROM clients WHERE name = ? COLLATE NOCASE AND id != ? LIMIT 1", (name, str(exclude_id))).fetchone()
        return row is not None

    def insert_client(self, connection: sqlite3.Connection, client: ClientDraft) -> Client:
        connection.execute(
            """INSERT INTO clients(
                id, name, address, public_key, allowed_ips_json, dns_json, enabled, created_at, updated_at, mtu, persistent_keepalive
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(client.id), client.name, str(client.address), client.public_key,
                json.dumps([str(item) for item in client.allowed_ips], separators=(",", ":")),
                json.dumps([str(item) for item in client.dns], separators=(",", ":")),
                int(client.enabled), _timestamp(client.created_at), _timestamp(client.updated_at), client.mtu, client.persistent_keepalive,
            ),
        )
        stored = self.get_client(connection, client.id)
        assert stored is not None
        return stored

    def update_client(self, connection: sqlite3.Connection, client: Client) -> Client:
        connection.execute(
            """UPDATE clients SET name=?, allowed_ips_json=?, dns_json=?, enabled=?, updated_at=?, mtu=?, persistent_keepalive=?
            WHERE id=?""",
            (
                client.name,
                json.dumps([str(item) for item in client.allowed_ips], separators=(",", ":")),
                json.dumps([str(item) for item in client.dns], separators=(",", ":")),
                int(client.enabled), _timestamp(client.updated_at), client.mtu, client.persistent_keepalive, str(client.id),
            ),
        )
        stored = self.get_client(connection, client.id)
        assert stored is not None
        return stored

    def delete_client(self, connection: sqlite3.Connection, client_id: UUID) -> bool:
        return connection.execute("DELETE FROM clients WHERE id=?", (str(client_id),)).rowcount == 1

    def allocate_address(self, connection: sqlite3.Connection, network: IPv4Network, requested: IPv4Address | None) -> IPv4Address:
        reserved = {network.network_address, network.broadcast_address, IPv4Address(int(network.network_address) + 1)}
        allocated = {IPv4Address(row[0]) for row in connection.execute("SELECT address FROM clients")}
        if requested is not None:
            if requested not in network or requested in reserved:
                raise ValueError("address is outside the allocatable VPN range")
            if requested in allocated:
                raise KeyError("address_conflict")
            return requested
        for candidate_int in range(int(network.network_address) + 2, int(network.broadcast_address)):
            candidate = IPv4Address(candidate_int)
            if candidate not in allocated:
                return candidate
        raise OverflowError("address_pool_exhausted")

    def create_share_token(
        self, connection: sqlite3.Connection, *, token_id: UUID, token_hash: bytes,
        client_id: UUID, expires_at: datetime, single_use: bool, created_at: datetime,
    ) -> None:
        connection.execute(
            """INSERT INTO share_tokens(id, token_hash, client_id, expires_at, single_use, used_at, created_at)
            VALUES(?, ?, ?, ?, ?, NULL, ?)""",
            (str(token_id), token_hash, str(client_id), _timestamp(expires_at), int(single_use), _timestamp(created_at)),
        )

    def peek_share_token(self, connection: sqlite3.Connection, token_hash: bytes, now: datetime) -> Client | None:
        row = connection.execute(
            """SELECT t.id token_id, t.expires_at, t.single_use, t.used_at, c.*
            FROM share_tokens t JOIN clients c ON c.id=t.client_id WHERE t.token_hash=?""",
            (token_hash,),
        ).fetchone()
        if row is None or row["used_at"] is not None or _parse_timestamp(row["expires_at"]) <= now or not bool(row["enabled"]):
            return None
        return _client_from_row(row)

    def consume_share_token(self, connection: sqlite3.Connection, token_hash: bytes, now: datetime) -> Client | None:
        row = connection.execute(
            """SELECT t.id token_id, t.expires_at, t.single_use, t.used_at, c.*
            FROM share_tokens t JOIN clients c ON c.id=t.client_id WHERE t.token_hash=?""",
            (token_hash,),
        ).fetchone()
        if row is None or row["used_at"] is not None or _parse_timestamp(row["expires_at"]) <= now or not bool(row["enabled"]):
            return None
        if bool(row["single_use"]):
            changed = connection.execute(
                "UPDATE share_tokens SET used_at=? WHERE id=? AND used_at IS NULL",
                (_timestamp(now), row["token_id"]),
            ).rowcount
            if changed != 1:
                return None
        return _client_from_row(row)

    def purge_expired_tokens(self, connection: sqlite3.Connection, now: datetime, *, limit: int = 100) -> int:
        rows = connection.execute(
            "SELECT id FROM share_tokens WHERE used_at IS NOT NULL OR expires_at <= ? LIMIT ?",
            (_timestamp(now), limit),
        ).fetchall()
        if not rows:
            return 0
        connection.executemany("DELETE FROM share_tokens WHERE id=?", [(row["id"],) for row in rows])
        return len(rows)
