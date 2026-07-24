"""Secret-safe WireGuard and L3 command control."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path
from uuid import UUID, uuid4

from .domain import InterfaceSnapshot, KeyPair, PeerRuntime
from .paths import fsync_directory


class WireGuardUnavailable(RuntimeError):
    pass


class WgCliControl:
    def __init__(self, *, timeout: int = 10) -> None:
        self.timeout = timeout

    def _run(self, argv: list[str], *, input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        if not argv or argv[0] not in {"wg", "ip"}:
            raise WireGuardUnavailable("wireguard command failed")
        try:
            completed = subprocess.run(
                argv,
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WireGuardUnavailable("wireguard command failed") from exc
        if completed.returncode != 0:
            raise WireGuardUnavailable("wireguard command failed")
        return completed

    def generate_keypair(self) -> KeyPair:
        private_key = self._run(["wg", "genkey"]).stdout.decode("ascii").strip()
        public_key = self._run(["wg", "pubkey"], input_data=(private_key + "\n").encode("ascii")).stdout.decode("ascii").strip()
        if not private_key or not public_key:
            raise WireGuardUnavailable("WireGuard generated an invalid key")
        return KeyPair(private_key=private_key, public_key=public_key)

    def public_key(self, private_key: str) -> str:
        return self._run(["wg", "pubkey"], input_data=(private_key + "\n").encode("ascii")).stdout.decode("ascii").strip()

    def read_private_key(self, path: str) -> str | None:
        candidate = Path(path)
        if not candidate.is_file():
            return None
        value = candidate.read_text(encoding="ascii").strip()
        return value or None

    def snapshot(self, interface: str) -> InterfaceSnapshot:
        link = self._run_optional(["ip", "-json", "link", "show", "dev", interface])
        if link is None:
            return InterfaceSnapshot(False, False, None, None, (), ())
        addresses = self._ip_addresses(interface)
        dump = self._run(["wg", "show", interface, "dump"]).stdout.decode("utf-8")
        lines = [line.split("\t") for line in dump.splitlines() if line]
        if not lines or len(lines[0]) < 4:
            raise WireGuardUnavailable("invalid wg dump")
        interface_row = lines[0]
        peers: list[PeerRuntime] = []
        for fields in lines[1:]:
            if len(fields) != 8:
                raise WireGuardUnavailable("invalid wg peer dump")
            handshake_seconds = int(fields[4])
            transfer_rx = int(fields[5])
            transfer_tx = int(fields[6])
            if handshake_seconds < 0 or transfer_rx < 0 or transfer_tx < 0:
                raise WireGuardUnavailable("invalid wg counters")
            peers.append(PeerRuntime(
                public_key=fields[0],
                endpoint=None if fields[2] == "(none)" else fields[2],
                last_handshake_at=None if handshake_seconds == 0 else datetime.fromtimestamp(handshake_seconds, UTC),
                transfer_rx_bytes=transfer_rx,
                transfer_tx_bytes=transfer_tx,
                allowed_ips=tuple(IPv4Network(value.strip()) for value in fields[3].split(",") if value),
            ))
        return InterfaceSnapshot(
            exists=True,
            up=bool(link[0].get("flags") and "UP" in link[0]["flags"]),
            listen_port=None if interface_row[2] == "0" else int(interface_row[2]),
            public_key=interface_row[1],
            addresses=addresses,
            peers=tuple(peers),
        )

    def _run_optional(self, argv: list[str]) -> list[dict[str, object]] | None:
        try:
            completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, timeout=self.timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise WireGuardUnavailable("network command failed") from exc
        if completed.returncode != 0:
            return None
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise WireGuardUnavailable("invalid ip JSON") from exc
        return value if isinstance(value, list) else None

    def _ip_addresses(self, interface: str) -> tuple[IPv4Interface, ...]:
        value = self._run(["ip", "-json", "-4", "address", "show", "dev", interface]).stdout
        try:
            entries = json.loads(value)
        except json.JSONDecodeError as exc:
            raise WireGuardUnavailable("invalid ip address JSON") from exc
        addresses: list[IPv4Interface] = []
        for entry in entries:
            for item in entry.get("addr_info", []):
                if item.get("family") == "inet" and item.get("local") and item.get("prefixlen") is not None:
                    addresses.append(IPv4Interface(f"{item['local']}/{item['prefixlen']}"))
        return tuple(addresses)

    def ensure_interface(self, interface: str, address: IPv4Interface) -> None:
        link = self._run_optional(["ip", "-json", "link", "show", "dev", interface])
        if link is None:
            self._run(["ip", "link", "add", "dev", interface, "type", "wireguard"])
        else:
            try:
                self._run(["wg", "show", interface])
            except WireGuardUnavailable as exc:
                raise WireGuardUnavailable("interface is not WireGuard") from exc
        self._run(["ip", "address", "replace", str(address), "dev", interface])
        self._run(["ip", "link", "set", "up", "dev", interface])

    def remove_interface(self, interface: str) -> None:
        if self._run_optional(["ip", "-json", "link", "show", "dev", interface]) is not None:
            self._run(["ip", "link", "delete", "dev", interface])

    def apply_config(self, interface: str, config_path: str) -> None:
        source = Path(config_path)
        stage = source.parent / f".afterglow-stage-{uuid4()}"
        stage.mkdir(mode=0o700)
        runtime = stage / source.name
        lines = source.read_text(encoding="utf-8").splitlines()
        stripped = [line for line in lines if not line.startswith("#") and not line.startswith("Address =")]
        _durable_replace(runtime, ("\n".join(stripped) + "\n").encode("utf-8"))
        try:
            self._run(["wg", "syncconf", interface, str(runtime)])
        finally:
            runtime.unlink(missing_ok=True)
            stage.rmdir()
            fsync_directory(source.parent)


def _durable_replace(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.parent / f".tmp-{uuid4()}"
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def write_private_key(path: Path, private_key: str) -> None:
    _durable_replace(path, (private_key + "\n").encode("ascii"))


def render_config(*, installation_id: UUID, private_key: str, address: IPv4Interface, port: int, clients: list[tuple[str, IPv4Interface, int]]) -> bytes:
    lines = [
        "# Managed by afterglow-wg-agent; DO NOT EDIT.",
        f"# Installation-ID: {installation_id}",
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}",
        f"ListenPort = {port}",
    ]
    for public_key, client_address, keepalive in clients:
        lines.extend(["", "[Peer]", f"PublicKey = {public_key}", f"AllowedIPs = {client_address.ip}/32", f"PersistentKeepalive = {keepalive}"])
    return ("\n".join(lines) + "\n").encode("utf-8")


def install_config(path: Path, content: bytes) -> None:
    stage = path.parent / f".afterglow-stage-{uuid4()}"
    stage.mkdir(mode=0o700)
    try:
        staged = stage / path.name
        _durable_replace(staged, content)
        os.replace(staged, path)
        os.chmod(path, 0o600)
        fsync_directory(path.parent)
    finally:
        if stage.exists():
            stage.rmdir()
            fsync_directory(path.parent)
