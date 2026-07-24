"""Fixed production storage paths and test-injectable runtime equivalents."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    """Runtime locations; only tests may inject an alternative instance."""

    state_dir: Path
    key_dir: Path
    database: Path
    instance_lock: Path
    operation_lock: Path
    wireguard_dir: Path

    @classmethod
    def production(cls) -> "RuntimePaths":
        state_dir = Path("/var/lib/waygate")
        return cls(
            state_dir=state_dir,
            key_dir=state_dir / "keys",
            database=state_dir / "agent.db",
            instance_lock=state_dir / "instance.lock",
            operation_lock=Path("/run/waygate/reconcile.lock"),
            wireguard_dir=Path("/etc/wireguard"),
        )

    @classmethod
    def temporary(cls, root: Path) -> "RuntimePaths":
        state_dir = root / "state"
        return cls(
            state_dir=state_dir,
            key_dir=state_dir / "keys",
            database=state_dir / "agent.db",
            instance_lock=state_dir / "instance.lock",
            operation_lock=root / "run" / "reconcile.lock",
            wireguard_dir=root / "wireguard",
        )

    def config_path(self, interface: str) -> Path:
        return self.wireguard_dir / f"{interface}.conf"

    def ensure_private_directories(self) -> None:
        for directory in (self.state_dir, self.key_dir, self.operation_lock.parent, self.wireguard_dir):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(directory, 0o700)

    def ensure_lock_files(self) -> None:
        self.ensure_private_directories()
        for lock in (self.instance_lock, self.operation_lock):
            fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)


def fsync_directory(directory: Path) -> None:
    """Persist a prior rename/unlink in *directory*."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
