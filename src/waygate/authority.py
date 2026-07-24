"""Ownership markers and immutable installation identity validation."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

MARKER = "# Managed by waygate; DO NOT EDIT."
INSTALLATION_PREFIX = "# Installation-ID: "


class AuthorityError(RuntimeError):
    code = "managed_state_identity_mismatch"


def managed_installation_id(content: bytes) -> UUID:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuthorityError("managed config is not UTF-8") from exc
    if any(separator in text for separator in ("\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")):
        raise AuthorityError("managed config must use LF")
    lines = text.splitlines()
    if len(lines) < 2 or lines[0] != MARKER or not lines[1].startswith(INSTALLATION_PREFIX):
        raise AuthorityError("managed config identity marker is missing")
    raw_id = lines[1][len(INSTALLATION_PREFIX):]
    try:
        installation_id = UUID(raw_id)
    except ValueError as exc:
        raise AuthorityError("managed config installation id is malformed") from exc
    marker_stems = ("# Managed by waygate", "# Installation-ID")
    if installation_id.version != 4 or raw_id != str(installation_id) or any(line.startswith(marker_stems) for line in lines[2:]):
        raise AuthorityError("managed config identity marker is ambiguous")
    return installation_id


def validate_config_identity(path: Path, expected: UUID) -> bool:
    """Return false only for absence; reject unowned, malformed, or wrong state."""
    if not path.exists():
        return False
    try:
        content = path.read_bytes()
    except (OSError, IsADirectoryError) as exc:
        raise AuthorityError("managed config cannot be read") from exc
    if managed_installation_id(content) != expected:
        raise AuthorityError("managed config installation id differs from database authority")
    return True
