"""Waygate AES-256-GCM encryption with stable domain separation."""

from __future__ import annotations

from afterglow_crypto import aesgcm

from waygate.config import get_settings

_DOMAIN_WG_CLIENT_KEY = b"wg_client_key"
_DOMAIN_WG_AGENT_TOKEN = b"wg_agent_token"


def _get_key() -> bytes:
    value = get_settings().waygate_encryption_key
    if not value or len(value) != 64:
        raise ValueError(
            "waygate_encryption_key must be 64 hex characters (32 bytes). Generate with: openssl rand -hex 32"
        )
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("waygate_encryption_key must be hexadecimal") from exc


def encrypt_wg_client_key(plaintext: str) -> str:
    return aesgcm.encrypt(_get_key(), _DOMAIN_WG_CLIENT_KEY, plaintext)


def decrypt_wg_client_key(ciphertext: str) -> str:
    return aesgcm.decrypt(_get_key(), _DOMAIN_WG_CLIENT_KEY, ciphertext)


def encrypt_wg_agent_token(plaintext: str) -> str:
    return aesgcm.encrypt(_get_key(), _DOMAIN_WG_AGENT_TOKEN, plaintext)


def decrypt_wg_agent_token(ciphertext: str) -> str:
    return aesgcm.decrypt(_get_key(), _DOMAIN_WG_AGENT_TOKEN, ciphertext)
