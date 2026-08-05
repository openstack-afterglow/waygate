"""Waygate configuration loaded from environment or ``waygate.conf``."""

from __future__ import annotations

import os
import tomllib
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _config_candidates() -> list[Path]:
    configured = os.environ.get("WAYGATE_CONFIG_FILE", "").strip()
    candidates = [Path(configured)] if configured else []
    candidates.extend(
        [
            Path.cwd() / "waygate.conf",
            Path.cwd().parent / "waygate.conf",
            Path("/etc/waygate/waygate.conf"),
            Path("/app/waygate.conf"),
        ]
    )
    return candidates


@lru_cache
def load_raw_toml() -> dict:
    for path in _config_candidates():
        if path.is_file() and path.stat().st_size > 0:
            with path.open("rb") as handle:
                return tomllib.load(handle)
    return {}


def _load_toml() -> dict:
    data = load_raw_toml()
    if not data:
        return {}
    keystone = data.get("keystone") or data.get("openstack", {})
    database = data.get("database", {})
    cache = data.get("cache", {})
    waygate = data.get("waygate", {})
    return {
        "os_auth_url": keystone.get("auth_url", ""),
        "os_username": keystone.get("username", ""),
        "os_password": keystone.get("password", ""),
        "os_project_name": keystone.get("project_name", "waygate"),
        "os_project_domain_name": keystone.get("project_domain_name", "Default"),
        "os_user_domain_name": keystone.get("user_domain_name", "Default"),
        "os_region_name": keystone.get("region", keystone.get("region_name", "RegionOne")),
        "os_interface": keystone.get("interface", "internal"),
        "os_insecure": keystone.get("insecure", False),
        "os_cacert": keystone.get("cacert", ""),
        "database_url": database.get("url", ""),
        "database_pool_size": database.get("pool_size", 5),
        "database_max_overflow": database.get("max_overflow", 10),
        "database_connect_timeout": database.get("connect_timeout", 10),
        "database_pool_timeout": database.get("pool_timeout", 10),
        "redis_url": cache.get("redis_url", "redis://localhost:6379/6"),
        "waygate_callback_base_url": waygate.get("callback_base_url", ""),
        "waygate_key_name": waygate.get("key_name", ""),
        "waygate_default_tunnel_cidr": waygate.get("default_tunnel_cidr", "10.8.0.0/24"),
        "waygate_default_listen_port": waygate.get("default_listen_port", 51820),
        "waygate_encryption_key": waygate.get("encryption_key", ""),
        "trusted_proxies": waygate.get("trusted_proxies", "127.0.0.1/32,::1/128"),
    }


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    os_auth_url: str = ""
    os_username: str = ""
    os_password: str = ""
    os_project_name: str = "waygate"
    os_project_domain_name: str = "Default"
    os_user_domain_name: str = "Default"
    os_region_name: str = "RegionOne"
    os_interface: str = "internal"
    os_insecure: bool = False
    os_cacert: str = ""

    database_url: str = ""
    database_pool_size: int = 5
    database_max_overflow: int = 10
    database_connect_timeout: int = 10
    database_pool_timeout: int = 10

    redis_url: str = "redis://localhost:6379/6"

    waygate_callback_base_url: str = ""
    waygate_key_name: str = ""
    waygate_default_tunnel_cidr: str = "10.8.0.0/24"
    waygate_default_listen_port: int = 51820
    waygate_encryption_key: str = ""
    trusted_proxies: str = "127.0.0.1/32,::1/128"

    @field_validator("waygate_encryption_key")
    @classmethod
    def validate_encryption_key(cls, value: str) -> str:
        value = value.strip()
        if value:
            if len(value) != 64:
                raise ValueError("waygate.encryption_key must be 64 hexadecimal characters")
            try:
                bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError("waygate.encryption_key must be hexadecimal") from exc
        return value

    @property
    def ssl_verify(self) -> bool | str:
        if self.os_insecure:
            return False
        return self.os_cacert or True


@lru_cache
def get_settings() -> Settings:
    for key, value in _load_toml().items():
        if not os.environ.get(key.upper()):
            os.environ[key.upper()] = str(value)
    return Settings()
