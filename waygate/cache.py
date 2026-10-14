"""Waygate Redis-protocol client lifecycle, including Sentinel primary routing."""

from __future__ import annotations

import redis.asyncio as aioredis
from redis.asyncio.connection import parse_url
from redis.asyncio.sentinel import Sentinel

from waygate.config import get_settings

_client: aioredis.Redis | None = None
_sentinel: Sentinel | None = None


def _get_client() -> aioredis.Redis:
    global _client, _sentinel
    if _client is None:
        settings = get_settings()
        options = {
            "encoding": "utf-8",
            "decode_responses": False,
            "socket_connect_timeout": 3,
            "socket_timeout": 5,
            "health_check_interval": 30,
        }
        if settings.sentinel_enabled:
            hosts = []
            for entry in settings.sentinel_hosts.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                host, port = entry.rsplit(":", 1) if ":" in entry else (entry, "26379")
                hosts.append((host.strip("[]"), int(port)))
            if not hosts or not settings.sentinel_master_name.strip():
                raise RuntimeError("Sentinel hosts and master name are required")
            # Sentinel control-plane authentication is separate from data-plane
            # credentials. Stock Kolla Sentinels do not require client AUTH.
            _sentinel = Sentinel(hosts, socket_connect_timeout=3, socket_timeout=5)
            url_options = parse_url(settings.redis_url)
            credentials = {key: url_options[key] for key in ("username", "password", "db") if key in url_options}
            _client = _sentinel.master_for(settings.sentinel_master_name, **credentials, **options)
        else:
            _client = aioredis.from_url(settings.redis_url, **options)
    return _client


async def close_cache() -> None:
    global _client, _sentinel
    try:
        if _client is not None:
            # master_for supplies a pool; Redis 5 otherwise leaves it open.
            await _client.close(close_connection_pool=True)
        if _sentinel is not None:
            for client in _sentinel.sentinels:
                await client.close(close_connection_pool=True)
    finally:
        _client = None
        _sentinel = None
