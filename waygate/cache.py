"""Waygate Redis client lifecycle."""

from __future__ import annotations

import redis.asyncio as aioredis

from waygate.config import get_settings

_client: aioredis.Redis | None = None


def _get_client() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.from_url(
            get_settings().redis_url,
            encoding="utf-8",
            decode_responses=False,
            socket_connect_timeout=3,
            socket_timeout=5,
            health_check_interval=30,
        )
    return _client


async def close_cache() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
    _client = None
