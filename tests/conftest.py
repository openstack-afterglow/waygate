from __future__ import annotations

import inspect
from types import SimpleNamespace

import fakeredis.aioredis
import pytest


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    from waygate.config import get_settings, load_raw_toml

    get_settings.cache_clear()
    load_raw_toml.cache_clear()
    yield
    get_settings.cache_clear()
    load_raw_toml.cache_clear()


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    from waygate.rate_limit import limiter

    try:
        limiter._storage.reset()
    except Exception:
        pass
    yield


@pytest.fixture(autouse=True)
async def _fake_redis(monkeypatch):
    from waygate import cache, crypto

    fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(cache, "_client", fake)
    monkeypatch.setattr(
        crypto,
        "get_settings",
        lambda: SimpleNamespace(waygate_encryption_key="a" * 64),
    )
    try:
        yield fake
    finally:
        closing = fake.close()
        if inspect.isawaitable(closing):
            await closing
        monkeypatch.setattr(cache, "_client", None)
