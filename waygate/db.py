"""Waygate SQLAlchemy async database lifecycle."""

from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

_logger = logging.getLogger(__name__)
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


class Base(DeclarativeBase):
    pass


def init_db(
    database_url: str,
    *,
    pool_size: int = 5,
    max_overflow: int = 10,
    connect_timeout: int = 10,
    pool_timeout: int = 10,
) -> None:
    global _engine, _session_factory
    if not database_url:
        raise RuntimeError("Waygate requires database.url")
    if _engine is not None:
        return
    options = {"pool_pre_ping": True, "echo": False}
    if database_url.startswith("sqlite+"):
        # Local synthetic-auth smoke uses file-backed SQLite; production remains MariaDB.
        options["connect_args"] = {"timeout": connect_timeout}
    else:
        options.update(
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_recycle=1800,
            connect_args={"connect_timeout": connect_timeout},
        )
    _engine = create_async_engine(database_url, **options)
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)


def get_session_factory() -> async_sessionmaker[AsyncSession] | None:
    return _session_factory


def is_db_available() -> bool:
    return _engine is not None and _session_factory is not None


async def check_db() -> bool:
    if _engine is None:
        return False
    try:
        async with _engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except Exception:
        _logger.warning("Waygate database health check failed", exc_info=True)
        return False


async def close_db() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
