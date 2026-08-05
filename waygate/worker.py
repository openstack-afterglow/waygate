"""Dedicated durable Waygate provision/delete worker."""

from __future__ import annotations

import asyncio
import logging
import os

from waygate.config import get_settings
from waygate.db import close_db, init_db
from waygate.services.jobs import process_one_job

_logger = logging.getLogger(__name__)


async def serve() -> None:
    settings = get_settings()
    if not settings.database_url:
        raise RuntimeError("Waygate worker requires database.url")
    init_db(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        connect_timeout=settings.database_connect_timeout,
        pool_timeout=settings.database_pool_timeout,
    )
    try:
        while True:
            try:
                processed = await process_one_job()
            except Exception:
                _logger.exception("Waygate worker iteration failed")
                processed = False
            if not processed:
                await asyncio.sleep(0.5)
    finally:
        await close_db()


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    asyncio.run(serve())


if __name__ == "__main__":
    main()
