"""Dedicated durable Waygate provision/delete worker."""

from __future__ import annotations

import asyncio
import logging

from waygate.config import get_settings, require_public_callback_base_url
from waygate.db import close_db, init_db
from waygate.observability import configure_logging
from waygate.services.jobs import process_one_job

_logger = logging.getLogger(__name__)


async def serve() -> None:
    configure_logging()
    settings = get_settings()
    require_public_callback_base_url(settings)
    if not settings.database_url:
        raise RuntimeError("Waygate worker requires database.url")
    init_db(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        connect_timeout=settings.database_connect_timeout,
        pool_timeout=settings.database_pool_timeout,
    )
    _logger.info("worker stage=ready status=started")
    try:
        while True:
            try:
                processed = await process_one_job()
            except Exception as exc:
                _logger.error("worker stage=poll status=failed error_type=%s", type(exc).__name__)
                processed = False
            if not processed:
                await asyncio.sleep(0.5)
    finally:
        await close_db()
        _logger.info("worker stage=shutdown status=stopped")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    configure_logging()
    asyncio.run(serve())


if __name__ == "__main__":
    main()
