"""Dedicated durable Waygate provision/delete worker."""

from __future__ import annotations

import asyncio
import logging
import signal

from waygate.config import get_settings, require_public_callback_base_url
from waygate.db import close_db, init_db
from waygate.observability import configure_logging
from waygate.services.jobs import process_one_job

_logger = logging.getLogger(__name__)


async def serve(stop: asyncio.Event | None = None) -> None:
    configure_logging()
    if stop is None:
        stop = asyncio.Event()
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
        while not stop.is_set():
            try:
                processed = await process_one_job()
            except Exception as exc:
                _logger.error("worker stage=poll status=failed error_type=%s", type(exc).__name__)
                processed = False
            if not processed and not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=0.5)
                except TimeoutError:
                    pass
    finally:
        await close_db()
        _logger.info("worker stage=shutdown status=stopped")


async def _main_async() -> None:
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    task = asyncio.create_task(serve(stop))
    for shutdown_signal in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(shutdown_signal, stop.set)
    try:
        await task
    except asyncio.CancelledError:
        pass
    finally:
        for shutdown_signal in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(shutdown_signal)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    configure_logging()
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
