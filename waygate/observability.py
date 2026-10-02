"""Shared service logging: opt-in Waygate DEBUG, never request or query values."""

from __future__ import annotations

import logging
import os
import time

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class _RateLimitLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # SlowAPI includes the unauthenticated decoded path and key in this
        # warning. Retain the event, not attacker-controlled values.
        if record.msg == "ratelimit %s (%s) exceeded at endpoint: %s":
            record.msg = "api rate_limit status=429"
            record.args = ()
        return True


_rate_limit_log_filter = _RateLimitLogFilter()


def configure_logging() -> None:
    """Enable DEBUG for Waygate only; never enable SQL/HTTP dependency debug logs."""
    # Uvicorn configures only its own loggers. Install a default sink when the
    # host has not configured one; keep dependency loggers at WARNING.
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s")
    level = logging.DEBUG if os.environ.get("LOG_LEVEL", "INFO").upper() == "DEBUG" else logging.INFO
    logging.getLogger("waygate").setLevel(level)
    logging.getLogger("slowapi").addFilter(_rate_limit_log_filter)
    # Uvicorn's access logger emits the untrusted raw URL (including query values).
    logging.getLogger("uvicorn.access").disabled = True


class SafeAccessLog:
    """Record resolved route templates after routing, not request paths or bodies."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.logger = logging.getLogger("waygate.access")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            method = "OTHER"
        started = time.monotonic()
        status = 500

        async def capture(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, capture)
        finally:
            route = scope.get("route")
            template = route.path if route is not None else "<unmatched>"
            self.logger.info("api method=%s route=%s status=%d", method, template, status)
            if self.logger.isEnabledFor(logging.DEBUG):
                query = scope.get("query_string", b"")
                # Count only, with a fixed cap even for arbitrarily long query strings.
                query_count = min(query.count(b"&", 0, 4096) + 1, 32) if query else 0
                self.logger.debug(
                    "api query_fields=%d duration_ms=%d result_status=%d",
                    query_count,
                    min(int((time.monotonic() - started) * 1000), 60000),
                    status,
                )
