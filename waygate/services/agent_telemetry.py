"""Server-observed agent interaction telemetry and the diagnostics verdict.

Agent endpoints record when Waygate itself received register, desired-state and
status calls. Writes are best-effort background Valkey/Redis tasks: they never
raise into, await inside, or slow the agent request path, and at most one write
per server and call kind is scheduled every ``WRITE_INTERVAL_SECONDS`` per
process. Agent-supplied clocks are never used. Telemetry is observational only;
agent authentication and durable server state remain in MariaDB.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime

from waygate.models.schemas import WaygateAgentDiagnostics

_logger = logging.getLogger(__name__)

_PREFIX = "afterglow:waygate:agent-telemetry:"
TELEMETRY_TTL_SECONDS = 14 * 24 * 3600
WRITE_INTERVAL_SECONDS = 5.0
WRITE_TIMEOUT_SECONDS = 2.0
_MAX_PENDING_WRITES = 256
_MAX_RATE_ENTRIES = 10_000

# The agent reconciles every 15 s and reports every 1-60 s (default 1 s).
POLL_STALE_SECONDS = 90
STATUS_STALE_SECONDS = 90
# A pre-0.3.0 oneshot agent fetches desired state once right after register.
ONESHOT_SIGNATURE_SECONDS = 300

_now: Callable[[], datetime] = lambda: datetime.now(UTC)  # noqa: E731 - patched by tests
_monotonic: Callable[[], float] = time.monotonic
_last_write: dict[tuple[str, str], float] = {}
_pending: set[asyncio.Task] = set()


class TelemetryUnavailable(RuntimeError):
    """Telemetry could not be read; absence of observations is not established."""


def _key(server_id: str) -> str:
    return f"{_PREFIX}{server_id}"


def _admit(server_id: str, kind: str) -> bool:
    now = _monotonic()
    key = (server_id, kind)
    previous = _last_write.get(key)
    if previous is not None and now - previous < WRITE_INTERVAL_SECONDS:
        return False
    if len(_last_write) >= _MAX_RATE_ENTRIES:
        _last_write.clear()
    _last_write[key] = now
    return True


async def _write(server_id: str, fields: dict[str, str]) -> None:
    try:
        from waygate.cache import _get_client

        client = _get_client()

        async def send() -> None:
            async with client.pipeline(transaction=False) as pipe:
                pipe.hset(_key(server_id), mapping=fields)
                pipe.expire(_key(server_id), TELEMETRY_TTL_SECONDS)
                await pipe.execute()

        await asyncio.wait_for(send(), WRITE_TIMEOUT_SECONDS)
    except Exception as error:  # Best-effort: never propagate telemetry failure.
        _logger.warning("waygate agent telemetry write skipped error_type=%s", type(error).__name__)


def _schedule(server_id: str, kind: str, fields: dict[str, str], *, rate_limited: bool = True) -> None:
    try:
        if rate_limited and not _admit(server_id, kind):
            return
        if len(_pending) >= _MAX_PENDING_WRITES:
            return
        task = asyncio.get_running_loop().create_task(_write(server_id, fields))
        _pending.add(task)
        task.add_done_callback(_pending.discard)
    except Exception as error:
        _logger.warning("waygate agent telemetry schedule skipped error_type=%s", type(error).__name__)


def observe_register(server_id: str) -> None:
    _schedule(server_id, "register", {"register_at": _now().isoformat()}, rate_limited=False)


def observe_desired_state(server_id: str) -> None:
    _schedule(server_id, "desired_state", {"desired_state_at": _now().isoformat()})


def observe_status(
    server_id: str,
    *,
    peers: int | None,
    agent_source: str | None,
    report_interval_seconds: int | None,
    diagnostics: WaygateAgentDiagnostics | None,
) -> None:
    """Record an accepted report; ``peers=None`` keeps the last observed peer count."""
    try:
        fields = {
            "status_at": _now().isoformat(),
            "diagnostics": json.dumps(diagnostics.model_dump()) if diagnostics is not None else "",
        }
        if peers is not None:
            fields["peers"] = str(peers)
        if agent_source:
            fields["agent_source"] = agent_source
        if report_interval_seconds is not None:
            fields["report_interval_seconds"] = str(report_interval_seconds)
    except Exception as error:
        _logger.warning("waygate agent telemetry schedule skipped error_type=%s", type(error).__name__)
        return
    _schedule(server_id, "status", fields)


async def drain_pending() -> None:
    """Wait for scheduled writes (tests and graceful shutdown)."""
    while _pending:
        await asyncio.gather(*list(_pending), return_exceptions=True)


def _text(value) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


async def get_telemetry(server_id: str) -> dict[str, str]:
    try:
        from waygate.cache import _get_client

        raw = await _get_client().hgetall(_key(server_id))
    except Exception as error:
        _logger.warning("waygate agent telemetry read unavailable error_type=%s", type(error).__name__)
        raise TelemetryUnavailable("Agent telemetry unavailable") from None
    return {_text(key): _text(value) for key, value in (raw or {}).items()}


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _parse_int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


def _parse_diagnostics(value: str | None) -> dict | None:
    if not value:
        return None
    try:
        return WaygateAgentDiagnostics.model_validate(json.loads(value)).model_dump()
    except ValueError:
        return None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def evaluate(
    server: dict,
    telemetry: dict[str, str],
    *,
    enabled_clients: int,
    attachments: int,
    now: datetime,
) -> dict:
    """Return the diagnostics contract from server-side observations only."""
    register_at = _parse_time(telemetry.get("register_at"))
    desired_at = _parse_time(telemetry.get("desired_state_at"))
    status_at = _parse_time(telemetry.get("status_at"))
    # A stored server public key is durable evidence of an earlier register even
    # after telemetry has expired or predates this release.
    registered = register_at is not None or bool(server.get("server_public_key"))
    peers = _parse_int(telemetry.get("peers"))
    install_mode = "prebuilt" if server.get("agent_install_mode") == "prebuilt" else "cloud-init"

    def stale(observed: datetime | None, limit: int) -> bool:
        reference = observed or register_at
        return reference is None or (now - reference).total_seconds() > limit

    hints: list[str] = []
    if not registered:
        verdict = "never_connected"
    elif stale(desired_at, POLL_STALE_SECONDS):
        verdict = "not_polling"
        hints.append("agent_not_polling")
    elif stale(status_at, STATUS_STALE_SECONDS):
        verdict = "not_reporting"
    elif (peers or 0) != enabled_clients:
        verdict = "peer_mismatch"
        hints.append("peers_mismatch")
    else:
        verdict = "ok"

    if registered and verdict in ("not_polling", "not_reporting"):
        if status_at is None:
            hints.append("agent_never_reported")
        elif (now - status_at).total_seconds() > STATUS_STALE_SECONDS:
            hints.append("agent_status_stale")
    if (
        verdict == "not_polling"
        and install_mode == "prebuilt"
        and register_at is not None
        and (desired_at is None or (desired_at - register_at).total_seconds() <= ONESHOT_SIGNATURE_SECONDS)
    ):
        hints.append("image_agent_outdated")

    last_status = None
    if status_at is not None:
        last_status = {
            "peers": peers or 0,
            "reported_at": status_at.isoformat(),
            "diagnostics": _parse_diagnostics(telemetry.get("diagnostics")),
        }
    return {
        "verdict": verdict,
        "checked_at": now.isoformat(),
        "agent": {
            "install_mode": install_mode,
            "image_id": server.get("image_id"),
            "source": telemetry.get("agent_source") or None,
            "report_interval_seconds": _parse_int(telemetry.get("report_interval_seconds")),
        },
        "last_register_at": _iso(register_at),
        "last_desired_state_at": _iso(desired_at),
        "last_status_at": _iso(status_at),
        "last_status": last_status,
        "expected": {"enabled_clients": enabled_clients, "attachments": attachments},
        "hints": hints,
    }


def now() -> datetime:
    return _now()
