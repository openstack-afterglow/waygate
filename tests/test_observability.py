"""Request and durable job logs must expose stages, never untrusted values."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import sys

import pytest
from httpx import ASGITransport, AsyncClient

from waygate import worker
from waygate.main import app
from waygate.observability import configure_logging

pytestmark = pytest.mark.asyncio


def _messages(caplog, name):
    return [record.getMessage() for record in caplog.records if record.name == name]


async def test_api_logs_route_templates_and_success_failure_without_request_values(caplog):
    with caplog.at_level(logging.DEBUG, logger="waygate.access"):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            good = await client.get("/v1/health?token=bootstrap-secret&private_key=private-secret")
            missing = await client.get("/private-secret?token=bootstrap-secret")
            denied = await client.get("/v1/servers/private-secret?psk=private-secret")
    assert (good.status_code, missing.status_code, denied.status_code) == (200, 404, 401)
    messages = _messages(caplog, "waygate.access")
    assert any("route=/v1/health status=200" in msg for msg in messages)
    assert any("route=<unmatched> status=404" in msg for msg in messages)
    assert any("route=/v1/servers/{server_id} status=401" in msg for msg in messages)
    assert any("query_fields=2" in msg and "result_status=200" in msg for msg in messages)
    assert "private-secret" not in " ".join(messages)
    assert "bootstrap-secret" not in " ".join(messages)


async def test_rate_limit_warning_never_logs_decoded_path_values(caplog):
    configure_logging()
    transport = ASGITransport(app=app, client=("192.0.2.123", 12345))
    path = "/v1/servers/path-secret%0AERROR%20forged/agent/status?token=query-secret"
    with caplog.at_level(logging.WARNING), caplog.at_level(logging.INFO, logger="waygate"):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            statuses = [(await client.post(path, json={"peers": []})).status_code for _ in range(121)]
    assert statuses == [401] * 120 + [429]
    warnings = _messages(caplog, "slowapi")
    assert warnings == ["api rate_limit status=429"]
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "path-secret" not in messages
    assert "query-secret" not in messages
    assert "forged" not in messages


async def test_debug_is_opt_in_and_scoped_to_waygate(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    configure_logging()
    try:
        assert logging.getLogger("waygate.access").isEnabledFor(logging.DEBUG)
        assert not logging.getLogger("sqlalchemy.engine").isEnabledFor(logging.DEBUG)
        assert logging.getLogger("uvicorn.access").disabled
    finally:
        monkeypatch.setenv("LOG_LEVEL", "INFO")
        configure_logging()


async def test_worker_iteration_failure_logs_type_not_exception_value(monkeypatch, caplog):
    async def broken_job():
        raise RuntimeError("bootstrap-secret raw SQL values")

    async def stop_after_iteration(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(worker, "get_settings", lambda: type("Settings", (), {
        "database_url": "sqlite://", "database_pool_size": 1, "database_max_overflow": 0,
        "database_connect_timeout": 1, "database_pool_timeout": 1,
    })())
    monkeypatch.setattr(worker, "require_public_callback_base_url", lambda _settings: None)
    monkeypatch.setattr(worker, "init_db", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(worker, "process_one_job", broken_job)
    monkeypatch.setattr(worker.asyncio, "sleep", stop_after_iteration)

    async def close_db():
        pass

    monkeypatch.setattr(worker, "close_db", close_db)
    with caplog.at_level(logging.INFO, logger="waygate.worker"):
        with pytest.raises(KeyboardInterrupt):
            await worker.serve()
    messages = " ".join(_messages(caplog, "waygate.worker"))
    assert "stage=ready status=started" in messages
    assert "stage=poll status=failed error_type=RuntimeError" in messages
    assert "stage=shutdown status=stopped" in messages
    assert "bootstrap-secret" not in messages


@pytest.mark.parametrize("shutdown_signal", [signal.SIGTERM, signal.SIGINT])
async def test_worker_signal_exits_cleanly_during_pending_database_connection(tmp_path, shutdown_signal):
    config = tmp_path / "waygate.conf"
    config.write_text('[waygate]\ncallback_base_url = "https://worker-test.invalid"\n')
    loop = asyncio.get_running_loop()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.setblocking(False)
        env = {
            **os.environ,
            "WAYGATE_CONFIG_FILE": str(config),
            "WAYGATE_CALLBACK_BASE_URL": "https://worker-test.invalid",
            "DATABASE_URL": (
                f"mysql+aiomysql://synthetic:synthetic@127.0.0.1:"
                f"{listener.getsockname()[1]}/isolated"
            ),
        }
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "waygate.worker", cwd=tmp_path, env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        connection = None
        try:
            connection, _ = await asyncio.wait_for(loop.sock_accept(listener), timeout=10)
            process.send_signal(shutdown_signal)
            output, _ = await asyncio.wait_for(process.communicate(), timeout=5)
            assert process.returncode == 0, output.decode()
        finally:
            if process.returncode is None:
                process.kill()
                await process.communicate()
            if connection is not None:
                connection.close()
