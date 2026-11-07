"""Server-observed agent telemetry, diagnostics verdicts and the tenant diagnostics API."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError

from waygate.api import servers
from waygate.auth import require_token
from waygate.main import app
from waygate.services import agent_telemetry, waygate_agent_auth, waygate_db

_T0 = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
_PEER = "A" * 43 + "="
_CONTRACT_KEYS = {
    "verdict", "checked_at", "agent", "last_register_at", "last_desired_state_at", "last_status_at",
    "last_status", "expected", "hints",
}


def _iso(seconds_before: float) -> str:
    return (_T0 - timedelta(seconds=seconds_before)).isoformat()


def _evaluate(telemetry: dict, *, mode="prebuilt", public_key=None, enabled_clients=0, attachments=0):
    server = {"agent_install_mode": mode, "image_id": "image-1", "server_public_key": public_key}
    return agent_telemetry.evaluate(
        server, telemetry, enabled_clients=enabled_clients, attachments=attachments, now=_T0
    )


# ---------------------------------------------------------------------------
# Verdict matrix (pure, fixed clock)
# ---------------------------------------------------------------------------


def test_verdict_never_connected_without_register_evidence():
    result = _evaluate({})
    assert result["verdict"] == "never_connected"
    assert result["hints"] == []
    assert result["last_status"] is None
    assert set(result) == _CONTRACT_KEYS
    assert result["agent"] == {"install_mode": "prebuilt", "image_id": "image-1", "source": None, "report_interval_seconds": None}


def test_durable_public_key_counts_as_earlier_register_after_telemetry_expiry():
    result = _evaluate({}, public_key=_PEER)
    assert result["verdict"] == "not_polling"
    # Register time is unknown, so the oneshot signature cannot be asserted.
    assert result["hints"] == ["agent_not_polling", "agent_never_reported"]


def test_prebuilt_oneshot_signature_reports_outdated_image_agent():
    telemetry = {
        "register_at": _iso(600),
        "desired_state_at": _iso(595),
        "status_at": _iso(594),
        "peers": "0",
        "agent_source": "prebuilt",
    }
    result = _evaluate(telemetry, enabled_clients=1)
    assert result["verdict"] == "not_polling"
    assert result["hints"] == ["agent_not_polling", "agent_status_stale", "image_agent_outdated"]
    assert result["last_status"] == {"peers": 0, "reported_at": _iso(594), "diagnostics": None}
    assert result["last_register_at"] == _iso(600)


def test_registered_prebuilt_agent_that_never_polled_is_outdated():
    result = _evaluate({"register_at": _iso(400)})
    assert result["verdict"] == "not_polling"
    assert result["hints"] == ["agent_not_polling", "agent_never_reported", "image_agent_outdated"]


def test_outdated_hint_requires_prebuilt_mode_and_early_stop():
    oneshot = {"register_at": _iso(600), "desired_state_at": _iso(595)}
    assert "image_agent_outdated" not in _evaluate(oneshot, mode="cloud-init")["hints"]
    long_running = {"register_at": _iso(7200), "desired_state_at": _iso(3600), "status_at": _iso(3600)}
    result = _evaluate(long_running)
    assert result["verdict"] == "not_polling"
    assert result["hints"] == ["agent_not_polling", "agent_status_stale"]


def test_verdict_not_reporting_distinguishes_never_and_stale():
    never = _evaluate({"register_at": _iso(300), "desired_state_at": _iso(10)})
    assert never["verdict"] == "not_reporting"
    assert never["hints"] == ["agent_never_reported"]
    stale = _evaluate({"register_at": _iso(300), "desired_state_at": _iso(10), "status_at": _iso(200)})
    assert stale["verdict"] == "not_reporting"
    assert stale["hints"] == ["agent_status_stale"]


def test_verdict_peer_mismatch_only_while_fresh():
    telemetry = {"register_at": _iso(300), "desired_state_at": _iso(5), "status_at": _iso(1), "peers": "1"}
    result = _evaluate(telemetry, enabled_clients=2, attachments=1)
    assert result["verdict"] == "peer_mismatch"
    assert result["hints"] == ["peers_mismatch"]
    assert result["expected"] == {"enabled_clients": 2, "attachments": 1}


def test_verdict_ok_and_freshness_boundary():
    telemetry = {
        "register_at": _iso(3600),
        "desired_state_at": _iso(agent_telemetry.POLL_STALE_SECONDS),
        "status_at": _iso(agent_telemetry.STATUS_STALE_SECONDS),
        "peers": "2",
        "agent_source": "cloud-init",
        "report_interval_seconds": "1",
        "diagnostics": '{"reconcile_ok": true, "wg_interface_up": true, "error": null}',
    }
    result = _evaluate(telemetry, enabled_clients=2)
    assert result["verdict"] == "ok"
    assert result["hints"] == []
    assert result["agent"]["source"] == "cloud-init"
    assert result["agent"]["report_interval_seconds"] == 1
    assert result["last_status"]["diagnostics"] == {"reconcile_ok": True, "wg_interface_up": True, "error": None}
    telemetry["desired_state_at"] = _iso(agent_telemetry.POLL_STALE_SECONDS + 1)
    assert _evaluate(telemetry, enabled_clients=2)["verdict"] == "not_polling"


def test_corrupt_telemetry_values_are_ignored():
    result = _evaluate({"register_at": "not-a-time", "peers": "x", "diagnostics": "{"})
    assert result["verdict"] == "never_connected"


# ---------------------------------------------------------------------------
# HTTP: agent endpoints → telemetry → tenant diagnostics endpoint
# ---------------------------------------------------------------------------


@pytest.fixture
def clock(monkeypatch):
    state = SimpleNamespace(now=_T0, mono=1000.0)

    def advance(seconds: float) -> None:
        state.now += timedelta(seconds=seconds)
        state.mono += seconds

    state.advance = advance
    monkeypatch.setattr(agent_telemetry, "_now", lambda: state.now)
    monkeypatch.setattr(agent_telemetry, "_monotonic", lambda: state.mono)
    return state


@pytest.fixture
async def diagnostics_api(monkeypatch, clock):
    record = {
        "id": "server-1",
        "project_id": "project-1",
        "name": "gateway-1",
        "status": "PROVISIONING",
        "listen_port": 51820,
        "tunnel_cidr": "10.8.0.0/24",
        "agent_install_mode": "prebuilt",
        "image_id": "image-1",
        "server_public_key": None,
        "agent_token_rotation_pending": False,
    }
    clients = [
        {"id": "c1", "public_key": _PEER, "preshared_key_encrypted": None, "tunnel_ip": "10.8.0.2", "enabled": True},
        {"id": "c2", "public_key": "B" * 43 + "=", "preshared_key_encrypted": None, "tunnel_ip": "10.8.0.3", "enabled": False},
    ]
    tokens = {}

    async def get_server(project_id, server_id):
        return dict(record) if (project_id, server_id) == (record["project_id"], record["id"]) else None

    async def get_server_by_id(server_id):
        return dict(record) if server_id == record["id"] else None

    async def update_server_status(server_id, status, reason, server_public_key=None):
        record.update(status=status, server_public_key=server_public_key)

    async def set_agent_token(server_id, encrypted):
        tokens[server_id] = encrypted

    async def get_agent_tokens_encrypted(server_id):
        return tokens.get(server_id), None

    async def list_all_active_clients(server_id):
        return list(clients)

    async def list_active_attachment_cidrs(server_id):
        return ["192.168.10.0/24"]

    monkeypatch.setattr(servers, "is_db_available", lambda: True)
    for name, function in {
        "get_server": get_server,
        "get_server_by_id": get_server_by_id,
        "update_server_status": update_server_status,
        "set_agent_token": set_agent_token,
        "get_agent_tokens_encrypted": get_agent_tokens_encrypted,
        "list_all_active_clients": list_all_active_clients,
        "list_active_attachment_cidrs": list_active_attachment_cidrs,
    }.items():
        monkeypatch.setattr(waygate_db, name, function)
    token = await waygate_agent_auth.issue_report_token(record["id"])
    identity = {"project_id": "project-1", "roles": ["reader"], "is_system_admin": False}
    monkeypatch.setitem(app.dependency_overrides, require_token, lambda: dict(identity))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield SimpleNamespace(client=client, record=record, token=token, identity=identity, clock=clock)


def _agent_headers(api) -> dict:
    return {"Authorization": f"Bearer {api.token}"}


async def _register(api):
    response = await api.client.post(
        "/v1/servers/server-1/agent/register", json={"public_key": _PEER}, headers=_agent_headers(api)
    )
    assert response.status_code == 204


async def _poll(api):
    response = await api.client.get("/v1/servers/server-1/agent/desired-state", headers=_agent_headers(api))
    assert response.status_code == 200


async def _report(api, body=None):
    payload = {"peers": [{"public_key": _PEER}], "agent_source": "prebuilt", "report_interval_seconds": 1}
    response = await api.client.post(
        "/v1/servers/server-1/agent/status", json=payload if body is None else body, headers=_agent_headers(api)
    )
    assert response.status_code == 204


async def _diagnostics(api):
    await agent_telemetry.drain_pending()
    response = await api.client.get("/v1/servers/server-1/diagnostics")
    assert response.status_code == 200, response.text
    return response.json()


async def test_stale_prebuilt_oneshot_agent_is_diagnosed_from_server_observations(diagnostics_api):
    api = diagnostics_api
    initial = await _diagnostics(api)
    assert initial["verdict"] == "never_connected"
    assert initial["expected"] == {"enabled_clients": 1, "attachments": 1}

    await _register(api)
    api.clock.advance(3)
    await _poll(api)
    await _report(api, {"peers": [], "reported_at": "1999-01-01T00:00:00+00:00"})
    registered = await _diagnostics(api)
    assert registered["last_register_at"] == _T0.isoformat()
    assert registered["last_desired_state_at"] == (_T0 + timedelta(seconds=3)).isoformat()
    # Agent-supplied clocks are ignored; reported_at is Waygate's receive time.
    assert registered["last_status"]["reported_at"] == registered["last_status_at"] == registered["last_desired_state_at"]
    assert registered["verdict"] == "peer_mismatch"

    # The oneshot agent never polls again.
    api.clock.advance(600)
    result = await _diagnostics(api)
    assert set(result) == _CONTRACT_KEYS
    assert result["verdict"] == "not_polling"
    assert result["hints"] == ["agent_not_polling", "agent_status_stale", "image_agent_outdated"]
    assert result["checked_at"] == api.clock.now.isoformat()
    assert result["agent"]["install_mode"] == "prebuilt"
    assert result["agent"]["image_id"] == "image-1"
    assert api.token not in str(result)


async def test_running_agent_is_ok_and_report_details_are_surfaced(diagnostics_api):
    api = diagnostics_api
    await _register(api)
    await _poll(api)
    await _report(api)
    result = await _diagnostics(api)
    assert result["verdict"] == "ok"
    assert result["hints"] == []
    assert result["last_status"] == {"peers": 1, "reported_at": _T0.isoformat(), "diagnostics": None}
    assert result["agent"]["source"] == "prebuilt"
    assert result["agent"]["report_interval_seconds"] == 1


async def test_failed_wg_read_keeps_cached_peers_and_surfaces_agent_diagnostics(diagnostics_api):
    api = diagnostics_api
    await _register(api)
    await _poll(api)
    await _report(api)
    api.clock.advance(6)
    await _report(api, {"peers": [], "diagnostics": {"wg_interface_up": False, "error": "wg_show_failed"}})
    cached = await waygate_agent_auth.get_status_result("server-1")
    assert [peer["public_key"] for peer in cached["peers"]] == [_PEER]
    result = await _diagnostics(api)
    assert result["last_status_at"] == api.clock.now.isoformat()
    assert result["last_status"]["peers"] == 1
    assert result["last_status"]["diagnostics"] == {"reconcile_ok": None, "wg_interface_up": False, "error": "wg_show_failed"}


async def test_status_telemetry_is_rate_limited_per_server(diagnostics_api):
    api = diagnostics_api
    await _register(api)
    await _report(api)
    api.clock.advance(2)
    await _report(api, {"peers": []})
    assert (await _diagnostics(api))["last_status"]["peers"] == 1
    api.clock.advance(agent_telemetry.WRITE_INTERVAL_SECONDS)
    await _report(api, {"peers": []})
    assert (await _diagnostics(api))["last_status"]["peers"] == 0


async def test_telemetry_keys_have_long_ttl(diagnostics_api, _fake_redis):
    await _register(diagnostics_api)
    await agent_telemetry.drain_pending()
    ttl = await _fake_redis.ttl("afterglow:waygate:agent-telemetry:server-1")
    assert 7 * 24 * 3600 <= ttl <= agent_telemetry.TELEMETRY_TTL_SECONDS


async def test_telemetry_write_failure_never_breaks_agent_endpoints(diagnostics_api, _fake_redis, monkeypatch, caplog):
    api = diagnostics_api
    sensitive = "redis://private:password@backend/6"

    def fail(*args, **kwargs):
        raise RedisConnectionError(sensitive)

    monkeypatch.setattr(_fake_redis, "pipeline", fail)
    await _register(api)
    await _poll(api)
    await _report(api)
    await agent_telemetry.drain_pending()
    assert sensitive not in caplog.text
    assert api.token not in caplog.text
    assert "waygate agent telemetry write skipped error_type=ConnectionError" in caplog.text


async def test_hanging_telemetry_write_never_delays_agent_endpoints(diagnostics_api, _fake_redis, monkeypatch):
    api = diagnostics_api
    release = asyncio.Event()

    class HangingPipeline:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def hset(self, *args, **kwargs):
            pass

        def expire(self, *args, **kwargs):
            pass

        async def execute(self):
            await release.wait()

    monkeypatch.setattr(_fake_redis, "pipeline", lambda **kwargs: HangingPipeline())
    await _register(api)
    await _report(api)
    # Both responses completed while their telemetry writes were still blocked.
    assert len(agent_telemetry._pending) == 2
    release.set()
    await agent_telemetry.drain_pending()
    assert not agent_telemetry._pending


async def test_timed_out_telemetry_write_is_dropped_quietly(diagnostics_api, _fake_redis, monkeypatch, caplog):
    class NeverPipeline:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def hset(self, *args, **kwargs):
            pass

        def expire(self, *args, **kwargs):
            pass

        async def execute(self):
            await asyncio.Event().wait()

    monkeypatch.setattr(_fake_redis, "pipeline", lambda **kwargs: NeverPipeline())
    monkeypatch.setattr(agent_telemetry, "WRITE_TIMEOUT_SECONDS", 0.01)
    await _register(diagnostics_api)
    await agent_telemetry.drain_pending()
    assert "waygate agent telemetry write skipped error_type=TimeoutError" in caplog.text


async def test_diagnostics_only_report_is_acknowledged_without_storage(diagnostics_api, _fake_redis, monkeypatch):
    async def fail_setex(*args, **kwargs):
        raise RedisConnectionError("unavailable")

    def fail_pipeline(*args, **kwargs):
        raise RedisConnectionError("unavailable")

    monkeypatch.setattr(_fake_redis, "setex", fail_setex)
    monkeypatch.setattr(_fake_redis, "pipeline", fail_pipeline)
    headers = _agent_headers(diagnostics_api)
    url = "/v1/servers/server-1/agent/status"
    # Peer-bearing reports still require an acknowledged cache write.
    assert (await diagnostics_api.client.post(url, json={"peers": []}, headers=headers)).status_code == 503
    # A diagnostics-only report has no peer observation and is not a storage acknowledgement.
    diagnostics_only = {"peers": [], "diagnostics": {"wg_interface_up": False, "error": "wg_show_failed"}}
    assert (await diagnostics_api.client.post(url, json=diagnostics_only, headers=headers)).status_code == 204
    await agent_telemetry.drain_pending()


async def test_diagnostics_read_failure_is_safe_503(diagnostics_api, _fake_redis, monkeypatch):
    async def fail(*args, **kwargs):
        raise RedisConnectionError("redis://private:password@backend")

    monkeypatch.setattr(_fake_redis, "hgetall", fail)
    response = await diagnostics_api.client.get("/v1/servers/server-1/diagnostics")
    assert response.status_code == 503
    assert response.json() == {"detail": "Agent telemetry storage unavailable"}


@pytest.mark.parametrize(
    "identity,status",
    [
        ({"project_id": "other-project", "roles": ["admin"], "is_system_admin": False}, 404),
        ({"project_id": "project-1", "roles": ["unrelated"], "is_system_admin": False}, 403),
        ({"project_id": None, "roles": ["admin"], "is_system_admin": False}, 400),
    ],
)
async def test_diagnostics_endpoint_uses_server_get_authorization(diagnostics_api, identity, status):
    diagnostics_api.identity.clear()
    diagnostics_api.identity.update(identity)
    response = await diagnostics_api.client.get("/v1/servers/server-1/diagnostics")
    assert response.status_code == status


async def test_diagnostics_endpoint_hides_missing_server_and_requires_db(diagnostics_api, monkeypatch):
    assert (await diagnostics_api.client.get("/v1/servers/missing/diagnostics")).status_code == 404
    monkeypatch.setattr(servers, "is_db_available", lambda: False)
    assert (await diagnostics_api.client.get("/v1/servers/server-1/diagnostics")).status_code == 503


@pytest.mark.parametrize(
    "diagnostics",
    [
        {"wg_interface_up": False, "detail": "extra field"},
        {"error": "HTTP 500 body: secret"},
        {"wg_interface_up": "false"},
    ],
)
async def test_status_report_rejects_unsafe_diagnostics(diagnostics_api, diagnostics):
    response = await diagnostics_api.client.post(
        "/v1/servers/server-1/agent/status",
        json={"peers": [], "diagnostics": diagnostics},
        headers=_agent_headers(diagnostics_api),
    )
    assert response.status_code == 422


def test_openapi_documents_diagnostics_contract():
    schema = app.openapi()
    operation = schema["paths"]["/v1/servers/{server_id}/diagnostics"]["get"]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/WaygateServerDiagnostics"
    )
    properties = schema["components"]["schemas"]["WaygateServerDiagnostics"]["properties"]
    assert set(properties) == _CONTRACT_KEYS


def test_server_get_policy_documents_diagnostics_route():
    from waygate.policy import list_rules

    rule = next(rule for rule in list_rules() if rule.name == "waygate:server:get")
    assert {"method": "GET", "path": "/v1/servers/{server_id}/diagnostics"} in rule.operations
