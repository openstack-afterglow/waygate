"""Exercise Redis 5 primary discovery over hermetic loopback RESP transports."""

import asyncio
from contextlib import asynccontextmanager

import pytest

from waygate import cache, config
from waygate.models.schemas import WaygateAgentStatusReport
from waygate.services import waygate_agent_auth


def _reply(value):
    if isinstance(value, list):
        return f"*{len(value)}\r\n".encode() + b"".join(_reply(item) for item in value)
    if value is None:
        return b"$-1\r\n"
    value = str(value).encode()
    return f"${len(value)}\r\n".encode() + value + b"\r\n"


@asynccontextmanager
async def _backend(*, sentinel=None):
    state = {"data": {}, "read_only": False, "connections": set()}

    async def serve(reader, writer):
        state["connections"].add(writer)
        authenticated = sentinel is not None
        database = 0
        try:
            while True:
                count = await reader.readline()
                if not count:
                    break
                args = []
                for _ in range(int(count[1:])):
                    size = int((await reader.readline())[1:])
                    args.append((await reader.readexactly(size + 2))[:-2].decode())
                command = args[0].upper()
                if command == "AUTH":
                    authenticated = args[1:] == ["default", "p@ss"]
                    reply = b"+OK\r\n" if authenticated else b"-WRONGPASS invalid credentials\r\n"
                elif not authenticated:
                    reply = b"-NOAUTH authentication required\r\n"
                elif command == "SELECT":
                    database = int(args[1])
                    reply = b"+OK\r\n"
                elif command == "SENTINEL":
                    address = sentinel["primary"]
                    reply = _reply([["name", sentinel["name"], "ip", address[0], "port", address[1],
                                     "flags", sentinel.get("flags", "master"), "num-other-sentinels", 2]])
                elif command == "SETEX":
                    if state["read_only"]:
                        reply = b"-READONLY replica is protected\r\n"
                    elif database != 6:
                        reply = b"-ERR status must use DB6\r\n"
                    else:
                        state["data"][args[1]] = args[3]
                        reply = b"+OK\r\n"
                elif command == "GET":
                    reply = _reply(state["data"].get(args[1]) if database == 6 else None)
                elif command == "PING":
                    reply = b"+PONG\r\n"
                else:
                    reply = b"+OK\r\n"
                writer.write(reply)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            state["connections"].discard(writer)

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    state["address"] = server.sockets[0].getsockname()[:2]
    try:
        yield state
    finally:
        server.close()
        await server.wait_closed()
        for writer in list(state["connections"]):
            writer.close()
            await writer.wait_closed()


def _configure(monkeypatch, address, *, master_name="kolla", hosts_prefix=""):
    # URL host is deliberately unusable; query DB has Redis URL precedence.
    settings = config.Settings(
        redis_url="redis://default:p%40ss@127.0.0.1:1/2?db=6",
        sentinel_enabled=True,
        sentinel_master_name=master_name,
        sentinel_hosts=f"{hosts_prefix}127.0.0.1:{address[1]}",
    )
    monkeypatch.setattr(cache, "get_settings", lambda: settings)
    monkeypatch.setattr(cache, "_client", None)
    monkeypatch.setattr(cache, "_sentinel", None)


async def test_primary_write_read_preserves_auth_db_and_survives_first_sentinel_outage(monkeypatch):
    async with _backend() as primary:
        discovery = {"name": "kolla", "primary": primary["address"]}
        async with _backend(sentinel=discovery) as sentinel:
            _configure(monkeypatch, sentinel["address"], hosts_prefix="127.0.0.1:1, ")
            try:
                await waygate_agent_auth.store_status_result("probe", WaygateAgentStatusReport(peers=[], report_interval_seconds=3))
                report = await waygate_agent_auth.get_status_result("probe")
                assert report["report_interval_seconds"] == 3
            finally:
                await cache.close_cache()


@pytest.mark.parametrize("flags,name", [("master,s_down", "kolla"), ("master", "other-service")])
async def test_missing_or_down_primary_never_falls_back_to_direct_url(monkeypatch, flags, name):
    async with _backend() as primary:
        discovery = {"name": name, "primary": primary["address"], "flags": flags}
        async with _backend(sentinel=discovery) as sentinel:
            _configure(monkeypatch, sentinel["address"])
            try:
                with pytest.raises(waygate_agent_auth.StatusStoreUnavailable):
                    await waygate_agent_auth.store_status_result("probe", WaygateAgentStatusReport(peers=[]))
                assert "afterglow:waygate:status:probe" not in primary["data"]
            finally:
                await cache.close_cache()


async def test_demoted_connection_fails_then_next_report_rediscovers_primary(monkeypatch):
    async with _backend() as old, _backend() as new:
        discovery = {"name": "kolla", "primary": old["address"]}
        async with _backend(sentinel=discovery) as sentinel:
            _configure(monkeypatch, sentinel["address"])
            try:
                await waygate_agent_auth.store_status_result("probe", WaygateAgentStatusReport(peers=[], report_interval_seconds=3))
                old["read_only"] = True
                discovery["primary"] = new["address"]
                report = WaygateAgentStatusReport(peers=[], report_interval_seconds=5)
                with pytest.raises(waygate_agent_auth.StatusStoreUnavailable):
                    await waygate_agent_auth.store_status_result("probe", report)
                await waygate_agent_auth.store_status_result("probe", report)
                assert (await waygate_agent_auth.get_status_result("probe"))["report_interval_seconds"] == 5
            finally:
                await cache.close_cache()


@pytest.mark.parametrize("hosts,name", [("", "kolla"), (" , ", "kolla"), ("127.0.0.1:26379", "")])
async def test_empty_sentinel_configuration_does_not_use_writable_direct_url(monkeypatch, hosts, name):
    async with _backend() as direct:
        settings = config.Settings(
            redis_url=f"redis://default:p%40ss@127.0.0.1:{direct['address'][1]}/6",
            sentinel_enabled=True,
            sentinel_hosts=hosts,
            sentinel_master_name=name,
        )
        monkeypatch.setattr(cache, "get_settings", lambda: settings)
        monkeypatch.setattr(cache, "_client", None)
        monkeypatch.setattr(cache, "_sentinel", None)
        try:
            with pytest.raises(waygate_agent_auth.StatusStoreUnavailable):
                await waygate_agent_auth.store_status_result("probe", WaygateAgentStatusReport(peers=[]))
            assert "afterglow:waygate:status:probe" not in direct["data"]
        finally:
            await cache.close_cache()
