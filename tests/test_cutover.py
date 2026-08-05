from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from waygate.scripts import cutover


def _policy(key: str, resource_id: str | None) -> dict[str, Any]:
    return {
        "policy_key": key,
        "resource_kind": "network",
        "resource_id": resource_id,
        "resource_name": resource_id,
        "constraints": {},
        "updated_by_user_id": None,
        "created_at": "2026-08-04T00:00:00",
        "updated_at": "2026-08-04T00:00:00",
    }


def test_table_plan_is_restart_safe_and_rejects_conflicts():
    spec = cutover.TableSpec("records", "id", ("id", "value"))
    source = [{"id": "one", "value": {"nested": [1, 2]}}]

    assert cutover._plan_table_changes(spec, source, []) == cutover.TablePlan((source[0],))
    assert cutover._plan_table_changes(spec, source, [{"id": "one", "value": '{"nested":[1,2]}'}]) == cutover.TablePlan(())

    with pytest.raises(cutover.CutoverError, match="conflicting records row"):
        cutover._plan_table_changes(spec, source, [{"id": "one", "value": {"nested": [2, 1]}}])
    with pytest.raises(cutover.CutoverError, match="rows absent from source"):
        cutover._plan_table_changes(spec, source, [*source, {"id": "two", "value": None}])


def test_policy_plan_replaces_only_empty_baseline_rows():
    source = [_policy("waygate.image", "image-1")]
    seeded = [_policy("waygate.image", None)]

    plan = cutover._plan_table_changes(
        cutover._POLICY_TABLE,
        source,
        seeded,
        allow_seeded_policy_updates=True,
    )
    assert plan == cutover.TablePlan((), (source[0],))

    conflicting = [_policy("waygate.image", "image-other")]
    with pytest.raises(cutover.CutoverError, match="conflicting resource_policies row"):
        cutover._plan_table_changes(
            cutover._POLICY_TABLE,
            source,
            conflicting,
            allow_seeded_policy_updates=True,
        )


def test_policy_validation_requires_all_rows_and_required_selections():
    rows = [
        _policy("waygate.provider_network", "network-1"),
        _policy("waygate.image", "image-1"),
        _policy("waygate.flavor", "flavor-1"),
        _policy("waygate.floating_network", None),
    ]
    cutover._validate_policy_rows(rows)

    with pytest.raises(cutover.CutoverError, match="missing Waygate resource policies"):
        cutover._validate_policy_rows(rows[:-1])
    with pytest.raises(cutover.CutoverError, match="not configured"):
        cutover._validate_policy_rows([*rows[:2], _policy("waygate.flavor", None), rows[-1]])


def test_ciphertext_verification_requires_identical_copy_and_valid_key(monkeypatch):
    observed: list[str] = []
    monkeypatch.setattr(cutover, "decrypt_wg_client_key", lambda value: observed.append(value) or "private-key")
    source = [{"id": "client-1", "private_key_encrypted": "v3:ciphertext"}]

    assert cutover._verify_ciphertext(source, list(source)) is True
    assert observed == ["v3:ciphertext"]

    with pytest.raises(cutover.CutoverError, match="byte-identically"):
        cutover._verify_ciphertext(source, [{"id": "client-1", "private_key_encrypted": "changed"}])


class _FakeRedis:
    def __init__(self, values: dict[bytes, tuple[bytes, int]]):
        self.values = values
        self.restored: list[tuple[bytes, int, bytes, bool]] = []

    async def scan_iter(self, *, match: str) -> AsyncIterator[bytes]:
        prefix = match.removesuffix("*").encode()
        for key in self.values:
            if key.startswith(prefix):
                yield key

    async def dump(self, key: bytes) -> bytes | None:
        item = self.values.get(key)
        return item[0] if item else None

    async def pttl(self, key: bytes) -> int:
        item = self.values.get(key)
        return item[1] if item else -2

    async def restore(self, key: bytes, ttl: int, payload: bytes, *, replace: bool) -> None:
        self.restored.append((key, ttl, payload, replace))


@pytest.mark.asyncio
async def test_redis_copy_preserves_payload_ttl_and_is_dry_run_safe():
    source = _FakeRedis(
        {
            b"afterglow:waygate:srvtoken:one": (b"dump-one", 3000),
            b"afterglow:waygate:status:one": (b"dump-status", -1),
        }
    )
    destination = _FakeRedis({})

    count = await cutover._copy_redis_pattern(
        source,
        destination,
        "afterglow:waygate:srvtoken:*",
        apply=False,
    )
    assert count == 1
    assert destination.restored == []

    count = await cutover._copy_redis_pattern(
        source,
        destination,
        "afterglow:waygate:status:*",
        apply=True,
    )
    assert count == 1
    assert destination.restored == [(b"afterglow:waygate:status:one", 0, b"dump-status", True)]


def test_database_url_normalization_and_backend_rejection():
    assert cutover._mysql_async_url("mysql+asyncmy://user:secret@db/source").drivername == "mysql+aiomysql"
    assert cutover._mysql_async_url("mysql://user:secret@db/source").drivername == "mysql+aiomysql"
    with pytest.raises(cutover.CutoverError, match="MySQL/MariaDB"):
        cutover._mysql_async_url("postgresql://user:secret@db/source")


class _ConnectionContext:
    def __init__(self, connection: object):
        self.connection = connection

    async def __aenter__(self) -> object:
        return self.connection

    async def __aexit__(self, *_args: object) -> None:
        return None


class _FakeEngine:
    def __init__(self, connection: object):
        self.connection = connection

    def connect(self) -> _ConnectionContext:
        return _ConnectionContext(self.connection)

    def begin(self) -> _ConnectionContext:
        return _ConnectionContext(self.connection)

    async def dispose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_migrate_database_applies_when_legacy_source_has_no_job_table(monkeypatch):
    source_connection = object()
    destination_connection = object()
    source_tables = {spec.name: [] for spec in cutover._TABLES}
    source_tables["waygate_servers"] = [{"id": "server-1"}]
    source_tables["waygate_clients"] = [
        {"id": "client-1", "server_id": "server-1", "private_key_encrypted": "v3:ciphertext"}
    ]
    source_policies = [
        _policy("waygate.provider_network", "network-1"),
        _policy("waygate.image", "image-1"),
        _policy("waygate.flavor", "flavor-1"),
        _policy("waygate.floating_network", None),
    ]
    destination_tables = {spec.name: [] for spec in cutover._TABLES}
    destination_tables["resource_policies"] = [_policy(key, None) for key in sorted(cutover._POLICY_KEYS)]

    engines = iter((_FakeEngine(source_connection), _FakeEngine(destination_connection)))
    monkeypatch.setattr(cutover, "create_async_engine", lambda *_args, **_kwargs: next(engines))
    monkeypatch.setattr(
        cutover,
        "_table_exists",
        lambda _connection, table_name: _async_value(table_name != "waygate_jobs"),
    )

    async def fetch(connection, spec, *, policies_only=False):
        if connection is source_connection:
            return list(source_policies if policies_only else source_tables[spec.name])
        return list(destination_tables["resource_policies"] if policies_only else destination_tables[spec.name])

    async def insert(_connection, spec, rows):
        destination_tables[spec.name].extend(dict(row) for row in rows)

    async def update(_connection, spec, rows):
        by_key = {row[spec.primary_key]: dict(row) for row in destination_tables[spec.name]}
        by_key.update({row[spec.primary_key]: dict(row) for row in rows})
        destination_tables[spec.name] = list(by_key.values())

    monkeypatch.setattr(cutover, "_fetch_rows", fetch)
    monkeypatch.setattr(cutover, "_insert_rows", insert)
    monkeypatch.setattr(cutover, "_update_rows", update)
    monkeypatch.setattr(cutover, "decrypt_wg_client_key", lambda _ciphertext: "private-key")

    report = await cutover.migrate_database(
        "mysql+asyncmy://afterglow:secret@db/afterglow",
        "mysql+aiomysql://waygate:secret@db/waygate",
        apply=True,
    )

    assert report["waygate_jobs"] == {"source": 0, "inserted": 0, "updated": 0}
    assert report["waygate_servers"]["inserted"] == 1
    assert report["waygate_clients"]["inserted"] == 1
    assert report["resource_policies"]["updated"] == 3
    assert report["ciphertext_verified"] is True


async def _async_value(value):
    return value
