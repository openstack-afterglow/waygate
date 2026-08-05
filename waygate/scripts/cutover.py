"""Move Waygate-owned state out of the Afterglow database and Redis.

Run during a maintenance window after applying the Waygate baseline migration and
before applying Afterglow migration 073. Source URLs are environment-only so
credentials do not appear in process listings::

    AFTERGLOW_SOURCE_DATABASE_URL=... AFTERGLOW_SOURCE_REDIS_URL=... \
      python -m waygate.scripts.cutover
    AFTERGLOW_SOURCE_DATABASE_URL=... AFTERGLOW_SOURCE_REDIS_URL=... \
      python -m waygate.scripts.cutover --apply

The destination database/Redis URLs and encryption key come from ``waygate.conf``
or the normal ``DATABASE_URL``, ``REDIS_URL``, and ``WAYGATE_ENCRYPTION_KEY``
environment variables. The copy is restart-safe: identical rows are retained,
missing rows are inserted, conflicting rows fail closed, and seeded empty policy
rows are replaced with Afterglow's authoritative selections.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from waygate.config import get_settings
from waygate.crypto import decrypt_wg_client_key


class CutoverError(RuntimeError):
    """The cutover cannot proceed without risking state loss."""


@dataclass(frozen=True)
class TableSpec:
    name: str
    primary_key: str
    columns: tuple[str, ...]
    json_columns: tuple[str, ...] = ()
    optional_source: bool = False


@dataclass(frozen=True)
class TablePlan:
    inserts: tuple[dict[str, Any], ...]
    updates: tuple[dict[str, Any], ...] = ()


_TABLES = (
    TableSpec(
        "waygate_servers",
        "id",
        (
            "id",
            "project_id",
            "name",
            "status",
            "status_reason",
            "server_vm_id",
            "flavor_id",
            "image_id",
            "provider_network_id",
            "floating_network_id",
            "resource_policy_snapshot",
            "provider_port_id",
            "security_group_id",
            "fip_id",
            "endpoint_ip",
            "key_name",
            "agent_token_encrypted",
            "server_public_key",
            "listen_port",
            "tunnel_cidr",
            "dns",
            "mtu",
            "created_by_user_id",
            "created_by_username",
            "created_at",
            "updated_at",
            "deleted_at",
            "deleted_by_user_id",
            "deleted_reason",
        ),
        ("resource_policy_snapshot",),
    ),
    TableSpec(
        "waygate_clients",
        "id",
        (
            "id",
            "server_id",
            "project_id",
            "name",
            "enabled",
            "public_key",
            "private_key_encrypted",
            "preshared_key_encrypted",
            "tunnel_ip",
            "allowed_ips",
            "dns",
            "created_at",
            "updated_at",
            "deleted_at",
            "deleted_by_user_id",
            "deleted_reason",
        ),
        ("allowed_ips",),
    ),
    TableSpec(
        "waygate_network_attachments",
        "id",
        (
            "id",
            "server_id",
            "project_id",
            "network_id",
            "subnet_id",
            "port_id",
            "cidr",
            "nat_mode",
            "status",
            "created_at",
            "updated_at",
        ),
    ),
    TableSpec(
        "waygate_jobs",
        "id",
        (
            "id",
            "server_id",
            "project_id",
            "kind",
            "status",
            "attempts",
            "last_error",
            "user_id",
            "username",
            "claimed_at",
            "created_at",
            "updated_at",
        ),
        optional_source=True,
    ),
)
_POLICY_TABLE = TableSpec(
    "resource_policies",
    "policy_key",
    (
        "policy_key",
        "resource_kind",
        "resource_id",
        "resource_name",
        "constraints",
        "updated_by_user_id",
        "created_at",
        "updated_at",
    ),
    ("constraints",),
)
_POLICY_KEYS = frozenset(
    {
        "waygate.provider_network",
        "waygate.image",
        "waygate.flavor",
        "waygate.floating_network",
    }
)
_REQUIRED_POLICY_KEYS = frozenset(
    {
        "waygate.provider_network",
        "waygate.image",
        "waygate.flavor",
    }
)
_REDIS_PATTERNS = (
    "afterglow:waygate:srvtoken:*",
    "afterglow:waygate:status:*",
)


def _mysql_async_url(raw_url: str) -> URL:
    if not raw_url.strip():
        raise CutoverError("database URL is required")
    url = make_url(raw_url)
    if url.get_backend_name() != "mysql":
        raise CutoverError("Waygate cutover supports MySQL/MariaDB databases only")
    if url.drivername in {"mysql", "mysql+asyncmy"}:
        url = url.set(drivername="mysql+aiomysql")
    if url.drivername != "mysql+aiomysql":
        raise CutoverError("database URL must use mysql, mysql+asyncmy, or mysql+aiomysql")
    return url


def _canonical(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in {"[", "{"}:
            try:
                return _canonical(json.loads(stripped))
            except json.JSONDecodeError:
                return value
        return value
    if isinstance(value, Mapping):
        return {key: _canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_canonical(item) for item in value]
    return value


def _rows_equal(left: Mapping[str, Any], right: Mapping[str, Any], columns: Sequence[str]) -> bool:
    return all(_canonical(left.get(column)) == _canonical(right.get(column)) for column in columns)


def _seeded_policy(row: Mapping[str, Any]) -> bool:
    return row.get("resource_id") is None and row.get("resource_name") is None and row.get("updated_by_user_id") is None


def _plan_table_changes(
    spec: TableSpec,
    source_rows: Sequence[Mapping[str, Any]],
    destination_rows: Sequence[Mapping[str, Any]],
    *,
    allow_seeded_policy_updates: bool = False,
) -> TablePlan:
    source = {row[spec.primary_key]: row for row in source_rows}
    destination = {row[spec.primary_key]: row for row in destination_rows}
    if len(source) != len(source_rows) or len(destination) != len(destination_rows):
        raise CutoverError(f"duplicate primary key detected in {spec.name}")

    extra = sorted(set(destination) - set(source), key=str)
    if extra:
        raise CutoverError(f"destination {spec.name} contains rows absent from source")

    inserts: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    for key, source_row in source.items():
        destination_row = destination.get(key)
        if destination_row is None:
            inserts.append(dict(source_row))
        elif _rows_equal(source_row, destination_row, spec.columns):
            continue
        elif allow_seeded_policy_updates and _seeded_policy(destination_row):
            updates.append(dict(source_row))
        else:
            raise CutoverError(f"conflicting {spec.name} row for primary key {key!r}")
    return TablePlan(tuple(inserts), tuple(updates))


def _validate_policy_rows(rows: Sequence[Mapping[str, Any]]) -> None:
    by_key = {str(row["policy_key"]): row for row in rows}
    missing = sorted(_POLICY_KEYS - set(by_key))
    if missing:
        raise CutoverError(f"Afterglow is missing Waygate resource policies: {', '.join(missing)}")
    unconfigured = sorted(key for key in _REQUIRED_POLICY_KEYS if not by_key[key].get("resource_id"))
    if unconfigured:
        raise CutoverError(f"required Waygate resource policies are not configured: {', '.join(unconfigured)}")


def _database_identity(url: URL) -> tuple[Any, ...]:
    return (url.drivername, url.username, url.password, url.host, url.port, url.database, tuple(sorted(url.query.items())))


async def _fetch_rows(connection: AsyncConnection, spec: TableSpec, *, policies_only: bool = False) -> list[dict[str, Any]]:
    columns = ", ".join(spec.columns)
    suffix = " WHERE policy_key LIKE 'waygate.%'" if policies_only else ""
    result = await connection.execute(text(f"SELECT {columns} FROM {spec.name}{suffix}"))
    return [dict(row) for row in result.mappings().all()]


async def _table_exists(connection: AsyncConnection, table_name: str) -> bool:
    result = await connection.execute(
        text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = DATABASE() AND table_name = :table_name LIMIT 1"
        ),
        {"table_name": table_name},
    )
    return result.scalar_one_or_none() is not None


async def _read_source_tables(connection: AsyncConnection) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = {}
    for spec in _TABLES:
        if spec.optional_source and not await _table_exists(connection, spec.name):
            rows[spec.name] = []
        else:
            rows[spec.name] = await _fetch_rows(connection, spec)
    return rows


def _bindable_row(spec: TableSpec, row: Mapping[str, Any]) -> dict[str, Any]:
    values = dict(row)
    for column in spec.json_columns:
        value = values.get(column)
        if value is not None and not isinstance(value, str):
            values[column] = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return values


async def _insert_rows(connection: AsyncConnection, spec: TableSpec, rows: Sequence[Mapping[str, Any]]) -> None:
    if not rows:
        return
    columns = ", ".join(spec.columns)
    bindings = ", ".join(f":{column}" for column in spec.columns)
    await connection.execute(
        text(f"INSERT INTO {spec.name} ({columns}) VALUES ({bindings})"),
        [_bindable_row(spec, row) for row in rows],
    )


async def _update_rows(connection: AsyncConnection, spec: TableSpec, rows: Sequence[Mapping[str, Any]]) -> None:
    assignments = ", ".join(f"{column} = :{column}" for column in spec.columns if column != spec.primary_key)
    statement = text(f"UPDATE {spec.name} SET {assignments} WHERE {spec.primary_key} = :{spec.primary_key}")
    for row in rows:
        await connection.execute(statement, _bindable_row(spec, row))


def _verify_ciphertext(source_rows: Sequence[Mapping[str, Any]], destination_rows: Sequence[Mapping[str, Any]]) -> bool:
    if not source_rows:
        return False
    destination = {row["id"]: row for row in destination_rows}
    sample = source_rows[0]
    ciphertext = sample.get("private_key_encrypted")
    copied = destination.get(sample["id"], {}).get("private_key_encrypted")
    if not isinstance(ciphertext, str) or copied != ciphertext:
        raise CutoverError("Waygate client ciphertext was not copied byte-identically")
    try:
        decrypt_wg_client_key(ciphertext)
    except Exception as exc:
        raise CutoverError("Waygate client ciphertext cannot be decrypted with the configured key") from exc
    return True


async def migrate_database(source_url: str, destination_url: str, *, apply: bool) -> dict[str, Any]:
    source_dsn = _mysql_async_url(source_url)
    destination_dsn = _mysql_async_url(destination_url)
    if _database_identity(source_dsn) == _database_identity(destination_dsn):
        raise CutoverError("source and destination databases must be different")

    source_engine = create_async_engine(source_dsn, pool_pre_ping=True)
    destination_engine = create_async_engine(destination_dsn, pool_pre_ping=True)
    try:
        async with source_engine.connect() as source_connection:
            source_tables = await _read_source_tables(source_connection)
            source_policies = await _fetch_rows(source_connection, _POLICY_TABLE, policies_only=True)
        _validate_policy_rows(source_policies)

        plans: dict[str, TablePlan] = {}
        async with destination_engine.begin() as destination_connection:
            for spec in _TABLES:
                destination_rows = await _fetch_rows(destination_connection, spec)
                plan = _plan_table_changes(spec, source_tables[spec.name], destination_rows)
                plans[spec.name] = plan
                if apply:
                    await _insert_rows(destination_connection, spec, plan.inserts)

            destination_policies = await _fetch_rows(destination_connection, _POLICY_TABLE, policies_only=True)
            policy_plan = _plan_table_changes(
                _POLICY_TABLE,
                source_policies,
                destination_policies,
                allow_seeded_policy_updates=True,
            )
            plans[_POLICY_TABLE.name] = policy_plan
            if apply:
                await _insert_rows(destination_connection, _POLICY_TABLE, policy_plan.inserts)
                await _update_rows(destination_connection, _POLICY_TABLE, policy_plan.updates)

        report: dict[str, Any] = {
            name: {"source": len(source_tables[name]), "inserted": len(plan.inserts), "updated": len(plan.updates)}
            for name, plan in plans.items()
            if name != _POLICY_TABLE.name
        }
        report[_POLICY_TABLE.name] = {
            "source": len(source_policies),
            "inserted": len(policy_plan.inserts),
            "updated": len(policy_plan.updates),
        }
        report["ciphertext_verified"] = False
        if not apply:
            return report

        async with destination_engine.connect() as destination_connection:
            for spec in _TABLES:
                destination_rows = await _fetch_rows(destination_connection, spec)
                if len(destination_rows) != len(source_tables[spec.name]):
                    raise CutoverError(f"row count mismatch after copying {spec.name}")
                if _plan_table_changes(spec, source_tables[spec.name], destination_rows) != TablePlan(()):
                    raise CutoverError(f"row verification failed after copying {spec.name}")
                if spec.name == "waygate_clients":
                    report["ciphertext_verified"] = _verify_ciphertext(source_tables[spec.name], destination_rows)
            destination_policies = await _fetch_rows(destination_connection, _POLICY_TABLE, policies_only=True)
            if _plan_table_changes(_POLICY_TABLE, source_policies, destination_policies) != TablePlan(()):
                raise CutoverError("resource policy verification failed")
        return report
    finally:
        await source_engine.dispose()
        await destination_engine.dispose()


async def _copy_redis_pattern(source: Redis, destination: Redis, pattern: str, *, apply: bool) -> int:
    count = 0
    async for key in source.scan_iter(match=pattern):
        payload = await source.dump(key)
        ttl_ms = await source.pttl(key)
        if payload is None or ttl_ms == -2:
            raise CutoverError(f"Redis key disappeared during maintenance copy: {key!r}")
        if apply:
            await destination.restore(key, max(ttl_ms, 0), payload, replace=True)
        count += 1
    return count


async def migrate_redis(source_url: str, destination_url: str, *, apply: bool) -> dict[str, int]:
    if not source_url.strip() or not destination_url.strip():
        raise CutoverError("source and destination Redis URLs are required")
    source = Redis.from_url(source_url)
    destination = Redis.from_url(destination_url)
    try:
        counts = {
            pattern: await _copy_redis_pattern(source, destination, pattern, apply=apply) for pattern in _REDIS_PATTERNS
        }
        if apply:
            for pattern, expected in counts.items():
                actual = sum(1 async for _ in destination.scan_iter(match=pattern))
                if actual != expected:
                    raise CutoverError(f"Redis key count mismatch after copying {pattern}")
        return counts
    finally:
        await source.aclose()
        await destination.aclose()


async def cutover(*, apply: bool) -> dict[str, Any]:
    settings = get_settings()
    source_database_url = os.environ.get("AFTERGLOW_SOURCE_DATABASE_URL", "")
    source_redis_url = os.environ.get("AFTERGLOW_SOURCE_REDIS_URL", "")
    database_report = await migrate_database(source_database_url, settings.database_url, apply=apply)
    redis_report = await migrate_redis(source_redis_url, settings.redis_url, apply=apply)
    return {"mode": "apply" if apply else "dry-run", "database": database_report, "redis": redis_report}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="perform the copy; default is a read-only dry run")
    args = parser.parse_args()
    try:
        report = asyncio.run(cutover(apply=args.apply))
    except CutoverError as exc:
        raise SystemExit(f"Waygate cutover refused: {exc}") from exc
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
