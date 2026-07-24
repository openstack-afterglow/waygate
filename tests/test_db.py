from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from uuid import uuid4

import pytest

from waygate.db import ClientDraft, Database
from waygate.paths import RuntimePaths


def test_paths_are_fixed_in_production() -> None:
    paths = RuntimePaths.production()
    assert paths.database == Path("/var/lib/waygate/agent.db")
    assert paths.key_dir == Path("/var/lib/waygate/keys")
    assert paths.instance_lock == Path("/var/lib/waygate/instance.lock")
    assert paths.operation_lock == Path("/run/waygate/reconcile.lock")


def test_migration_and_lowest_address_reuse(tmp_path: Path) -> None:
    db = Database(RuntimePaths.temporary(tmp_path))
    db.migrate()
    network = IPv4Network("10.8.0.0/29")
    now = datetime.now(UTC)
    with db.operation(exclusive=True) as connection:
        first = db.allocate_address(connection, network, None)
        assert first == IPv4Address("10.8.0.2")
        db.insert_client(connection, ClientDraft(uuid4(), "first", first, "key-one", (IPv4Network("0.0.0.0/0"),), (), True, now, now))
    with db.operation(exclusive=True) as connection:
        assert db.allocate_address(connection, network, None) == IPv4Address("10.8.0.3")
        with pytest.raises(KeyError, match="address_conflict"):
            db.allocate_address(connection, network, IPv4Address("10.8.0.2"))
