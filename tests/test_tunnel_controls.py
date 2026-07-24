from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from uuid import uuid4

from afterglow_wg_agent.db import ClientDraft, Database
from afterglow_wg_agent.paths import RuntimePaths


def test_nondefault_mtu_and_keepalive_round_trip(tmp_path):
    db = Database(RuntimePaths.temporary(tmp_path))
    db.migrate()
    now = datetime.now(UTC)
    draft = ClientDraft(uuid4(), "tunnel", IPv4Address("10.8.0.2"), "key", (IPv4Network("0.0.0.0/0"),), (), True, now, now, 1300, 0)
    with db.operation(exclusive=True) as connection:
        stored = db.insert_client(connection, draft)
    assert (stored.mtu, stored.persistent_keepalive) == (1300, 0)
