"""Waygate baseline migration ledger contracts."""

from waygate.scripts import migrate


def test_manifest_covers_checksum_verified_baseline():
    migrations = migrate.load_manifest()
    assert [(item.logical_id, item.relative_path) for item in migrations] == [
        ("001_baseline", "001_baseline.sql")
    ]


def test_baseline_statements_are_idempotent_and_complete():
    statements = migrate._statements(migrate.MIGRATIONS / "001_baseline.sql")
    normalized = "\n".join(statements).upper()
    for table in (
        "WAYGATE_SERVERS",
        "WAYGATE_CLIENTS",
        "WAYGATE_NETWORK_ATTACHMENTS",
        "WAYGATE_JOBS",
        "RESOURCE_POLICIES",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in normalized
    assert "INSERT IGNORE INTO RESOURCE_POLICIES" in normalized
