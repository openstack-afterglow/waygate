"""Checksum-verified migration manifest rejects changed or unlisted SQL."""

import hashlib
import sqlite3
from contextlib import closing

import pytest

from waygate.scripts import migrate


def test_manifest_rejects_modified_migration(tmp_path, monkeypatch):
    sql = tmp_path / "001_example.sql"
    sql.write_text("SELECT 1;\n")
    manifest = tmp_path / "manifest.txt"
    manifest.write_text(f"001_example|001_example.sql|{hashlib.sha256(sql.read_bytes()).hexdigest()}\n")
    monkeypatch.setattr(migrate, "MIGRATIONS", tmp_path)
    assert migrate.load_manifest(manifest)[0].logical_id == "001_example"

    sql.write_text("SELECT 2;\n")
    with pytest.raises(migrate.MigrationLedgerError, match="checksum drift"):
        migrate.load_manifest(manifest)


def test_manifest_rejects_unlisted_migration(tmp_path, monkeypatch):
    sql = tmp_path / "001_example.sql"
    sql.write_text("SELECT 1;\n")
    manifest = tmp_path / "manifest.txt"
    manifest.write_text(f"001_example|001_example.sql|{hashlib.sha256(sql.read_bytes()).hexdigest()}\n")
    (tmp_path / "002_unlisted.sql").write_text("SELECT 2;\n")
    monkeypatch.setattr(migrate, "MIGRATIONS", tmp_path)
    with pytest.raises(migrate.MigrationLedgerError, match="absent from manifest"):
        migrate.load_manifest(manifest)


def test_server_client_defaults_migration_preserves_explicit_legacy_settings():
    migration = next(item for item in migrate.load_manifest() if item.logical_id == "004_server_client_defaults")
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(
            """
            CREATE TABLE waygate_servers (id TEXT PRIMARY KEY, dns TEXT, mtu INT);
            CREATE TABLE waygate_clients (
                id TEXT PRIMARY KEY, server_id TEXT NOT NULL,
                dns TEXT, mtu INT, persistent_keepalive INT NOT NULL DEFAULT 25
            );
            INSERT INTO waygate_servers VALUES ('old', '1.1.1.1', 1420);
            INSERT INTO waygate_clients VALUES ('explicit', 'old', '8.8.8.8', 1380, 0);
            INSERT INTO waygate_clients VALUES ('unset', 'old', NULL, NULL, 25);
            """
        )

        # SQLite lacks MariaDB's ADD COLUMN IF NOT EXISTS; leave the DDL unchanged otherwise.
        for statement in migrate._statements(migrate.MIGRATIONS / migration.relative_path):
            connection.execute(statement.replace("ADD COLUMN IF NOT EXISTS", "ADD COLUMN"))

        assert connection.execute(
            "SELECT dns, mtu, persistent_keepalive FROM waygate_servers WHERE id = 'old'"
        ).fetchone() == ("1.1.1.1", 1420, 25)
        assert connection.execute(
            "SELECT id, dns, mtu, persistent_keepalive, inherit_dns, "
            "inherit_persistent_keepalive FROM waygate_clients ORDER BY id"
        ).fetchall() == [
            ("explicit", "8.8.8.8", 1380, 0, 0, 0),
            ("unset", None, None, 25, 0, 0),
        ]

        connection.execute("INSERT INTO waygate_servers (id) VALUES ('new')")
        connection.execute("INSERT INTO waygate_clients (id, server_id) VALUES ('new-explicit', 'new')")
        connection.execute(
            "INSERT INTO waygate_clients (id, server_id, inherit_dns, "
            "inherit_persistent_keepalive) VALUES ('new-inherited', 'new', TRUE, TRUE)"
        )
        assert connection.execute("SELECT persistent_keepalive FROM waygate_servers WHERE id = 'new'").fetchone() == (
            25,
        )
        assert connection.execute(
            "SELECT id, persistent_keepalive, inherit_dns, inherit_persistent_keepalive "
            "FROM waygate_clients WHERE server_id = 'new' ORDER BY id"
        ).fetchall() == [
            ("new-explicit", 25, 0, 0),
            ("new-inherited", 25, 1, 1),
        ]
        for column in ("inherit_dns", "inherit_persistent_keepalive"):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(f"UPDATE waygate_clients SET {column} = NULL WHERE id = 'explicit'")


def test_native_migration_manifest_includes_additive_owner_upgrade():
    assert [entry.logical_id for entry in migrate.load_manifest()] == [
        "001_baseline", "002_agent_install_mode_and_token_rotation", "003_client_tunnel_settings",
        "004_server_client_defaults", "005_client_owner", "006_execution_grants",
    ]


def test_owner_upgrade_preserves_credentials_and_leaves_legacy_clients_unassigned(tmp_path):
    migration = next(entry for entry in migrate.load_manifest() if entry.logical_id == "005_client_owner")
    path = tmp_path / "legacy-owner.sqlite"
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(
            """
            CREATE TABLE waygate_clients (
                id TEXT PRIMARY KEY, project_id TEXT NOT NULL, enabled BOOLEAN NOT NULL,
                private_key_encrypted TEXT NOT NULL, preshared_key_encrypted TEXT,
                tunnel_ip TEXT NOT NULL, allowed_ips TEXT
            );
            INSERT INTO waygate_clients VALUES
                ('legacy', 'project-a', 1, 'private-ciphertext', 'psk-ciphertext', '10.8.0.2', '["10.8.0.0/24"]'),
                ('disabled', 'project-a', 0, 'other-ciphertext', NULL, '10.8.0.3', NULL);
            """
        )
        before = connection.execute("SELECT * FROM waygate_clients ORDER BY id").fetchall()
        for statement in migrate._statements(migrate.MIGRATIONS / migration.relative_path):
            connection.execute(statement.replace("ADD COLUMN IF NOT EXISTS", "ADD COLUMN"))
        connection.commit()
    # Close and reopen the persistent database, not merely the same cursor.
    with closing(sqlite3.connect(path)) as connection:
        after = connection.execute("SELECT * FROM waygate_clients ORDER BY id").fetchall()
        assert [row[:-1] for row in after] == before
        assert all(row[-1] is None for row in after)
        connection.execute("UPDATE waygate_clients SET owner_user_id = 'user-a' WHERE id = 'legacy'")
        assert connection.execute(
            "SELECT owner_user_id, private_key_encrypted, preshared_key_encrypted FROM waygate_clients WHERE id = 'legacy'"
        ).fetchone() == ("user-a", "private-ciphertext", "psk-ciphertext")
