"""Checksum-verified migration manifest rejects changed or unlisted SQL."""

import hashlib

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
