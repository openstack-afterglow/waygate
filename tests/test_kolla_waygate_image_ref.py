"""Regression tests for the Waygate Kolla-Ansible image reference validator.

Migrated from afterglow/backend/tests/test_kolla_waygate_image_ref.py once the
Waygate Kolla role moved out of the Afterglow monorepo into this repo. Path
resolution uses this repo's own root (parents[1]: tests/ -> repo root)
instead of the former Afterglow layout (parents[2]: backend/tests/ -> repo
root). Error wording is intentionally not pinned so the validator's messages
can evolve without breaking this suite; only accept/reject behavior is
asserted.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_VALIDATOR_PATH = Path(__file__).resolve().parents[1] / "deploy/kolla/ansible/roles/waygate/files/validate_image_ref.py"
_SPEC = importlib.util.spec_from_file_location("kolla_waygate_image_ref", _VALIDATOR_PATH)
assert _SPEC and _SPEC.loader
_VALIDATOR = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_VALIDATOR)


def test_accepts_canonical_remote_digest_reference() -> None:
    _VALIDATOR.validate_image_ref(
        "ghcr.io/openstack-afterglow/waygate-worker@sha256:"
        "52a69c5349141677163a8fbaf5c1dacad03fdbb4d2b2d9b30c1c4b1a9cacb235",
        source_mode=False,
    )


def test_rejects_truncated_remote_digest() -> None:
    with pytest.raises(ValueError):
        _VALIDATOR.validate_image_ref(
            "ghcr.io/openstack-afterglow/waygate-worker@sha256:"
            "52a69c5349141677163a8fbaf5c1dacad03fdbb4d2d9b30c1c4b1a9cacb235",
            source_mode=False,
        )


def test_rejects_latest_remote_tag() -> None:
    with pytest.raises(ValueError):
        _VALIDATOR.validate_image_ref(
            "ghcr.io/openstack-afterglow/waygate-worker:latest",
            source_mode=False,
        )
    with pytest.raises(ValueError):
        _VALIDATOR.validate_image_ref(
            "ghcr.io/openstack-afterglow/waygate-api:LATEST",
            source_mode=False,
        )


def test_rejects_bare_remote_reference() -> None:
    with pytest.raises(ValueError):
        _VALIDATOR.validate_image_ref(
            "ghcr.io/openstack-afterglow/waygate-worker",
            source_mode=False,
        )


def test_accepts_version_tag_reference() -> None:
    _VALIDATOR.validate_image_ref(
        "ghcr.io/openstack-afterglow/waygate-worker:v1.21.0",
        source_mode=False,
    )
    _VALIDATOR.validate_image_ref(
        "ghcr.io/openstack-afterglow/waygate-api:1.0.0",
        source_mode=False,
    )
    _VALIDATOR.validate_image_ref(
        "ghcr.io/openstack-afterglow/waygate-api:2024.1",
        source_mode=False,
    )
    _VALIDATOR.validate_image_ref(
        "ghcr.io/openstack-afterglow/waygate-worker:v2.0.0-rc1",
        source_mode=False,
    )


def test_accepts_source_build_commit_tag() -> None:
    _VALIDATOR.validate_image_ref(
        "afterglow-local/waygate-api:e83ce559e3e3",
        source_mode=True,
    )
