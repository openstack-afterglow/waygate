"""Resource policy image guard for ``waygate.agent_install_mode``."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from waygate.services.resource_policies import (
    ResourcePolicyValidationError,
    _discover_sync,
    _validate_existing_sync,
    get_spec,
)

_IMAGE = get_spec("waygate.image")


def _mode(mode: str):
    return patch(
        "waygate.services.resource_policies.get_settings",
        return_value=SimpleNamespace(waygate_agent_install_mode=mode),
    )


def _image(image_id="img-1", name="gw", visibility="public", **attrs):
    return SimpleNamespace(id=image_id, name=name, visibility=visibility, status="active", **attrs)


def _conn_with(image) -> MagicMock:
    conn = MagicMock()
    conn.image.get_image.return_value = image
    return conn


def test_prebuilt_mode_rejects_selected_image_without_property():
    conn = _conn_with(_image(properties={}))

    with _mode("prebuilt"), pytest.raises(ResourcePolicyValidationError, match="waygate_agent=prebuilt"):
        _validate_existing_sync(conn, _IMAGE, "img-1")


@pytest.mark.parametrize("value", ["cloud-init", "", "PREBUILT"])
def test_prebuilt_mode_rejects_other_property_values(value):
    conn = _conn_with(_image(properties={"waygate_agent": value}))

    with _mode("prebuilt"), pytest.raises(ResourcePolicyValidationError):
        _validate_existing_sync(conn, _IMAGE, "img-1")


@pytest.mark.parametrize(
    "image",
    [
        _image(properties={"waygate_agent": "prebuilt"}),
        _image(properties=None, waygate_agent="prebuilt"),
    ],
    ids=["properties-dict", "attribute"],
)
def test_prebuilt_mode_accepts_property_bearing_image(image):
    with _mode("prebuilt"):
        assert _validate_existing_sync(_conn_with(image), _IMAGE, "img-1") == {"id": "img-1", "name": "gw"}


def test_prebuilt_mode_still_rejects_private_image():
    conn = _conn_with(_image(visibility="private", properties={"waygate_agent": "prebuilt"}))

    with _mode("prebuilt"), pytest.raises(ResourcePolicyValidationError, match="unavailable"):
        _validate_existing_sync(conn, _IMAGE, "img-1")


def test_cloud_init_mode_accepts_image_without_property():
    with _mode("cloud-init"):
        assert _validate_existing_sync(_conn_with(_image(properties={})), _IMAGE, "img-1") == {
            "id": "img-1",
            "name": "gw",
        }


def _catalog() -> MagicMock:
    conn = MagicMock()
    conn.image.images.return_value = [
        _image("stock", "ubuntu", properties={}),
        _image("baked", "waygate-gateway", properties={"waygate_agent": "prebuilt"}),
        _image("baked-private", "private", visibility="private", properties={"waygate_agent": "prebuilt"}),
    ]
    return conn


def test_prebuilt_mode_discovery_lists_only_property_bearing_images():
    with _mode("prebuilt"):
        assert [option["id"] for option in _discover_sync(_catalog(), _IMAGE)] == ["baked"]


def test_cloud_init_mode_discovery_lists_all_visible_images():
    with _mode("cloud-init"):
        assert [option["id"] for option in _discover_sync(_catalog(), _IMAGE)] == ["stock", "baked"]
