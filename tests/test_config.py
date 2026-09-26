"""Standalone Waygate configuration compatibility contracts."""

import os
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from waygate import config


def test_empty_environment_value_falls_back_to_toml(monkeypatch):
    monkeypatch.setattr(config, "_load_toml", lambda: {"os_auth_url": "https://keystone.example.test/v3"})

    with patch.dict(os.environ, {"OS_AUTH_URL": ""}, clear=True):
        config.get_settings.cache_clear()
        try:
            assert config.get_settings().os_auth_url == "https://keystone.example.test/v3"
        finally:
            config.get_settings.cache_clear()


def test_afterglow_openstack_section_is_mapped(monkeypatch):
    monkeypatch.setattr(
        config,
        "load_raw_toml",
        lambda: {"openstack": {"auth_url": "https://keystone.example.test/v3", "region_name": "RegionTwo"}},
    )

    settings = config._load_toml()

    assert settings["os_auth_url"] == "https://keystone.example.test/v3"
    assert settings["os_region_name"] == "RegionTwo"


def test_agent_install_mode_is_mapped_from_toml(monkeypatch):
    monkeypatch.setattr(config, "load_raw_toml", lambda: {"waygate": {"agent_install_mode": "prebuilt"}})

    with patch.dict(os.environ, {}, clear=True):
        assert config.get_settings().waygate_agent_install_mode == "prebuilt"


def test_agent_install_mode_defaults_to_cloud_init_and_rejects_unknown_value():
    with patch.dict(os.environ, {}, clear=True):
        assert config.Settings().waygate_agent_install_mode == "cloud-init"
        assert config.Settings(waygate_agent_install_mode=" prebuilt ").waygate_agent_install_mode == "prebuilt"
        with pytest.raises(ValidationError, match="agent_install_mode"):
            config.Settings(waygate_agent_install_mode="iso")


def test_public_callback_base_url_is_required():
    settings = config.Settings(waygate_callback_base_url="")

    with pytest.raises(RuntimeError, match="callback_base_url"):
        config.require_public_callback_base_url(settings)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8010",
        "http://api.localhost:8010",
        "http://127.0.0.1:8010",
        "http://127.42.0.9:8010",
        "http://[::1]:8010",
        "http://0.0.0.0:8010",
    ],
)
def test_public_callback_base_url_rejects_loopback_and_unspecified_targets(url):
    settings = config.Settings(waygate_callback_base_url=url)

    with pytest.raises(RuntimeError, match="gateway VM"):
        config.require_public_callback_base_url(settings)


def test_public_callback_base_url_accepts_vm_reachable_http_endpoint():
    settings = config.Settings(waygate_callback_base_url="https://waygate.example.test/control/")

    assert config.require_public_callback_base_url(settings) == "https://waygate.example.test/control"


@pytest.mark.asyncio
async def test_api_startup_rejects_missing_callback_before_database_initialization(monkeypatch):
    from waygate import main

    settings = config.Settings(database_url="mysql+aiomysql://unused", waygate_callback_base_url="")
    init_db = MagicMock()
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "init_db", init_db)

    with pytest.raises(RuntimeError, match="callback_base_url"):
        async with main.lifespan(main.app):
            pass

    init_db.assert_not_called()
