"""Standalone Waygate configuration compatibility contracts."""

import os
from unittest.mock import patch

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
