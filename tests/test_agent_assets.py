"""Gateway agent asset and standalone agent behavior tests."""

import importlib.util
import json
import stat
import subprocess
from pathlib import Path

import pytest

from waygate.services.config_render import AGENT_DIR, AGENT_FILES

_AGENT_PATH = AGENT_DIR / "waygate_agent.py"


@pytest.fixture
def agent(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("waygate_agent_under_test", _AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "LOG", str(tmp_path / "agent.log"))
    return module


def _config(**overrides) -> dict:
    return {
        "bootstrap_token": "current-token-abcdefghijklmnop",
        "listen_port": 51820,
        "tunnel_address": "10.8.0.1/24",
        "tunnel_cidr": "10.8.0.0/24",
    } | overrides


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_install_sh_installs_every_agent_file_with_manifest_mode(tmp_path):
    root = tmp_path / "root"
    subprocess.run(["sh", str(AGENT_DIR / "install.sh"), str(AGENT_DIR), str(root)], check=True)

    installed = {path for path in root.rglob("*") if path.is_file()}
    assert installed == {root / target.lstrip("/") for _, target, _ in AGENT_FILES}
    for name, target, mode in AGENT_FILES:
        path = root / target.lstrip("/")
        assert path.read_bytes() == (AGENT_DIR / name).read_bytes()
        assert _mode(path) == int(mode, 8)


def test_interface_section_includes_gateway_address_and_port(agent):
    assert agent.interface_section(_config(), "private-key") == [
        "[Interface]",
        "Address = 10.8.0.1/24",
        "ListenPort = 51820",
        "SaveConfig = false",
        "PrivateKey = private-key",
        "",
    ]


def test_write_wg_conf_skips_disabled_peers_and_includes_psk(agent, monkeypatch, tmp_path):
    wg_conf = tmp_path / "wg0.conf"
    monkeypatch.setattr(agent, "WG_CONF", str(wg_conf))

    agent.write_wg_conf(
        _config(),
        "private-key",
        {
            "peers": [
                {"public_key": "enabled-key", "preshared_key": "psk", "allowed_ips": ["10.8.0.2/32"]},
                {"public_key": "disabled-key", "enabled": False, "allowed_ips": ["10.8.0.3/32"]},
            ]
        },
    )

    text = wg_conf.read_text()
    assert "Address = 10.8.0.1/24" in text
    assert "PublicKey = enabled-key\nPresharedKey = psk\nAllowedIPs = 10.8.0.2/32" in text
    assert "disabled-key" not in text
    assert _mode(wg_conf) == 0o600


def test_adopt_next_token_persists_before_switching(agent, monkeypatch, tmp_path):
    config_path = tmp_path / "agent.json"
    cfg = _config()
    config_path.write_text(json.dumps(cfg))
    monkeypatch.setattr(agent, "CONFIG_PATH", str(config_path))
    fsync = agent.os.fsync
    synced = {"file": False, "directory": False}

    def durable_before_adoption(fd):
        assert cfg == _config()
        if stat.S_ISDIR(agent.os.fstat(fd).st_mode):
            assert synced["file"]
            assert json.loads(config_path.read_text())["bootstrap_token"] == "new-token-abcdefghijklmnop"
            synced["directory"] = True
        else:
            synced["file"] = True
        fsync(fd)

    monkeypatch.setattr(agent.os, "fsync", durable_before_adoption)

    assert agent.adopt_next_token(cfg, {"next_token": "new-token-abcdefghijklmnop"}) is True

    assert synced["directory"]
    assert cfg["bootstrap_token"] == "new-token-abcdefghijklmnop"
    assert json.loads(config_path.read_text()) == cfg
    assert _mode(config_path) == 0o600
    assert not (tmp_path / "agent.json.tmp").exists()


def test_adopt_next_token_keeps_current_when_persist_fails(agent, monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "CONFIG_PATH", str(tmp_path / "missing" / "agent.json"))
    cfg = _config()

    assert agent.adopt_next_token(cfg, {"next_token": "new-token-abcdefghijklmnop"}) is False

    assert cfg == _config()


def test_failed_directory_sync_blocks_adoption_and_later_loading(agent, monkeypatch, tmp_path):
    config_path = tmp_path / "agent.json"
    cfg = _config()
    config_path.write_text(json.dumps(cfg))
    monkeypatch.setattr(agent, "CONFIG_PATH", str(config_path))
    fsync = agent.os.fsync

    def fail_directory_sync(fd):
        if stat.S_ISDIR(agent.os.fstat(fd).st_mode):
            raise OSError("directory sync failed")
        fsync(fd)

    monkeypatch.setattr(agent.os, "fsync", fail_directory_sync)
    assert agent.adopt_next_token(cfg, {"next_token": "new-token-abcdefghijklmnop"}) is False
    assert cfg == _config()
    with pytest.raises(OSError, match="directory sync failed"):
        agent.load_config()
    monkeypatch.setattr(agent.os, "fsync", fsync)
    assert agent.load_config()["bootstrap_token"] == "new-token-abcdefghijklmnop"


@pytest.mark.parametrize("desired", [{}, {"next_token": None}, {"next_token": "current-token-abcdefghijklmnop"}])
def test_adopt_next_token_noop_when_absent_or_same(agent, monkeypatch, tmp_path, desired):
    config_path = tmp_path / "agent.json"
    monkeypatch.setattr(agent, "CONFIG_PATH", str(config_path))
    cfg = _config()

    assert agent.adopt_next_token(cfg, desired) is False

    assert cfg == _config()
    assert not config_path.exists()


def test_agent_source_prebuilt_when_image_info_exists(agent, monkeypatch, tmp_path):
    image_info = tmp_path / "image-info.json"
    monkeypatch.setattr(agent, "IMAGE_INFO_PATH", str(image_info))
    assert agent.agent_source() == "cloud-init"

    image_info.write_text("{}")
    assert agent.agent_source() == "prebuilt"
