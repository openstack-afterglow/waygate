from ipaddress import IPv4Interface

from fastapi.testclient import TestClient

from afterglow_wg_agent.domain import InterfaceSnapshot, KeyPair
from afterglow_wg_agent.main import create_app
from afterglow_wg_agent.paths import RuntimePaths
from afterglow_wg_agent.settings import Settings


class FakeControl:
    def __init__(self):
        self.ready = False

    def generate_keypair(self):
        return KeyPair("private", "public")

    def snapshot(self, _interface):
        return InterfaceSnapshot(True, True, 51820, "public", (IPv4Interface("10.8.0.1/24"),), ()) if self.ready else InterfaceSnapshot(False, False, None, None, (), ())

    def ensure_interface(self, _interface, _address):
        self.ready = True

    def apply_config(self, _interface, _config_path):
        pass


def test_health_starts_lifespan_with_fake_control(tmp_path):
    settings = Settings(wg_server_host="127.0.0.1", api_auth_token="t" * 32, api_host="127.0.0.1")
    app = create_app(settings, paths=RuntimePaths.temporary(tmp_path), control=FakeControl())
    with TestClient(app) as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    config = (tmp_path / "wireguard" / "wg0.conf").read_text()
    assert config.startswith("# Managed by afterglow-wg-agent; DO NOT EDIT.\n# Installation-ID: ")
    assert "PrivateKey = private" in config
