from ipaddress import IPv4Interface

from fastapi.testclient import TestClient

from waygate.domain import InterfaceSnapshot, KeyPair
from waygate.main import create_app
from waygate.paths import RuntimePaths
from waygate.settings import Settings


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


def test_temporary_console_is_same_origin_and_nonpersistent(tmp_path):
    settings = Settings(wg_server_host="127.0.0.1", api_auth_token="t" * 32, api_host="127.0.0.1")
    with TestClient(create_app(settings, paths=RuntimePaths.temporary(tmp_path), control=FakeControl())) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert "TEMPORARY OPERATOR CONSOLE" in response.text
    assert "/api/v1/clients" in response.text
    assert "localStorage" not in response.text
    assert "sessionStorage" not in response.text
