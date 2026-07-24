from ipaddress import IPv4Interface

from fastapi.testclient import TestClient

from waygate.domain import InterfaceSnapshot, KeyPair
from waygate.main import create_app
from waygate.paths import RuntimePaths
from waygate.settings import Settings


class FakeControl:
    def __init__(self):
        self.ready = False

    def generate_keypair(self): return KeyPair("private", "public")
    def snapshot(self, _): return InterfaceSnapshot(True, True, 51820, "public", (IPv4Interface("10.8.0.1/24"),), ()) if self.ready else InterfaceSnapshot(False, False, None, None, (), ())
    def ensure_interface(self, *_): self.ready = True
    def apply_config(self, *_): pass


def test_traffic_is_authenticated_and_no_store(tmp_path):
    token = "t" * 32
    app = create_app(Settings(wg_server_host="127.0.0.1", api_auth_token=token, api_host="127.0.0.1"), paths=RuntimePaths.temporary(tmp_path), control=FakeControl())
    with TestClient(app) as client:
        assert client.get("/api/v1/traffic").status_code == 401
        response = client.get("/api/v1/traffic", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"peers": []}
    assert response.headers["cache-control"] == "no-store"
