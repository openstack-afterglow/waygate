from ipaddress import IPv4Interface

import pytest
from fastapi.testclient import TestClient

from afterglow_wg_agent.domain import InterfaceSnapshot, KeyPair
from afterglow_wg_agent.main import create_app
from afterglow_wg_agent.paths import RuntimePaths
from afterglow_wg_agent.settings import Settings


class WrongReadbackControl:
    def __init__(self): self.ready = False
    def generate_keypair(self): return KeyPair("private", "public")
    def ensure_interface(self, *_): self.ready = True
    def apply_config(self, *_): pass
    def snapshot(self, _): return InterfaceSnapshot(True, False, 51820, "public", (IPv4Interface("10.8.0.1/24"),), ()) if self.ready else InterfaceSnapshot(False, False, None, None, (), ())


class NetworkProbe:
    def __init__(self): self.released = False
    def reconcile(self, *_): pass
    def release_first_activation_forward_guard(self): self.released = True


def test_wrong_runtime_readback_does_not_release_forward_guard(tmp_path):
    network = NetworkProbe()
    settings = Settings(wg_server_host="127.0.0.1", api_auth_token="t" * 32, api_host="127.0.0.1", wg_outbound_interface="eth0")
    with pytest.raises(Exception):
        with TestClient(create_app(settings, paths=RuntimePaths.temporary(tmp_path), control=WrongReadbackControl(), network=network)):
            pass
    assert not network.released
