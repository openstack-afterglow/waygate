from pathlib import Path
from ipaddress import IPv4Interface, IPv4Network

import pytest

from afterglow_wg_agent.domain import InterfaceSnapshot, KeyPair, PeerRuntime
from afterglow_wg_agent.paths import RuntimePaths
from afterglow_wg_agent.services import AgentService
from afterglow_wg_agent.settings import Settings


class FakeWireGuard:
    def __init__(self):
        self.generated = 0
        self.peers = ()
        self.ready = False
        self.fail_apply = False

    def generate_keypair(self):
        self.generated += 1
        return KeyPair(f"private-{self.generated}", f"public-{self.generated}")

    def ensure_interface(self, *_):
        self.ready = True

    def apply_config(self, _interface, path):
        if self.fail_apply:
            raise RuntimeError("apply failed")
        peers = []
        for line in Path(path).read_text().splitlines():
            if line.startswith("PublicKey = "):
                public = line.split("=", 1)[1].strip()
                peers.append(PeerRuntime(public, None, None, 0, 0, (IPv4Network("10.8.0.2/32"),)))
        self.peers = tuple(peers)

    def snapshot(self, _):
        if not self.ready:
            return InterfaceSnapshot(False, False, None, None, (), ())
        return InterfaceSnapshot(True, True, 51820, "public-1", (IPv4Interface("10.8.0.1/24"),), self.peers)


class FakeNetwork:
    def __init__(self): self.events = []; self.fail_unstage = False
    def reconcile(self, *_): self.events.append("reconcile")
    def release_first_activation_forward_guard(self): self.events.append("release-global")
    def stage_client(self, *_): self.events.append("stage")
    def unstage_client(self, *_):
        self.events.append("unstage")
        if self.fail_unstage: raise RuntimeError("unstage failed")


def make_service(tmp_path: Path):
    settings = Settings(wg_server_host="127.0.0.1", api_auth_token="t" * 32, api_host="127.0.0.1")
    wg, network = FakeWireGuard(), FakeNetwork()
    service = AgentService(settings, RuntimePaths.temporary(tmp_path), wg, network)
    service.startup()
    return service, wg, network


def test_create_stages_before_commit_and_unstages_after(tmp_path):
    service, _wg, network = make_service(tmp_path)
    service.create_client(name="one", address=None, allowed_ips=[IPv4Network("0.0.0.0/0")], dns=[])
    assert network.events[-1] == "unstage"
    assert network.events.index("stage") < network.events.index("unstage")
    with service.database.operation(exclusive=False) as connection:
        assert len(service.database.list_clients(connection)) == 1
    service.shutdown()


def test_apply_failure_does_not_commit_candidate(tmp_path):
    service, wg, _network = make_service(tmp_path)
    wg.fail_apply = True
    with pytest.raises(RuntimeError, match="apply failed"):
        service.create_client(name="failed", address=None, allowed_ips=[IPv4Network("0.0.0.0/0")], dns=[])
    with service.database.operation(exclusive=False) as connection:
        assert service.database.list_clients(connection) == []
    assert not list((tmp_path / "state" / "keys").glob("client-*.key"))
    service.shutdown()


def test_unstage_failure_is_fatal_after_commit(tmp_path):
    service, _wg, network = make_service(tmp_path)
    network.fail_unstage = True
    with pytest.raises(Exception, match="State reconciliation failed"):
        service.create_client(name="blocked", address=None, allowed_ips=[IPv4Network("0.0.0.0/0")], dns=[])
    assert service.fatal_reconciliation
    with service.database.operation(exclusive=False) as connection:
        assert len(service.database.list_clients(connection)) == 1
    service.shutdown()
