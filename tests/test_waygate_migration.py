"""Waygate 백업/마이그레이션(Phase 3) — 패스프레이즈 래핑 + export/import 서비스 + API.

- crypto: wrap/unwrap 왕복, 잘못된 패스프레이즈 fail-closed.
- export: 서버 private key 미포함, 클라이언트 private key/PSK 는 래핑되어 포함.
- import: 키/터널 설정 보존, 레거시 번들 호환, 잘못된 설정/PSK 거부.
- API: export/import 소유권(IDOR), 패스프레이즈 최소 길이 검증.
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from waygate.main import app
from waygate.services import k3s_crypto, waygate_keys, waygate_migration
from waygate.services.migration import WaygateMigrationError

_VALID_KEY_HEX = "0123456789abcdef" * 4  # 64 hex chars (32 bytes)


@pytest.fixture(autouse=True)
def _encryption_key(monkeypatch):
    """k3s_crypto._get_key() 가 유효 키를 얻도록 (클라이언트 키 암/복호화용)."""
    monkeypatch.setattr(
        "waygate.crypto.get_settings",
        lambda: SimpleNamespace(waygate_encryption_key=_VALID_KEY_HEX),
    )


def _server(**overrides) -> dict:
    base = {
        "id": "srv-1",
        "project_id": "test-project-123",
        "name": "gw",
        "status": "ACTIVE",
        "server_vm_id": "vm-1",
        "tunnel_cidr": "10.8.0.0/24",
        "listen_port": 51820,
        "endpoint_ip": "203.0.113.10",
        "dns": None,
        "mtu": None,
        "server_public_key": "A" * 43 + "=",
    }
    base.update(overrides)
    return base


def _make_client(name: str = "laptop", tunnel_ip: str = "10.8.0.2") -> tuple[dict, str, str]:
    priv, pub = waygate_keys.generate_keypair()
    rec = {
        "id": "c-" + name,
        "name": name,
        "tunnel_ip": tunnel_ip,
        "allowed_ips": ["10.8.0.0/24"],
        "dns": None,
        "enabled": True,
        "public_key": pub,
        "private_key_encrypted": k3s_crypto.encrypt_wg_client_key(priv),
    }
    return rec, priv, pub


# ---------------------------------------------------------------------------
# 패스프레이즈 래핑 crypto
# ---------------------------------------------------------------------------


class TestPassphraseWrap:
    def test_wrap_unwrap_roundtrip(self):
        blob = waygate_migration.wrap_with_passphrase("secret-key-data", "correct horse battery")
        assert blob.startswith("wgm1:")
        assert "secret-key-data" not in blob  # 평문 미노출
        assert waygate_migration.unwrap_with_passphrase(blob, "correct horse battery") == "secret-key-data"

    def test_wrong_passphrase_fails_closed(self):
        blob = waygate_migration.wrap_with_passphrase("secret", "right-passphrase")
        with pytest.raises(WaygateMigrationError) as ei:
            waygate_migration.unwrap_with_passphrase(blob, "wrong-passphrase")
        assert ei.value.status_code == 400

    def test_malformed_blob_rejected(self):
        with pytest.raises(WaygateMigrationError):
            waygate_migration.unwrap_with_passphrase("not-a-wrapped-blob", "x")


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


class TestExportBundle:
    @pytest.mark.asyncio
    async def test_export_wraps_keys_and_excludes_server_key(self, monkeypatch):
        rec, priv, pub = _make_client()
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[rec]))
        monkeypatch.setattr(waygate_migration.waygate_db, "list_attachments", AsyncMock(return_value=[]))

        bundle = await waygate_migration.export_bundle("test-project-123", _server(), "passphrase-1234")

        assert bundle["version"] == waygate_migration.BUNDLE_VERSION
        # 서버 섹션에 private key 계열 필드가 없어야 한다
        assert "private_key" not in bundle["server"]
        assert "server_public_key" not in bundle["server"]
        c = bundle["clients"][0]
        assert c["public_key"] == pub
        assert c["private_key_wrapped"].startswith("wgm1:")
        # 래핑을 풀면 원본 private key 복원
        assert waygate_migration.unwrap_with_passphrase(c["private_key_wrapped"], "passphrase-1234") == priv

    @pytest.mark.asyncio
    async def test_export_wraps_psk_and_client_settings_without_plaintext(self, monkeypatch):
        rec, priv, _ = _make_client()
        psk = waygate_keys.generate_preshared_key()
        rec.update(
            dns="1.1.1.1, 8.8.8.8",
            mtu=1420,
            persistent_keepalive=0,
            preshared_key_encrypted=k3s_crypto.encrypt_wg_client_key(psk),
        )
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[rec]))
        monkeypatch.setattr(waygate_migration.waygate_db, "list_attachments", AsyncMock(return_value=[]))

        bundle = await waygate_migration.export_bundle("test-project-123", _server(), "pw-abcdefgh")

        entry = bundle["clients"][0]
        assert bundle["version"] == 1
        assert (entry["dns"], entry["mtu"], entry["persistent_keepalive"]) == ("1.1.1.1, 8.8.8.8", 1420, 0)
        assert waygate_migration.unwrap_with_passphrase(entry["preshared_key_wrapped"], "pw-abcdefgh") == psk
        serialized = json.dumps(bundle)
        assert priv not in serialized
        assert psk not in serialized
        assert rec["preshared_key_encrypted"] not in serialized

    @pytest.mark.asyncio
    async def test_export_skips_client_with_undecryptable_psk(self, monkeypatch):
        rec, _, _ = _make_client()
        rec["preshared_key_encrypted"] = "corrupt"
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[rec]))
        monkeypatch.setattr(waygate_migration.waygate_db, "list_attachments", AsyncMock(return_value=[]))

        bundle = await waygate_migration.export_bundle("test-project-123", _server(), "pw-abcdefgh")

        assert bundle["clients"] == []


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------


class TestImportBundle:
    @pytest.mark.asyncio
    async def test_roundtrip_preserves_client_key(self, monkeypatch):
        rec, priv, pub = _make_client()
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[rec]))
        monkeypatch.setattr(waygate_migration.waygate_db, "list_attachments", AsyncMock(return_value=[]))
        bundle = await waygate_migration.export_bundle("test-project-123", _server(), "pw-abcdefgh")
        bundle["clients"][0].pop("mtu")
        bundle["clients"][0].pop("persistent_keepalive")

        created: list[dict] = []

        async def _capture(server_id, project_id, client_id, data):
            created.append(data)

        # 대상 서버에는 기존 클라이언트 없음 → IPAM 이 .2 할당
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[]))
        monkeypatch.setattr(waygate_migration.waygate_db, "create_client_record", AsyncMock(side_effect=_capture))

        result = await waygate_migration.import_bundle("test-project-123", _server(id="srv-2"), bundle, "pw-abcdefgh")
        assert result["imported"] == 1
        assert result["skipped"] == []
        # 키 보존: 재암호화된 private key 를 복호화하면 원본과 동일 → public key 일치
        stored = created[0]
        assert stored["public_key"] == pub
        assert k3s_crypto.decrypt_wg_client_key(stored["private_key_encrypted"]) == priv
        assert "preshared_key_wrapped" not in bundle["clients"][0]
        assert stored["preshared_key_encrypted"] is None
        assert stored["mtu"] is None
        assert stored["persistent_keepalive"] == 25

    @pytest.mark.asyncio
    async def test_roundtrip_preserves_existing_psk_and_tunnel_settings(self, monkeypatch):
        rec, priv, pub = _make_client()
        psk = waygate_keys.generate_preshared_key()
        rec.update(
            dns="9.9.9.9",
            mtu=9000,
            persistent_keepalive=65535,
            preshared_key_encrypted=k3s_crypto.encrypt_wg_client_key(psk),
        )
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[rec]))
        monkeypatch.setattr(waygate_migration.waygate_db, "list_attachments", AsyncMock(return_value=[]))
        bundle = await waygate_migration.export_bundle("test-project-123", _server(), "pw-abcdefgh")
        create = AsyncMock()
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[]))
        monkeypatch.setattr(waygate_migration.waygate_db, "create_client_record", create)

        result = await waygate_migration.import_bundle("test-project-123", _server(id="srv-2"), bundle, "pw-abcdefgh")

        assert result == {"imported": 1, "skipped": []}
        stored = create.await_args.args[3]
        assert stored["public_key"] == pub
        assert k3s_crypto.decrypt_wg_client_key(stored["private_key_encrypted"]) == priv
        assert k3s_crypto.decrypt_wg_client_key(stored["preshared_key_encrypted"]) == psk
        assert (stored["dns"], stored["mtu"], stored["persistent_keepalive"]) == ("9.9.9.9", 9000, 65535)

    @pytest.mark.asyncio
    async def test_wrong_passphrase_skips_client(self, monkeypatch):
        rec, priv, pub = _make_client()
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[rec]))
        monkeypatch.setattr(waygate_migration.waygate_db, "list_attachments", AsyncMock(return_value=[]))
        bundle = await waygate_migration.export_bundle("test-project-123", _server(), "correct-pw-1")

        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[]))
        monkeypatch.setattr(waygate_migration.waygate_db, "create_client_record", AsyncMock())

        result = await waygate_migration.import_bundle("test-project-123", _server(id="srv-2"), bundle, "WRONG-pw-9")
        assert result["imported"] == 0
        assert len(result["skipped"]) == 1

    @pytest.mark.asyncio
    async def test_malicious_client_name_rejected(self, monkeypatch):
        # 유효 키를 래핑하되 이름에 개행/쉘 메타문자를 주입 → validator 가 거부해 스킵
        priv, pub = waygate_keys.generate_keypair()
        bundle = {
            "version": waygate_migration.BUNDLE_VERSION,
            "server": {},
            "clients": [
                {
                    "name": "evil\nruncmd: rm -rf /",
                    "tunnel_ip": "10.8.0.2",
                    "allowed_ips": ["10.8.0.0/24"],
                    "dns": None,
                    "enabled": True,
                    "public_key": pub,
                    "private_key_wrapped": waygate_migration.wrap_with_passphrase(priv, "pw-abcdefgh"),
                }
            ],
            "network_attachments": [],
        }
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[]))
        monkeypatch.setattr(waygate_migration.waygate_db, "create_client_record", AsyncMock())

        result = await waygate_migration.import_bundle("test-project-123", _server(id="srv-2"), bundle, "pw-abcdefgh")
        assert result["imported"] == 0
        assert len(result["skipped"]) == 1

    @pytest.mark.asyncio
    async def test_multi_client_import_sequences_ips_and_skips_name_collision(self, monkeypatch):
        """2개 클라이언트는 서로 다른 터널 IP 를 받고, 이름 충돌은 500 이 아닌 skipped 로 처리된다.

        stateful list_clients 로 매 반복마다 직전 생성분이 보이도록 해 IPAM 순차 할당을 실제로 검증한다.
        """
        from waygate.services.store import WaygateClientConflictError

        p1, pub1 = waygate_keys.generate_keypair()
        p2, pub2 = waygate_keys.generate_keypair()
        p3, pub3 = waygate_keys.generate_keypair()

        def _entry(name, priv, pub):
            return {
                "name": name,
                "tunnel_ip": "10.8.0.9",  # import 는 이 값을 무시하고 IPAM 으로 재할당
                "allowed_ips": ["10.8.0.0/24"],
                "dns": None,
                "enabled": True,
                "public_key": pub,
                "private_key_wrapped": waygate_migration.wrap_with_passphrase(priv, "pw-abcdefgh"),
            }

        bundle = {
            "version": waygate_migration.BUNDLE_VERSION,
            "server": {},
            "clients": [_entry("alpha", p1, pub1), _entry("beta", p2, pub2), _entry("alpha", p3, pub3)],
            "network_attachments": [],
        }

        created: list[dict] = []  # stateful 저장소

        async def _stateful_list(server_id, project_id):
            return [{"tunnel_ip": c["tunnel_ip"], "name": c["name"]} for c in created]

        async def _stateful_create(server_id, project_id, client_id, data):
            if any(c["name"] == data["name"] for c in created):
                raise WaygateClientConflictError(field="name")
            created.append({"name": data["name"], "tunnel_ip": data["tunnel_ip"]})

        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", _stateful_list)
        monkeypatch.setattr(waygate_migration.waygate_db, "create_client_record", _stateful_create)

        result = await waygate_migration.import_bundle("test-project-123", _server(id="srv-2"), bundle, "pw-abcdefgh")
        assert result["imported"] == 2
        assert len(result["skipped"]) == 1  # 중복 'alpha'
        ips = sorted(c["tunnel_ip"] for c in created)
        assert ips == ["10.8.0.2", "10.8.0.3"]  # 서로 다른 순차 IP
        assert len(set(ips)) == 2

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("dns", "not a dns address"),
            ("mtu", 575),
            ("mtu", 9001),
            ("mtu", "1420"),
            ("persistent_keepalive", -1),
            ("persistent_keepalive", 65536),
            ("persistent_keepalive", "25"),
            ("persistent_keepalive", None),
        ],
    )
    async def test_import_skips_invalid_client_settings(self, monkeypatch, field, value):
        priv, pub = waygate_keys.generate_keypair()
        entry = {
            "name": "laptop",
            "public_key": pub,
            "private_key_wrapped": waygate_migration.wrap_with_passphrase(priv, "pw-abcdefgh"),
            field: value,
        }
        create = AsyncMock()
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[]))
        monkeypatch.setattr(waygate_migration.waygate_db, "create_client_record", create)

        result = await waygate_migration.import_bundle(
            "test-project-123", _server(), {"version": 1, "clients": [entry]}, "pw-abcdefgh"
        )

        assert result["imported"] == 0
        assert len(result["skipped"]) == 1
        assert result["skipped"][0]["name"] == "laptop"
        assert "검증 오류" in result["skipped"][0]["reason"]
        create.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("bad_psk", "reason"),
        [
            ("not-base64!", "클라이언트 PSK 형식이 유효하지 않습니다"),
            ("YQ==", "클라이언트 PSK 형식이 유효하지 않습니다"),
            (None, "클라이언트 PSK 래핑 형식이 유효하지 않습니다"),
            ("wgm1:invalid", "패스프레이즈가 올바르지 않거나 번들이 손상되었습니다"),
        ],
    )
    async def test_import_skips_invalid_wrapped_psk(self, monkeypatch, bad_psk, reason):
        priv, pub = waygate_keys.generate_keypair()
        entry = {
            "name": "laptop",
            "public_key": pub,
            "private_key_wrapped": waygate_migration.wrap_with_passphrase(priv, "pw-abcdefgh"),
            "preshared_key_wrapped": (
                waygate_migration.wrap_with_passphrase(bad_psk, "pw-abcdefgh")
                if bad_psk not in (None, "wgm1:invalid")
                else bad_psk
            ),
        }
        create = AsyncMock()
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[]))
        monkeypatch.setattr(waygate_migration.waygate_db, "create_client_record", create)

        result = await waygate_migration.import_bundle(
            "test-project-123", _server(), {"version": 1, "clients": [entry]}, "pw-abcdefgh"
        )

        assert result["imported"] == 0
        assert result["skipped"] == [{"name": "laptop", "reason": reason}]
        create.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_import_rejects_psk_wrapped_with_different_passphrase(self, monkeypatch):
        priv, pub = waygate_keys.generate_keypair()
        entry = {
            "name": "laptop",
            "public_key": pub,
            "private_key_wrapped": waygate_migration.wrap_with_passphrase(priv, "pw-abcdefgh"),
            "preshared_key_wrapped": waygate_migration.wrap_with_passphrase(
                waygate_keys.generate_preshared_key(), "different-passphrase"
            ),
        }
        create = AsyncMock()
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[]))
        monkeypatch.setattr(waygate_migration.waygate_db, "create_client_record", create)

        result = await waygate_migration.import_bundle(
            "test-project-123", _server(), {"version": 1, "clients": [entry]}, "pw-abcdefgh"
        )

        assert result["imported"] == 0
        assert len(result["skipped"]) == 1
        assert result["skipped"][0]["reason"] == "패스프레이즈가 올바르지 않거나 번들이 손상되었습니다"
        create.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_import_preserves_minimum_tunnel_settings(self, monkeypatch):
        priv, pub = waygate_keys.generate_keypair()
        entry = {
            "name": "laptop",
            "public_key": pub,
            "private_key_wrapped": waygate_migration.wrap_with_passphrase(priv, "pw-abcdefgh"),
            "mtu": 576,
            "persistent_keepalive": 0,
        }
        create = AsyncMock()
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[]))
        monkeypatch.setattr(waygate_migration.waygate_db, "create_client_record", create)

        result = await waygate_migration.import_bundle(
            "test-project-123", _server(), {"version": 1, "clients": [entry]}, "pw-abcdefgh"
        )

        assert result == {"imported": 1, "skipped": []}
        assert create.await_args.args[3]["mtu"] == 576
        assert create.await_args.args[3]["persistent_keepalive"] == 0
        assert create.await_args.args[3]["preshared_key_encrypted"] is None

    @pytest.mark.asyncio
    async def test_import_rejects_private_key_public_key_mismatch(self, monkeypatch):
        priv, _ = waygate_keys.generate_keypair()
        _, other_pub = waygate_keys.generate_keypair()
        entry = {
            "name": "laptop",
            "public_key": other_pub,
            "private_key_wrapped": waygate_migration.wrap_with_passphrase(priv, "pw-abcdefgh"),
        }
        create = AsyncMock()
        monkeypatch.setattr(waygate_migration.waygate_db, "list_clients", AsyncMock(return_value=[]))
        monkeypatch.setattr(waygate_migration.waygate_db, "create_client_record", create)

        result = await waygate_migration.import_bundle(
            "test-project-123", _server(), {"version": 1, "clients": [entry]}, "pw-abcdefgh"
        )

        assert result["imported"] == 0
        assert result["skipped"][0]["reason"] == "클라이언트 키 무결성 검증 실패"
        create.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unsupported_bundle_version_rejected(self):
        with pytest.raises(WaygateMigrationError) as ei:
            await waygate_migration.import_bundle(
                "test-project-123", _server(), {"version": 999, "clients": []}, "pw-abcdefgh"
            )
        assert ei.value.status_code == 422


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _db_available(monkeypatch):
    monkeypatch.setattr("waygate.api.migration.is_db_available", lambda: True)


@pytest.fixture
async def api_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


def _override_token_info(project_id: str = "test-project-123"):
    from waygate.auth import require_token

    async def _fn():
        return {"project_id": project_id, "user_id": "test-user-123", "username": "testuser"}

    app.dependency_overrides[require_token] = _fn


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


class TestMigrationApi:
    @pytest.mark.asyncio
    async def test_export_404_when_not_owned(self, api_client):
        _override_token_info()
        with patch("waygate.api.migration.waygate_db") as db:
            db.get_server = AsyncMock(return_value=None)
            resp = await api_client.post("/v1/servers/srv-x/export", json={"passphrase": "passphrase-1"})
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_export_422_short_passphrase(self, api_client):
        _override_token_info()
        resp = await api_client.post("/v1/servers/srv-1/export", json={"passphrase": "short"})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_export_success(self, api_client):
        _override_token_info()
        with (
            patch("waygate.api.migration.waygate_db") as db,
            patch("waygate.api.migration.waygate_migration") as mig,
        ):
            db.get_server = AsyncMock(return_value=_server())
            mig.export_bundle = AsyncMock(
                return_value={"version": 1, "server": {}, "clients": [], "network_attachments": []}
            )
            resp = await api_client.post("/v1/servers/srv-1/export", json={"passphrase": "passphrase-1"})
        assert resp.status_code == 200
        assert resp.headers.get("cache-control") == "no-store"
        assert resp.json()["version"] == 1

    @pytest.mark.asyncio
    async def test_import_404_when_not_owned(self, api_client):
        _override_token_info()
        with patch("waygate.api.migration.waygate_db") as db:
            db.get_server = AsyncMock(return_value=None)
            resp = await api_client.post(
                "/v1/servers/srv-x/import",
                json={"passphrase": "passphrase-1", "bundle": {"version": 1, "clients": []}},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_import_success_returns_summary(self, api_client):
        _override_token_info()
        with (
            patch("waygate.api.migration.waygate_db") as db,
            patch("waygate.api.migration.waygate_migration") as mig,
        ):
            db.get_server = AsyncMock(return_value=_server())
            mig.parse_bundle = lambda b: b
            mig.import_bundle = AsyncMock(return_value={"imported": 2, "skipped": []})
            resp = await api_client.post(
                "/v1/servers/srv-1/import",
                json={"passphrase": "passphrase-1", "bundle": {"version": 1, "clients": []}},
            )
        assert resp.status_code == 200
        assert resp.json()["imported"] == 2
