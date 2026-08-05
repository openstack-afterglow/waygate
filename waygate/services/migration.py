"""Waygate 백업/마이그레이션 (Phase 3) — 클라이언트 export/import.

목적: Waygate 서버 설정(클라이언트 인증정보 + 라우팅 + 네트워크 연결)을 번들로 내보내고, 다른
(이미 프로비저닝된) Waygate 서버로 이전한다. 서버 private key 는 애초에 백엔드에 저장하지 않으므로
번들에서 제외되고, 대상 서버는 자체 키로 동작한다(엔드포인트/서버 pubkey 가 바뀌므로 클라이언트는
`.conf` 를 다시 내려받는다).

**클라이언트 private key 처리(3a)**: DB 에는 마스터키(k3s_kubeconfig_encryption_key) 도메인 분리로
암호화 저장돼 있다. export 는 이를 복호화한 뒤 **사용자 패스프레이즈**로 다시 래핑(scrypt→AES-256-GCM)해
번들에 담는다. 이렇게 하면 (a) 마스터키가 다른 배포로도 이전 가능하고, (b) 클라이언트 키가 보존되어
기존 peer 신원(public key)이 유지된다. import 는 패스프레이즈로 언래핑 후 대상 배포의 마스터키로
재암호화한다. 패스프레이즈가 틀리면 GCM 인증 실패로 fail-closed.
"""

from __future__ import annotations

import base64
import json
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from waygate.services import k3s_crypto, waygate_db, waygate_ipam, waygate_keys

_logger = logging.getLogger(__name__)

_WRAP_PREFIX = "wgm1:"
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_LEN = 16
_NONCE_LEN = 12
_KEY_LEN = 32
BUNDLE_VERSION = 1


class WaygateMigrationError(Exception):
    """export/import 실패 — status_code + 안전한 공개 detail (라우터가 HTTP 로 매핑)."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=_KEY_LEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def wrap_with_passphrase(plaintext: str, passphrase: str) -> str:
    """plaintext 를 패스프레이즈로 래핑: prefix + base64(salt||nonce||ciphertext)."""
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _WRAP_PREFIX + base64.b64encode(salt + nonce + ct).decode()


def unwrap_with_passphrase(blob: str, passphrase: str) -> str:
    """패스프레이즈로 언래핑. 형식 오류/패스프레이즈 불일치 시 WaygateMigrationError(400)."""
    if not blob.startswith(_WRAP_PREFIX):
        raise WaygateMigrationError(422, "래핑 형식이 유효하지 않습니다")
    try:
        raw = base64.b64decode(blob[len(_WRAP_PREFIX) :])
        salt, nonce, ct = raw[:_SALT_LEN], raw[_SALT_LEN : _SALT_LEN + _NONCE_LEN], raw[_SALT_LEN + _NONCE_LEN :]
        key = _derive_key(passphrase, salt)
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except WaygateMigrationError:
        raise
    except Exception as e:
        # GCM 인증 실패(패스프레이즈 오류) 포함 — 원인 상세는 노출하지 않는다
        raise WaygateMigrationError(400, "패스프레이즈가 올바르지 않거나 번들이 손상되었습니다") from e


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


async def export_bundle(project_id: str, server: dict, passphrase: str) -> dict:
    """서버의 클라이언트 + 네트워크 연결을 패스프레이즈로 래핑해 번들 dict 를 반환한다."""
    server_id = server["id"]
    clients = await waygate_db.list_clients(server_id, project_id)
    attachments = await waygate_db.list_attachments(server_id, project_id)

    client_entries = []
    for c in clients:
        try:
            plain_priv = k3s_crypto.decrypt_wg_client_key(c["private_key_encrypted"])
        except Exception:
            _logger.error("export: 클라이언트 private key 복호화 실패 (client=%s) — 건너뜀", c["id"])
            continue
        client_entries.append(
            {
                "name": c["name"],
                "tunnel_ip": c["tunnel_ip"],
                "allowed_ips": c.get("allowed_ips") or [],
                "dns": c.get("dns"),
                "enabled": c.get("enabled", True),
                "public_key": c["public_key"],
                "private_key_wrapped": wrap_with_passphrase(plain_priv, passphrase),
            }
        )

    return {
        "version": BUNDLE_VERSION,
        "server": {
            "name": server.get("name"),
            "listen_port": server.get("listen_port"),
            "tunnel_cidr": server.get("tunnel_cidr"),
            "dns": server.get("dns"),
            "mtu": server.get("mtu"),
        },
        "clients": client_entries,
        "network_attachments": [
            {
                "network_id": a["network_id"],
                "subnet_id": a.get("subnet_id"),
                "cidr": a.get("cidr"),
                "nat_mode": a.get("nat_mode", "snat"),
            }
            for a in attachments
        ],
    }


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------


async def import_bundle(project_id: str, target_server: dict, bundle: dict, passphrase: str) -> dict:
    """번들의 클라이언트를 대상 서버로 재생성한다(키 보존). 네트워크 재연결은 후속(수동)로 안내.

    반환: {"imported": n, "skipped": [{"name","reason"}]}
    각 클라이언트 이름/allowed_ips/dns 는 기존 validator 로 재검증한다(신뢰 금지 — CLAUDE.md §2).
    """
    from waygate.models.schemas import WaygateClientCreateRequest

    server_id = target_server["id"]
    if not isinstance(bundle, dict) or bundle.get("version") != BUNDLE_VERSION:
        raise WaygateMigrationError(422, "지원하지 않는 번들 버전입니다")
    entries = bundle.get("clients")
    if not isinstance(entries, list):
        raise WaygateMigrationError(422, "번들에 clients 목록이 없습니다")

    tunnel_cidr = target_server["tunnel_cidr"]
    imported = 0
    skipped: list[dict] = []

    for entry in entries:
        name = entry.get("name") if isinstance(entry, dict) else None
        try:
            # 입력 재검증 — 악의적 번들의 name/CIDR/dns 가 실행 컨텍스트로 흐르지 않도록.
            validated = WaygateClientCreateRequest(
                name=name or "",
                allowed_ips=entry.get("allowed_ips") or None,
                dns=entry.get("dns") or None,
            )
            wrapped = entry.get("private_key_wrapped")
            if not wrapped:
                raise WaygateMigrationError(422, "클라이언트에 private_key_wrapped 가 없습니다")
            plain_priv = unwrap_with_passphrase(wrapped, passphrase)
            # 무결성: 언래핑한 private key 로부터 public key 재유도해 번들 값과 대조.
            derived_pub = waygate_keys.public_key_from_private(plain_priv)
            if entry.get("public_key") and entry["public_key"] != derived_pub:
                raise WaygateMigrationError(400, "클라이언트 키 무결성 검증 실패")

            existing = await waygate_db.list_clients(server_id, project_id)
            used = [c["tunnel_ip"] for c in existing]
            tunnel_ip = waygate_ipam.allocate_next_ip(tunnel_cidr, used)

            import uuid

            await waygate_db.create_client_record(
                server_id,
                project_id,
                str(uuid.uuid4()),
                {
                    "name": validated.name,
                    "enabled": bool(entry.get("enabled", True)),
                    "public_key": derived_pub,
                    "private_key_encrypted": k3s_crypto.encrypt_wg_client_key(plain_priv),
                    "tunnel_ip": tunnel_ip,
                    "allowed_ips": validated.allowed_ips or [],
                    "dns": validated.dns,
                },
            )
            imported += 1
        except WaygateMigrationError as e:
            skipped.append({"name": name, "reason": e.detail})
        except Exception as e:
            # 이름 충돌(이미 존재) 등 — 개별 스킵, 나머지는 계속 진행
            _logger.warning("import: 클라이언트 '%s' 재생성 실패: %s", name, e)
            skipped.append({"name": name, "reason": "생성 실패(이름/IP 충돌 또는 검증 오류)"})

    return {"imported": imported, "skipped": skipped}


def parse_bundle(raw: str | dict) -> dict:
    """문자열이면 JSON 파싱, dict 면 그대로. 파싱 실패 시 422."""
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except Exception as e:
        raise WaygateMigrationError(422, "번들 JSON 파싱에 실패했습니다") from e
