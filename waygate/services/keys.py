"""WireGuard 클라이언트 X25519 키쌍 생성.

`cryptography` 라이브러리가 X25519 스칼라 클램핑을 내부적으로 처리하므로
`wg genkey`/`wg pubkey`와 동일한 base64 44자 포맷과 완전히 호환된다.
`wg` 바이너리 호출이 불필요하다.

서버 키쌍은 백엔드가 생성하지 않는다 — VM 내부 에이전트가 부팅 시 생성하고
public key만 register 콜백으로 보고한다(서버 private key는 백엔드 DB에 저장 안 함).
"""

import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def generate_keypair() -> tuple[str, str]:
    """X25519 키쌍을 생성해 (private_key_b64, public_key_b64)를 반환한다.

    반환되는 두 값은 WireGuard 표준 base64 44자 포맷(32바이트 raw + base64 패딩)이다.
    """
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(priv_bytes).decode(), base64.b64encode(pub_bytes).decode()


def generate_preshared_key() -> str:
    """WireGuard preshared key(32바이트 랜덤, base64 44자)를 생성한다."""
    return base64.b64encode(os.urandom(32)).decode()


def public_key_from_private(private_key_b64: str) -> str:
    """WireGuard base64 private key 로부터 대응하는 public key(base64)를 유도한다.

    마이그레이션 import 시 언래핑한 private key 의 무결성(번들의 public_key 와 일치)을
    검증하는 데 사용한다.
    """
    raw = base64.b64decode(private_key_b64)
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_bytes).decode()
