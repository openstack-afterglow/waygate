"""VPN 서버/클라이언트 DB CRUD.

k3s_db.py 패턴을 미러링하되, VPN은 신규 기능이라 Redis 폴백 없이 DB 전용으로 동작한다.
DB가 설정되지 않은 경우(is_db_available()==False) 503을 반환하도록 호출부에서 처리한다.
"""

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from waygate.db import get_session_factory, is_db_available
from waygate.models.orm import WaygateClient, WaygateNetworkAttachment, WaygateServer

_logger = logging.getLogger(__name__)


class WaygateClientConflictError(Exception):
    """create_client_record 가 UniqueConstraint 위반으로 실패했을 때 발생.

    field는 "name" | "tunnel_ip" | None(구분 불가) — 호출부(API 라우터)가 안내 메시지를
    분기하는 데 사용한다. 원본 SQL 예외 텍스트는 클라이언트에 노출하지 않는다(CLAUDE.md §6).
    """

    def __init__(self, field: str | None = None):
        self.field = field
        super().__init__(f"vpn client unique constraint violation (field={field})")


# ---------------------------------------------------------------------------
# 내부 헬퍼 — ORM → dict 변환
# ---------------------------------------------------------------------------


def _server_to_dict(s: WaygateServer) -> dict:
    return {
        "id": s.id,
        "project_id": s.project_id,
        "name": s.name,
        "status": s.status,
        "status_reason": s.status_reason,
        "server_vm_id": getattr(s, "server_vm_id", None),
        "flavor_id": getattr(s, "flavor_id", None),
        "image_id": getattr(s, "image_id", None),
        "provider_network_id": getattr(s, "provider_network_id", None),
        "floating_network_id": getattr(s, "floating_network_id", None),
        "provider_port_id": getattr(s, "provider_port_id", None),
        "security_group_id": getattr(s, "security_group_id", None),
        "fip_id": getattr(s, "fip_id", None),
        "endpoint_ip": getattr(s, "endpoint_ip", None),
        "key_name": getattr(s, "key_name", None),
        "resource_policy_snapshot": getattr(s, "resource_policy_snapshot", None),
        "server_public_key": getattr(s, "server_public_key", None),
        "listen_port": s.listen_port,
        "tunnel_cidr": s.tunnel_cidr,
        "dns": getattr(s, "dns", None),
        "mtu": getattr(s, "mtu", None),
        "created_by_user_id": getattr(s, "created_by_user_id", None),
        "created_by_username": getattr(s, "created_by_username", None),
        "created_at": s.created_at.isoformat() if getattr(s, "created_at", None) else None,
        "updated_at": s.updated_at.isoformat() if getattr(s, "updated_at", None) else None,
        "deleted_at": s.deleted_at.isoformat() if getattr(s, "deleted_at", None) else None,
        "deleted_by_user_id": getattr(s, "deleted_by_user_id", None),
        "deleted_reason": getattr(s, "deleted_reason", None),
    }


def _client_to_dict(c: WaygateClient) -> dict:
    return {
        "id": c.id,
        "server_id": c.server_id,
        "project_id": c.project_id,
        "name": c.name,
        "enabled": c.enabled,
        "public_key": c.public_key,
        "private_key_encrypted": c.private_key_encrypted,
        "preshared_key_encrypted": c.preshared_key_encrypted,
        "tunnel_ip": c.tunnel_ip,
        "allowed_ips": c.allowed_ips or [],
        "dns": c.dns,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        "deleted_at": c.deleted_at.isoformat() if c.deleted_at else None,
    }


# ---------------------------------------------------------------------------
# VpnServer CRUD
# ---------------------------------------------------------------------------


def add_server_record(session, project_id: str, server_id: str, data: dict) -> WaygateServer:
    """Add a Waygate server to an existing transaction without committing it."""
    server = WaygateServer(
        id=server_id,
        project_id=project_id,
        name=data.get("name", ""),
        status=data.get("status", "CREATING"),
        status_reason=data.get("status_reason") or None,
        flavor_id=data.get("flavor_id") or None,
        image_id=data.get("image_id") or None,
        provider_network_id=data.get("provider_network_id") or None,
        floating_network_id=data.get("floating_network_id") or None,
        resource_policy_snapshot=data.get("resource_policy_snapshot") or None,
        listen_port=int(data.get("listen_port") or 51820),
        tunnel_cidr=data.get("tunnel_cidr") or "10.8.0.0/24",
        dns=data.get("dns") or None,
        mtu=data.get("mtu") or None,
        created_by_user_id=data.get("created_by_user_id") or None,
        created_by_username=data.get("created_by_username") or None,
    )
    session.add(server)
    return server


async def create_server_record(project_id: str, server_id: str, data: dict) -> None:
    factory = get_session_factory()
    async with factory() as session:
        add_server_record(session, project_id, server_id, data)
        await session.commit()

async def get_server(project_id: str, server_id: str) -> dict | None:
    """소유권 검증 포함 단일 서버 조회. project_id 불일치 시 None (IDOR 방어)."""
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateServer).where(
            WaygateServer.id == server_id, WaygateServer.project_id == project_id, WaygateServer.deleted_at.is_(None)
        )
        result = await session.execute(stmt)
        server = result.scalar_one_or_none()
        if server is None:
            return None
        return _server_to_dict(server)


async def list_servers(project_id: str, *, limit: int | None = None) -> list[dict]:
    factory = get_session_factory()
    async with factory() as session:
        stmt = (
            select(WaygateServer)
            .where(WaygateServer.project_id == project_id, WaygateServer.deleted_at.is_(None))
            .order_by(WaygateServer.created_at.desc())
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        result = await session.execute(stmt)
        return [_server_to_dict(s) for s in result.scalars().all()]


async def get_server_by_id(server_id: str) -> dict | None:
    """소유권 검증 없이 server_id 만으로 조회 — 에이전트 베어러 토큰 경로 전용.

    에이전트 엔드포인트는 verify_report_token 으로 이미 server_id 바인딩을 검증했으므로
    project_id 필터가 불필요하다.
    """
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateServer).where(WaygateServer.id == server_id, WaygateServer.deleted_at.is_(None))
        result = await session.execute(stmt)
        server = result.scalar_one_or_none()
        if server is None:
            return None
        return _server_to_dict(server)


_SERVER_COLUMN_MAP = {
    "server_vm_id",
    "flavor_id",
    "image_id",
    "provider_network_id",
    "floating_network_id",
    "resource_policy_snapshot",
    "provider_port_id",
    "security_group_id",
    "fip_id",
    "endpoint_ip",
    "key_name",
    "server_public_key",
    "listen_port",
    "tunnel_cidr",
    "dns",
    "mtu",
}


async def update_server_status(
    server_id: str,
    status: str | None = None,
    status_reason: str | None = None,
    only_if_status: str | None = None,
    **extra_fields,
) -> None:
    """상태/추가 필드 업데이트. project_id 필터 없음(백그라운드 프로비저닝 태스크 전용).

    only_if_status가 주어지면 현재 status가 그 값일 때만 status를 갱신한다(경합 방지용
    CAS). 예: provisioner가 "PROVISIONING"으로 쓰려는 사이 에이전트 register가 먼저
    도착해 이미 "ACTIVE"로 전이된 경우, provisioner 쓰기가 이를 덮어쓰지 않도록 한다.
    extra_fields는 only_if_status와 무관하게 항상 반영된다(정보 손실 방지).
    """
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateServer).where(WaygateServer.id == server_id)
        result = await session.execute(stmt)
        server = result.scalar_one_or_none()
        if server is None:
            _logger.warning("update_server_status: server %s not found", server_id)
            return

        if status is not None and (only_if_status is None or server.status == only_if_status):
            server.status = status
            if status_reason is not None:
                server.status_reason = status_reason
        server.updated_at = datetime.now(UTC)

        for key, value in extra_fields.items():
            if key in _SERVER_COLUMN_MAP:
                setattr(server, key, value)

        await session.commit()


async def set_agent_token(server_id: str, token_encrypted: str | None) -> None:
    """에이전트 제어채널 토큰(암호화)을 waygate_servers 행에 durable 하게 저장.

    DB 미가용 시 no-op — 이 경우 호출부(waygate_agent_auth)는 Redis 캐시만으로 degrade 동작한다.
    project_id 필터 없음(백그라운드 프로비저닝/에이전트 인증 경로 전용, server_id 로 직접 접근).
    """
    if not is_db_available():
        return
    factory = get_session_factory()
    if factory is None:
        return
    async with factory() as session:
        stmt = select(WaygateServer).where(WaygateServer.id == server_id)
        result = await session.execute(stmt)
        server = result.scalar_one_or_none()
        if server is None:
            _logger.warning("set_agent_token: server %s not found", server_id)
            return
        server.agent_token_encrypted = token_encrypted
        server.updated_at = datetime.now(UTC)
        await session.commit()


async def get_agent_token_encrypted(server_id: str) -> str | None:
    """waygate_servers 행에서 암호화된 에이전트 토큰을 조회. 삭제된 서버는 제외(제어채널 무효화).

    DB 미가용 시 None — 호출부는 Redis 캐시 fallback 으로 동작한다.
    """
    if not is_db_available():
        return None
    factory = get_session_factory()
    if factory is None:
        return None
    async with factory() as session:
        stmt = select(WaygateServer.agent_token_encrypted).where(
            WaygateServer.id == server_id, WaygateServer.deleted_at.is_(None)
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()


async def soft_delete_server(project_id: str, server_id: str, user_id: str, reason: str = "") -> bool:
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateServer).where(
            WaygateServer.id == server_id, WaygateServer.project_id == project_id, WaygateServer.deleted_at.is_(None)
        )
        result = await session.execute(stmt)
        server = result.scalar_one_or_none()
        if server is None:
            return False
        server.deleted_at = datetime.now(UTC)
        server.deleted_by_user_id = user_id
        server.deleted_reason = reason
        server.status = "DELETING"
        await session.commit()
        return True


# ---------------------------------------------------------------------------
# VpnClient CRUD
# ---------------------------------------------------------------------------


async def create_client_record(server_id: str, project_id: str, client_id: str, data: dict) -> None:
    """클라이언트 레코드 생성.

    (server_id, name)/(server_id, tunnel_ip) UniqueConstraint 위반 시 IntegrityError를
    잡아 롤백 후 VpnClientConflictError로 변환한다 — 호출부(API 라우터)가 409로 매핑한다.
    소프트삭제된 클라이언트는 soft_delete_client()가 name/tunnel_ip를 NULL로 비우므로
    정상적으로는 이름/IP 재사용 시 충돌하지 않지만, 동시 요청 경합(TOCTOU) 등 경우
    이 방어선이 최종 방어선이 된다.
    """
    factory = get_session_factory()
    async with factory() as session:
        client = WaygateClient(
            id=client_id,
            server_id=server_id,
            project_id=project_id,
            name=data["name"],
            enabled=data.get("enabled", True),
            public_key=data["public_key"],
            private_key_encrypted=data["private_key_encrypted"],
            preshared_key_encrypted=data.get("preshared_key_encrypted") or None,
            tunnel_ip=data["tunnel_ip"],
            allowed_ips=data.get("allowed_ips") or [],
            dns=data.get("dns") or None,
        )
        session.add(client)
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            field = _classify_unique_violation(exc)
            _logger.warning("Waygate 클라이언트 생성 unique 충돌 (server=%s, field=%s)", server_id, field or "unknown")
            raise WaygateClientConflictError(field) from exc


def _classify_unique_violation(exc: IntegrityError) -> str | None:
    """IntegrityError 메시지에서 위반된 제약(name vs tunnel_ip)을 판별한다.

    MySQL/MariaDB는 "uq_waygate_client_server_name" 같은 제약명을, SQLite는
    "waygate_clients.server_id, waygate_clients.name" 같은 컬럼명을 에러 텍스트에 포함하므로
    두 형태 모두 텍스트 매칭으로 분기한다. 판별 불가 시 None(호출부가 일반 메시지 사용).
    """
    text = str(exc.orig or exc).lower()
    if "uq_waygate_client_server_name" in text or "waygate_clients.name" in text:
        return "name"
    if "uq_waygate_client_server_tunnel_ip" in text or "waygate_clients.tunnel_ip" in text:
        return "tunnel_ip"
    return None


async def list_clients(server_id: str, project_id: str) -> list[dict]:
    factory = get_session_factory()
    async with factory() as session:
        stmt = (
            select(WaygateClient)
            .where(
                WaygateClient.server_id == server_id,
                WaygateClient.project_id == project_id,
                WaygateClient.deleted_at.is_(None),
            )
            .order_by(WaygateClient.created_at.desc())
        )
        result = await session.execute(stmt)
        return [_client_to_dict(c) for c in result.scalars().all()]


async def list_all_active_clients(server_id: str) -> list[dict]:
    """desired-state 렌더용 — project_id 필터 없이 서버의 모든 활성 클라이언트 조회."""
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateClient).where(WaygateClient.server_id == server_id, WaygateClient.deleted_at.is_(None))
        result = await session.execute(stmt)
        return [_client_to_dict(c) for c in result.scalars().all()]


async def get_client(server_id: str, project_id: str, client_id: str) -> dict | None:
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateClient).where(
            WaygateClient.id == client_id,
            WaygateClient.server_id == server_id,
            WaygateClient.project_id == project_id,
            WaygateClient.deleted_at.is_(None),
        )
        result = await session.execute(stmt)
        client = result.scalar_one_or_none()
        if client is None:
            return None
        return _client_to_dict(client)


async def update_client(server_id: str, project_id: str, client_id: str, **fields) -> dict | None:
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateClient).where(
            WaygateClient.id == client_id,
            WaygateClient.server_id == server_id,
            WaygateClient.project_id == project_id,
            WaygateClient.deleted_at.is_(None),
        )
        result = await session.execute(stmt)
        client = result.scalar_one_or_none()
        if client is None:
            return None
        if "name" in fields and fields["name"] is not None:
            client.name = fields["name"]
        if "enabled" in fields and fields["enabled"] is not None:
            client.enabled = fields["enabled"]
        client.updated_at = datetime.now(UTC)
        await session.commit()
        return _client_to_dict(client)


# ---------------------------------------------------------------------------
# WaygateNetworkAttachment CRUD (Phase 2)
# ---------------------------------------------------------------------------


def _attachment_to_dict(a: WaygateNetworkAttachment) -> dict:
    return {
        "id": a.id,
        "server_id": a.server_id,
        "project_id": a.project_id,
        "network_id": a.network_id,
        "subnet_id": a.subnet_id,
        "port_id": a.port_id,
        "cidr": a.cidr,
        "nat_mode": a.nat_mode,
        "status": a.status,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


async def create_attachment_record(server_id: str, project_id: str, data: dict) -> dict:
    """네트워크 연결 레코드 생성 후 dict 반환."""
    factory = get_session_factory()
    async with factory() as session:
        att = WaygateNetworkAttachment(
            server_id=server_id,
            project_id=project_id,
            network_id=data["network_id"],
            subnet_id=data.get("subnet_id") or None,
            port_id=data.get("port_id") or None,
            cidr=data.get("cidr") or None,
            nat_mode=data.get("nat_mode") or "snat",
            status=data.get("status") or "CREATING",
        )
        session.add(att)
        await session.commit()
        await session.refresh(att)
        return _attachment_to_dict(att)


async def list_attachments(server_id: str, project_id: str) -> list[dict]:
    factory = get_session_factory()
    async with factory() as session:
        stmt = (
            select(WaygateNetworkAttachment)
            .where(
                WaygateNetworkAttachment.server_id == server_id,
                WaygateNetworkAttachment.project_id == project_id,
            )
            .order_by(WaygateNetworkAttachment.created_at.asc())
        )
        result = await session.execute(stmt)
        return [_attachment_to_dict(a) for a in result.scalars().all()]


async def list_active_attachment_cidrs(server_id: str) -> list[str]:
    """desired-state 렌더용 — project_id 필터 없이 서버의 ACTIVE attachment CIDR 목록.

    에이전트(베어러 토큰) 경로 전용. cidr 가 없는(아직 미해석) 항목은 제외한다.
    """
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateNetworkAttachment.cidr).where(
            WaygateNetworkAttachment.server_id == server_id,
            WaygateNetworkAttachment.status == "ACTIVE",
            WaygateNetworkAttachment.cidr.is_not(None),
        )
        result = await session.execute(stmt)
        return [c for c in result.scalars().all() if c]


async def get_attachment(server_id: str, project_id: str, attachment_id: int) -> dict | None:
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateNetworkAttachment).where(
            WaygateNetworkAttachment.id == attachment_id,
            WaygateNetworkAttachment.server_id == server_id,
            WaygateNetworkAttachment.project_id == project_id,
        )
        result = await session.execute(stmt)
        att = result.scalar_one_or_none()
        return _attachment_to_dict(att) if att else None


async def update_attachment(attachment_id: int, **fields) -> None:
    """status/port_id/cidr 등 필드 업데이트 (백그라운드/서비스 경로 전용)."""
    allowed = {"status", "port_id", "cidr", "subnet_id"}
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateNetworkAttachment).where(WaygateNetworkAttachment.id == attachment_id)
        result = await session.execute(stmt)
        att = result.scalar_one_or_none()
        if att is None:
            return
        for k, v in fields.items():
            if k in allowed:
                setattr(att, k, v)
        att.updated_at = datetime.now(UTC)
        await session.commit()


async def delete_attachment(server_id: str, project_id: str, attachment_id: int) -> dict | None:
    """소유권 검증 후 하드 삭제. 삭제된 레코드 dict(포트 정리용) 반환, 없으면 None."""
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateNetworkAttachment).where(
            WaygateNetworkAttachment.id == attachment_id,
            WaygateNetworkAttachment.server_id == server_id,
            WaygateNetworkAttachment.project_id == project_id,
        )
        result = await session.execute(stmt)
        att = result.scalar_one_or_none()
        if att is None:
            return None
        data = _attachment_to_dict(att)
        await session.delete(att)
        await session.commit()
        return data


async def soft_delete_client(server_id: str, project_id: str, client_id: str, user_id: str) -> bool:
    """클라이언트 소프트삭제.

    deleted_at 설정과 함께 name/tunnel_ip를 NULL로 비워 uq_vpn_client_server_name /
    uq_vpn_client_server_tunnel_ip unique 슬롯을 즉시 해제한다. MySQL/MariaDB는
    partial(filtered) unique index를 지원하지 않아 deleted_at IS NULL 조건부 unique를
    걸 수 없으므로, 값 자체를 비우는 것이 유일한 방법이다(NULL은 unique index에서
    여러 행에 걸쳐 허용됨). 이렇게 하지 않으면 동일 이름/IP로 재생성 시 소프트삭제된
    행과 충돌해 IntegrityError → 500이 발생한다.
    """
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(WaygateClient).where(
            WaygateClient.id == client_id,
            WaygateClient.server_id == server_id,
            WaygateClient.project_id == project_id,
            WaygateClient.deleted_at.is_(None),
        )
        result = await session.execute(stmt)
        client = result.scalar_one_or_none()
        if client is None:
            return False
        client.deleted_at = datetime.now(UTC)
        client.deleted_by_user_id = user_id
        client.name = None
        client.tunnel_ip = None
        await session.commit()
        return True
