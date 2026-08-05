"""Waygate-owned SQLAlchemy ORM models."""

from datetime import UTC, datetime

from sqlalchemy import BOOLEAN, CHAR, INT, JSON, TEXT, VARCHAR, DateTime, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from waygate.db import Base


def _now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Waygate (WireGuard 게이트웨이 — Phase 1 서버 프로비저닝 + 클라이언트 관리)
# ---------------------------------------------------------------------------


class WaygateServer(Base):
    """Waygate 게이트웨이 인스턴스 1개.

    테넌트 프로젝트에 부팅되는 bastion VM. 서버 private key는 VM 내부에서만
    생성되고 백엔드 DB에는 절대 저장하지 않는다(마이그레이션 요구사항 ③ 자연 충족).
    """

    __tablename__ = "waygate_servers"

    id: Mapped[str] = mapped_column(CHAR(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(VARCHAR(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(VARCHAR(63), nullable=False)
    status: Mapped[str] = mapped_column(VARCHAR(20), nullable=False, default="CREATING")
    status_reason: Mapped[str | None] = mapped_column(TEXT)

    # OpenStack 리소스 ID
    server_vm_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    flavor_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    image_id: Mapped[str | None] = mapped_column(VARCHAR(128))
    provider_network_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    floating_network_id: Mapped[str | None] = mapped_column(VARCHAR(128))
    provider_port_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    security_group_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    fip_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    endpoint_ip: Mapped[str | None] = mapped_column(VARCHAR(45))  # FIP 또는 provider fixed IP
    key_name: Mapped[str | None] = mapped_column(VARCHAR(255))
    resource_policy_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # 에이전트 제어채널 자격증명 — AES-256-GCM 암호화 저장(도메인 wg_agent_token).
    # Redis(휘발성)가 아니라 여기에 durable 하게 보관해, Redis eviction/재시작이나 이전
    # 7일 TTL 만료 후에도 에이전트 register/desired-state/status 채널이 유지된다.
    agent_token_encrypted: Mapped[str | None] = mapped_column(TEXT)

    # WireGuard 설정
    server_public_key: Mapped[str | None] = mapped_column(VARCHAR(64))  # 에이전트 register가 채움
    listen_port: Mapped[int] = mapped_column(INT, nullable=False, default=51820)
    tunnel_cidr: Mapped[str] = mapped_column(VARCHAR(43), nullable=False, default="10.8.0.0/24")
    dns: Mapped[str | None] = mapped_column(VARCHAR(255))
    mtu: Mapped[int | None] = mapped_column(INT)

    # 생성자 정보
    created_by_user_id: Mapped[str | None] = mapped_column(VARCHAR(64), index=True)
    created_by_username: Mapped[str | None] = mapped_column(VARCHAR(255))

    # 타임스탬프
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)

    # soft-delete
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    deleted_by_user_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    deleted_reason: Mapped[str | None] = mapped_column(VARCHAR(255))

    # 관계
    clients: Mapped[list["WaygateClient"]] = relationship(
        "WaygateClient", back_populates="server", cascade="all, delete-orphan"
    )
    network_attachments: Mapped[list["WaygateNetworkAttachment"]] = relationship(
        "WaygateNetworkAttachment", back_populates="server", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("idx_waygate_server_project_created", "project_id", "created_at"),)


class WaygateClient(Base):
    """WireGuard peer(=wg-easy client). 클라이언트 private key는 AES-256-GCM 암호화 저장.

    private key는 백엔드가 X25519로 생성하며 서버 VM에는 절대 전송하지 않는다
    (서버는 peer의 public key만 필요).
    """

    __tablename__ = "waygate_clients"

    id: Mapped[str] = mapped_column(CHAR(36), primary_key=True)
    server_id: Mapped[str] = mapped_column(
        CHAR(36), ForeignKey("waygate_servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(VARCHAR(64), nullable=False, index=True)
    # NOTE: soft-delete 시 NULL로 비워 uq_waygate_client_server_name 슬롯을 해제한다(아래 참고).
    name: Mapped[str | None] = mapped_column(VARCHAR(63))
    enabled: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=True)

    public_key: Mapped[str] = mapped_column(VARCHAR(64), nullable=False)
    private_key_encrypted: Mapped[str] = mapped_column(TEXT, nullable=False)
    preshared_key_encrypted: Mapped[str | None] = mapped_column(TEXT)

    # NOTE: soft-delete 시 NULL로 비워 uq_waygate_client_server_tunnel_ip 슬롯을 해제한다.
    # MySQL/MariaDB는 partial/filtered unique index를 지원하지 않으므로, 활성 클라이언트만
    # unique 제약을 갖도록 하려면 값 자체를 NULL로 비우는 방법뿐이다(NULL은 unique index에서
    # 여러 번 허용됨). list_clients/list_all_active_clients 등 조회 경로는 전부
    # deleted_at IS NULL 필터를 거치므로, 활성 클라이언트의 name/tunnel_ip는 항상 non-null이다.
    tunnel_ip: Mapped[str | None] = mapped_column(VARCHAR(45))
    allowed_ips: Mapped[list | None] = mapped_column(JSON, nullable=True)  # 클라이언트→서버 방향 route 대상
    dns: Mapped[str | None] = mapped_column(VARCHAR(255))

    # 타임스탬프
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)

    # soft-delete
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    deleted_by_user_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    deleted_reason: Mapped[str | None] = mapped_column(VARCHAR(255))

    server: Mapped["WaygateServer"] = relationship("WaygateServer", back_populates="clients")

    __table_args__ = (
        UniqueConstraint("server_id", "tunnel_ip", name="uq_waygate_client_server_tunnel_ip"),
        UniqueConstraint("server_id", "name", name="uq_waygate_client_server_name"),
        Index("idx_waygate_client_project_created", "project_id", "created_at"),
    )


class WaygateNetworkAttachment(Base):
    """Waygate VM에 붙은 테넌트 네트워크 (Phase 2용 스키마 — Phase 1 API는 이 테이블을 사용하지 않음).

    다중 테넌트 네트워크 연결(요구사항 ②) 시 nova.attach_interface로 생성된 포트를 기록한다.
    """

    __tablename__ = "waygate_network_attachments"

    id: Mapped[int] = mapped_column(INT, primary_key=True, autoincrement=True)
    server_id: Mapped[str] = mapped_column(
        CHAR(36), ForeignKey("waygate_servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(VARCHAR(64), nullable=False, index=True)
    network_id: Mapped[str] = mapped_column(VARCHAR(64), nullable=False)
    subnet_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    port_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    cidr: Mapped[str | None] = mapped_column(VARCHAR(43))  # NAT 대상
    nat_mode: Mapped[str] = mapped_column(VARCHAR(16), nullable=False, default="snat")
    status: Mapped[str] = mapped_column(VARCHAR(20), nullable=False, default="CREATING")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)

    server: Mapped["WaygateServer"] = relationship("WaygateServer", back_populates="network_attachments")

    __table_args__ = (Index("idx_waygate_netattach_server", "server_id"),)


class WaygateJob(Base):
    """Durable Waygate server provision/delete work item."""

    __tablename__ = "waygate_jobs"

    id: Mapped[str] = mapped_column(CHAR(36), primary_key=True)
    server_id: Mapped[str] = mapped_column(CHAR(36), nullable=False)
    project_id: Mapped[str] = mapped_column(VARCHAR(64), nullable=False)
    kind: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    status: Mapped[str] = mapped_column(VARCHAR(16), nullable=False, default="queued")
    attempts: Mapped[int] = mapped_column(INT, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(TEXT)
    user_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    username: Mapped[str | None] = mapped_column(VARCHAR(255))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)

    __table_args__ = (Index("idx_waygate_jobs_claim", "status", "created_at"),)



class ResourcePolicy(Base):
    """Global admin-owned selection of a discovered OpenStack resource."""

    __tablename__ = "resource_policies"

    policy_key: Mapped[str] = mapped_column(VARCHAR(100), primary_key=True)
    resource_kind: Mapped[str] = mapped_column(VARCHAR(32), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(VARCHAR(128))
    resource_name: Mapped[str | None] = mapped_column(VARCHAR(255))
    constraints: Mapped[dict | None] = mapped_column(JSON)
    updated_by_user_id: Mapped[str | None] = mapped_column(VARCHAR(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)

    __table_args__ = (Index("idx_resource_policies_kind", "resource_kind"),)

