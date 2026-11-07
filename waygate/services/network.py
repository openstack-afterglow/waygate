"""Waygate 다중 테넌트 네트워크 연결 (Phase 2) — nova.attach_interface + SNAT 기록.

waygate VM 에 추가 테넌트 네트워크를 attach 해, VPN 클라이언트가 터널을 통해 그 네트워크
내부 인스턴스에 접근하도록 한다. 실제 SNAT masquerade 는 VM 내부 에이전트가 desired-state 의
nat_networks(attachment CIDR 목록)를 받아 iptables 로 적용한다(templates/waygate_agent.yaml.j2).
Attachment 는 물리 인터페이스만 의미하며, 클라이언트 AllowedIPs 라우팅은 attachment 별
`allowed_ips` 설정이다(subnet CIDR 을 자동으로 광고하지 않는다).

소유권 검증은 호출부(API 라우터)에서 _get_owned_server 로 이미 수행하고, 이 모듈은 서버 dict 를
받아 OpenStack 작업 + DB 기록을 담당한다.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging

from waygate.services import neutron, nova, waygate_db
from waygate.services.execution import ExecutionDenied, ExecutionUnavailable
from waygate.services.store import WaygateServerInactiveError

_logger = logging.getLogger(__name__)


class WaygateNetworkError(Exception):
    """네트워크 연결/해제 실패 — status_code + 안전한 공개 detail 을 담는다(라우터가 HTTP 로 매핑)."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def validate_attachment_routes(allowed_ips: list[str], tunnel_cidr: str) -> list[str]:
    """Schema-canonical routes must not overlap the gateway tunnel subnet (422 otherwise)."""
    tunnel = ipaddress.ip_network(tunnel_cidr, strict=False)
    for route in allowed_ips:
        network = ipaddress.ip_network(route, strict=False)
        if network.version == tunnel.version and network.overlaps(tunnel):
            raise WaygateNetworkError(422, f"allowed_ips {route} overlaps the Waygate tunnel subnet {tunnel}")
    return list(allowed_ips)


def _network_attachable(net, project_id: str) -> bool:
    """Own tenant network, or a provider network shared with / external to every project.

    Neutron already returned it to this caller's scoped connection; anything else stays 404.
    """
    if net is None:
        return False
    if getattr(net, "is_shared", False) is True or getattr(net, "is_router_external", False) is True:
        return True
    return getattr(net, "project_id", None) == project_id


def _resolve_cidr(conn, network_id: str, subnet_id: str | None) -> tuple[str, str]:
    """(subnet_id, cidr) 반환. subnet_id 미지정 시 네트워크의 첫 IPv4 서브넷을 사용."""
    if subnet_id:
        subnet = conn.network.get_subnet(subnet_id)
        if subnet is None or subnet.network_id != network_id:
            raise WaygateNetworkError(404, "서브넷을 찾을 수 없거나 네트워크와 일치하지 않습니다")
        if getattr(subnet, "ip_version", 4) != 4:
            raise WaygateNetworkError(422, "Waygate 네트워크 연결은 IPv4 서브넷만 지원합니다")
        return subnet.id, subnet.cidr

    subnets = [s for s in conn.network.subnets(network_id=network_id)]
    # IPv4 우선 (SNAT 대상은 IPv4)
    ipv4 = [s for s in subnets if getattr(s, "ip_version", 4) == 4]
    chosen = ipv4 or subnets
    if not chosen:
        raise WaygateNetworkError(422, "네트워크에 서브넷이 없어 CIDR 을 확인할 수 없습니다")
    return chosen[0].id, chosen[0].cidr


async def attach_network(
    project_id: str,
    server: dict,
    network_id: str,
    subnet_id: str | None,
    nat_mode: str,
    *,
    conn,
    allowed_ips: list[str] | None = None,
) -> dict:
    """서버에 네트워크 인터페이스를 연결하고 attachment dict 를 반환한다."""
    server_id = server["id"]
    vm_id = server.get("server_vm_id")
    if server.get("status") != "ACTIVE" or not vm_id:
        raise WaygateNetworkError(409, "Waygate 서버가 ACTIVE 상태가 아닙니다")
    routes = validate_attachment_routes(allowed_ips or [], server["tunnel_cidr"])

    # 중복 연결 방지
    existing = await waygate_db.list_attachments(server_id, project_id)
    if any(a["network_id"] == network_id and a["status"] != "ERROR" for a in existing):
        raise WaygateNetworkError(409, "이미 연결된 네트워크입니다")

    net = await asyncio.to_thread(conn.network.get_network, network_id)
    if not _network_attachable(net, project_id):
        # 존재하지 않음/타 프로젝트 소유(비공유) 모두 동일 404 (정보 노출 방지)
        raise WaygateNetworkError(404, "네트워크를 찾을 수 없습니다")

    resolved_subnet_id, cidr = await asyncio.to_thread(_resolve_cidr, conn, network_id, subnet_id)

    try:
        att = await waygate_db.create_attachment_record(
            server_id,
            project_id,
            {
                "network_id": network_id,
                "subnet_id": resolved_subnet_id,
                "cidr": cidr,
                "allowed_ips": routes,
                "nat_mode": nat_mode,
                "status": "CREATING",
            },
        )
    except WaygateServerInactiveError as exc:
        raise WaygateNetworkError(409, "Waygate 서버가 ACTIVE 상태가 아닙니다") from exc
    port_id: str | None = None
    try:
        port = await asyncio.to_thread(
            neutron.create_port,
            conn,
            network_id,
            f"waygate-{server_id}-{att['id']}",
            fixed_ips=[{"subnet_id": resolved_subnet_id}],
        )
        port_id = port["id"]
        await waygate_db.update_attachment(att["id"], port_id=port_id)
        await asyncio.to_thread(nova.attach_interface, conn, vm_id, port_id)
    except (ExecutionDenied, ExecutionUnavailable):
        await waygate_db.update_attachment(att["id"], status="ERROR", port_id=port_id)
        raise
    except Exception as e:
        _logger.error(
            "waygate_network: subnet port attach 실패 (server=%s, subnet=%s): %s",
            server_id,
            resolved_subnet_id,
            e,
            exc_info=True,
        )
        if port_id:
            try:
                await asyncio.to_thread(neutron.delete_port, conn, port_id)
            except Exception:
                _logger.error(
                    "waygate_network: attach rollback port 삭제 실패 (port=%s)",
                    port_id,
                    exc_info=True,
                )
                await waygate_db.update_attachment(att["id"], status="ERROR", port_id=port_id)
                raise WaygateNetworkError(500, "네트워크 인터페이스 연결에 실패했습니다") from e
        await waygate_db.delete_attachment(server_id, project_id, att["id"])
        raise WaygateNetworkError(500, "네트워크 인터페이스 연결에 실패했습니다") from e

    await waygate_db.update_attachment(att["id"], status="ACTIVE")
    att.update(
        {"status": "ACTIVE", "port_id": port_id, "cidr": cidr, "subnet_id": resolved_subnet_id, "allowed_ips": routes}
    )
    _logger.info(
        "waygate_network: server=%s network=%s subnet=%s attached (port=%s, cidr=%s)",
        server_id,
        network_id,
        resolved_subnet_id,
        port_id,
        cidr,
    )
    return att


async def update_attachment_routes(project_id: str, server: dict, attachment_id: int, allowed_ips: list[str]) -> dict:
    """Replace one ACTIVE attachment's client routes; no OpenStack call, NAT/interface unchanged."""
    routes = validate_attachment_routes(allowed_ips, server["tunnel_cidr"])
    try:
        att = await waygate_db.update_attachment_routes(server["id"], project_id, attachment_id, routes)
    except WaygateServerInactiveError as exc:
        raise WaygateNetworkError(409, "Waygate 서버와 네트워크 연결이 모두 ACTIVE 상태여야 합니다") from exc
    if att is None:
        raise WaygateNetworkError(404, "네트워크 연결을 찾을 수 없습니다")
    _logger.info(
        "waygate_network: server=%s attachment=%s routes updated (count=%d)", server["id"], attachment_id, len(routes)
    )
    return att


async def detach_network(project_id: str, server: dict, attachment_id: int, *, conn) -> None:
    """네트워크 연결을 해제한다(포트 삭제 + 레코드 삭제)."""
    server_id = server["id"]
    att = await waygate_db.get_attachment(server_id, project_id, attachment_id)
    if not att:
        raise WaygateNetworkError(404, "네트워크 연결을 찾을 수 없습니다")
    if att.get("status") == "CREATING":
        raise WaygateNetworkError(409, "네트워크 연결 생성이 아직 진행 중입니다")

    vm_id = server.get("server_vm_id")
    port_id = att.get("port_id")
    if vm_id and port_id:
        try:
            await asyncio.to_thread(nova.detach_interface, conn, vm_id, port_id)
        except (ExecutionDenied, ExecutionUnavailable):
            raise
        except Exception:
            _logger.warning(
                "waygate_network: detach_interface 실패 (port=%s); explicit port cleanup 계속",
                port_id,
                exc_info=True,
            )
    if port_id:
        try:
            await asyncio.to_thread(neutron.delete_port, conn, port_id)
        except (ExecutionDenied, ExecutionUnavailable):
            await waygate_db.update_attachment(attachment_id, status="ERROR", port_id=port_id)
            raise
        except Exception as e:
            _logger.error("waygate_network: port 삭제 실패 (port=%s)", port_id, exc_info=True)
            await waygate_db.update_attachment(attachment_id, status="ERROR", port_id=port_id)
            raise WaygateNetworkError(500, "네트워크 인터페이스 해제에 실패했습니다") from e
    await waygate_db.delete_attachment(server_id, project_id, attachment_id)
    _logger.info("waygate_network: server=%s attachment=%s detached", server_id, attachment_id)
