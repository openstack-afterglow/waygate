"""Waygate 다중 테넌트 네트워크 연결 (Phase 2) — nova.attach_interface + SNAT 기록.

waygate VM 에 추가 테넌트 네트워크를 attach 해, VPN 클라이언트가 터널을 통해 그 네트워크
내부 인스턴스에 접근하도록 한다. 실제 SNAT masquerade 는 VM 내부 에이전트가 desired-state 의
nat_networks(CIDR 목록)를 받아 iptables 로 적용한다(templates/waygate_agent.yaml.j2).

소유권 검증은 호출부(API 라우터)에서 _get_owned_server 로 이미 수행하고, 이 모듈은 서버 dict 를
받아 OpenStack 작업 + DB 기록을 담당한다.
"""

from __future__ import annotations

import asyncio
import logging

from waygate.services import keystone, nova, waygate_db

_logger = logging.getLogger(__name__)


class WaygateNetworkError(Exception):
    """네트워크 연결/해제 실패 — status_code + 안전한 공개 detail 을 담는다(라우터가 HTTP 로 매핑)."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _resolve_cidr(conn, network_id: str, subnet_id: str | None) -> tuple[str, str]:
    """(subnet_id, cidr) 반환. subnet_id 미지정 시 네트워크의 첫 IPv4 서브넷을 사용."""
    if subnet_id:
        subnet = conn.network.get_subnet(subnet_id)
        if subnet is None or subnet.network_id != network_id:
            raise WaygateNetworkError(404, "서브넷을 찾을 수 없거나 네트워크와 일치하지 않습니다")
        return subnet.id, subnet.cidr

    subnets = [s for s in conn.network.subnets(network_id=network_id)]
    # IPv4 우선 (SNAT 대상은 IPv4)
    ipv4 = [s for s in subnets if getattr(s, "ip_version", 4) == 4]
    chosen = ipv4 or subnets
    if not chosen:
        raise WaygateNetworkError(422, "네트워크에 서브넷이 없어 CIDR 을 확인할 수 없습니다")
    return chosen[0].id, chosen[0].cidr


async def attach_network(project_id: str, server: dict, network_id: str, subnet_id: str | None, nat_mode: str) -> dict:
    """서버에 테넌트 네트워크를 연결하고 attachment dict 를 반환한다."""
    server_id = server["id"]
    vm_id = server.get("server_vm_id")
    if server.get("status") != "ACTIVE" or not vm_id:
        raise WaygateNetworkError(409, "Waygate 서버가 ACTIVE 상태가 아닙니다")

    # 중복 연결 방지
    existing = await waygate_db.list_attachments(server_id, project_id)
    if any(a["network_id"] == network_id and a["status"] != "ERROR" for a in existing):
        raise WaygateNetworkError(409, "이미 연결된 네트워크입니다")

    try:
        conn = await asyncio.to_thread(keystone.get_admin_connection_for_project, project_id)
    except Exception as e:
        _logger.error("waygate_network: OpenStack 연결 실패 (project=%s): %s", project_id, e)
        raise WaygateNetworkError(503, "OpenStack 연결에 실패했습니다") from e

    try:
        net = await asyncio.to_thread(conn.network.get_network, network_id)
        # project_id 가 있는 테넌트 네트워크는 소유 프로젝트와 일치해야 한다.
        # 엣지: shared/external 네트워크는 project_id 가 falsy 라 이 검사를 통과할 수 있으나,
        # 그런 네트워크는 이미 이 프로젝트에서 조회·사용 가능한(의도적으로 공유된) 것이므로
        # 자신의 게이트웨이 VM 에 붙이는 것은 교차 테넌트 데이터 접근이 아니다.
        if net is None or (getattr(net, "project_id", None) and net.project_id != project_id):
            # 존재하지 않음/타 프로젝트 소유 모두 동일 404 (정보 노출 방지)
            raise WaygateNetworkError(404, "네트워크를 찾을 수 없습니다")

        resolved_subnet_id, cidr = await asyncio.to_thread(_resolve_cidr, conn, network_id, subnet_id)

        att = await waygate_db.create_attachment_record(
            server_id,
            project_id,
            {
                "network_id": network_id,
                "subnet_id": resolved_subnet_id,
                "cidr": cidr,
                "nat_mode": nat_mode,
                "status": "CREATING",
            },
        )

        try:
            iface = await asyncio.to_thread(nova.attach_interface, conn, vm_id, network_id)
        except Exception as e:
            _logger.error("waygate_network: attach_interface 실패 (server=%s): %s", server_id, e, exc_info=True)
            await waygate_db.update_attachment(att["id"], status="ERROR")
            raise WaygateNetworkError(500, "네트워크 인터페이스 연결에 실패했습니다") from e

        await waygate_db.update_attachment(att["id"], status="ACTIVE", port_id=iface["port_id"])
        att.update({"status": "ACTIVE", "port_id": iface["port_id"], "cidr": cidr, "subnet_id": resolved_subnet_id})
        _logger.info(
            "waygate_network: server=%s network=%s attached (port=%s, cidr=%s)",
            server_id,
            network_id,
            iface["port_id"],
            cidr,
        )
        return att
    finally:
        try:
            await asyncio.to_thread(conn.close)
        except Exception:
            pass


async def detach_network(project_id: str, server: dict, attachment_id: int) -> None:
    """네트워크 연결을 해제한다(포트 삭제 + 레코드 삭제)."""
    server_id = server["id"]
    att = await waygate_db.get_attachment(server_id, project_id, attachment_id)
    if not att:
        raise WaygateNetworkError(404, "네트워크 연결을 찾을 수 없습니다")

    try:
        conn = await asyncio.to_thread(keystone.get_admin_connection_for_project, project_id)
    except Exception as e:
        _logger.error("waygate_network: detach 시 OpenStack 연결 실패: %s", e)
        raise WaygateNetworkError(503, "OpenStack 연결에 실패했습니다") from e

    try:
        vm_id = server.get("server_vm_id")
        port_id = att.get("port_id")
        if vm_id and port_id:
            try:
                await asyncio.to_thread(nova.detach_interface, conn, vm_id, port_id)
            except Exception:
                # best-effort: 포트가 이미 없거나 VM 이 사라진 경우에도 DB 레코드는 정리한다
                _logger.warning(
                    "waygate_network: detach_interface 실패 (port=%s) — 레코드는 정리", port_id, exc_info=True
                )
        await waygate_db.delete_attachment(server_id, project_id, attachment_id)
        _logger.info("waygate_network: server=%s attachment=%s detached", server_id, attachment_id)
    finally:
        try:
            await asyncio.to_thread(conn.close)
        except Exception:
            pass
