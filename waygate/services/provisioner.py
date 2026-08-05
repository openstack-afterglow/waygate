"""WireGuard VPN 서버 프로비저닝 오케스트레이션.

builder_vm.py 의 VM 부팅 스캐폴드(_wait_for_active/_extract_fixed_ip/_allocate_new_fip)와
neutron.py 의 포트/SG/FIP CRUD, provision_default_network 의 롤백 패턴을 미러링한다.
"""

from __future__ import annotations

import asyncio
import logging

from waygate.config import get_settings
from waygate.services import neutron, nova, waygate_agent_auth, waygate_config, waygate_db
from waygate.services.openstack_ops import _allocate_new_fip, _extract_fixed_ip, _wait_for_active

_logger = logging.getLogger(__name__)

_WG_INGRESS_SG_NAME = "afterglow-waygate-wireguard"


# ---------------------------------------------------------------------------
# WireGuard ingress SG (idempotent) — neutron._ensure_single_port_ingress_sg 미러
# ---------------------------------------------------------------------------


def _ensure_wireguard_sg(conn, project_id: str, listen_port: int) -> str:
    """WireGuard UDP ingress SG를 idempotent 하게 확보하고 SG ID를 반환한다.

    ingress: UDP/listen_port from 0.0.0.0/0. egress: all (기본 SG 규칙 유지, 별도 rule 불필요).
    """
    sg_name = _WG_INGRESS_SG_NAME
    sgs = neutron.list_security_groups(conn, project_id=project_id)
    existing = next((sg for sg in sgs if sg["name"] == sg_name), None)

    if existing is None:
        sg = neutron.create_security_group(
            conn,
            sg_name,
            f"Waygate WireGuard gateway UDP ingress {neutron.AFTERGLOW_MANAGED_TAG}",
        )
        sg_id = sg["id"]
        existing_rules: list[dict] = []
    else:
        sg_id = existing["id"]
        existing_rules = existing.get("rules", [])

    existing_keys = {
        (r.get("protocol"), r.get("port_range_min"), r.get("port_range_max"), r.get("remote_ip_prefix"))
        for r in existing_rules
        if r.get("direction") == "ingress"
    }
    if ("udp", listen_port, listen_port, "0.0.0.0/0") not in existing_keys:
        neutron.create_security_group_rule(
            conn,
            sg_id,
            direction="ingress",
            protocol="udp",
            port_range_min=listen_port,
            port_range_max=listen_port,
            remote_ip_prefix="0.0.0.0/0",
        )

    return sg_id


# ---------------------------------------------------------------------------
# 프로비저닝
# ---------------------------------------------------------------------------


async def provision_waygate_server(
    project_id: str,
    server_id: str,
    user_id: str,
    username: str,
) -> None:
    """VPN 서버 프로비저닝 백그라운드 태스크.

    DB에 CREATING 레코드가 이미 존재한다고 가정(호출부에서 먼저 insert).
    실패 시 이미 생성한 리소스를 역순 정리하고 DB status=ERROR 기록.
    """
    from waygate.services import keystone

    settings = get_settings()

    created_sg_id: str | None = None
    created_port_id: str | None = None
    created_server_vm_id: str | None = None
    created_fip_id: str | None = None

    try:
        conn = await asyncio.to_thread(keystone.get_admin_connection_for_project, project_id)
    except Exception as e:
        _logger.error("waygate_provisioner: OpenStack 연결 실패 (project=%s): %s", project_id, e)
        await waygate_db.update_server_status(server_id, "ERROR", f"OpenStack 연결 실패: {e}")
        return

    try:
        server_record = await waygate_db.get_server_by_id(server_id)
        if not server_record:
            _logger.error("waygate_provisioner: server %s not found in DB", server_id)
            return

        name = server_record["name"]
        listen_port = server_record["listen_port"]
        snapshot = server_record.get("resource_policy_snapshot") or {}
        provider_network_id = server_record.get("provider_network_id") or (
            snapshot.get("waygate.provider_network") or {}
        ).get("id")
        flavor_id = server_record.get("flavor_id") or (snapshot.get("waygate.flavor") or {}).get("id")
        image_id = server_record.get("image_id") or (snapshot.get("waygate.image") or {}).get("id")
        floating_network_id = server_record.get("floating_network_id") or (
            snapshot.get("waygate.floating_network") or {}
        ).get("id")
        if not all((provider_network_id, flavor_id, image_id)):
            raise RuntimeError("Waygate resource policy snapshot is incomplete")

        # 1. WireGuard ingress SG (idempotent)
        sg_id = await asyncio.to_thread(_ensure_wireguard_sg, conn, project_id, listen_port)
        created_sg_id = sg_id

        # 2. provider 네트워크 포트 생성
        port = await asyncio.to_thread(neutron.create_port, conn, provider_network_id, f"{name}-port", [sg_id])
        created_port_id = port["id"]

        # 3. reconcile 베어러 토큰 발급
        bootstrap_token = await waygate_agent_auth.issue_report_token(server_id, project_id)

        callback_base = settings.waygate_callback_base_url.rstrip("/")
        register_url = f"{callback_base}/v1/servers/{server_id}/agent/register"
        desired_state_url = f"{callback_base}/v1/servers/{server_id}/agent/desired-state"
        status_url = f"{callback_base}/v1/servers/{server_id}/agent/status"

        userdata = waygate_config.render_agent_userdata(
            server_name=name,
            listen_port=listen_port,
            register_url=register_url,
            desired_state_url=desired_state_url,
            status_url=status_url,
            bootstrap_token=bootstrap_token,
        )

        create_kwargs: dict = {
            "name": name,
            "image_id": image_id,
            "flavor_id": flavor_id,
            "networks": [{"port": port["id"]}],
            "user_data": userdata,
            "metadata": {"afterglow_managed": "true", "waygate_type": "gateway", "waygate_server_id": server_id},
        }
        server = await asyncio.to_thread(conn.compute.create_server, **create_kwargs)
        created_server_vm_id = server.id
        await waygate_db.update_server_status(
            server_id,
            "CREATING",
            "VM 생성 중",
            server_vm_id=server.id,
            provider_network_id=provider_network_id,
            provider_port_id=port["id"],
            security_group_id=sg_id,
            flavor_id=flavor_id,
        )

        # 5. ACTIVE 대기
        await _wait_for_active(conn, server.id)
        server = await asyncio.to_thread(conn.compute.get_server, server.id)
        fixed_ip = _extract_fixed_ip(server)
        if not fixed_ip:
            raise RuntimeError(f"Waygate VM {server.id}: fixed IP를 찾을 수 없습니다")

        if floating_network_id:
            fip_addr, fip_id = await _allocate_new_fip(conn, server.id, floating_network_id)
            created_fip_id = fip_id
            endpoint_ip = fip_addr
        else:
            endpoint_ip = fixed_ip
            fip_id = None

        # only_if_status="CREATING" — 에이전트 register가 이 쓰기보다 먼저 도착해 이미
        # ACTIVE로 전이된 경우(경합) status를 덮어쓰지 않는다. endpoint_ip 등 필드는 항상 반영.
        await waygate_db.update_server_status(
            server_id,
            "PROVISIONING",
            "에이전트 register 대기 중",
            only_if_status="CREATING",
            endpoint_ip=endpoint_ip,
            fip_id=fip_id,
            key_name=None,
        )
        _logger.info(
            "waygate_provisioner: server %s VM active (vm_id=%s, endpoint=%s), waiting for agent register",
            server_id,
            server.id,
            endpoint_ip,
        )

    except Exception as e:
        _logger.error("waygate_provisioner: 프로비저닝 실패 (server=%s): %s", server_id, e, exc_info=True)
        await _rollback(
            conn,
            server_vm_id=created_server_vm_id,
            fip_id=created_fip_id,
            port_id=created_port_id,
            sg_id=created_sg_id,
        )
        await waygate_db.update_server_status(server_id, "ERROR", f"프로비저닝 실패: {e}")
    finally:
        try:
            await asyncio.to_thread(conn.close)
        except Exception:
            pass


async def _rollback(
    conn, *, server_vm_id: str | None, fip_id: str | None, port_id: str | None, sg_id: str | None
) -> None:
    """생성된 리소스를 역순으로 정리한다 (provision_default_network 롤백 패턴 미러). best-effort."""
    if server_vm_id:
        try:
            await asyncio.to_thread(nova.delete_server, conn, server_vm_id)
            await asyncio.to_thread(nova.wait_server_deleted, conn, server_vm_id, 120)
        except Exception:
            _logger.warning("vpn_provisioner rollback: VM 삭제 실패 (%s)", server_vm_id, exc_info=True)
    if fip_id:
        try:
            await asyncio.to_thread(conn.network.delete_ip, fip_id, ignore_missing=True)
        except Exception:
            _logger.warning("vpn_provisioner rollback: FIP 삭제 실패 (%s)", fip_id, exc_info=True)
    if port_id:
        try:
            await asyncio.to_thread(neutron.delete_port, conn, port_id)
        except Exception:
            _logger.warning("vpn_provisioner rollback: 포트 삭제 실패 (%s)", port_id, exc_info=True)
    # SG는 idempotent 공유 리소스이므로 롤백 시 삭제하지 않는다(다른 서버가 재사용 가능).


# ---------------------------------------------------------------------------
# 삭제
# ---------------------------------------------------------------------------


async def delete_waygate_server(project_id: str, server_id: str, user_id: str) -> None:
    """Waygate 서버 삭제 백그라운드 태스크. 소유권 검증은 호출부(API)에서 이미 수행됨."""
    from waygate.services import keystone

    server_record = await waygate_db.get_server(project_id, server_id)
    if not server_record:
        _logger.warning("waygate_provisioner: delete 대상 server %s not found (project=%s)", server_id, project_id)
        return

    try:
        conn = await asyncio.to_thread(keystone.get_admin_connection_for_project, project_id)
    except Exception as e:
        _logger.error("waygate_provisioner: delete 시 OpenStack 연결 실패: %s", e)
        await waygate_db.update_server_status(server_id, "ERROR", f"삭제 중 연결 실패: {e}")
        return

    try:
        vm_id = server_record.get("server_vm_id")
        fip_id = server_record.get("fip_id")
        if vm_id:
            # FIP는 VM 삭제 전에 정리한다 — cleanup_instance_fips는 인스턴스 포트의
            # device_id로 FIP를 찾으므로, VM이 먼저 삭제되면 포트의 device_id가 비어
            # 매칭에 실패해 FIP가 누수된다. VM 삭제 전 선제 정리로 방지.
            await asyncio.to_thread(neutron.cleanup_instance_fips, conn, vm_id)
            await asyncio.to_thread(nova.delete_server, conn, vm_id)
            try:
                await asyncio.to_thread(nova.wait_server_deleted, conn, vm_id, 120)
            except Exception:
                _logger.warning("waygate_provisioner: VM %s 삭제 대기 타임아웃 — 계속 진행", vm_id)

        # 위 cleanup_instance_fips가 놓쳤을 경우(예: FIP가 이미 disassociate된 상태)에
        # 대비해 저장된 fip_id로 직접 한 번 더 삭제를 시도한다 (best-effort).
        if fip_id:
            try:
                await asyncio.to_thread(conn.network.delete_ip, fip_id, ignore_missing=True)
            except Exception:
                _logger.warning("waygate_provisioner: FIP %s 삭제 실패", fip_id, exc_info=True)

        port_id = server_record.get("provider_port_id")
        if port_id:
            await asyncio.to_thread(neutron.delete_port, conn, port_id)

        await waygate_agent_auth.revoke_report_token_by_server(server_id)
        await waygate_db.soft_delete_server(project_id, server_id, user_id, reason="사용자 요청")
        _logger.info("waygate_provisioner: server %s 삭제 완료", server_id)
    except Exception as e:
        _logger.error("waygate_provisioner: 삭제 실패 (server=%s): %s", server_id, e, exc_info=True)
        await waygate_db.update_server_status(server_id, "ERROR", f"삭제 실패: {e}")
    finally:
        try:
            await asyncio.to_thread(conn.close)
        except Exception:
            pass
