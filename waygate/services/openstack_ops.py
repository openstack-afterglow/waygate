"""OpenStack operations owned by Waygate."""

from __future__ import annotations

import asyncio
import logging
import time

_logger = logging.getLogger(__name__)
AFTERGLOW_MANAGED_TAG = "[afterglow-managed]"


def attach_interface(conn, server_id: str, net_id: str) -> dict:
    interface = conn.compute.create_server_interface(server_id, net_id=net_id)
    return {
        "port_id": interface.port_id,
        "net_id": interface.net_id,
        "fixed_ips": interface.fixed_ips or [],
    }


def detach_interface(conn, server_id: str, port_id: str) -> None:
    conn.compute.delete_server_interface(port_id, server=server_id)


def delete_server(conn, server_id: str) -> None:
    try:
        conn.compute.delete_server(server_id, force=True)
    except Exception as exc:
        message = str(exc).lower()
        if "404" in message or "not found" in message or "409" in message or "conflict" in message:
            return
        raise


def wait_server_deleted(conn, server_id: str, timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if conn.compute.find_server(server_id, ignore_missing=True) is None:
            return
        time.sleep(3)
    raise TimeoutError(f"서버 {server_id} 삭제 대기 타임아웃 ({timeout}s)")


def create_port(conn, network_id: str, name: str, security_group_ids: list[str] | None = None) -> dict:
    kwargs: dict = {"network_id": network_id, "name": name}
    if security_group_ids:
        kwargs["security_groups"] = list(security_group_ids)
    port = conn.network.create_port(**kwargs)
    fixed_ip = port.fixed_ips[0].get("ip_address", "") if port.fixed_ips else ""
    return {"id": port.id, "fixed_ip": fixed_ip}


def delete_port(conn, port_id: str) -> None:
    conn.network.delete_port(port_id, ignore_missing=True)


def cleanup_instance_fips(conn, instance_id: str) -> None:
    try:
        ports = list(conn.network.ports(device_id=instance_id))
    except Exception:
        _logger.warning("Failed to list instance ports instance=%s", instance_id, exc_info=True)
        return
    port_ids = {port.id for port in ports}
    if not port_ids:
        return
    try:
        fips = [floating_ip for floating_ip in conn.network.ips() if floating_ip.port_id in port_ids]
    except Exception:
        _logger.warning("Failed to list instance floating IPs instance=%s", instance_id, exc_info=True)
        return
    for floating_ip in fips:
        try:
            conn.network.update_ip(floating_ip.id, port_id=None)
            conn.network.delete_ip(floating_ip.id, ignore_missing=True)
        except Exception:
            _logger.warning("Failed to clean floating IP %s", floating_ip.id, exc_info=True)


def _security_group_to_dict(group) -> dict:
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description or "",
        "rules": [
            {
                "id": rule["id"],
                "direction": rule["direction"],
                "protocol": rule.get("protocol"),
                "port_range_min": rule.get("port_range_min"),
                "port_range_max": rule.get("port_range_max"),
                "remote_ip_prefix": rule.get("remote_ip_prefix"),
                "ethertype": rule.get("ethertype"),
            }
            for rule in (group.security_group_rules or [])
        ],
    }


def list_security_groups(conn, project_id: str | None = None) -> list[dict]:
    kwargs = {"project_id": project_id} if project_id else {}
    return [_security_group_to_dict(group) for group in conn.network.security_groups(**kwargs)]


def create_security_group(conn, name: str, description: str = "") -> dict:
    return _security_group_to_dict(conn.network.create_security_group(name=name, description=description))


def create_security_group_rule(
    conn,
    sg_id: str,
    direction: str,
    protocol: str | None = None,
    port_range_min: int | None = None,
    port_range_max: int | None = None,
    remote_ip_prefix: str | None = None,
    ethertype: str = "IPv4",
    remote_group_id: str | None = None,
) -> dict:
    kwargs: dict = {"security_group_id": sg_id, "direction": direction, "ether_type": ethertype}
    if protocol:
        kwargs["protocol"] = protocol
    if port_range_min is not None:
        kwargs["port_range_min"] = port_range_min
    if port_range_max is not None:
        kwargs["port_range_max"] = port_range_max
    if remote_ip_prefix:
        kwargs["remote_ip_prefix"] = remote_ip_prefix
    if remote_group_id:
        kwargs["remote_group_id"] = remote_group_id
    rule = conn.network.create_security_group_rule(**kwargs)
    return {
        "id": rule.id,
        "direction": rule.direction,
        "protocol": rule.protocol,
        "port_range_min": rule.port_range_min,
        "port_range_max": rule.port_range_max,
        "remote_ip_prefix": rule.remote_ip_prefix,
        "ethertype": rule.ether_type,
    }


async def _wait_for_active(conn, server_id: str, timeout_seconds: int = 600) -> None:
    for _ in range(timeout_seconds // 10):
        await asyncio.sleep(10)
        server = await asyncio.to_thread(conn.compute.get_server, server_id)
        if server.status == "ACTIVE":
            return
        if server.status == "ERROR":
            raise RuntimeError(f"Waygate VM {server_id}가 ERROR 상태로 전환됨")
    raise TimeoutError(f"Waygate VM {server_id}가 {timeout_seconds}초 내 ACTIVE 상태가 되지 않음")


def _extract_fixed_ip(server) -> str | None:
    for addresses in (server.addresses or {}).values():
        for address in addresses:
            if address.get("OS-EXT-IPS:type") == "fixed":
                return address["addr"]
    return None


async def _allocate_new_fip(conn, server_id: str, floating_network_id: str) -> tuple[str, str]:
    ports = await asyncio.to_thread(lambda: list(conn.network.ports(device_id=server_id)))
    if not ports:
        raise RuntimeError(f"서버 {server_id}에 네트워크 포트가 없습니다")
    floating_ip = await asyncio.to_thread(
        conn.network.create_ip,
        floating_network_id=floating_network_id,
        port_id=ports[0].id,
    )
    return floating_ip.floating_ip_address, floating_ip.id
