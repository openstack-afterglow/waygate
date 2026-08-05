"""WireGuard 터널 서브넷 IPAM — tunnel_cidr 내 다음 가용 host IP 할당.

WG 터널 서브넷(예 10.8.0.0/24)은 WireGuard 내부 IPAM일 뿐 Neutron 네트워크가
아니다. 서버 자신은 첫 host(.1), 클라이언트는 그다음 host부터 순차 할당한다.
"""

import ipaddress


def server_tunnel_ip(tunnel_cidr: str) -> str:
    """터널 서브넷의 첫 host를 서버 자신의 터널 IP로 반환한다 (예: 10.8.0.0/24 → 10.8.0.1)."""
    net = ipaddress.ip_network(tunnel_cidr, strict=False)
    return str(next(net.hosts()))


def allocate_next_ip(tunnel_cidr: str, used_ips: list[str]) -> str:
    """tunnel_cidr 내에서 서버 IP(.1)와 used_ips를 제외한 첫 빈 host를 반환한다.

    Args:
        tunnel_cidr: 예 "10.8.0.0/24"
        used_ips: 이미 할당된 IP 목록 (서버 자신의 IP 포함 여부 무관 — 자동 제외됨)

    Raises:
        RuntimeError: 서브넷에 가용 IP가 없는 경우
    """
    net = ipaddress.ip_network(tunnel_cidr, strict=False)
    reserved = {server_tunnel_ip(tunnel_cidr)}
    used_set = reserved | set(used_ips)

    for host in net.hosts():
        addr = str(host)
        if addr not in used_set:
            return addr

    raise RuntimeError(f"tunnel_cidr {tunnel_cidr} 에 가용 IP가 없습니다 (모두 할당됨)")
