"""WireGuard VPN 클라이언트 `.conf` 렌더 + 에이전트 desired-state 렌더 + cloud-init 렌더.

Jinja2 Environment 설정은 app/services/cloudinit.py 를 그대로 미러링한다
(shlex_quote 필터 등록, autoescape=False, base64 출력).
"""

import base64
import re
import shlex
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"

_jinja = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    # 출력은 YAML/Bash/Python 이라 HTML autoescape 는 의미 없음 — 명시적으로 비활성하고,
    # 모든 사용자 입력은 템플릿 측에서 반드시 `| shlex_quote` 를 거치도록 한다.
    autoescape=False,
)
_jinja.filters["shlex_quote"] = shlex.quote

# 서버 이름은 이미 WaygateServerCreateRequest 에서 화이트리스트 검증되지만, cloud-init
# 렌더 직전 심층 방어로 재검증한다 (개행/쉘 메타문자 → YAML 구조 파괴 차단).
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}\Z")
_URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-:\[\]]+(?:/[A-Za-z0-9._~\-%/]*)?\Z")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}\Z")


def _validate_cloudinit_inputs(
    server_name: str,
    register_url: str,
    desired_state_url: str,
    status_url: str,
    bootstrap_token: str,
    listen_port: int,
) -> None:
    """VPN cloud-init 템플릿 보간 값 형식 검증. 불일치 시 ValueError."""
    if not _NAME_RE.match(server_name):
        raise ValueError(f"유효하지 않은 server_name 형식: {server_name!r}")
    for label, url in (
        ("register_url", register_url),
        ("desired_state_url", desired_state_url),
        ("status_url", status_url),
    ):
        if not _URL_RE.match(url):
            raise ValueError(f"유효하지 않은 {label} 형식: {url!r}")
    if not _TOKEN_RE.match(bootstrap_token):
        raise ValueError("유효하지 않은 bootstrap_token 형식")
    if not (1 <= listen_port <= 65535):
        raise ValueError(f"유효하지 않은 listen_port: {listen_port}")


# ---------------------------------------------------------------------------
# 클라이언트 .conf 렌더
# ---------------------------------------------------------------------------


def render_client_conf(
    *,
    private_key: str,
    tunnel_ip: str,
    dns: str | None,
    server_public_key: str,
    endpoint_ip: str,
    listen_port: int,
    allowed_ips: list[str],
    nat_cidrs: list[str] | None = None,
) -> str:
    """클라이언트용 WireGuard `.conf` 파일 텍스트를 렌더한다.

    AllowedIPs = 터널 서브넷(+ 클라이언트 지정 allowed_ips) + 연결된 테넌트 네트워크 CIDR(nat_cidrs).
    nat_cidrs 를 포함해야 클라이언트가 그 네트워크로 향하는 트래픽을 터널로 라우팅한다(Phase 2 split-tunnel).
    순서를 보존하며 중복은 제거한다.
    """
    merged: list[str] = []
    for cidr in [*allowed_ips, *(nat_cidrs or [])]:
        if cidr and cidr not in merged:
            merged.append(cidr)

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {tunnel_ip}/32",
    ]
    if dns:
        lines.append(f"DNS = {dns}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_public_key}")
    lines.append(f"Endpoint = {endpoint_ip}:{listen_port}")
    lines.append(f"AllowedIPs = {', '.join(merged)}")
    lines.append("PersistentKeepalive = 25")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 에이전트 desired-state 렌더
# ---------------------------------------------------------------------------


def render_agent_desired_state(
    *,
    listen_port: int,
    tunnel_cidr: str,
    clients: list[dict],
    nat_networks: list[str] | None = None,
) -> dict:
    """에이전트가 폴링하는 desired-state dict를 렌더한다.

    clients: [{public_key, preshared_key, tunnel_ip, enabled}]
    enabled=False 클라이언트는 peers 목록에서 제외한다 (soft-disable = wg에서 제거).
    nat_networks: 연결된 테넌트 네트워크 CIDR 목록 — 에이전트가 각 CIDR 로 SNAT masquerade 를 적용한다.
    """
    peers = []
    for c in clients:
        if not c.get("enabled", True):
            continue
        peers.append(
            {
                "public_key": c["public_key"],
                "preshared_key": c.get("preshared_key"),
                "allowed_ips": [f"{c['tunnel_ip']}/32"],
                "enabled": True,
            }
        )
    return {
        "listen_port": listen_port,
        "tunnel_cidr": tunnel_cidr,
        "peers": peers,
        "nat_networks": list(nat_networks or []),
    }


# ---------------------------------------------------------------------------
# 에이전트 cloud-init userdata 렌더
# ---------------------------------------------------------------------------


def render_agent_userdata(
    *,
    server_name: str,
    listen_port: int,
    register_url: str,
    desired_state_url: str,
    status_url: str,
    bootstrap_token: str,
    reconcile_interval_seconds: int = 15,
) -> str:
    """Waygate 에이전트 cloud-init YAML을 렌더하고 base64 인코딩해 반환한다.

    Nova user_data 는 base64 인코딩된 문자열을 기대한다.
    """
    _validate_cloudinit_inputs(server_name, register_url, desired_state_url, status_url, bootstrap_token, listen_port)

    yaml_str = _jinja.get_template("waygate_agent.yaml.j2").render(
        server_name=server_name,
        listen_port=listen_port,
        register_url=register_url,
        desired_state_url=desired_state_url,
        status_url=status_url,
        bootstrap_token=bootstrap_token,
        reconcile_interval_seconds=reconcile_interval_seconds,
    )
    return base64.b64encode(yaml_str.encode()).decode()
