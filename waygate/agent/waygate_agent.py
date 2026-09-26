#!/usr/bin/env python3
"""Waygate gateway agent: `register` bootstraps WireGuard; `reconcile` syncs desired state and reports status.

Runtime settings come from /etc/waygate/agent.json. Stdlib-only and Python 3.10 compatible.
"""
import ipaddress
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

CONFIG_PATH = "/etc/waygate/agent.json"
IMAGE_INFO_PATH = "/etc/waygate/image-info.json"
WG_IFACE = "wg0"
WG_CONF = "/etc/wireguard/wg0.conf"
PRIVATE_KEY_PATH = "/etc/wireguard/privatekey"
PUBLIC_KEY_PATH = "/etc/wireguard/publickey"
NAT_CHAIN = "WAYGATE-NAT"
LOG = "/var/log/waygate-agent.log"
_UTC = timezone.utc  # noqa: UP017 - gateway images may run Python 3.10.


def _sync_config_directory(path) -> None:
    directory_fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def load_config(path=None) -> dict:
    path = os.fspath(CONFIG_PATH if path is None else path)
    with open(path) as f:
        cfg = json.load(f)
    # A previous reconcile may have failed after rename but before directory
    # fsync. Do not use that bearer on a later run until the rename is durable.
    _sync_config_directory(path)
    return cfg


def save_config(cfg: dict, path=None) -> None:
    path = os.fspath(CONFIG_PATH if path is None else path)
    temporary = path + ".tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(json.dumps(cfg, indent=2))
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        _sync_config_directory(path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def agent_source() -> str:
    return "prebuilt" if os.path.exists(IMAGE_INFO_PATH) else "cloud-init"


def ensure_keypair() -> tuple[str, str]:
    if not os.path.exists(PRIVATE_KEY_PATH):
        previous_umask = os.umask(0o077)
        try:
            private = subprocess.run(
                ["wg", "genkey"], capture_output=True, text=True, check=True
            ).stdout.strip()
            public = subprocess.run(
                ["wg", "pubkey"], input=private + "\n", capture_output=True, text=True, check=True
            ).stdout.strip()
            with open(PRIVATE_KEY_PATH, "w") as f:
                f.write(private + "\n")
            with open(PUBLIC_KEY_PATH, "w") as f:
                f.write(public + "\n")
            os.chmod(PRIVATE_KEY_PATH, 0o600)
            os.chmod(PUBLIC_KEY_PATH, 0o644)
        finally:
            os.umask(previous_umask)
    with open(PRIVATE_KEY_PATH) as f:
        private = f.read().strip()
    with open(PUBLIC_KEY_PATH) as f:
        public = f.read().strip()
    return private, public


def interface_section(cfg: dict, private_key: str) -> list[str]:
    return [
        "[Interface]",
        f"Address = {cfg['tunnel_address']}",
        f"ListenPort = {cfg['listen_port']}",
        "SaveConfig = false",
        f"PrivateKey = {private_key}",
        "",
    ]


def log(msg: str) -> None:
    line = f"[{datetime.now(_UTC).isoformat()}] {msg}"
    print(line)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def http_request(cfg, url: str, method: str = "GET", body: dict | None = None) -> tuple[int | None, dict | None]:
    headers = {"Authorization": f"Bearer {cfg['bootstrap_token']}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.URLError as e:
        # Never log response bodies or credentials from the request.
        log(f"HTTP {method} failed ({getattr(e, 'code', None)})")
        return getattr(e, "code", None), None


def adopt_next_token(cfg: dict, desired: dict) -> bool:
    next_token = desired.get("next_token")
    if not next_token or next_token == cfg["bootstrap_token"]:
        return False
    new = dict(cfg, bootstrap_token=next_token)
    try:
        save_config(new)
    except OSError:
        log("next token persist failed; keeping current token")
        return False
    cfg.update(new)
    log("agent token rotated")
    return True


def write_wg_conf(cfg: dict, private_key: str, desired: dict) -> None:
    lines = interface_section(cfg, private_key)
    for peer in desired.get("peers", []):
        if not peer.get("enabled", True):
            continue
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer['public_key']}")
        if peer.get("preshared_key"):
            lines.append(f"PresharedKey = {peer['preshared_key']}")
        allowed = ", ".join(peer.get("allowed_ips", []))
        lines.append(f"AllowedIPs = {allowed}")
        lines.append("")

    fd = os.open(WG_CONF, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write("\n".join(lines))


def syncconf() -> None:
    strip = subprocess.run(
        ["wg-quick", "strip", WG_IFACE], capture_output=True, text=True, check=False
    )
    if strip.returncode != 0:
        log(f"wg-quick strip 실패: {strip.stderr.strip()}")
        return
    sync = subprocess.run(
        ["wg", "syncconf", WG_IFACE, "/dev/stdin"],
        input=strip.stdout,
        capture_output=True,
        text=True,
        check=False,
    )
    if sync.returncode != 0:
        log(f"wg syncconf 실패: {sync.stderr.strip()}")


def collect_status() -> list[dict]:
    dump = subprocess.run(
        ["wg", "show", WG_IFACE, "dump"], capture_output=True, text=True, check=False
    )
    if dump.returncode != 0:
        return []
    peers = []
    for i, line in enumerate(dump.stdout.strip().splitlines()):
        if i == 0:
            continue  # 첫 줄은 인터페이스 자체 정보
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pubkey, _psk, _endpoint, _allowed, latest_handshake, rx, tx, _keepalive = parts[:8]
        peers.append(
            {
                "public_key": pubkey,
                "last_handshake_at": (
                    datetime.fromtimestamp(int(latest_handshake), tz=_UTC).isoformat()
                    if latest_handshake and latest_handshake != "0"
                    else None
                ),
                "rx_bytes": int(rx or 0),
                "tx_bytes": int(tx or 0),
            }
        )
    return peers


def _interfaces_without_ipv4() -> list:
    """IPv4 주소가 없는 인터페이스(핫플러그 직후 NIC) 목록. lo/wg0 제외."""
    have_ip = set()
    addr = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, check=False)
    for line in addr.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            have_ip.add(parts[1])
    missing = []
    link = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, check=False)
    for line in link.stdout.splitlines():
        seg = line.split(":")
        if len(seg) >= 2:
            name = seg[1].strip().split("@")[0]
            if name in ("lo", WG_IFACE):
                continue
            if name and name not in have_ip:
                missing.append(name)
    return missing


def bring_up_hotplug_nics() -> None:
    """핫플러그된 NIC 를 up + DHCP 로 구성한다(cloud image 는 부팅 NIC 만 자동 구성).

    nova.attach_interface 는 Neutron 포트만 붙일 뿐 게스트 내부 IP 를 구성하지 않으므로,
    이 단계 없이는 아래 masquerade 가 IP 없는 죽은 NIC 에 바인딩된다.
    """
    for nic in _interfaces_without_ipv4():
        subprocess.run(["ip", "link", "set", nic, "up"], check=False)
        try:
            subprocess.run(["dhclient", "-1", nic], capture_output=True, check=False, timeout=30)
        except subprocess.TimeoutExpired:
            log(f"dhclient {nic} 타임아웃 — 다음 주기 재시도")
        log(f"핫플러그 NIC {nic} DHCP 구성 시도")


def _outbound_nic(cidr: str):
    try:
        host = str(next(ipaddress.ip_network(cidr, strict=False).hosts()))
    except (ValueError, StopIteration):
        host = cidr.split("/")[0]
    route = subprocess.run(["ip", "-o", "route", "get", host], capture_output=True, text=True, check=False)
    parts = route.stdout.split()
    if "dev" in parts:
        return parts[parts.index("dev") + 1]
    return None


def apply_masquerade(tunnel_cidr: str, nat_networks: list) -> None:
    """tunnel_cidr → 각 nat CIDR 트래픽을 해당 NIC 로 SNAT masquerade. idempotent.

    전용 체인 WAYGATE-NAT 를 flush 후 재적용하므로, 연결 해제된 네트워크의 규칙도 자동 반영된다
    (nat_networks 가 비면 체인이 비워져 모든 SNAT 규칙이 제거됨). 모든 인자는 subprocess 리스트
    인자(shell=False)로만 전달되고 CIDR 은 백엔드에서 ip_network 검증된 값이라 주입 위험이 없다.
    """
    subprocess.run(["iptables", "-t", "nat", "-N", NAT_CHAIN], capture_output=True, check=False)
    hooked = subprocess.run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING", "-j", NAT_CHAIN], capture_output=True, check=False
    )
    if hooked.returncode != 0:
        subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", NAT_CHAIN], check=False)
    subprocess.run(["iptables", "-t", "nat", "-F", NAT_CHAIN], check=False)
    for cidr in nat_networks:
        nic = _outbound_nic(cidr)
        if not nic:
            log(f"masquerade: {cidr} 로의 NIC 미발견 — 스킵(다음 주기 재시도)")
            continue
        subprocess.run(
            ["iptables", "-t", "nat", "-A", NAT_CHAIN, "-s", tunnel_cidr, "-o", nic, "-j", "MASQUERADE"],
            check=False,
        )


def cmd_register(cfg: dict) -> int:
    private, public = ensure_keypair()
    write_wg_conf(cfg, private, {"peers": []})
    subprocess.run(["systemctl", "enable", "wg-quick@wg0"], check=True)
    start = subprocess.run(["systemctl", "start", "wg-quick@wg0"], check=False)
    if start.returncode != 0:
        subprocess.run(["systemctl", "restart", "wg-quick@wg0"], check=True)
    status, _ = http_request(
        cfg, cfg["register_url"], "POST",
        {"public_key": public, "listen_port_confirm": cfg["listen_port"]},
    )
    if status in (200, 204):
        log(f"register succeeded (HTTP {status})")
    else:
        log(f"register failed (HTTP {status})")
    return 0


def cmd_reconcile(cfg: dict) -> int:
    _, desired = http_request(cfg, cfg["desired_state_url"])
    if desired is not None:
        adopt_next_token(cfg, desired)
        with open(PRIVATE_KEY_PATH) as f:
            private = f.read().strip()
        write_wg_conf(cfg, private, desired)
        syncconf()
        nat_networks = desired.get("nat_networks", []) or []
        if nat_networks:
            bring_up_hotplug_nics()
        # Flush the chain even when empty, removing detached network rules.
        apply_masquerade(desired.get("tunnel_cidr", cfg["tunnel_cidr"]), nat_networks)
    else:
        log("desired-state 조회 실패 — 이번 주기 스킵")
    http_request(
        cfg, cfg["status_url"], "POST",
        {"peers": collect_status(), "reported_at": datetime.now(_UTC).isoformat(),
         "agent_source": agent_source()},
    )
    return 0


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in ("register", "reconcile"):
        print("Usage: waygate_agent.py register | reconcile", file=sys.stderr)
        return 2
    cfg = load_config()
    return cmd_register(cfg) if args[0] == "register" else cmd_reconcile(cfg)


if __name__ == "__main__":
    sys.exit(main())
