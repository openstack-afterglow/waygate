# Waygate

Waygate는 OpenStack project별 WireGuard gateway VM과 client 설정을 관리하는 독립 FastAPI 서비스다. API는 Keystone project ownership을 적용하고, MariaDB durable job/secret records와 Redis 보조 cache를 사용한다.

- [Architecture](ARCHITECTURE.md): 현재 구현, 책임 경계, 데이터 정본, 운영 한계
- [Package manifest](pyproject.toml): `waygate` distribution ships the Kolla role as wheel shared data at `share/kolla-ansible/ansible/roles/waygate`; install the runtime with the `service` extra. The wheel has no Kolla-Ansible dependency.
- [CI](.github/workflows/ci.yml): architecture check, service/SDK test 및 lint workflow
- [Dockerfile](docker/Dockerfile): API와 worker image targets

개발 환경에서는 `uv sync --extra service --extra dev --frozen` 후 `uv run pytest tests`를 실행한다. 변경을 제출하기 전 `python3 scripts/check_architecture.py`와 staged 검사도 실행한다. 실제 OpenStack/MariaDB/Redis 환경이 필요한 검증은 [Architecture의 Development and verification](ARCHITECTURE.md#development-and-verification)을 따른다.
