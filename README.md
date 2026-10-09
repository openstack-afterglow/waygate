# Waygate

Waygate는 OpenStack project별 WireGuard gateway VM과 client 설정을 관리하는 독립 FastAPI 서비스다. API는 Keystone project ownership을 적용하고, MariaDB durable job/secret records와 Redis 보조 cache를 사용한다.

- [Architecture](ARCHITECTURE.md): 현재 구현, 책임 경계, 데이터 정본, 운영 한계
- [Release notes and 0.3.3 authorization repair](RELEASE_NOTES.md): candidate patch `0.3.3` fixes direct-system-admin and enabled/current-member owner validation atop immutable `v0.3.2` (migrations 005–006). Local full service/SDK gates passed; publication and production runtime replacement are separate. Independent SDK `0.2.0`, schemas and authority ceilings are unchanged. Preserve existing tags/artifacts; no automatic owner assignments or new user grants. Before rollout, retain a recovery point, validate the existing migration ledger and drain jobs.
- [Package manifest](pyproject.toml): `waygate` distribution ships the Kolla role as wheel shared data at `share/kolla-ansible/ansible/roles/waygate`; install the runtime with the `service` extra. The wheel has no Kolla-Ansible dependency.
- [CI](.github/workflows/ci.yml): architecture check, service/SDK test 및 lint workflow. `pull_request`에서 직접 실행되고, push/tag에서는 [Docker Build & Push](.github/workflows/docker-build.yml)가 이 workflow를 호출해 테스트 성공 시에만 이미지를 발행한다.
- [Dockerfile](docker/Dockerfile): API와 worker image targets
- [Gateway modes and image build](ARCHITECTURE.md#gateway-installation-modes-and-image-operations): shared agent assets, cloud-init/prebuilt selection, Packer QEMU build/upload or [direct OpenStack build](ARCHITECTURE.md#native-openstack-build-no-local-qemu-or-separate-upload) with `scripts/build_gateway_image.sh --builder openstack`. Apply all pending checksum migrations (currently through 006) before upgrading API/worker; new prebuilt gateways require an image with the single long-lived `run` service. Existing VMs are not changed automatically.
- [Agent token rotation](ARCHITECTURE.md#agent-token-rotation): tenant-triggered persisted handoff, existing-VM upgrade requirement and concurrency/failure limits.

개발 환경에서는 `uv sync --extra service --extra dev --frozen` 후 `uv run pytest tests`를 실행한다. 변경을 제출하기 전 `python3 scripts/check_architecture.py`와 staged 검사도 실행한다. 실제 OpenStack/MariaDB/Redis 환경이 필요한 검증은 [Architecture의 Development and verification](ARCHITECTURE.md#development-and-verification)을 따른다.
