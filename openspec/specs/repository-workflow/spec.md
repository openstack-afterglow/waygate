# Waygate repository workflow specification

## Purpose

Waygate의 architecture 유지보수, 검증 진술, 보안·운영·발행 경계를 정의한다. [root instructions](../../../AGENTS.md), [ARCHITECTURE.md](../../../ARCHITECTURE.md), [release notes](../../../RELEASE_NOTES.md), [CI 규격](../ci-workflow/spec.md)을 함께 읽는다. 명령과 source 경로는 저장소 루트 기준이다. 이 문서 이동은 source 구현, CI 설정, 운영 배포 또는 release 승인이 아니다.

## Requirements

### Requirement: Architecture review follows the actual change

작업자는 root architecture와 변경 영역의 source, 테스트, migration/config/CI 상세 문서를 먼저 읽어야 한다(SHALL). code/config/schema/dependency/deployment/test를 바꾸면 영향받는 architecture 본문, code map, 상세 문서와 검증 명령을 같은 변경에서 갱신해야 한다(SHALL). 구조 영향이 없는 bugfix/refactor도 실제 source를 읽고 그 이유를 architecture review summary에 기록한다. 계획·roadmap보다 현재 source와 테스트 정의가 우선한다.

#### Scenario: Runtime boundary is changed
- **WHEN** API, worker, agent, SDK, schema 또는 배포 경계를 바꾼다
- **THEN** [Change guide](../../../ARCHITECTURE.md#change-guide)의 해당 source와 계약을 검토하고 동일 변경의 문서를 갱신한다.

### Requirement: Review stamp is evidence, not a bypass

모든 의도한 source/document 변경 후 실제 source를 다시 검토한 뒤 canonical guard로 stamp하고 check해야 한다(SHALL). 자동 stage/commit하지 않는다. marker digest·UTC timestamp·summary를 손으로 조작하거나 검토하지 않은 사용자 변경까지 검증했다고 기록해서는 안 된다(SHALL NOT).

```sh
python3 scripts/check_architecture.py --stamp --summary "검토한 변경 경로와 구조 영향 또는 영향 없음의 이유"
python3 scripts/check_architecture.py
python3 scripts/check_architecture.py --staged
```

`--staged` 제출은 의도한 source를 index에서 검토한 뒤 `python3 scripts/check_architecture.py --stamp --staged --summary "..."`를 사용하고 `ARCHITECTURE.md`를 stage한 뒤 다시 검사한다. 완료/commit/PR의 gate 실패를 성공으로 보고하지 않는다. 이 절은 staging·commit·publication에 대한 사전 승인이 아니다.

#### Scenario: Documentation migration beside dirty source
- **WHEN** root 지침 이동 중 검토 범위 밖 사용자 source 변경이 있고 guard가 stale을 보고한다
- **THEN** 그 source와 기존 marker를 보존하고 stale 상태·범위를 명시하며 임의 stamp로 완료된 source review를 가장하지 않는다.

### Requirement: Verification claims match observed boundaries

`implemented`와 `test-defined`를 실행하지 않은 `test-passed` 또는 live 증거로 승격해서는 안 된다(SHALL NOT). 실행 명령·환경·revision·실패/skip·한계를 함께 기록해야 한다(SHALL). 로컬 DB/Redis/HTTP, isolated WireGuard, QEMU, 실제 Nova/Glance boot, 배포 lifecycle은 서로 다른 evidence다. `/v1/health`는 process 응답이지 외부 서비스 readiness가 아니다.

검증 진입점:

- Service: `uv run pytest tests` 및 `uv run ruff check .`.
- CI 형태: `uv run pytest tests -n 4 --dist worksteal`; 직렬 명령과 수집 수가 같아야 한다.
- CI 계약: `uv run pytest tests/test_ci_workflow_contract.py -q`; workflow 변경은 `actionlint`도 실행하고 결과를 PR 또는 커밋 본문에 남긴다.
- Focused: `uv run pytest tests/test_waygate_jobs.py tests/test_waygate_provisioner.py tests/test_waygate_agent.py tests/test_waygate_clients.py tests/test_waygate_network.py -q`.
- SDK: `cd sdk && uv run pytest && uv run ruff check .`.
- Schema: `uv run waygate-migrate --database-url "$WAYGATE_DATABASE_URL" --apply`; 실제 MariaDB와 migration 권한이 전제다.
- Live lifecycle은 [명시적 opt-in과 전제조건](../../../ARCHITECTURE.md#waygate-service)을 따르는 별도 승인된 실행이다. 성공한 token rotation은 202뿐 아니라 새 issued timestamp, pending 해제, 이후 status report를 관찰해야 한다.

#### Scenario: Prior successful deployment is cited
- **WHEN** 과거 DMSLAB 또는 isolated 검증 결과를 현재 candidate 설명에 인용한다
- **THEN** 해당 revision·환경·날짜를 유지하고 현재 candidate의 배포/검증 증거로 재해석하지 않는다.

### Requirement: Ownership, durable credentials and secret handling remain enforced

서비스는 Keystone project 소유권을 지키고 전역 resource policy는 system-scope admin만 변경하도록 유지해야 한다(SHALL). API → services → DB/ORM 또는 OpenStack, worker → services 방향을 유지하고 SDK나 형제 저장소의 private 모듈을 서버 runtime에 import하지 않는다. MariaDB는 durable server/client/job/policy/암호화 credential 정본이며 Redis는 관측 status cache다.

Agent 인증은 server-bound bearer와 DB 정본을 timing-safe 검증하고 DB 불가·불일치에 fail-closed해야 한다(SHALL). 발급·staging·조건부 pending 승격·폐기는 성공한 durable commit을 전제로 한다. Redis credential cache를 부활시키거나 cutover로 복사하지 않는다. 혼합 old/new API rollout 중 rotation을 활성화하지 않고, 모든 old API 교체 후 obsolete plaintext token cache를 제거한다. Agent는 mode-0600 파일을 fsync/atomic replace/directory fsync한 뒤 bearer를 바꾼다. 기존 pending rotation을 반복 요청으로 덮어쓰지 않는다.

실제 credential/token/password/private key/encryption key를 문서·로그·예제·review summary에 기록해서는 안 된다(SHALL NOT). 서버 WireGuard private key는 VM을 떠나지 않는다. client private key와 PSK는 DB에 암호화하고 목록에 평문을 넣지 않는다. 인증·소유권 검사를 거친 `.conf` 응답의 의도적 평문을 BFF/로그로 누출하지 않는다. 손상된 PSK는 다운로드 실패·desired-state peer 제외로 처리하며 PSK 없는 연결로 낮추지 않는다. 기존 무PSK client를 자동 회전하지 않는다. Export는 passphrase로 다시 감싸고 `Cache-Control: no-store`를 유지한다.

#### Scenario: Cached credentials survive a revocation
- **WHEN** 폐기된 bearer가 Redis에 남거나 DB가 응답하지 않는다
- **THEN** cache로 인증을 허용하지 않고 durable DB 권한을 기준으로 실패 처리한다.

#### Scenario: Dependent data races with deletion
- **WHEN** client/attachment 생성·수정 또는 서버 기본값 변경이 삭제와 경합한다
- **THEN** 동일 parent-row admission lock과 ACTIVE 검사를 유지하고 cloud cleanup 및 client 비활성화·키 삭제·attachment 정리 후에만 durable DELETED tombstone으로 job 완료를 판정한다.

### Requirement: Migrations and operator trust are explicit

적용된 migration identity/checksum을 바꾸지 않고 additive migration과 manifest를 함께 유지해야 한다(SHALL). Published 0.2.0은 001–003을 포함한다. Candidate 0.3.0 프로세스 전에 001–004 schema를 준비하고 004의 false 상속 flags로 기존 client override와 key를 보존한다. Existing isolated/production DB의 004 ledger가 다르면 SQL을 덮어쓰거나 ledger를 재작성하지 말고 additive 후속 migration을 준비한다. Kolla migration은 `deploy --tags waygate` bootstrap에서 실행되며 `reconfigure`는 대체 경로가 아니다. DB와 이전 image/config를 먼저 백업한다.

Callback은 gateway VM에서 도달 가능한 명시적 public HTTP(S) endpoint여야 하며 missing/loopback을 내부 주소로 대체하지 않는다. 서비스 계정은 각 요청 project에서 provisioning 권한을 가져야 한다. zero-root-disk flavor는 cloud의 Nova admin 정책을 확인한다. Trusted proxy는 실제 proxy IP/CIDR만 허용하며 `*` 또는 tenant network 전체를 신뢰하지 않는다. HAProxy는 입력 `X-Forwarded-Proto`를 버리고 TLS 연결에서 설정한다. Native build TLS 검증은 유지하고 private CA는 `OS_CACERT`로 제공한다.

#### Scenario: Operator reconfigures an old schema
- **WHEN** 0.3.0 rollout에서 reconfigure만 실행하려 한다
- **THEN** 이를 migration 완료로 간주하지 않고 backup과 deploy/bootstrap으로 004 적용을 확인한 뒤 새 프로세스를 시작한다.

### Requirement: Image, release and production authorization are separate

[Release notes](../../../RELEASE_NOTES.md#maintainer-gates-and-manual-publication)의 검증·수동 발행 순서를 따라야 한다(SHALL). 지침 변경만으로 stage/commit/tag/push/GitHub Release·wheel upload/Glance upload/배포를 실행해서는 안 된다(SHALL NOT). 이미 발행된 tag·artifact를 이동하거나 덮어쓰지 않는다. 검증된 정확한 release commit에 annotated tag를 만들고 tag-triggered 전체 test gate가 성공한 API/worker tag와 digest를 확인한다. CI는 GitHub Release나 wheel을 만들지 않는다. 동일 tagged source에서 wheel/Kolla shared-data를 검증한 maintainer가 수동 asset 업로드하며 PyPI 발행으로 취급하지 않는다. SDK는 별도 version/release다.

운영 rollout은 별도 명시적 승인을 받고 published image digest·source commit·wheel checksum·이전 config/DB backup을 보존해야 한다(SHALL). source-build role의 기존 immutable pin이 release source와 같다고 가정하지 않는다. Afterglow operator role은 release-tag 승격 후 설치한다. 배포 후 opt-in lifecycle과 client inheritance/override, cadence, PSK, data-plane 검증을 별도로 관찰한다.

Prebuilt 이미지는 public/community visibility와 `waygate_agent=prebuilt`, version/source hash가 필요하다. shared installer로 build하고 snapshot에는 bearer/private key/per-server config/상속 SSH authorized keys를 남기지 않는다. 기존 timer-based 이미지/VM을 0.3.0 single-run agent로 자동 승격하지 않는다. 새 gateway는 새로 build·boot 검증한 이미지를 사용한다. 기존 VM agent migration은 별도 승인을 받으며 timer 옆에 incompatible service를 켜거나 old image를 덮어쓰지 않는다. Gateway build는 Ubuntu 24.04 amd64만 지원하고 provisioner가 다른 architecture를 거부한다. CI image publish는 hosted default linux/amd64이며 별도 arm64 publication 검증 없이 arm64 tag 지원을 주장하지 않는다. Native Nova/Glance build는 billable operator action이며 QCOW2 upload 대상이 아니다. interrupted build는 잔여 VM/keypair/FIP를 확인한다.

#### Scenario: Candidate metadata exists without published artifacts
- **WHEN** source version과 Kolla registry default가 candidate 0.3.0이다
- **THEN** 이를 publication이나 production deployment 증거로 쓰지 않고 owner main integration·tag/image gate·수동 wheel asset·승인된 운영 rollout을 각각 확인한다. main-target PR 생성/수정과 merge는 pie_root에게만 예약하며 session은 local proposed PR body만 준비한다.

## Preserved evidence and known limits

2026-09-28 문서 이동 시 architecture/release notes는 0.2.0을 **candidate for release, not deployed to production**으로 기록한다. SDK는 0.1.2이며 0.2.0 release에 포함되지 않는다. `fda693a`와 `682161a`의 DMSLAB 증거, earlier prebuilt cutover, current candidate의 로컬/isolated 증거는 원문에 날짜·revision별로 보존되어 있다. 이번 이동은 그 증거를 재실행하거나 승격하지 않았다.

미해결 경계도 보존한다: `X-Project-Id` 생략 시 token scope 대신 default project로 동작하는 관측, system-admin lookup의 `waygate.os_interface` 미반영 및 public Keystone timeout, 수동 network reconnect가 필요한 import, token overlap expiry/자동 rollback 부재. 새 문서는 이를 해결했다고 주장하지 않는다.

CI의 2026-09 기준선과 settings 관측, guard 한계, owner 작업은 [CI 규격](../ci-workflow/spec.md)에 있다. root 지침을 줄이고 의무를 durable spec으로 옮긴 것 외에는 runtime 구조를 변경하지 않는다.
