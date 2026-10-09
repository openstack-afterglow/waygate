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

Applied migration identities and checksums SHALL remain immutable; additive migrations and manifest entries SHALL be maintained together. New API/worker processes SHALL start only after the candidate's complete schema is applied. Existing records, encrypted credentials and earlier ledger entries SHALL remain preserved. Kolla migration executes in deploy bootstrap; reconfigure is not evidence of schema application. Operators SHALL preserve previous image/config and DB backup before a separately authorized rollout.

Callback endpoints SHALL be explicit VM-reachable public HTTP(S) URLs, never a loopback or internal fallback. The configured service identity SHALL stay in its own service project and SHALL NOT require tenant membership. Tenant cloud work SHALL use the current user's bounded delegation. Zero-root-disk flavors SHALL use member-compatible volume-backed root boot, with Cinder policy, image minimum size and project quota qualified separately; Nova's admin-only image-backed zero-disk policy SHALL remain unchanged. Trusted proxy settings SHALL be limited to actual proxies and ingress SHALL discard caller-supplied forwarded scheme. Native build TLS verification SHALL remain enabled, with OS_CACERT for private CAs.

#### Scenario: Operator reconfigures an old schema
- **WHEN** a candidate rollout uses reconfigure without applying its additive migrations
- **THEN** this is not treated as migration completion, and new API/worker startup requires backup and deploy/bootstrap schema verification

#### Scenario: Tenant service roles remain from an old deployment
- **WHEN** the isolated execution candidate is locally implemented
- **THEN** no production role is automatically removed; operators separately qualify fresh delegated create/delete/routing and verify old assignments are unused before scoped retirement

### Requirement: Image, release and production authorization are separate

[Release notes](../../../RELEASE_NOTES.md#maintainer-gates-and-manual-publication)의 검증·수동 발행 순서를 따라야 한다(SHALL). 지침 변경만으로 stage/commit/tag/push/GitHub Release·wheel upload/Glance upload/배포를 실행해서는 안 된다(SHALL NOT). 이미 발행된 tag·artifact를 이동하거나 덮어쓰지 않는다. 검증된 정확한 release commit에 annotated tag를 만들고 tag-triggered 전체 test gate가 성공한 API/worker tag와 digest를 확인한다. CI는 GitHub Release나 wheel을 만들지 않는다. 동일 tagged source에서 wheel/Kolla shared-data를 검증한 maintainer가 수동 asset 업로드하며 PyPI 발행으로 취급하지 않는다. SDK는 별도 version/release다.

운영 rollout은 별도 명시적 승인을 받고 published image digest·source commit·wheel checksum·이전 config/DB backup을 보존해야 한다(SHALL). source-build role의 기존 immutable pin이 release source와 같다고 가정하지 않는다. Afterglow operator role은 release-tag 승격 후 설치한다. 배포 후 opt-in lifecycle과 client inheritance/override, cadence, PSK, data-plane 검증을 별도로 관찰한다.

Prebuilt 이미지는 public/community visibility와 `waygate_agent=prebuilt`, version/source hash가 필요하다. shared installer로 build하고 snapshot에는 bearer/private key/per-server config/상속 SSH authorized keys를 남기지 않는다. 기존 timer-based 이미지/VM을 0.3.0에서 도입한 single-run agent로 자동 승격하지 않으며 0.3.1 metadata patch도 agent migration이 아니다. 새 gateway는 새로 build·boot 검증한 이미지를 사용한다. 기존 VM agent migration은 별도 승인을 받으며 timer 옆에 incompatible service를 켜거나 old image를 덮어쓰지 않는다. Gateway build는 Ubuntu 24.04 amd64만 지원하고 provisioner가 다른 architecture를 거부한다. CI image publish는 hosted default linux/amd64이며 별도 arm64 publication 검증 없이 arm64 tag 지원을 주장하지 않는다. October 2 로컬 amd64/arm64 증거는 historical이며 CI의 multiarch 발행 증거가 아니다. Native Nova/Glance build는 billable operator action이며 QCOW2 upload 대상이 아니다. interrupted build는 잔여 VM/keypair/FIP를 확인한다.

#### Scenario: Candidate metadata exists without published artifacts
- **WHEN** source distribution version과 Kolla registry default가 candidate 0.3.2이며 independent SDK는 0.2.0이다
- **THEN** 이를 publication이나 production deployment 증거로 쓰지 않고 정확한 owner-approved release commit·tag/image gate·수동 wheel asset·승인된 운영 rollout을 각각 확인한다. Published `v0.3.1`(`37a57fa`)과 그 tag/image/wheel은 이동하거나 덮어쓰지 않는다. main-target PR 생성/수정과 merge는 pie_root에게만 예약하며 session은 local proposed PR body만 준비한다.

Published `v0.3.2` (`7da6a270`, 2026-10-08) contains service grades/ownership (005) and isolated execution (006). Candidate `0.3.3` adds the later direct-system-admin/owner repair; SDK `0.2.0`, runtime dependencies, source-build pin and historical prebuilt artifacts are retained. [Current repair gates](../../../RELEASE_NOTES.md#parent-repair-gates) separate local service/SDK results, reported prior owner PATCH, new immutable publication and all-controller rollout. Existing tags/artifacts are not overwritten and old successes do not qualify the repair.

Existing [Docker metadata policy](../../../.github/workflows/docker-build.yml) emits semver `0.3.2` on `v0.3.2`, raw `dev` on dev and explicit raw `latest` on main, plus SHA tags. No `flavor` override disables metadata-action v5's default [`latest=auto`](https://github.com/docker/metadata-action/tree/v5#latest-tag), so a stable semver tag also generates `latest`; latest is not main-only. Service/SDK CI still gates publication, PR builds push nothing, and CI images remain linux/amd64 only. No workflow or publication policy is changed by this release preparation.

## Framework remediation handoff

The dependency-only change [remediate-framework-advisories](../../changes/archive/2026-10-02-remediate-framework-advisories/design.md) follows candidate `29f28cdcb572660fc3f693457b007435c0da81ef` (service 0.3.0 / SDK 0.2.0). Root service metadata now selects FastAPI `==0.136.3` and Starlette `>=1.3.1`, with root uv lock `0.136.3` / `1.3.1`. Existing Pydantic 2.13.4, AnyIO 4.14.2 and all unrelated package selections are retained. Published metadata and advisory ranges are recorded in the design. No product requirement, route registration, middleware, auth, rate limit, logging source, Host-domain allowlist, SDK public contract, schema or deployment structure is changed by this dependency slice. Its metadata inspection alone is not runtime/security acceptance, publication or production evidence.

Source inspection covers `waygate/main.py`, `waygate/observability.py` and `waygate/api/agent.py`. `SafeAccessLog` is the only application consumer found of the matched route's `.path`; it records the prefixed template after routing, or `<unmatched>`. Tagged FastAPI 0.136.3 still flattens included routes and places an `APIRoute` with `.path` into the matched scope. Keep existing source rather than add a router-tree adapter. Metadata/source compatibility is not an executed middleware proof. Upstream strict Content-Type parsing can affect JSON callers without a Content-Type header; Main was notified, and no strictness override is added. Report any actual required contract/policy change before widening the design.

### Existing focused selectors (Main only; not executed in this slice)

```sh
uv run pytest tests/test_waygate_feature_flag.py tests/test_observability.py -q
uv run pytest tests/test_waygate_agent.py::TestAgentAuthMissingToken tests/test_waygate_agent.py::TestAgentAuthServerIdMismatch tests/test_waygate_agent.py::TestAgentStatusHappyPath -q
```

These cover discovery/health, trusted forwarded scheme/client identity, tenant-admin denial, matched and unmatched logging, safe over-limit warnings, missing/cross-server auth, invalid status-body validation, the 120/minute per-(IP,server) status budget and the independent 1200/minute shared-IP ceiling. In `sdk/`, `uv run pytest tests/test_proxy.py -q` covers actual `Connection` discovery through an isolated HTTP transport, one negotiated `/v1/` prefix, JSON method paths, null/zero PATCH, conflict propagation and config download. These are existing test definitions, not actual Uvicorn smoke or proof of this update. Main also runs the full service serial/four-worker and SDK suites plus existing lint commands under the established gates above.

### Isolated runtime plan (executed 2026-10-02)

1. Frozen-sync root service/dev and the unchanged SDK lock; observe installed FastAPI 0.136.3 / Starlette 1.3.1. Start the real `waygate-api` / Uvicorn process with disposable MariaDB (packaged schema 001–004), Redis and an isolated HTTP Keystone fixture. Do not use production SQL, cloud credentials or enqueue cloud provisioning jobs.
2. Over real HTTP, exercise `/`, `/v1` -> `/v1/` 307 and `/v1/health`; trusted/untrusted proxy discovery; owner/foreign-project routes; JSON body validation including null/zero PATCH, `application/json` / `application/*+json`, and missing/wrong Content-Type behavior. Exercise existing admin and agent auth boundaries, successful agent status 204, foreign bearer 401 and the two independent finite status budgets. If an upstream parsing change breaks a required client contract, report it before adding settings/shims or changing policy.
3. Use public SDK `register(Connection(...))` against this running API from root and versioned endpoint overrides; observe exactly one `/v1/` prefix, server PATCH null/zero and authenticated `.conf` download with an isolated seeded fixture. SDK response mocks alone do not prove server/framework compatibility.
4. Capture actual Uvicorn stdout/stderr separately at INFO and DEBUG. Exercise health 200, unmatched 404, matched auth denial 401, 405/422 and 429; route templates must retain full prefixes and exclude path/query/body/header/bearer/key sentinels. Observe sanitized `api rate_limit status=429`, DEBUG count-only query metadata, and absence of DEBUG detail at INFO. Check discovery and implicit redirects with malformed Host and malformed request targets where the ASGI server accepts them; rejection at the server is a server-boundary result, not proof of unreachable framework input. Do not add a new Host-domain policy or claim production ingress proof.
5. Build API and worker targets from this frozen lock for linux/amd64 and linux/arm64; observe each running image's machine architecture/framework versions, HTTP behavior and worker DB polling, plus lifespan startup/shutdown. This is isolated evidence, not published multiarch tag support or production rollout.
6. The [completed acceptance checklist](../../changes/archive/2026-10-02-remediate-framework-advisories/tasks.md) records actual outcomes and limits. Both local architectures passed the HTTP/SDK/middleware checks above and worker SQL polling; serial and four-worker suites each passed 471 tests with 1 opt-in live skip, SDK 44 and root/SDK Ruff passed. Canonical working/staged architecture guards passed. The separate [worker signal repair](../../changes/archive/2026-10-02-fix-worker-sigterm/tasks.md) reproduced forced Docker exit137 before the fix and exit0 afterward without changing durable lease/retry. No genuine Keystone/cloud lifecycle, production ingress, publication or default-branch alert closure is claimed.

## Preserved evidence and known limits

2026-09-28 문서 이동 시 architecture/release notes는 0.2.0을 **candidate for release, not deployed to production**으로 기록한다. SDK는 0.1.2이며 0.2.0 release에 포함되지 않는다. `fda693a`와 `682161a`의 DMSLAB 증거, earlier prebuilt cutover, current candidate의 로컬/isolated 증거는 원문에 날짜·revision별로 보존되어 있다. 이번 이동은 그 증거를 재실행하거나 승격하지 않았다.

미해결 경계도 보존한다: `X-Project-Id` 생략 시 token scope 대신 default project로 동작하는 관측, system-admin lookup의 `waygate.os_interface` 미반영 및 public Keystone timeout, 수동 network reconnect가 필요한 import, token overlap expiry/자동 rollback 부재. 새 문서는 이를 해결했다고 주장하지 않는다.

CI의 2026-09 기준선과 settings 관측, guard 한계, owner 작업은 [CI 규격](../ci-workflow/spec.md)에 있다. root 지침을 줄이고 의무를 durable spec으로 옮긴 것 외에는 runtime 구조를 변경하지 않는다.
