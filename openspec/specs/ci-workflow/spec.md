# Waygate CI workflow specification

## Purpose

Waygate CI의 성능·발행·PR 보안 의무를 보존한다. 이 규격은 기존 root 지침을 이동한 것이며 CI 동작이나 저장소 설정을 바꾸지 않는다. 경로·명령은 저장소 루트 기준이다. [작업 규격](../repository-workflow/spec.md), [architecture](../../../ARCHITECTURE.md), [CI 계약 테스트](../../../tests/test_ci_workflow_contract.py), [CI](../../../.github/workflows/ci.yml), [이미지 workflow](../../../.github/workflows/docker-build.yml)를 함께 읽는다.

## Historical evidence (not fresh verification)

기원은 afterglow 2026-09 실측 40건(크리티컬 패스 중앙값 143초)과 Linear 사례지만, 아래 의무와 비교 모집단은 Waygate 전용이다. 다른 저장소의 정책을 적용하는 근거가 아니다. 다음은 이전 지침의 측정 기록이며 이번 문서 이동으로 재측정하거나 검증을 승격하지 않았다. 기준선 수치는 requirement 12의 재측정 trigger이지 현재 성능 보증이 아니다.

2026-08-05~2026-09-18에 완료된 gating run 전체 29건(CI 12건, Docker Build & Push 17건)을 `gh api .../actions/runs/<id>/jobs`로 측정했다. 모든 지표는 성공 run만 모집단으로 한다. 실패 run은 10~14초에 끝나므로 포함하면 값이 빌드·테스트 성능이 아니라 실패율에 따라 움직인다. 규칙 1의 20회 기준보다 적으므로 표본 수를 함께 적는다. p90은 선형 보간이다.

| 지표 | 정의(모집단) | 표본 | 중앙값 | p90 |
|---|---|---|---|---|
| test critical path (push/tag) | 테스트를 실행한 각 run의 생성부터 그 run의 마지막 test job 종료까지. run의 모든 test job(`Service tests and lint`, `SDK tests and lint`)이 success인 run만 센다(10~13초에 끝난 실패 run 5건 제외). 기준 시점에는 branch push마다 CI와 Docker Build & Push 두 run이 테스트를 실행해 둘 다 표본이다(tag push는 Docker Build & Push run만). 실패 run을 넣으면 n=21, 23.0초 / 27.0초 | n=16 | 24.0초 | 29.0초 |
| test critical path (pull_request) | 위와 같음(실패 run 2건 제외. 넣으면 n=6, 38.0초 / 65.5초) | n=4 | 50.0초 | 68.5초 |
| commit-to-image (push/tag) | Docker Build & Push run 생성부터 `Build & Push Waygate Images` 종료까지. 그 job이 success이고 run에 `test` job이 있는 test-gated run만 센다. 테스트 실패로 build가 skipped된 run 3건(35203776224, 35203780457, 35403219366)과 `test` job 도입 전 run 2건(31033382233, 31066557569)은 제외 | n=9 | 89.0초 | 111.0초 |
| (참고) pooled test critical path | 모든 event와 워크플로우를 합산, 성공 run만 | n=20 | 24.5초 | 43.6초 |
| (참고) pooled commit-to-image | push, tag, pull_request 합산, 위 commit-to-image 필터(PR skipped run 35404041637 추가 제외) | n=11 | 93.0초 | 122.0초 |

job 중앙값(성공 job 기준): `Service tests and lint` 21초(setup 약 8초, pytest 11초), `SDK tests and lint` 9초, `Build & Push Waygate Images` 62초. 이 기준은 push와 PR sync마다 중복되던 test 실행을 dedup하기 전의 값이다. dedup 이후 push/tag test critical path 표본은 Docker Build & Push의 `test` job에서만, pull_request 표본은 CI의 pull_request run에서만 나온다. pull_request 이미지 빌드는 이제 테스트를 기다리지 않으므로 commit-to-image는 push/tag event만으로 비교한다.

## Requirements

### Requirement: Rule 1 — 측정 먼저, 추정 금지.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

CI를 바꾸기 전과 후에 최근 20회 이상 실행(부족하면 존재하는 전체와 n)의 잡·스텝 시간을 `gh run list` / `gh api repos/openstack-afterglow/waygate/actions/runs/<id>/jobs`로 수집한다. 위 정의의 크리티컬 패스 중앙값과 p90을 커밋 본문에 남긴다. 절감 효과는 합산되지 않으므로 가장 긴 잡부터 줄이고, 실제 CI 전후 수치로만 효과를 주장한다. 로컬 측정은 추정치로 표시한다. 전후 비교는 위 기준표와 같은 모집단(같은 event 구분과 같은 success 필터)으로 계산한다.

#### Scenario: CI 성능 변경의 근거
- **WHEN** CI 변경을 제안하거나 결과를 보고한다
- **THEN** 동일 event·success 필터로 전후 중앙값/p90과 표본 n을 기록하고 로컬 수치는 추정으로 표시한다.

### Requirement: Rule 2 — 목표 지표를 먼저 정한다.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

이 저장소는 public이고 GitHub-hosted `ubuntu-latest`만 쓰므로 runner-minutes는 무료이고 wall-clock(대기 시간)이 목표다. 조직 `openstack-afterglow`는 Free plan이어서 형제 저장소(afterglow, drover, lumen, palimpsest 등)가 동시 실행 잡 한도를 공유한다. 중복 잡은 조직 전체 burst 때 queue 대기(p90)를 늘리므로 잡 수도 함께 본다. 저장소가 private로 바뀌거나 유료·self-hosted runner를 쓰면 runner-minutes(비용)도 함께 본다.

#### Scenario: 목표와 공유 비용
- **WHEN** runner 또는 저장소 비용 조건이 바뀐다
- **THEN** wall-clock과 공유 잡 수를 검토하고 private·유료·self-hosted 조건에서는 runner-minutes도 평가한다.

### Requirement: Rule 3 — 게이트 잡을 다른 잡 앞에 두지 않는다.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

architecture check 같은 fail-fast 검사는 `service` job의 첫 step으로 두고, 별도 job을 만들어 테스트 job의 `needs:`로 걸지 않는다. `ci.yml`의 job은 서로 `needs`가 없다. 이미지·package **발행(push)과 배포**는 `ci.yml` 전체 결과(Docker Build & Push의 `build-and-push`가 `needs: test`이고 `needs.test.result == 'success'`)로 게이팅하며, 발행할 수 있는 job은 모두 이 게이트를 거친다. 현재 workflow는 `ci.yml`과 `docker-build.yml` 둘뿐이고 배포 workflow는 없다. 아무것도 발행하지 않는 PR 검증 빌드는 테스트와 병렬로 돌려도 된다. 게이트는 `ci.yml`의 결과만큼만 강하다. 그래서 `ci.yml`의 job과 step에는 `continue-on-error`와 `if:`를 두지 않는다. 실패가 `success`로 보고되거나, 테스트 step이나 job이 skip된 채 `success`가 되어 이미지가 발행되기 때문이다. workflow·job `env`, `defaults`(sdk job의 `working-directory: sdk`만 예외), step `env`/`shell`/`working-directory`로 고정된 명령의 대상이나 동작을 바꾸지도 않는다.
   - pull_request 이미지 빌드는 이 규칙이 허용하는 비발행 PR 검증 빌드이며 테스트를 기다리지 않는다. 계약 테스트가 발행하지 않음을 다음 세 가지로 고정한다. 두 build step은 PR에서 `push`가 false다(`push: ${{ github.event_name != 'pull_request' }}`). `Log in to GHCR` step은 PR에서 실행되지 않는다. build step input은 정확히 `context`, `file`, `target`, `push`, `tags`, `labels`이므로 `outputs`나 `cache-to`로 registry에 쓰지 않는다.
   - `permissions`는 event별로 나눌 수 없어서 job token에는 `packages: write`가 남아 있다. fork PR의 token은 GitHub이 read-only로 제한한다.
   - tradeoff: 테스트가 실패하는 PR도 약 62초의 빌드 job 하나를 조직 공유 동시 실행 한도에서 쓴다. PR 빌드 대기를 없애려고 받아들였고, 규칙 2의 잡 수 목표와는 상충한다. 실패하는 PR의 빌드가 조직 동시 실행 한도를 압박하면 PR 빌드도 테스트 결과로 게이팅한다(예: Docker Build & Push의 PR `test` 복사본을 되살린다).

#### Scenario: 실패한 테스트와 비발행 PR
- **WHEN** 테스트가 실패하거나 PR 이미지 검증을 실행한다
- **THEN** 발행은 차단하고 PR은 no-push·no-login·고정 build inputs를 지켜 registry에 쓰지 않는다.

### Requirement: Rule 4 — 잡당 고정비를 측정한다.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

checkout, `setup-uv`(cache 복원 포함), `uv sync` 시간을 잰다(현재 service job 약 8초). 캐시 복원이 재설치보다 느리면 캐시를 쓰지 않는다. 현재 서비스 컨테이너는 없다(fakeredis/in-process). 추가하면 health-check는 짧은 interval(예: 2초)과 충분한 retries(또는 start-period)로 설정한다.

#### Scenario: 고정비 변경
- **WHEN** cache 또는 서비스 컨테이너를 도입한다
- **THEN** 복원/설치 시간을 비교하고 느린 cache는 제거하며 충분한 health-check 대기 창을 유지한다.

### Requirement: Rule 5 — 샤딩은 고정비가 작을 때만 한다.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

service job은 고정비 약 8초에 pytest 11초라서 잡 샤딩 대신 잡 내부 병렬화(pytest-xdist)를 쓴다. 샤딩하면 pytest가 작업을 나누는 단위(파일 또는 test)로 균형을 맞추고, 샤드 명령은 `uv run pytest`를 직접 호출하며, 샤드별 수집 테스트 수를 CI에서 검증한다. 래퍼 스크립트 뒤에 인자를 붙이면 전달되지 않아 전체 스위트가 조용히 돌 수 있다.

#### Scenario: 샤딩 검토
- **WHEN** 테스트를 분할하려 한다
- **THEN** 잡 고정비와 균형을 확인하고 러너 직접 호출 및 샤드별 수집 수로 중복 전체 실행을 막는다.

### Requirement: Rule 6 — 격리 해제는 opt-in으로만 한다.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

워커 간 모듈·상태 공유 같은 최적화는 전역에 적용하지 않는다. 먼저 순서를 섞어 2회 이상 실행해 상태 누수를 확인하고, 안전한 파일만 명시적으로 opt-in한다. `monkeypatch`로 바꾼 전역과 settings cache(`tests/conftest.py`의 `get_settings.cache_clear()`)는 반드시 복원한다.

#### Scenario: 격리 완화
- **WHEN** 상태 공유 최적화를 제안한다
- **THEN** 섞인 순서로 두 번 이상 확인한 안전한 파일만 opt-in하고 전역/cache 상태를 복원한다.

### Requirement: Rule 7 — 테스트는 hermetic해야 병렬화할 수 있다.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

단위 테스트는 실제 Keystone, OpenStack, MariaDB, Redis에 접속하지 않는다(live 테스트는 명시적 opt-in). 로컬 `waygate.conf` 후보 파일이 있느냐에 따라 결과나 시간이 달라지면 결함이다. CI는 `uv run pytest tests -n 4 --dist worksteal`처럼 워커 수를 CI vCPU(public `ubuntu-latest` 4 vCPU)에 맞춰 명시한다(`-n auto` 금지). xdist 옵션은 `ci.yml`에만 두고 `addopts`에 넣지 않아 직렬 `uv run pytest tests`가 계속 유효하게 한다. `-p xdist`는 넘기지 않는다. `pytest11` entry point가 이미 `xdist.plugin`을 로드하므로 불필요하기 때문이다(pytest 9.1.1과 pytest-xdist 3.8.0에서 `-p xdist -n 2`도 오류나 중복 등록 없이 동작한다). `-p`는 `PYTEST_DISABLE_PLUGIN_AUTOLOAD`로 자동 로드를 끈 경우에만 필요하다.

#### Scenario: 직렬과 CI 실행
- **WHEN** 단위 테스트를 로컬 또는 CI에서 실행한다
- **THEN** 실제 외부 서비스나 로컬 설정에 의존하지 않고 직렬 entrypoint와 CI 전용 고정 4-worker 구성을 유지한다.

### Requirement: Rule 8 — 변경 감지의 diff 기준을 정확히 한다.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

현재 paths filter나 diff 기반 변경 감지는 없다. 도입하면 push는 `github.event.before..github.sha`로 비교하고, zero SHA·forced push·fetch 실패 시에는 전체를 대상으로 한다. PR은 base..head로 비교한다. `HEAD^1..HEAD`처럼 마지막 커밋만 보는 비교는 금지한다. 발행 이미지는 실제 발행된 revision을 기준으로 판단한다.

#### Scenario: 변경 감지 도입
- **WHEN** push diff의 기준을 신뢰할 수 없다
- **THEN** 전체를 실행 대상으로 하고 마지막 커밋만 비교해 변경을 누락하지 않는다.

### Requirement: Rule 9 — 중복 실행은 입력 동일성으로만 제거한다.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

같은 저장소의 브랜치에서 온 PR이고 merge 트리가 head 트리와 같을 때만 PR 테스트를 건너뛴다. fork PR과 dependabot PR은 항상 테스트한다. 브랜치 이름만으로 판단하지 않는다(fork의 동명 브랜치 우회). 이 일반 규칙은 앞으로의 모든 skip 최적화(예: dev push가 이미 테스트한 head라는 이유로 dev→main PR 테스트를 건너뛰기)에 그대로 적용된다.
   - 현재 구성: pushed ref(branch push, tag push), `workflow_dispatch` 실행, PR sync마다 테스트를 한 번 실행한다. 단 release tag(`v*`)는 branch push로 이미 테스트된 SHA를 다시 테스트한다. 같은 SHA의 dev push와 tag push가 각각 별도의 `push` event run이기 때문이다(예: 6b7bbc7 dev + v0.1.0은 35127710307 / 35127715555, 0257ac1 dev + v0.1.2는 35205182389 / 35205187680). tag와 branch 사이의 dedup은 구현하지 않았고 이 규칙의 범위 밖 lever다.
   - push(main, dev), tag(`v*`), `workflow_dispatch`에서는 Docker Build & Push의 `test` job(`uses: ./.github/workflows/ci.yml`)이 유일한 테스트 실행이며 이미지 발행을 게이팅한다. 그래서 `ci.yml`에는 `push` trigger를 두지 않는다.
   - pull_request에서는 PR 테스트를 건너뛰지 않는다. CI 자체의 pull_request run이 base가 main 또는 dev인 모든 PR(fork·dependabot PR 포함)을 테스트하고, Docker Build & Push는 같은 pull_request event의 같은 merge ref에서 같은 `ci.yml`을 실행할 두 번째 복사본(`test` job)만 건너뛴다. 이 skip의 근거는 입력 동일성이며 브랜치 이름에 의존하지 않는다. 그래서 두 워크플로우의 `pull_request` 설정은 항상 같아야 한다. PR 이미지 빌드는 push하지 않는다.

#### Scenario: 중복 테스트 제거
- **WHEN** PR 중복을 제거한다
- **THEN** fork·dependabot PR 테스트를 유지하며 같은 merge-ref의 두 번째 복사본만 생략하고 양쪽 PR trigger를 일치시킨다.

### Requirement: Rule 10 — 보안: public 저장소의 `pull_request` 코드를 self-hosted runner에서 실행하지 않는다.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

모든 job은 GitHub-hosted `ubuntu-latest`만 쓰고, workflow YAML의 `runs-on`과 `if:` guard를 유지한다. 계약 테스트가 이를 고정한다. 다만 YAML은 PR이 수정할 수 있으므로 runner group의 저장소 제한과 fork PR 승인 설정으로도 보장한다. 이 settings 수준 통제는 저장소·조직 owner가 해야 하며 PR로는 적용할 수 없다. 2026-09-24에 read-only API로 확인한 상태는 다음과 같다.
   - 저장소 runner: `Settings > Actions > Runners`(`https://github.com/openstack-afterglow/waygate/settings/actions/runners`). 등록된 self-hosted runner는 0개다(`GET repos/openstack-afterglow/waygate/actions/runners`).
   - runner group: 조직 `openstack-afterglow`는 Free plan이다. GitHub 문서에 따르면 추가 group은 Team plan 이상에서만 만들 수 있으므로, 기본 `Default` group 외의 group은 만들 수 없다. 설정 위치는 `Organization settings > Actions > Runner groups`(`https://github.com/organizations/openstack-afterglow/settings/actions/runner-groups`)다. Default group의 저장소 접근과 public 저장소 허용 여부는 확인하지 못했다. API가 `admin:org` 권한을 요구해 403을 반환했다. self-hosted runner를 도입하기 전에 owner가 이 설정에서 이 저장소를 포함한 public 저장소의 접근을 막는다.
   - fork PR 승인: `Settings > Actions > General > Approval for running fork pull request workflows from contributors`. 현재 값은 `first_time_contributors`("Require approval for first-time contributors")다(`GET repos/openstack-afterglow/waygate/actions/permissions/fork-pr-contributor-approval`). self-hosted runner를 도입하면 owner가 `Require approval for all external contributors`로 올린다.
   - trigger: 모든 workflow의 trigger는 `push`, `pull_request`, `workflow_dispatch`, `workflow_call`, `schedule`만 쓴다. `pull_request_target`, `workflow_run`, `issue_comment`처럼 외부 입력을 base 저장소의 secret이나 write token으로 처리하는 trigger는 쓰지 않는다.
   - `run:` 보간: `run:`의 `${{ }}` 안에서는 `github.event`와 `github.head_ref`를 어떤 형태로도 참조하지 않는다. 금지 형태는 `github.event.x`, `github.event['x']`, `github['event']`, `toJSON(github.event)`, `format('{0}', github.event.x)`다. 값은 `env:`로 넘기고 shell 변수를 quote한다.

#### Scenario: 외부 PR 신뢰 경계
- **WHEN** PR 입력을 실행하거나 runner 설정을 바꾼다
- **THEN** hosted runner와 trigger allowlist를 유지하고 shell에는 env로 전달해 quote하며 owner 설정의 미확인 상태를 해결 전까지 완료로 표시하지 않는다.

### Requirement: Rule 11 — CI 형태는 계약 테스트로 고정한다.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

`tests/test_ci_workflow_contract.py`가 아래 불변식을 검증한다. CI 형태를 바꾸면 이 테스트와 `ARCHITECTURE.md`의 CI 설명을 같은 변경에서 갱신하고 `actionlint`로 워크플로우를 검사한다.
   - trigger: `ci.yml`과 Docker Build & Push의 trigger 집합(`ci.yml`의 `workflow_call`은 input 없음), 두 워크플로우의 pull_request 설정 동일성, dedup `if:`, 모든 `*.yml`/`*.yaml` workflow의 trigger allowlist(규칙 10).
   - 테스트 실행 횟수(규칙 9): `push`나 `pull_request` trigger가 있는 모든 workflow에서 테스트를 실행하는 job은 `ci.yml`의 `service`·`sdk`와 Docker Build & Push의 `test`뿐이다. `run:`에 `pytest`가 있는 job과 reusable workflow를 호출하는 job을 센다. local composite action이나 `make`처럼 다른 경로로 테스트를 실행하는 job은 보지 못한다.
   - 발행 게이팅: 빌드 게이팅 식, PR 빌드 no-push와 no-login, Docker Build & Push `test` job의 key 집합(`if`, `uses`만)을 검증한다. PR 빌드 no-push는 두 build step의 `push`가 PR에서 false이고 `with` key 집합이 정확히 `context`, `file`, `target`, `push`, `tags`, `labels`라는 뜻이다. 모든 workflow에서 발행할 수 있는 job은 `needs: test`와 같은 게이트 식을 가져야 하며, 현재 그런 job은 `build-and-push` 하나다. 발행할 수 있는 job은 다음 중 하나에 해당한다.
     - 검토된 allowlist(`actions/checkout`, `astral-sh/setup-uv`, `docker/setup-buildx-action`, `docker/metadata-action`) 밖의 action을 쓴다. local composite `./...`와 `docker://`도 포함한다.
     - `push`가 false가 아니거나 어떤 input(`outputs`, `cache-to`, `set` 등)에 `push=true`/`type=registry`가 있는 build/bake action을 쓴다. 또는 registry·package 발행 명령(`docker push`/`docker login`, `--push`, `push=true`, `type=registry`, `buildx build`, `imagetools create`, `crane`, `skopeo`, `oras`, `twine`, `uv publish`)을 실행한다.
     - token에 write scope가 하나라도 있다(`write-all` 포함, `read`와 `none`만 안전하다). `statuses`·`checks` write는 required check가 읽는 결과를 만들 수 있고, 다른 write scope도 저장소 상태를 바꾸므로 모두 포함한다. job과 workflow 모두 `permissions`를 지정하지 않아 저장소 기본값을 상속하는 경우도 포함한다. 현재 기본값은 read지만 PR 없이 설정만으로 바뀔 수 있다.
     - `${{ }}` expression에서 `secrets`를 참조한다(`secrets.NAME`, `secrets['NAME']`, `toJSON(secrets)`, `format('{0}', secrets.NAME)`, 대소문자 무관). job 안의 모든 값과 모든 job에 보이는 workflow-level `env`를 검사한다.
     - `ci.yml` 이외의 reusable workflow를 호출한다.
     - 이 판정 helper와 secret·event payload·xdist 옵션 패턴은 같은 파일 끝의 합성 workflow parametrized 테스트로 고정한다(양성 사례와 `push: false` 빌드, read-only lint, `env:` pass-through 같은 음성 대조군).
   - `ci.yml` 구조:
     - workflow key 집합은 `name`, `on`, `permissions`(`contents: read`), `jobs`뿐이다. workflow `env`, `defaults`, `concurrency`는 없다.
     - job key 집합: service는 `name`, `runs-on`, `steps`, sdk는 여기에 `defaults`(`run.working-directory: sdk`만)를 더한 것이다. 따라서 job `if`, `continue-on-error`, `env`, `strategy`, `permissions`, `needs`가 없다.
     - step key는 `name`, `uses`, `with`, `run`만 쓴다. step `if`, `continue-on-error`, `env`, `shell`, `working-directory`는 없다. checkout에는 `with`가 없다(`ref`, `sparse-checkout` 등으로 테스트 대상 tree를 바꾸지 못한다).
     - 두 job의 순서 있는 step 목록: action 이름과 공백을 정규화한 `run` 명령 전체를 고정한다. 그래서 `|| true`나 step 삽입은 실패한다. action version은 고정하지 않는다. setup-uv의 `with`는 정확히 `python-version: '3.12'`, `enable-cache: true`이다. 이미지의 `python:3.12-slim`과 같은 인터프리터로 테스트한다.
     - xdist 워커 수(`-n 4 --dist worksteal`, `-n auto`와 `-p xdist` 금지).
     - 직렬 entrypoint 유지: pytest가 실제로 읽은 설정 파일이 root `pyproject.toml`이다. 그래서 root나 `tests/`의 `pytest.ini`·`pytest.toml` 같은 우선 설정 파일이 끼어들 수 없다. 그 `[tool.pytest]`와 `[tool.pytest.ini_options]`의 `addopts`에는 어떤 표기의 xdist 옵션(`-n 4`, `-n4`, `-nauto`, `--numprocesses`, `--maxprocesses`, `--dist`, `--tx`)도 없다.
   - 보안: `run:`의 event payload 보간 금지(규칙 10의 dot·bracket·함수 인자 형태), `*.yml`/`*.yaml` 전체 workflow의 `ubuntu-latest` 전용 runner. runner group과 fork PR 승인 같은 settings 수준 통제는 계약 테스트가 볼 수 없다(규칙 10).
   - 이 guard의 한계: 계약 테스트는 자신이 판정해야 할 pytest 설정 아래에서 실행된다. 그래서 pytest가 테스트를 건너뛰거나 수집만 하게 만드는 변경(`pyproject.toml`·`sdk/pyproject.toml`의 `addopts`, `conftest.py`)은 잡지 못한다. `actionlint`는 로컬 전용 검사이며 어떤 workflow도 실행하지 않는다. 계약 테스트는 `ci.yml`을 통해서만 실행된다. 그래서 `docker-build.yml`의 게이트를 바꾸는 PR은 merge 전 CI pull_request run에서 잡히지만, `ci.yml` 자신의 `pull_request` trigger를 제거·축소하거나 `paths-ignore`를 추가하는 PR은 merge 전에 테스트가 전혀 실행되지 않을 수 있다(Docker Build & Push의 PR `test` 복사본도 skip된다). 이런 회귀는 merge 뒤 branch push에서 Docker Build & Push `test` job의 계약 테스트가 실패하고 이미지 발행을 막을 때 드러난다. branch protection이 없으므로 workflow 파일을 바꾸는 PR은 로컬 계약 테스트와 `actionlint` 출력을 PR 설명(PR이 없으면 커밋 본문)에 붙인다.
   - 근본 완화는 main과 dev에 required status check를 거는 저장소 설정이다. 대상은 CI pull_request run의 check run 이름 `Service tests and lint`와 `SDK tests and lint`이고, PR 화면에는 `CI / ...`로 표시된다. 보고되지 않은 required check는 merge를 막으므로 trigger를 제거하는 PR도 merge할 수 없게 된다. 다만 required check가 걸린 branch에는 check가 통과하지 않은 commit을 직접 push할 수 없으므로, 적용 범위와 bypass는 maintainer가 정한다. 이 설정은 maintainer 권한의 변경이며 아직 적용되지 않았다. 2026-09-24 확인 시 ruleset `main`은 enforcement `disabled`였고 main과 dev 모두 branch protection이 없었다.

#### Scenario: CI 계약 변경
- **WHEN** workflow나 pytest 실행 구조를 수정한다
- **THEN** 계약 테스트·architecture와 actionlint를 함께 검토하고 trigger/설정 자체로 검사가 사라질 수 있는 한계와 로컬 검증 출력을 제출 기록에 남긴다.

### Requirement: Rule 12 — 지속 개선.

Waygate CI 변경은 다음 의무를 준수해야 한다(SHALL). 과거 날짜의 관측, 수치, 미확인 상태는 기록된 evidence이며 현재 확인 결과가 아니다.

CI를 바꾸는 변경에는 전후 실측을 첨부한다. 위 기준표의 크리티컬 패스 중앙값보다 20% 이상 나빠지거나(중앙값 × 1.2: push/tag test critical path 28.8초 초과, push/tag commit-to-image 106.8초 초과, 같은 success 필터로 계산), 테스트 수가 크게 늘거나(기준 시점 243건), 새 테스트 계층을 추가하면 규칙 1 절차로 다시 측정하고 가장 긴 잡부터 개선한다. dedup 이후의 새 기준은 변경이 반영된 뒤 20회 이상 실행으로 다시 기록한다.

#### Scenario: 기준선 회귀
- **WHEN** 기록된 임계치를 넘거나 테스트 수/계층이 늘어난다
- **THEN** 같은 모집단으로 다시 측정하고 가장 긴 잡부터 개선하며 dedup 이후 새 기준은 최소 20회 후 기록한다.
