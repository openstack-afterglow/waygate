# Waygate 작업 규칙

## Architecture maintenance

- 작업을 시작하기 전에 root [`ARCHITECTURE.md`](ARCHITECTURE.md)와 변경 영역의 source, 테스트, migration/config/CI 상세 문서를 읽는다.
- code, config, schema, dependency, deployment, test를 바꾸면 영향을 받는 architecture 본문·code map·상세 문서·검증 명령을 같은 변경에서 갱신한다.
- 구조 영향이 없는 bugfix/refactor도 실제 source를 읽은 뒤 그 이유를 architecture review summary에 기록한다.
- 계획이나 roadmap이 아닌 현재 source와 테스트 정의를 정본으로 삼는다. `implemented`와 `test-defined`를 실행하지 않은 검증 결과로 승격하지 않는다.
- 모든 의도한 source/document 변경 후 실제 source를 다시 검토하고 stamp한 뒤 check를 실행한다. 자동 stage/commit하지 않는다.

```sh
python3 scripts/check_architecture.py --stamp --summary "검토한 변경 경로와 구조 영향 또는 영향 없음의 이유"
python3 scripts/check_architecture.py
python3 scripts/check_architecture.py --staged
```

`--staged` 제출에서는 `--stamp --staged --summary "..."`로 index source를 검토한 뒤 `ARCHITECTURE.md`를 stage하여 다시 확인한다. 실제 credential, token, password, private key는 문서·로그·코드 예시에 기록하지 않는다.

## Verification entrypoints

- Service: `uv run pytest tests` 및 `uv run ruff check .`
- Service CI 형태: `uv run pytest tests -n 4 --dist worksteal` (pytest-xdist. 직렬 명령과 같은 테스트 수가 수집되어야 한다)
- CI 형태 계약: `uv run pytest tests/test_ci_workflow_contract.py -q`
- Focused boundaries: `uv run pytest tests/test_waygate_jobs.py tests/test_waygate_provisioner.py tests/test_waygate_agent.py tests/test_waygate_clients.py tests/test_waygate_network.py -q`
- SDK: `cd sdk && uv run pytest && uv run ruff check .`
- Schema: `uv run waygate-migrate --database-url "$WAYGATE_DATABASE_URL" --apply` (실제 MariaDB 전제조건 필요)

## CI 파이프라인 성능 규정 (critical-path first)

근거: afterglow CI 실측(2026-09, 실행 40건, 크리티컬 패스 중앙값 143초)과 Linear의 CI 개편 사례를 이 저장소에 맞게 옮겼다. CI(`.github/workflows/ci.yml`, `.github/workflows/docker-build.yml`)를 바꾸는 모든 변경은 아래 규칙을 따른다. 이 저장소에는 OpenSpec이 없으므로 변경 기록은 커밋 본문(PR이 있으면 PR 설명 포함)에 남긴다.

### 기록된 기준 (rule 12의 비교 기준)

2026-08-05~2026-09-18에 완료된 gating run 전체 29건(CI 12건, Docker Build & Push 17건)을 측정했다. 규칙 1의 20회 기준보다 적으므로 표본 수를 함께 적는다. p90은 선형 보간이다.

| 지표 | 정의 | 표본 | 중앙값 | p90 |
|---|---|---|---|---|
| test critical path (push/tag) | 테스트를 실행한 각 run의 생성부터 그 run의 마지막 test job 종료까지. 기준 시점에는 push SHA마다 CI와 Docker Build & Push 두 run이 테스트를 실행해 둘 다 표본이다 | n=21 | 23.0초 | 27.0초 |
| test critical path (pull_request) | 위와 같음 | n=6 | 38.0초 | 65.5초 |
| commit-to-image (push/tag) | Docker Build & Push run 생성부터 `Build & Push Waygate Images` 종료까지 | n=14 | 84.5초 | 95.4초 |
| (참고) pooled test critical path | 모든 event와 워크플로우를 합산 | n=27 | 24.0초 | 39.6초 |
| (참고) pooled commit-to-image | push, tag, pull_request 합산 | n=17 | 87초 | 106.4초 |

job 중앙값(성공 run 기준): `Service tests and lint` 21초(setup 약 8초, pytest 11초), `SDK tests and lint` 9초, `Build & Push Waygate Images` 62초. 이 기준은 test job을 SHA·event당 한 번만 실행하도록 dedup하기 전의 값이다. pull_request 이미지 빌드는 이제 테스트를 기다리지 않으므로 commit-to-image는 push/tag event만으로 비교한다.

### 규칙

1. **측정 먼저, 추정 금지.** CI를 바꾸기 전과 후에 최근 20회 이상 실행(부족하면 존재하는 전체와 n)의 잡·스텝 시간을 `gh run list` / `gh api repos/openstack-afterglow/waygate/actions/runs/<id>/jobs`로 수집한다. 위 정의의 크리티컬 패스 중앙값과 p90을 커밋 본문에 남긴다. 절감 효과는 합산되지 않으므로 가장 긴 잡부터 줄이고, 실제 CI 전후 수치로만 효과를 주장한다. 로컬 측정은 추정치로 표시한다.
2. **목표 지표를 먼저 정한다.** 이 저장소는 public이고 GitHub-hosted `ubuntu-latest`만 쓰므로 runner-minutes는 무료이고 wall-clock(대기 시간)이 목표다. 조직 `openstack-afterglow`는 Free plan이어서 형제 저장소(afterglow, drover, lumen, palimpsest 등)가 동시 실행 잡 한도를 공유한다. 중복 잡은 조직 전체 burst 때 queue 대기(p90)를 늘리므로 잡 수도 함께 본다.
3. **게이트 잡을 다른 잡 앞에 두지 않는다.** architecture check 같은 fail-fast 검사는 `service` job의 첫 step으로 두고, 별도 job을 만들어 테스트 job의 `needs:`로 걸지 않는다. `ci.yml`의 job은 서로 `needs`가 없다. 이미지 빌드·발행 게이팅은 `ci.yml` 전체 결과(Docker Build & Push의 `build-and-push`가 `needs: test`)로 한다.
4. **잡당 고정비를 측정한다.** checkout, `setup-uv`(cache 복원 포함), `uv sync` 시간을 잰다(현재 service job 약 8초). 캐시 복원이 재설치보다 느리면 캐시를 쓰지 않는다. 현재 서비스 컨테이너는 없다(fakeredis/in-process). 추가하면 health-check는 짧은 interval(예: 2초)과 충분한 retries(또는 start-period)로 설정한다.
5. **샤딩은 고정비가 작을 때만 한다.** service job은 고정비 약 8초에 pytest 11초라서 잡 샤딩 대신 잡 내부 병렬화(pytest-xdist)를 쓴다. 샤딩하면 pytest가 작업을 나누는 단위(파일 또는 test)로 균형을 맞추고, 샤드 명령은 `uv run pytest`를 직접 호출하며, 샤드별 수집 테스트 수를 CI에서 검증한다. 래퍼 스크립트 뒤에 인자를 붙이면 전달되지 않아 전체 스위트가 조용히 돌 수 있다.
6. **격리 해제는 opt-in으로만 한다.** 워커 간 모듈·상태 공유 같은 최적화는 전역에 적용하지 않는다. 먼저 순서를 섞어 2회 이상 실행해 상태 누수를 확인하고, 안전한 파일만 명시적으로 opt-in한다. `monkeypatch`로 바꾼 전역과 settings cache(`tests/conftest.py`의 `get_settings.cache_clear()`)는 반드시 복원한다.
7. **테스트는 hermetic해야 병렬화할 수 있다.** 단위 테스트는 실제 Keystone, OpenStack, MariaDB, Redis에 접속하지 않는다(live 테스트는 명시적 opt-in). 로컬 `waygate.conf` 후보 파일이 있느냐에 따라 결과나 시간이 달라지면 결함이다. CI는 `uv run pytest tests -n 4 --dist worksteal`처럼 워커 수를 CI vCPU(public `ubuntu-latest` 4 vCPU)에 맞춰 명시한다(`-n auto` 금지). xdist 옵션은 `ci.yml`에만 두고 `addopts`에 넣지 않아 직렬 `uv run pytest tests`가 계속 유효하게 한다. entry point가 plugin을 등록하므로 `-p xdist`를 넘기지 않는다(중복 등록).
8. **변경 감지의 diff 기준을 정확히 한다.** 현재 paths filter나 diff 기반 변경 감지는 없다. 도입하면 push는 `github.event.before..github.sha`로 비교하고, zero SHA·forced push·fetch 실패 시에는 전체를 대상으로 한다. PR은 base..head로 비교한다. `HEAD^1..HEAD`처럼 마지막 커밋만 보는 비교는 금지한다. 발행 이미지는 실제 발행된 revision을 기준으로 판단한다.
9. **중복 실행은 입력 동일성으로만 제거한다.** 현재 구성은 SHA·event당 테스트를 한 번 실행한다. push(main, dev), tag(`v*`), `workflow_dispatch`에서는 Docker Build & Push의 `test` job(`uses: ./.github/workflows/ci.yml`)이 유일한 실행이며 이미지 빌드를 게이팅한다. 그래서 `ci.yml`에는 `push` trigger를 두지 않는다. pull_request에서는 CI 자체의 pull_request run이 같은 merge ref에서 같은 `ci.yml`을 실행하므로 Docker Build & Push의 `test` job을 건너뛴다. PR 이미지 빌드는 push하지 않는다. 두 워크플로우의 `pull_request` 설정은 항상 같아야 한다. fork PR과 dependabot PR은 CI의 pull_request run으로 항상 테스트한다. 브랜치 이름만으로 dedup하지 않는다(fork의 동명 브랜치 우회).
10. **보안: public 저장소의 `pull_request` 코드를 self-hosted runner에서 실행하지 않는다.** 워크플로우 YAML의 `if:`는 PR이 수정할 수 있으므로, self-hosted runner를 도입하면 runner group의 저장소 제한과 fork PR 승인 설정으로도 보장한다.
11. **CI 형태는 계약 테스트로 고정한다.** `tests/test_ci_workflow_contract.py`가 trigger 집합, pull_request 설정 동일성, dedup `if:`, 빌드 게이팅 식, PR 빌드 no-push, `ci.yml` job 간 `needs` 부재, xdist 워커 수, 직렬 entrypoint 유지, runner 종류를 검증한다. CI 형태를 바꾸면 이 테스트와 `ARCHITECTURE.md`의 CI 설명을 같은 변경에서 갱신하고 `actionlint`로 워크플로우를 검사한다.
12. **지속 개선.** CI를 바꾸는 변경에는 전후 실측을 첨부한다. 위 기준표의 크리티컬 패스 중앙값보다 20% 이상 나빠지거나(push/tag test critical path 27.6초 초과, push/tag commit-to-image 101.4초 초과), 테스트 수가 크게 늘거나(기준 시점 243건), 새 테스트 계층을 추가하면 규칙 1 절차로 다시 측정하고 가장 긴 잡부터 개선한다. dedup 이후의 새 기준은 변경이 반영된 뒤 20회 이상 실행으로 다시 기록한다.
