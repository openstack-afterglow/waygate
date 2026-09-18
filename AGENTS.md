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
- Focused boundaries: `uv run pytest tests/test_waygate_jobs.py tests/test_waygate_provisioner.py tests/test_waygate_agent.py tests/test_waygate_clients.py tests/test_waygate_network.py -q`
- SDK: `cd sdk && uv run pytest && uv run ruff check .`
- Schema: `uv run waygate-migrate --database-url "$WAYGATE_DATABASE_URL" --apply` (실제 MariaDB 전제조건 필요)
