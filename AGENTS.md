# Waygate 작업 규칙

## 먼저 읽기
- [ARCHITECTURE.md](ARCHITECTURE.md)와 변경 영역의 source·테스트·migration/config/배포 문서를 읽는다. 현재 source가 계획·roadmap보다 우선한다.
- 필수 상세 규칙: [작업·검증·보안·release](openspec/specs/repository-workflow/spec.md), [CI 성능·발행 게이트·PR 보안](openspec/specs/ci-workflow/spec.md). CI 규격의 날짜별 실측은 역사 기록이지 새 검증 결과가 아니다.
- 배포·발행은 [RELEASE_NOTES.md](RELEASE_NOTES.md)의 해당 release 경계를 함께 확인한다.

## 비협상 경계
- MariaDB는 durable 상태와 암호화 credential 정본, Redis는 status cache다. Agent 인증을 cache로 우회하지 않는다. Keystone project 소유권과 system-admin policy 경계를 유지한다.
- 실제 credential/token/password/private key는 문서·로그·예제에 쓰지 않는다. `.conf`의 평문 key와 VM-only server key 경계를 지킨다.
- `implemented`, `test-defined`, 실제 test 통과, isolated/live/운영 증거를 구분한다. 과거 성공을 현재 candidate 검증으로 승격하지 않는다.
- code/config/schema/dependency/deploy/test 변경은 관련 architecture·code map·문서·검증 명령을 함께 갱신한다. 구조 영향이 없어도 source 검토 후 이유를 남긴다.
- 실제 검토 뒤 `python3 scripts/check_architecture.py --stamp --summary "검토 경로와 영향"`, 이어 `python3 scripts/check_architecture.py`를 실행한다. index 제출은 상세 규격의 staged 절차와 `--staged` check를 따른다. 검토하지 않은 사용자 변경을 임의 stamp하지 않는다.
- Service: `uv run pytest tests`, `uv run ruff check .`; CI 형태: `uv run pytest tests -n 4 --dist worksteal`; SDK·schema·live 전제조건은 상세 규격을 따른다.
- 요청 밖 변경·형제 checkout·branch를 보존한다. 자동 stage/commit하지 않고 승인 없이 tag/push/upload/배포하지 않는다. test gate 없는 발행, PR registry 쓰기, public PR의 self-hosted 실행은 금지한다. 기존 release tag·artifact를 덮어쓰지 않는다.
