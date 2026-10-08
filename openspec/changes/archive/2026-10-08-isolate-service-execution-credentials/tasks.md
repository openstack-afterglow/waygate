## 1. Delegation and durable schema

- [x] 1.1 Add bounded caller-created Trust execution grants, exact scope/current-authority guards and separate durable cleanup.
- [x] 1.2 Add immutable migration 006, grant model and one-grant job binding while preserving existing schema/records.

## 2. Execution cutover

- [x] 2.1 Migrate create/delete admission and worker execution; preserve lease/attempt/terminal-state recovery and delete reauthorization.
- [x] 2.2 Migrate routing attach/detach to caller delegation and remove tenant-password factory/all obsolete callers.
- [x] 2.3 Add member-compatible zero-disk volume-backed boot without policy/role expansion.

## 3. Verification and contracts

- [x] 3.1 Update affected real contract tests and add authorization/revocation/cleanup/zero-disk boundary regressions.
- [x] 3.2 Run focused service regressions and native SDK/HTTP/MariaDB smoke, including current-role removal and independent terminal cleanup.
- [x] 3.3 Update source-linked architecture/operator docs and run applicable architecture/OpenSpec guards; distinguish synthetic/local evidence from separately approved production cutover.

## Evidence (2026-10-07, local)

- `uv run --frozen pytest tests -n 4 --dist worksteal`: 628 passed, 3 skipped (opt-in live/container smokes); `uv run --frozen ruff check .`: passed.
- `tests/test_execution_delegation.py`: 12 passed on SQLite and 12 passed with `WAYGATE_DELEGATION_MARIADB_URL` against disposable MariaDB 11.4 (per-test database built by the 001–006 ledger, container removed afterwards). Real keystoneauth1 5.15.0, python-keystoneclient 5.4.0 and openstacksdk 3.3.0 over loopback HTTP.
- The native run exposed and fixed two defects that mocks hid: `TrustManager.create` requires a `datetime` expiry, and `openstack.connect(session=...)` ignores the session; execution now builds `openstack.connection.Connection(session=...)`.
- MariaDB: re-running every 006 statement was a no-op; a second grant binding returned 1062 and an unknown grant 1452; `waygate-migrate --apply` then reported nothing pending.
- Not exercised: live Keystone trust policy, Cinder quota for volume-backed boot, image builds, deployment, or removal of the service user's existing DMSLAB grants.
