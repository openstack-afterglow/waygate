## 1. Renewable SQL authority

- [x] 1.1 Retain existing per-server SQL `SKIP LOCKED` queue and add independent renewable attempt/freshness ownership.
- [x] 1.2 Fence subsequent provider HTTP sends and durable identity writes against stale/current-attempt loss without bypassing caller Trust/project checks.
- [x] 1.3 Prevent expired same-attempt renewal/completion/retry and keep running bound grants out of background retirement.
- [x] 1.4 Commit versioned protocol admission before the first executable claim; define native pre-create failure recovery and missing/unsupported/unbound legacy fail-closed cases without retrofitting provenance.
- [x] 1.5 Write retry `CREATING`/`DELETING` status under the same SQL transaction that revalidates the exact fresh attempt/project/server; define a native stale-paused provision/delete takeover regression.

## 2. Durable lifecycle and drain

- [x] 2.1 Persist port/VM/FIP intent before create POST and returned IDs in existing durable JSON/columns, with no new migration.
- [x] 2.2 Recover exact owned targets or remain unresolved; preserve intent/resources, remove replay-prone rollback and reject unsafe legacy partial retries.
- [x] 2.3 Suppress scoped installed-SDK POST replay and move lazy proxy discovery into drained provider threads.
- [x] 2.4 Drain SDK/factory/current-job work before close/release and make SIGTERM/SIGINT stop polling then drain with DB/connection live.

## 3. Test definitions and documentation

- [x] 3.1 Define real SQL/native HTTP ownership, takeover, cancellation, accepted-response-loss and actual-process signal regressions, preserving unrelated authorization assertions.
- [x] 3.2 Complete absent/ambiguous exact-target recovery regressions proving no second POST or destructive rollback.
- [x] 3.3 Update architecture/code map, changelog, rollout limits and executable actual-worker smoke recipe without claiming unexecuted evidence.

## 4. Parent-only acceptance evidence

- [x] 4.1 Run focused lifecycle/native SQL selectors on file-backed SQLite and disposable migration-built MariaDB; record native request counts, attempt/freshness outcomes, drain order and accepted port/VM recovery receipts. Parent receipt (2026-10-14): focused 115 passed; MariaDB 49 passed, 0 skipped, including accepted-response-loss/no-second-POST and stale-attempt/takeover regressions; [named selectors and proof root](design.md#parent-execution-receipt-2026-10-14).
- [x] 4.2 Run actual worker subprocess SIGTERM/SIGINT held-SDK smoke and capture process/SQL output and exit outcomes. Parent MariaDB receipt includes `test_native_worker_process_signal_drains_sdk_before_database_shutdown[SIGTERM,SIGINT]` (actual subprocess holding SDK work); SQLite also passed `test_worker_signal_drains_pending_database_connection_before_exit[SIGTERM,SIGINT]` in the full suite.
- [x] 4.3 Run integrated service gates/lint and complete native architecture source review/stamp/check; preserve branch/index/concurrent WIP, no stage/commit/push/deploy. Parent receipt: full `pytest tests -n 4 --dist worksteal` 671 passed, 3 skipped (2 opt-in Docker/MariaDB image smokes, 1 live lifecycle requiring `WAYGATE_RUN_LIVE`); `ruff check .` clean after B023/SIM102 fixes, no formatting applied. Architecture stamp/check is in the parent receipt (isolated clone, shared marker untouched).

## Evidence status

The implementation slice itself ran no builds, tests, lint, formatter, smoke, live provider calls or deployment. Acceptance above instead records the parent's 2026-10-14 execution on a frozen public clone synced byte-for-byte from the current working tree, including concurrent WIP: focused 115 passed, MariaDB 49 passed/0 skipped, full 671 passed/3 skipped and Ruff clean. See the [design receipt](design.md#parent-execution-receipt-2026-10-14) for snapshot identity, named tests, logs/JUnit/execution JSON proof root and boundaries. These are local `test-passed` results, not `live-verified`: disposable owned fixtures and synthetic providers only; production Redis/Sentinel failover, async-replication lease/journal loss, promoted-node TIME skew, mixed-version rolling upgrade, live provider/cloud and deployment remain unqualified. No private config/credentials, paid inference, publication, stage, commit or push was used. The parent's isolated-clone architecture stamp/check leaves the shared marker untouched. Existing historical receipts remain historical.
