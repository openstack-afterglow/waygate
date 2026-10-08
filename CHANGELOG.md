# Changelog

## 0.3.2 — 2026-10-08 (service 0.3.2 / SDK 0.2.0; not deployed)

- Root service distribution/runtime, root `uv.lock` and packaged Kolla `waygate_image_tag` move together to `0.3.2`, the next patch after published `v0.3.1`; the independent SDK stays `0.2.0` (its existing `**attrs` forwarding carries `owner_user_id`, and its public API is unchanged). The root `dev` extra adds `aiosqlite>=0.20.0` (lock `0.22.1`) for the persistent SQLite synthetic-auth smoke only; service/runtime image dependencies are unchanged. Kolla `waygate_source_version` remains the stale immutable pin `1c59b5e…`; source-mode operators must select the reviewed release commit.
- **Operator cutover prerequisites:** back up the Waygate database and keep the 0.3.1 image/config references; apply additive migrations 005 and 006 through Kolla `deploy --tags waygate` bootstrap (or `upgrade`) or `waygate-migrate --apply` before the new API/worker start, because `reconfigure` does not migrate. The global Keystone `waygate_*` grade roles, `waygate-*` action leaves and their implication edges must exist (Afterglow's system-admin role preset apply seeds them) and users need effective grade assignments before cutover; otherwise every tenant route fails closed with 403. Drain the job queue first: jobs queued under 0.3.1 have no execution grant and fail terminally. The Waygate service user keeps `admin` on its own `waygate-service` project (directory reads and `ADMIN_OR_TRUSTOR` Trust deletion) and needs no tenant role.

### Isolated tenant execution credentials

- **BREAKING:** Tenant Nova/Neutron/Glance execution no longer authenticates the service password in the caller's project. Gateway create, delete and network attach/detach admit an operation Trust created by the caller's original project token: two-hour, impersonating, only the caller's current global `member` role, trustee resolved from the service identity's own project. Every SDK request rechecks the enabled actor/project, exact action capability, `member` and the live Trust; denial fails closed (API 403, terminal job) and authority outages return 503 or retry. The tenant-password connection factory and its `keystone` service alias are removed.
- Add additive checksum-ledger migration `006_execution_grants` (grant table plus unique `waygate_jobs.execution_grant_id`); run `uv run waygate-migrate --database-url "$WAYGATE_DATABASE_URL" --apply` before the updated API/worker. Jobs queued before the upgrade have no grant and fail authorization; drain or resubmit them. A newer authorized delete replaces a queued delete; completed, failed, abandoned and expired grants are deleted by the worker and a cleanup outage never repeats the cloud mutation.
- Zero-disk flavors boot volume-backed (image→volume, `max(10 GiB, image min_disk)`, delete-on-termination) and consume tenant Cinder quota; positive-disk flavors stay image-backed. No Nova policy relaxation or tenant `admin` is required. The service user needs no tenant role; existing DMSLAB `member`/`admin` grants are unused but are removed only in a separately approved cutover.
- Verification (2026-10-07, local, synthetic): real keystoneauth1/keystoneclient/openstacksdk over a loopback Keystone/Nova/Glance/Neutron, 12 delegation cases on SQLite and on MariaDB 11.4 built from migrations 001–006; 006 re-ran idempotently and enforced its unique/foreign-key constraints; `uv run pytest tests -n 4 --dist worksteal` 628 passed, 3 skipped; `ruff check .` passed. No live Keystone policy, Cinder quota, image build or deployment was exercised.

### Native service grades

- Enforce native Waygate action capabilities from the current Keystone global role catalog, implication DAG and effective assignments, with native member/reader baseline. Static parent labels cannot resurrect removed edges. Unknown/ambiguous/domain/unsafe graphs and provider failures fail closed; plain project roles and unverified admin/manager cannot substitute for service authority. Project isolation remains mandatory.
- Restrict config downloads to the assigned owner with connect-user on an enabled profile, with no admin bypass. The create response applies that same current connect-user, ownership and enabled gate to `tunnel_conf`, otherwise `null`; clients-editor alone cannot acquire VPN use authority. Owners are assign-once while unknown (transfer 409, clear 422), assignments require enabled effective native membership, and any enabled change requires clients-admin. Add nullable `owner_user_id`, no-store credential responses and additive checksum-ledger migration `005_client_owner`; unknown legacy and imported owners remain unassigned. Run `uv run waygate-migrate --database-url "$WAYGATE_DATABASE_URL" --apply` before updated API/worker startup. Authority-provider outages return 503 instead of 401.
- Separate client/gateway create/update from deletion/revocation/token rotation, routing and credential import/export. Export includes caller-owned and unassigned profiles only, skipping foreign-assigned private keys/PSKs before decryption; bundles expose the subset scope and excluded client count/IDs, not a complete project backup. Global resource policies retain strictly verified system-admin authority; machine callback authority is unchanged.
- Retain persistent SQLite/synthetic Keystone native HTTP regressions and add an opt-in real-image smoke using the installed Keystone directory client and public Waygate SDK over HTTP. On 2026-10-07, canonical API/worker images ran on arm64 and amd64 with MariaDB 11.4.12/Redis 7: 2 smoke cases passed, covering grades/owners, downgrade, export subset, machine callbacks/token handoff, worker SQL polling and exit-0 shutdown. Real additive 005 preserved 001–004 ledger/records/encrypted keys and bearer, left legacy owners NULL, and passed reconnect plus competing assign-once claims. The parent separately reported 313 selected regressions passed; no production migration/deployment or full release gate is claimed. Existing SDK `**attrs` forwards owner assignment without a new SDK API; exact reproduction and image IDs are in the native OpenSpec design.

## 0.3.1 — published 2026-10-05 (service 0.3.1 / SDK 0.2.0)

Published as annotated tag `v0.3.1` on `37a57fa0691a7aa28513c39d93752077699d7679` with a successful tag-triggered Docker Build & Push and a GitHub Release carrying `waygate-0.3.1-py3-none-any.whl` (SHA-256 `600542c3c6ead26d7a422dfb7e732eabb6c0e9e2b9cd86162ea324d55cde1d21`) and `waygate_sdk-0.2.0-py3-none-any.whl` (SHA-256 `16783c60b774fd853d327e736a82d89b9192ae00003a4d6cd2e08255f0e22332`). The preparation text below is retained as written before publication.

### Changed

- Metadata-only root service patch atop `a6e7dfd3f5f4745fcf6c9e059a0e4e9b66531e55`; no new features, dependency changes or SDK bump. All 0.3.0 functionality, framework/signal fixes, migration 004, source-build pin, old prebuilt references and operator prerequisites remain retained.
- Main `cf72df3` already integrates the same baseline tree. At preparation time, any future integrated 0.3.1 release commit, tag/image publication, manual wheel/GitHub Release and production rollout required owner authorization and remote `v0.3.1` was absent; it was later published as recorded above.

### Fixed

- Isolate the installed-agent test's one-cycle shutdown clock stub to the agent namespace. Mutating the shared `time.sleep` also interrupted Python's timed `wg show` subprocess wait, causing an intermittent missing status POST; HTTP, installed assets and all payload assertions remain unchanged. Runtime agent code is unchanged.

### Verification status

No new checks are claimed by this documentation preparation. The October 2 receipts below apply to historical service 0.3.0 / SDK 0.2.0 source, not fresh 0.3.1 verification. Current exact runtime/gate receipts are recorded separately by the parent after execution.

## Historical service 0.3.0 / SDK 0.2.0 candidate — 2026-10-02

### Changed

- Dependency-only framework remediation after candidate `29f28cdcb572660fc3f693457b007435c0da81ef`: service extra FastAPI `==0.136.3` and explicit Starlette `>=1.3.1`, with root uv lock FastAPI 0.136.3 / Starlette 1.3.1. Published metadata allows the pair; unrelated package versions and the separate SDK lock remain unchanged. No route registration, middleware, SDK public contract, auth, rate-limit budgets, logging source, Host-domain policy, schema or deployment structure is changed.
- Starlette 1.3.1 is outside the five inherited advisory affected ranges; [version boundaries and sources](openspec/changes/archive/2026-10-02-remediate-framework-advisories/design.md#known-advisory-version-boundaries) are recorded without claiming verified runtime fixes or closed alerts. FastAPI 0.137+ included-router changes and compatibility shims are not introduced.

### Fixed

- CLI worker SIGTERM/SIGINT now cancels and awaits the existing serve cleanup. Real Docker worker termination changed from the reproduced137 after30s to exit0 on arm64/amd64 in under1s. Durable job lease/retry policy is unchanged; cloud job draining is not promised.
- Remove obsolete tests copying the old FastAPI0.125.0 pin instead of re-pinning implementation strings. Preserve wheel install/uninstall and optional-service dependency isolation checks.

### Verification status

Historical October 2 framework and signal changes were exercised through canonical isolated API/worker images on aarch64/x86_64 with real MariaDB/Redis and an HTTP Keystone fixture. Real public SDK Connection, ownership/auth, JSON/+json/null/zero, malformed Host/path normalization, safe INFO/DEBUG logs, status budgets120/1200 and process SIGTERM exit0 passed. Missing/wrong Content-Type returns422; the then-current shared agent, immutable-v0.1.4 cloud-init template and Afterglow JSON transports provide/preserve application/json. The running production prebuilt agent was not inspected. Final serial and four-worker suites each passed471 with1 opt-in live skip, SDK44 and root/SDK Ruff passed; architecture guards passed. No genuine cloud lifecycle, provider, publication, production rollout or default-branch alert closure is claimed.

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for complete current candidate changes, maintainer gates and immutable historical release records.
