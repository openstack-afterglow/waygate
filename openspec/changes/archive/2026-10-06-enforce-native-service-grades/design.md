## Decisions
Use exact service action leaves and explicit endpoint dependencies, never HTTP-verb shortcuts or suffix authority. Reload Keystone's current global role catalog, implication DAG and effective project assignments on every native authentication. Expand only edges actually present, never a static parent-label bundle; removed edges must immediately remove authority even when an older token still names the parent. Reject malformed/unknown, domain/ambiguous and unsafe graph authority or lookup failure. Project ownership remains mandatory even for verified system administrators.

Every nonreader capability additionally requires effective native `member`; inventory accepts `reader` or `member`. No implicit authority comes from project-admin/owner labels. Nonverified raw `admin`/`manager` fails closed; only separately verified current system-admin has platform authority. Leaf/parent reachability is determined by the current trusted DAG, not locally restored role implications.

The configured trusted Keystone service identity must be able to list global role definitions, grouped `/role_inferences`, effective user/project role assignments (including group/inherited grants), enabled user records and effective system-all admin assignments. Unavailable catalog/inference/assignment lookups never fall back to parent labels or old token role claims. This is a read-only dependency; the native service does not seed or mutate roles or implications.

Inventory responses expose only schema-filtered nonsecret metadata. Client create/update requires clients-editor; delete and any enabled change require clients-admin. Profile download requires current connect-user and an enabled client whose persisted owner exactly matches the caller. There is no editor, service-admin or system-admin bypass, because private ownership is preserved. The create response applies the same current connect-user, persisted ownership and enabled gate to tunnel_conf; metadata-only clients-editor cannot reconstruct use authority, even when the owner is the caller. Assignment requires a current enabled Keystone user with effective native member through the current DAG. Owners are assign-once while NULL, so transfer and clear are rejected and delete/recreate requires clients-admin. Keystone token failure returns 401, authority-provider outage 503 and rejected graphs 403. Legacy clients are unassigned and never inferred from creator metadata.

Gateway create/update requires gateways-editor; delete and agent-token rotation require gateways-admin. Attach/detach requires routing-admin. Export/import requires clients-admin plus routing-admin since bundles carry credentials and routing state. Global resource policy remains verified system-admin only. Machine callbacks keep server-bound durable bearer authority.

Credential export preserves known private ownership: only caller-owned and unassigned administrative profiles are exported. Other members' key ciphertext is skipped before decryption, including for service or system administrators. Server and routing state stay included. Export reports export_scope=caller_owned_and_unassigned_profiles, excluded_assigned_client_count and nonsecret excluded_assigned_client_ids; callers must not label the subset a complete project backup. Export remains available to clients-admin plus routing-admin for eligible profiles. Unknown legacy profiles are administrative until assigned, while ordinary config download still fails closed for unknown owners.

Migration 005 adds nullable owner_user_id without altering 001–004 identities. Import never trusts bundle owner IDs: imported clients are unassigned and must be explicitly assigned through validated PATCH.

## Verification boundary
The parent reported 313 selected native/old regressions passed after the legacy fixture owner was explicitly set to None. The subsequent 2026-10-07 opt-in smoke passed both canonical image architectures against real MariaDB and Redis, with the installed directory SDK over synthetic HTTP and the public installed Waygate SDK over real Uvicorn HTTP. This is isolated acceptance, not production migration, live Keystone/cloud/dataplane or publication evidence. No runtime defect was found; runtime source and migrations 001–005 were unchanged by this smoke slice.

## Operator handoff (run only after integration approval)

Production schema upgrade, before updated API/worker startup: `uv run waygate-migrate --database-url "$WAYGATE_DATABASE_URL" --apply`. Back up the database first. Existing 001–004 checksums are unchanged; 005 adds NULL owner_user_id without assigning legacy clients or changing credentials. This SQL CLI is MariaDB-specific, not a SQLite migration runner.

Default local regressions use disposable file-backed SQLite initialized from ORM metadata, a local synthetic Keystone token HTTP boundary, and the registered FastAPI application. The separate opt-in container smoke below starts only its own API/worker, MariaDB and Redis; it does not enqueue provisioning jobs or use production credentials. HTTP credentials use `X-Auth-Token`, with optional matching `X-Project-Id`; no role headers are trusted.

Prepare dependencies with `uv sync --extra service --extra dev --frozen`. Default focused definitions are `uv run pytest tests/test_native_service_grades.py tests/test_migrations.py`; the parent already ran its selected native/old regression gate and it was not repeated here. The dev-only aiosqlite dependency is locked at 0.22.1. The default HTTP fixture uses the real main.app lifespan, real Keystone v3.Token/get_access token authentication against local synthetic HTTP, and file-backed SQLite; its trusted directory client is mocked. Only the separate real-image smoke below proves the installed trusted directory SDK and MariaDB migration/locking. Full service serial/four-worker, SDK-suite and repository-wide lint/release gates remain parent responsibilities, not claims of this scoped smoke.

| Smoke endpoint | Required behavior |
| --- | --- |
| `GET /v1/health` | Public process health only |
| `GET /v1/servers`, `GET /v1/servers/{server_id}` | Inventory role plus reader/member, no credential/error-detail leakage |
| `GET /v1/servers/{server_id}/clients` | Nonsecret metadata including nullable owner_user_id |
| `POST /v1/servers/{server_id}/clients` | Client editor plus member; validated owner defaults to caller; tunnel_conf additionally requires current connect-user on enabled owned profile, otherwise null; no-store |
| `PATCH /v1/servers/{server_id}/clients/{client_id}` | Editor update and assign-once owner while NULL; transfer 409, clear 422; any enabled change requires clients-admin |
| `GET /v1/servers/{server_id}/clients/{client_id}/config` | Connect-user owner of enabled client only; no admin/system bypass; no-store |
| `DELETE /v1/servers/{server_id}/clients/{client_id}` | Clients-admin; user/editor denied |
| `POST /v1/servers/{server_id}/agent-token/rotate`, `DELETE /v1/servers/{server_id}` | Gateways-admin; user/editor denied |
| `POST /v1/servers/{server_id}/networks`, `DELETE /v1/servers/{server_id}/networks/{attachment_id}` | Routing-admin; user/editor denied |
| `POST /v1/servers/{server_id}/export`, `POST /v1/servers/{server_id}/import` | Clients-admin and routing-admin; export is owner-scoped subset with exclusion count/IDs; imported owner remains NULL |
| `GET /v1/admin/resource-policies`, catalog GET, policy PUT | Verified system-admin only; service admin denied |
| `/v1/servers/{server_id}/agent/{register,desired-state,status}` | Existing server-bound durable bearer authority unchanged |

Repeat foreign-project requests as waygate_admin and verified system-admin: existing resource filters must return 404. Persistent SQLite smoke is not a substitute for MariaDB migration/locking, live Keystone, Nova/Neutron or WireGuard dataplane evidence.

## Isolated acceptance receipt — 2026-10-07

Run from this repository only. Docker Desktop supports native arm64 and emulated amd64 execution. Hosted image publication remains amd64-only; these local receipts do not assert published multiarch tags. The gateway image/VM agent source was unchanged and no gateway image was built.

```sh
uv sync --extra service --extra dev --frozen
uv pip install --python .venv/bin/python --no-deps ./sdk
docker buildx build --platform linux/arm64 --file docker/Dockerfile --target waygate-api --load --tag waygate-native-20261007-api:arm64 .
docker buildx build --platform linux/arm64 --file docker/Dockerfile --target waygate-worker --load --tag waygate-native-20261007-worker:arm64 .
docker buildx build --platform linux/amd64 --file docker/Dockerfile --target waygate-api --load --tag waygate-native-20261007-api:amd64 .
docker buildx build --platform linux/amd64 --file docker/Dockerfile --target waygate-worker --load --tag waygate-native-20261007-worker:amd64 .
WAYGATE_NATIVE_CONTAINER_SMOKE=1 uv run pytest tests/test_native_service_grades.py -k native_built_images_and_mariadb_upgrade -q -s --tb=short
uv run ruff check tests/native_container_smoke.py tests/test_native_service_grades.py
```

The existing environment was used; the SDK install, four builds, smoke and scoped lint commands above were executed. The sync line is a reproduction prerequisite, not a freshly executed receipt. Result: **2 passed, 152 deselected in 20.49s**; scoped Ruff passed. Tests are skipped unless explicitly opted in. The helper provisions fresh random-name MariaDB 11.4/Redis 7 containers, loopback-only ephemeral SQL/API ports and a dedicated network, and cleans up only those containers/anonymous volumes/network. It never accepts a production DSN. Synthetic directory HTTP binds a temporary host port for Docker access and is closed at teardown.

| Image | Observed machine | Local image ID |
| --- | --- | --- |
| API arm64 | aarch64 | `sha256:852482167f097c046abb3aa1ad93a2d6c82cfce08db3d9e333d77f929d1127a2` |
| Worker arm64 | aarch64 | `sha256:374f798ccea72e379e4c75f647e0954ae493700866f4c24574654ec3e02c006e` |
| API amd64 | x86_64 | `sha256:f64e927563ac346ef47ce3c37a282562f5dab2f1321be8faea7a61d916527f7d` |
| Worker amd64 | x86_64 | `sha256:6e0f78bd15179c0accf3fd2c93dc5d6d1c605a3f0454963f372ac5bb72ab055e` |

- **Real upgrade:** isolated MariaDB reported `11.4.12-MariaDB-ubu2404`. The checksum runner seeded 001–004 before inserting legacy server/client rows containing generated AES-GCM client private-key, PSK and agent-bearer ciphertext. Server creator metadata deliberately did not identify an owner. The built image's `waygate-migrate --database-url <isolated-internal-DSN> --apply` applied 005. Comparing all pre-existing columns across server/client/job/attachment/policy tables and the original ledger paths/SHA-256/applied timestamps passed. Every legacy owner remained NULL, and a second migration run had no pending entries. No migration file or historical identity was edited.
- **Reopen/assignment:** dispose and reopen SQL/application pools without rebuilding schema; legacy owner remains NULL and credential ciphertext/decryption survives. Two concurrent competing store claims on one unassigned profile yield one winner and one owner conflict under MariaDB's parent-row lock; reconnect preserves the winner. HTTP PATCH validates enabled membership and assigns an unknown owner once; disabled/unknown owner 422, transfer 409, clear 422.
- **Actual SDK/HTTP:** no authentication dependency or trusted directory-client override in the image. Installed python-keystoneclient reads `/roles`, grouped `/role_inferences`, `/role_assignments` with effective project queries and `/users/{id}` from the synthetic HTTP directory. Installed public `register(Connection(...))` performs root and versioned discovery, server inventory and owned PSK-bearing config download over Uvicorn HTTP.
- **Tenant boundaries:** plain member/project-admin denied; reader receives nonsecret inventory, cannot create; native reader baseline plus service-admin still cannot write. User cannot create or download unknown/foreign/disabled profiles. Editor creates/updates, clients-editor-only issuance has tunnel_conf null, and editor cannot delete/rotate/route/export. Admin revokes/deletes/rotates and exports only caller-owned/unassigned profiles with no-store and scope/exclusion metadata; corrupt foreign-assigned PSK is excluded without a decrypt-failure log. Foreign project returns 404 and service-admin cannot read global resource policies. Removing current DAG edges or effective assignments denies an unchanged old admin token.
- **Machine/worker:** tenant grades cannot authenticate callbacks. Server-bound bearer permits desired-state, register and status; pending bearer promotion invalidates old bearer, foreign server returns 401, and tenant downgrade does not disable machine status. Workers performed 8 arm64 / 9 amd64 real queue SELECTs, with no cloud jobs. API and worker SIGTERM shutdown markers appeared and all four processes exited 0.

Limits: the earlier parent-reported 313 selected regressions are separate evidence, not rerun or a full-suite result here. No real Keystone mutation, Nova/Neutron operation, gateway build/boot, WireGuard dataplane, production schema application, Kolla rollout, commit, publication or registry push occurred. SQLite's existing proof is not used as MariaDB upgrade evidence.

Canonical working architecture review/stamp/check subsequently passed over 117 files, digest `ef2c76da2b065482e5504b6e9b0639e08e547af7eabcf97f5cbfe4b3f404f961`. The reviewed scope was native auth/DAG/owner checks, API callsites, ORM/store/schema/migration/export/import, SQLite dependency/fixture adaptations and the new opt-in image smoke. Used `python3 scripts/check_architecture.py --stamp --summary <scoped-review-summary>` followed by `python3 scripts/check_architecture.py`; no index change or staged check was performed.

Final parent integration gate subsequently executed: `uv run pytest tests -q` →625 passed/3 skipped; `uv run pytest tests -n 4 --dist worksteal -q` →625 passed/3 skipped; `uv run ruff check .` passed; `uv run --project sdk pytest sdk/tests -q` →44 passed with44 existing OpenStack SDK `service_type` deprecation warnings; `uv run --project sdk ruff check sdk` passed. These later receipts complete the previously unexecuted full-suite/SDK/lint gate and do not change the isolated cloud/dataplane/publication limits above.

