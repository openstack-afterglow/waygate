## Context

The source review found SQL `SKIP LOCKED` claims with a 900-second stale threshold but no renewal, and unshielded provider/factory threads that could outlive worker cancellation, DB disposal and connection/Trust retirement. The queue already divides jobs: a second global leader would conflict with its per-server/attempt authority. The implementation slice supplied source/test definitions without running checks; the parent's local SQL/native HTTP/process execution receipts are now recorded below.

## Goals / Non-Goals

**Goals:** Keep healthy long-running attempts owned independently of SDK latency; prevent former/stale attempts from beginning subsequent mutations; drain owned SDK/factory work before releasing resources; make accepted-response loss non-replayable through durable intent and exact observation.

**Non-Goals:** No request/agent policy changes, tenant admin/service-account fallback, global leader, new agent scheduling or request-stream coordination, migration, deployment, publication or live-cloud evidence.

## Decisions

1. **Renew the existing SQL lease, not a separate leader.** `Claim` identifies job ID, attempt, project and server; every 30 seconds its independent asyncio task locks and validates the running row before refreshing `claimed_at`. Freshness is strictly newer than `now - 900s`; the exact boundary is stale. Once ownership checking fails, that attempt remains locally lost and cannot revive itself. Completion/retry also require a fresh matching attempt. Existing `SKIP LOCKED` and parent-server admission remain authoritative. Alternative: increasing TTL merely postpones duplicate execution; a global leader removes useful SQL concurrency.

The first zero-attempt, no-resource provision claim also commits a version-1 `waygate.provision_protocol` admission marker bound to that job/project/server in the same SQL transaction, before any factory or SDK I/O. This proves that a later missing create intent belongs to the new intent-before-POST protocol: a transient failure before the first create may retry normally. Attempted legacy rows never receive this marker retroactively; missing, unsupported or differently bound provenance cannot authorize an unrecorded create. Any committed resource intent still requires exact recovery and is never replayed, regardless of the protocol marker.

2. **Fence at both lifecycle and actual native transport boundaries.** Intent/returned-identity writes lock the current job and server in the transaction. Provider boundaries check before entering a drained thread; the operation-bound Keystone session captures the claim and checks it before requests and final `_send_request`, after slow directory/auth/discovery. The latter also catches mutations inside SDK helpers and pagination. Lazy SDK proxy discovery must run inside the provider thread, never on the claim's asyncio loop. Caller Trust/current capability/project checks are retained independently. Alternative: checking only when the job starts cannot fence a slow factory or subsequent mutation after takeover.

3. **Own work until it exits.** `drain_task`/`drain_thread` shield work and tolerate repeated caller cancellation, waiting for completion before propagating cancellation. A canceled connection factory closes a successfully returned connection only after the factory exits. `process_one_job` drains its owned job task; SIGTERM/SIGINT sets a stop event instead of canceling it, so polling stops and current-job completion precedes DB close. Grant cleanup excludes running bound jobs. No lease/job/connection is retired merely because its caller canceled. Alternative: plain `asyncio.to_thread` cancellation only cancels the awaiter, not the SDK thread.

4. **Intent precedes POST; retry is observation, not create.** Existing `WaygateServer.resource_policy_snapshot["waygate.provision_intents"]` contains port/VM/FIP UUID markers, project and selected network/port scope plus returned identities; existing ID columns are updated immediately on response. Policy entries remain intact. Neutron descriptions carry exact owned markers; Nova metadata carries `waygate_create_intent` and the gateway/server markers. Recovery requires a unique exact marker, project, selected network and VM/provider-port relationship; ID-based recovery also validates scope. Missing, conflicting or ambiguous observations remain unresolved. A committed intent cannot authorize a second POST, even if the first operation never reached the provider. Ordinary errors preserve durable resources instead of destructive rollback. Deletion resolves pending intent before tombstoning and requires its independently admitted delete Trust. Alternative: name-based adoption can select unrelated tenant resources; retry-after-empty-list can duplicate an eventually visible accepted create.

Deletion without resource intent/identity remains supported when exact SQL job history proves either that all provisioning attempts are zero or that every attempted provision belongs to its supported, job/project/server-bound intent-before-POST admission marker. Missing, attempted legacy, unsupported or unbound history is not such proof. A durably identified floating IP that is already detached may be deleted only after exact project/network/marker validation; association to an unrelated port still fails closed. SDK discovery filters are not ownership evidence: the split attached-port/FIP cleanup validates returned scope before mutation.

5. **Suppress native replay in the narrow execution session.** Operation-bound POSTs set connection/status retries to zero and disable redirect and reauthentication replay (`allow_reauth=False`). Initial Trust authentication and current caller/project capability checks remain mandatory; a mutation is not retried with alternate credentials. GETs and unrelated requester sessions retain existing behavior. Tests explicitly configure the installed adapter to retry accepted 503 responses, proving the override rather than relying on defaults. No SDK global monkeypatch or authorization fallback is introduced.

The current lock selects openstacksdk 3.3.0 and keystoneauth1 5.15.0. The [Session request API](https://docs.openstack.org/keystoneauth/latest/api/keystoneauth1.session.html) exposes per-request `connect_retries`, `status_code_retries` and `redirect`; requests-library `allow_redirects` is not the authoritative redirect switch. The final-send fence deliberately uses the installed Session's `_send_request` boundary, so future SDK upgrades must retain the slow-authority/final-send native regression rather than assume this private transport contract is stable. Static source/API inspection is not execution evidence.

## Risks / Trade-offs

- **Unresolved is deliberately conservative:** eventual absence does not prove nonacceptance. Operators must observe/reconcile exact owned resources under valid caller authority; clearing intent to force another POST is unsafe. The three-attempt queue limit remains; exhaustion retains records rather than claiming cleanup.
- **Drain can exceed deployment grace:** give the current job and SDK calls enough shutdown time, including VM waits. SIGKILL cannot drain; its recovery depends on committed intent and exact observation. A POST already sent cannot be revoked by SQL takeover; the former attempt is blocked from subsequent sends/writes while its already-started call drains.
- **Legacy partial records:** drain old workers before cutover. A retried legacy partial row without adequate durable identities/intents remains unresolved rather than assuming an accepted POST did not occur. Do not run a mixed renewal/nonrenewal fleet or erase records to force replay.
- **No schema migration:** JSON intent shares an existing private durable record, avoiding a separate ledger with competing authority. Client-visible schemas and policy-selection entries remain unchanged.
- **Evidence limit:** default file-backed SQLite tests exercise persistent SQL but do not prove MariaDB locking. The opt-in native suite uses disposable migration-built MariaDB for real `SKIP LOCKED`/transaction evidence. Synthetic HTTP is not real cloud acceptance or deployment evidence. FIP support is implemented, while the named accepted-response-loss native cases target port/VM.

## Parent execution receipt (2026-10-14)

Evidence source: the Waygate section and common boundary of `local://ownership-native-evidence.md`. The parent ran checks on a frozen public clone synced byte-for-byte from the canonical working tree, including concurrent WIP (branch `dev`, HEAD `eedebf28`; snapshot 155 files, manifest digest `32f074cd72807904ad3a4ee6414b2b3a13242bc288b1edcec10ab9f36b26670f`). Logs, JUnit XML and per-lane execution JSON are under `/Users/pieroot/.local/share/afterglow-proofs/afterglow-process-ownership-n7xrnua4/`. These results are `test-passed`, not `live-verified`; they are parent execution evidence, not checks run by the implementation slice.

- **Focused SQLite:** `tests/test_execution_delegation.py tests/test_waygate_jobs.py tests/test_waygate_provisioner.py tests/test_observability.py` on file-backed SQLite: **115 passed**.
- **Native MariaDB:** `tests/test_execution_delegation.py` with `WAYGATE_DELEGATION_MARIADB_URL`, disposable MariaDB 11.4 and per-test databases built from the migration ledger: **49 passed, 0 skipped**, including:
  - `test_native_worker_process_signal_drains_sdk_before_database_shutdown[SIGTERM,SIGINT]`: actual worker subprocess holding SDK work.
  - `test_native_accepted_create_response_failure_recovers_without_second_post[disconnect|503|401 × port|vm]`: accepted port/VM response-loss recovery without a second POST.
  - `test_native_lost_attempt_cannot_make_next_provider_mutation_or_release_lease`.
  - `test_native_takeover_during_authority_check_blocks_final_http_send`.
  - `test_native_admitted_protocol_recovers_failure_before_first_create[retry|delete]`.
  - `test_native_stale_retry_attempt_cannot_write_server_status_after_takeover[provision|delete]`.
- **Full service suite:** `pytest tests -n 4 --dist worksteal`: **671 passed, 3 skipped** (2 opt-in Docker/MariaDB image smokes, 1 live lifecycle requiring `WAYGATE_RUN_LIVE`). Actual-process signal tests also ran on SQLite: `tests/test_observability.py::test_worker_signal_drains_pending_database_connection_before_exit[SIGTERM,SIGINT]`.
- **Lint:** `ruff check .`: **all checks passed**. B023 was fixed by default-binding the floating IP in the cleanup lambda; SIM102 by combining the legacy-deletion condition while preserving short-circuit order. CI runs only `ruff check .`; HEAD had 4 unformatted files and no formatting was applied.
- **Architecture:** stamp/check is in the parent receipt (isolated clone, shared marker untouched). No shared review marker/digest/UTC block was changed or manually forged by this evidence update.

**Boundaries:** disposable owned fixtures only: Docker MariaDB 11.4 (tmpfs, loopback `127.0.0.1:56498`) and Docker Redis 7 (loopback `127.0.0.1:56497`); providers are synthetic loopback HTTP or in-process fakes. No private config, credentials, live OpenStack/Keystone/K3s/Nova/Octavia/Glance/KVM, paid inference, deployment, image publication, commit, stage or push. Production Redis/Sentinel failover, async-replication lease/journal loss, promoted-node TIME skew, mixed-version rolling upgrade and live provider/cloud remain unqualified. File-backed SQLite does not establish MariaDB locking; the separate MariaDB lane supplies that local SQL boundary. Named accepted-response-loss cases cover port/VM, not FIP response-loss qualification.

## Parent validation and actual-worker/process smoke recipe

No command below was executed in the implementation slice. The parent results above identify the lanes actually executed; this recipe is not an additional serial-suite or live-cloud receipt. Architecture commands are for the parent's isolated review clone only, never the shared checkout.

```sh
# Registered application, installed keystoneauth1/keystoneclient/openstacksdk,
# persistent SQL, loopback synthetic Keystone/Nova/Neutron/Glance.
uv run pytest tests/test_execution_delegation.py tests/test_waygate_jobs.py tests/test_waygate_provisioner.py tests/test_observability.py -q

# Actual Python worker subprocess, real SIGTERM and SIGINT during a held
# installed-SDK create POST; not a serve() mock or an idle polling receipt.
uv run pytest tests/test_execution_delegation.py::test_native_worker_process_signal_drains_sdk_before_database_shutdown -q

# Configure WAYGATE_DELEGATION_MARIADB_URL in the environment to a privileged
# disposable MariaDB DSN (never production; tests CREATE/DROP randomized DBs).
# Parent MariaDB lane (49 passed, 0 skipped):
uv run pytest tests/test_execution_delegation.py -q

# Parent integration gates, after all edits are integrated:
uv run pytest tests
uv run pytest tests -n 4 --dist worksteal
uv run ruff check .
# Parent isolated review clone ONLY; leave the shared architecture marker untouched:
python3 scripts/check_architecture.py --stamp --summary "Reviewed renewable SQL ownership, durable create recovery, SDK/factory drain and native/process tests"
python3 scripts/check_architecture.py
```

The process smoke seeds an admitted job through the real app, launches `sys.executable -m waygate.worker` with isolated fixture config/DB, holds its native Neutron POST, sends each signal and observes the process remains alive, its job running, Trust not retired and a competing claim unavailable. Releasing HTTP must lead to job completion, one VM/port, Trust retirement, shutdown log and exit 0. The parent's passing native SIGTERM/SIGINT cases and proof root are recorded above and in tasks 4.1–4.3. Architecture stamping belongs to the parent's complete integrated source review in an isolated clone; the shared marker remains untouched.
