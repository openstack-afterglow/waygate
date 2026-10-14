# durable-job-ownership Specification

## Purpose
Define renewable SQL attempt ownership, drained worker shutdown and non-replayable provider create recovery while retaining current requester/project delegation.
## Requirements
### Requirement: SQL attempt ownership renews independently of provider latency
The worker SHALL retain SQL per-server/job/attempt authority, renew a healthy running claim independently of slow provider I/O, and reject expired or replaced attempts from renewal, subsequent provider mutations and job transitions. SQL queue division SHALL NOT be wrapped in a conflicting global leader.

#### Scenario: Three workers contend beyond the original TTL
- **WHEN** a healthy attempt continues provider I/O longer than its original 900-second lease and two or three workers query the queue
- **THEN** independent renewal keeps its SQL claim fresh and contenders cannot take that job or a conflicting same-server job.

#### Scenario: Old attempt resumes after takeover or exact stale boundary
- **WHEN** a former attempt returns from slow I/O after replacement, or its lease reaches the stale threshold without renewal
- **THEN** it drains the already-started call but cannot begin another provider mutation, revive the lease, overwrite returned identity or release the current job.

#### Scenario: Directory verification is slow
- **WHEN** ownership changes during current-authority/auth/discovery verification before SDK transport
- **THEN** the final native HTTP send rechecks ownership and the former attempt emits no mutation.

#### Scenario: Paused retry resumes after takeover before its status write
- **WHEN** a provision or delete retry passes its ownership check, pauses, and another attempt replaces it before it writes `CREATING` or `DELETING`
- **THEN** the status write revalidates the exact current attempt in its SQL transaction, leaves server status unchanged and lets the replacement keep ownership.

### Requirement: Provider work is drained before lifecycle retirement
The worker SHALL stop polling on SIGTERM/SIGINT and drain current job, SDK and connection-factory work with DB/connection available before closing, transitioning/releasing jobs or retiring their delegation. Repeated cancellation SHALL NOT orphan owned threads.

#### Scenario: Signal arrives during an accepted SDK create
- **WHEN** the real worker process receives SIGTERM or SIGINT while an SDK POST is held
- **THEN** SQL ownership remains running and DB/connection stays usable, no early Trust retirement occurs, and shutdown follows operation drain and job completion.

#### Scenario: Cancellation arrives during connection creation
- **WHEN** a factory thread returns a connection after its caller is canceled
- **THEN** the thread is awaited before closing the returned connection, and no job release or DB close happens before drain.

### Requirement: Committed create intent is never replayed
Before creating a provider port or VM, the lifecycle SHALL commit owned intent in existing durable records and SHALL promptly persist returned identity. Recovery SHALL observe an exact owned target under its original caller/project authority or remain unresolved; absent/ambiguous observation SHALL NOT authorize another create POST or terminal deletion. Native SDK replay of operation-bound POSTs SHALL be suppressed without changing unrelated request policy or using tenant service/admin fallback.

#### Scenario: Provider accepts but response is lost or retry-provoking
- **WHEN** the installed SDK receives a dropped connection or 503 after the provider accepted a port/VM POST
- **THEN** it sends one POST, retains durable intent, and recovery reuses a uniquely matching owned target without bearer rotation for an existing VM.

#### Scenario: Crash occurs between intent and returned identity
- **WHEN** a job restarts with intent but no returned identity
- **THEN** exact UUID marker/project/network/port observation resolves identity or leaves the operation unresolved with no new POST.

#### Scenario: Admitted protocol fails before its first create
- **WHEN** the first claim durably admitted the versioned job/project/server-bound intent-before-POST protocol and a transient native read fails before any create intent or POST
- **THEN** a later attempt may proceed under that unchanged admission marker and create each target once.

#### Scenario: Admitted pre-create failure is independently deleted
- **WHEN** a supported exact-bound provision has no create intent or resource identity after its native pre-create failure and a separately admitted authorized delete is queued
- **THEN** SQL history proves no unrecorded create, so deletion may finalize its tombstone without a tenant create POST; missing or unsupported attempted legacy provenance remains unresolved.

#### Scenario: Legacy or unsupported provenance has no create identity
- **WHEN** an attempted row lacks supported, exact-bound protocol admission and has no owned create intent or identity
- **THEN** retry remains unresolved, never retrofits admission or emits a new create POST.

#### Scenario: Target observation is absent or ambiguous
- **WHEN** a committed intent matches zero or multiple provider targets, or a target's scope conflicts
- **THEN** recovery preserves intent/resources and sends no replacement POST or unrelated destructive mutation.

### Requirement: Evidence remains scoped and explicit
Lifecycle changes SHALL include SQL and installed-SDK loopback HTTP test definitions plus actual-worker/process smoke instructions, preserving local request streams and node WireGuard behavior. Unexecuted acceptance SHALL be recorded as pending parent evidence, not test-passed, live or deployment proof.

#### Scenario: Implementation handoff without verification
- **WHEN** this scoped implementation completes before parent checks
- **THEN** docs distinguish implemented/test-defined from executed SQL/native HTTP/process acceptance and retain pending evidence gates.

