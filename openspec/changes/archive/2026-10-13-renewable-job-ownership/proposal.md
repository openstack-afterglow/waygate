## Why

SQL jobs currently expire after 900 seconds without renewal and an unshielded SDK thread can outlive its connection and DB during shutdown. Accepted creates without a durable returned ID can be replayed, producing duplicate tenant resources.

## What Changes

- Renew each running SQL attempt independently of provider I/O and fence subsequent mutations against current, non-stale ownership.
- Drain connection creation and SDK calls before close, claim transition or delegation retirement; SIGTERM stops polling and drains the current job.
- Persist owned create intents and returned identities in existing durable server records. Retry observes an exact owned target or remains unresolved, never repeats a committed create intent.
- Suppress native SDK POST retries only in operation-bound execution sessions.
- Define SQL/native loopback HTTP regressions and actual-worker process smoke; the parent's 2026-10-14 local acceptance receipts are recorded in the [design](design.md#parent-execution-receipt-2026-10-14) and [tasks](tasks.md#evidence-status), not live-cloud or deployment proof.

## Capabilities

### New Capabilities
- `durable-job-ownership`: Renewable per-server attempts, mutation fencing, drained lifecycle and ambiguity-safe provider creation.

### Modified Capabilities

None. Caller/project authorization, native service grades, node agent and request streams are unchanged.

## Impact

Scope: `waygate/services/jobs.py`, `provisioner.py`, `execution.py`, required `worker.py` lifecycle changes, related tests and documentation. Existing SQL schema and SKIP LOCKED queue remain authoritative; no global leader, schema migration, admin/service-account tenant fallback, Afterglow edits or agent scheduler changes.
