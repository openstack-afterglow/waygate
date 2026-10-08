## Context

The API preflights and synchronous routing, and the durable provision/delete worker, currently authenticate the configured service password against a caller-selected tenant project. Jobs retain actor IDs but no delegated execution authority. Existing native role graph checks must remain authoritative and job leases/terminal-state recovery must remain unchanged.

## Goals / Non-Goals

**Goals:** tenant resources and quota remain in the caller's project; service user stays in its own project; current role revocation stops new cloud I/O; bounded Trust grants and cleanup survive worker restarts; authorized deletion is independent of the original creator.

**Non-Goals:** production role cleanup or migration, policy relaxation, new API responses, automatic resource-policy replacement, changes to agent/client key authority, or a shared cross-repository auth package.

## Decisions

1. Use two-hour per-operation Keystone Trusts with impersonation and only a uniquely resolved current global member role. Trustee identity is resolved from service-project authentication. Password-with-trust authentication omits project selectors. Validate token Trust fields, exact actor/project/role and expiry; no tenant password fallback.
2. Store a durable execution grant separately from jobs and bind each job to one grant. Admission records purpose, project/server, actor, trustee, role and deadline; only provider-confirmed active grants can be bound. Failed or abandoned admissions retain a finite deadline and pending cleanup. Legacy jobs cannot infer a grant from their actor IDs.
3. A guarded Keystone session rechecks current enabled identity/project, exact service capability and live grant/token metadata before each SDK request. This includes read/discovery calls and token renewal; directory sessions used for this check are independent. The overhead is an intentional revocation boundary, not an authority cache.
4. Cleanup is separate from cloud execution state. Terminal/expired/unbound grants are deleted by the worker and marked revoked; cleanup failure never requeues a completed cloud mutation. A fresh authorized delete request can replace a queued delete's delegation; a running leased attempt is not rewritten.
5. Provisioner/network services accept the admitted connection explicitly; the execution owner closes it. API and jobs own delegation lifetime and cleanup.
6. For zero-disk flavors only, use Nova image-to-volume root block-device mapping with delete_on_termination. Root volume size is max(10 GiB, image min_disk). Positive-disk image-backed boot remains unchanged. Do not grant admin or change zero_disk_flavor policy.

## Risks / Trade-offs

- Directory/Trust service outage blocks new cloud work; do not report an authorization outage as token expiry or silently elevate. Existing mutation retries remain bounded.
- Role revocation between a provider request and its response cannot undo already accepted work. Cleanup also respects revoked authority; partial resources remain discoverable for a new authorized deletion.
- A crash after Keystone creates a Trust but before its reference commits can leave that Trust until its finite two-hour expiry; no durable requester token/password is stored to bridge that window.
- Old jobs/resources need explicit new authorization. The code does not remove existing project role assignments; operators retire them only after a separately approved cutover proves they are unused.
- Native SDK/HTTP fixture proof is not production Keystone policy/Cinder quota acceptance.
- Trust deletion uses the service identity: Keystone `identity:delete_trust` is `ADMIN_OR_TRUSTOR`, satisfied today by the existing service-project `admin` registration. If that registration is ever reduced, cleanup must move to the impersonating trust-scoped token (trustor) and Trusts whose trustor lost roles stay inert until their finite expiry.
