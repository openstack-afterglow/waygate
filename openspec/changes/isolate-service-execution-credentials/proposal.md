## Why

Tenant-scoped service password authentication requires Waygate's service user to be a member of every target project. Separate current user authorization from least-privilege execution so project members cannot remove a shared service principal and the worker cannot outlive revoked user authority.

## What Changes

- **BREAKING:** remove tenant service-password connection factory; old queued jobs without explicit delegation fail closed and require a current authorized user to re-admit them.
- Admit bounded, caller-created Keystone Trusts for gateway provision/delete and routing changes. The trustee is the configured service identity, not a tenant member. Delegate only the current global `member` role and impersonate the requesting user.
- Persist operation/project/server/actor scope and Trust references, revalidate live enabled identity/project/capability before cloud requests, and clean up grants independently of cloud mutation retry.
- Use volume-backed boot for zero-disk flavors, preserving positive-disk image-backed boot and Nova's existing role policy.
- Keep project quotas, current native capability graph, agent machine authority, client credentials and API/SDK response shapes.

## Capabilities

### New Capabilities

- `isolated-tenant-execution`: per-operation least-privilege execution, bounded delegation, current authorization and durable revocation.

### Modified Capabilities

- `repository-workflow`: operator credential prerequisites no longer require tenant membership or admin-only zero-disk image-backed boot.

## Impact

A new additive schema migration stores delegation references and job binding; previously applied migrations and encrypted agent/client credentials remain unchanged. API and worker require the same candidate and schema. Keystone Trust create/consume/delete and Cinder volume-backed boot must be qualified with native SDK/HTTP fixtures before release and with separately approved cloud acceptance before production. No production permission removal, schema application, resource mutation, build/upload, publication or deployment occurs in this change.
