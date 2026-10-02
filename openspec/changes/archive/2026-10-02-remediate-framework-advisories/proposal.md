## Why

Candidate `29f28cdcb572660fc3f693457b007435c0da81ef` (service 0.3.0 / SDK 0.2.0) inherits five Starlette advisories while FastAPI 0.125.0 requires Starlette below 0.51. A compatible dependency-only update is needed before Main can verify the candidate again; forcing Starlette 1.x beneath the old FastAPI constraint is not acceptable.

## What Changes

- Select FastAPI `==0.136.3`, retain flat router registration, and declare Starlette `>=1.3.1` in the existing service extra.
- Resolve the root uv lock to FastAPI 0.136.3 / Starlette 1.3.1, preserving unrelated dependency selections and service/SDK versions.
- Record metadata compatibility, advisory version boundaries, unchanged source/contract boundaries and Main's pending verification in architecture, release notes, changelog and this checklist.
- Do not change route registration, middleware, authentication, rate limits, logging, SDK public operations, database schema, Host-domain policy or deployment configuration. Do not select FastAPI 0.137+ or add compatibility shims.

## Capabilities

### New Capabilities

None. This is dependency remediation, not a new product capability.

### Modified Capabilities

None. Existing repository-workflow and ci-workflow requirements remain unchanged; no API or policy requirement changes are intended. The change's specs artifact records that there is no behavioral delta.

## Impact

Implementation edits are limited to root `pyproject.toml` and `uv.lock`; documentation edits remain in this checkout. Main owns frozen synchronization, final suites/lint, actual API/SDK/logging smoke, amd64/arm64 images, architecture stamp/check, commit/push and any separately authorized production action. Existing candidate evidence predates this update and cannot verify it. Metadata incompatibility or a required contract/policy change must be reported before expanding this design.
