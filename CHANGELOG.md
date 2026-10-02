# Changelog

## Unreleased — service 0.3.0 / SDK 0.2.0 candidate

### Changed

- Dependency-only framework remediation after candidate `29f28cdcb572660fc3f693457b007435c0da81ef`: service extra FastAPI `==0.136.3` and explicit Starlette `>=1.3.1`, with root uv lock FastAPI 0.136.3 / Starlette 1.3.1. Published metadata allows the pair; unrelated package versions and the separate SDK lock remain unchanged. No route registration, middleware, SDK public contract, auth, rate-limit budgets, logging source, Host-domain policy, schema or deployment structure is changed.
- Starlette 1.3.1 is outside the five inherited advisory affected ranges; [version boundaries and sources](openspec/changes/archive/2026-10-02-remediate-framework-advisories/design.md#known-advisory-version-boundaries) are recorded without claiming verified runtime fixes or closed alerts. FastAPI 0.137+ included-router changes and compatibility shims are not introduced.

### Fixed

- CLI worker SIGTERM/SIGINT now cancels and awaits the existing serve cleanup. Real Docker worker termination changed from the reproduced137 after30s to exit0 on arm64/amd64 in under1s. Durable job lease/retry policy is unchanged; cloud job draining is not promised.
- Remove obsolete tests copying the old FastAPI0.125.0 pin instead of re-pinning implementation strings. Preserve wheel install/uninstall and optional-service dependency isolation checks.

### Verification status

Current framework and signal changes were exercised through canonical isolated API/worker images on aarch64/x86_64 with real MariaDB/Redis and an HTTP Keystone fixture. Real public SDK Connection, ownership/auth, JSON/+json/null/zero, malformed Host/path normalization, safe INFO/DEBUG logs, status budgets120/1200 and process SIGTERM exit0 passed. Missing/wrong Content-Type returns422; current shared agent, immutable-v0.1.4 cloud-init template and Afterglow JSON transports provide/preserve application/json. The running production prebuilt agent was not inspected. Final serial and four-worker suites each passed471 with1 opt-in live skip, SDK44 and root/SDK Ruff passed; architecture guards passed. No genuine cloud lifecycle, provider, publication, production rollout or default-branch alert closure is claimed.

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for complete current candidate changes, maintainer gates and immutable historical release records.
