# Changelog

## Unreleased — service 0.3.1 / SDK 0.2.0 candidate

### Changed

- Metadata-only root service patch atop `a6e7dfd3f5f4745fcf6c9e059a0e4e9b66531e55`; no new features, dependency changes or SDK bump. All 0.3.0 functionality, framework/signal fixes, migration 004, source-build pin, old prebuilt references and operator prerequisites remain retained.
- Main `cf72df3` already integrates the same baseline tree. Any future integrated 0.3.1 release commit, tag/image publication, manual wheel/GitHub Release and production rollout require owner authorization; remote `v0.3.1` is absent. Later manual publication examples use 0.3.1 and have not been executed here.

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
