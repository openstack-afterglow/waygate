## Implementation
- [x] Implement explicit native capability dependencies and verified owner assignment.
- [x] Persist nullable client owner with additive migration and fail-closed profile access.
- [x] Gate gateway, routing and credential import/export actions; preserve machine authority.
- [x] Add/update behavior regression tests and persistent SQLite synthetic Keystone smoke.
- [x] Update architecture/changelog and schema/smoke operator instructions.

## Parent integration gate
- [x] Parent reported selected native/old regressions: 313 passed after the legacy fixture owner_user_id=None correction; do not rerun or relabel this as a full-suite result.
- [x] Build canonical API/worker targets for linux/arm64 and linux/amd64 and execute each image; observed aarch64/x86_64, real worker queue SELECTs 8/9, API/worker exit-0 shutdown. Exact local image IDs are in design.md.
- [x] Isolated REAL MariaDB 11.4.12 upgrade: checksum runner seeds 001–004, seed rows contain encrypted client keys/PSK/agent bearer and unknown owner, packaged image CLI applies 005; original ledger/records/ciphertext preserved, NULL owners maintained, reopen and competing assign-once claims pass. No production apply; migrations 001–004 identities unchanged.
- [x] Registered app/Uvicorn native HTTP with installed Keystone directory SDK over synthetic directory HTTP and installed public Waygate SDK: reader/user/editor/admin and client-owner boundaries, downgrade, export subset and machine register/desired-state/status/token handoff pass on both architectures. Opt-in smoke: 2 passed, 152 deselected in 20.49s. Scoped native Ruff passed. No runtime defect found.
- [x] Update scoped native architecture/changelog/OpenSpec after smoke, retaining historical evidence and production/cloud/publication limits.
- [x] Reviewed affected native source/callsites, schema/manifest and fixture adaptations; canonical working architecture stamp/check passed over 117 files: source_sha256=ef2c76da2b065482e5504b6e9b0639e08e547af7eabcf97f5cbfe4b3f404f961. Real index was not changed; no staged-guard claim.
- [x] Parent executed the remaining integration gates: serial service suite625 passed/3 skipped and four-worker suite625 passed/3 skipped; repository-wide Ruff passed; SDK44 passed and SDK Ruff passed. The installed OpenStack SDK emitted44 existing service_type deprecation warnings. These are separate from the earlier selected313 and opt-in image2 smoke receipts; no production migration or publication is implied.
