# Implementation and verification

- [x] 1. Reproduce canonical worker SIGTERM failure: arm64, 937 real SQL polls, stop timeout 30s, worker exit137; API exit0. Read actual runner and existing cancellation/lease boundary.
- [x] 2. Add and run failing-before subprocess regression for SIGTERM/SIGINT during pending DB connect: return codes -15/-2 before the fix, both exit0 after it. The regression proves clean process exit, not database cleanup independently of OS descriptor closure.
- [x] 3. Add CLI-owned signal handling without changing serve/job lease/retry/API contracts; cancellation awaits the existing serve finally/close_db path.
- [x] 4. Regression and unchanged cancelled-job lease test passed (3 cases). Final canonical Docker API/worker images on aarch64/x86_64 performed real MariaDB queue polling; Docker stop -t30 completed in under1s with both exit0 and existing worker shutdown marker. No claimed cloud operation was executed; lease/retry source is unchanged.
- [x] 5. Architecture/release evidence updated; final serial/four-worker471 passed/1 live skip, SDK44 passed and both Ruff gates passed. Canonical working/staged guard passed f4a82dc0df31e3b3912156cc2ac004bca47ddf964ee67cf68ec11cf06c3751bc. Implementation is accepted for archive; parent records subsequent dev commit/push separately, never as production delivery.
