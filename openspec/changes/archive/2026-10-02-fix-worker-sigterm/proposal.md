# Why

The canonical linux/arm64 worker completed 937 real SQL claim polls but ignored Docker SIGTERM; `docker compose stop -t 30` forced exit 137. Python is PID 1 and `asyncio.run(serve())` installs no SIGTERM handler. The existing `serve()` finally block therefore never closed the DB. API lifespan stopped with exit 0. This is a separate observed release defect, not a framework compatibility finding.

# What Changes

Own SIGTERM/SIGINT handling in the worker CLI lifecycle, cancel its existing serve task, await existing DB cleanup, and exit normally. Preserve durable job leases, attempts, admission and recovery behavior. Keep API/SDK/version/config/image commands unchanged. Add a subprocess regression for shutdown during a pending database handshake and prove final canonical containers on both architectures.

# Impact

Only worker lifecycle source, its consumer regression, and architecture/release/OpenSpec documentation. No production mutation, cloud jobs, or deployment configuration change.
