# Design

The private CLI async runner owns process signal handlers and one serve task. SIGTERM/SIGINT cancel that task; await propagates through the existing `serve()` finally/`close_db()` path. Cancellation exits normally, other failures still propagate. Remove installed handlers in finally. Library callers of `serve()` do not gain process-global handlers.

The existing job service treats cancellation as cancellation rather than a cloud-operation failure, retaining the durable running lease for recovery. Do not mark an interrupted job completed or increment retry attempts. This is orderly cancellation, not a promise to drain all in-flight cloud operations.

Regression: a real worker subprocess connects to an isolated loopback listener that intentionally withholds the MySQL handshake. Send SIGTERM/SIGINT after accept; require exit 0 and EOF at the listener. No sleep races, production DB, external cloud, or logging-wording assertions. Keep the existing cancelled-job lease regression.

Runtime: rebuild canonical API/worker images for arm64 and amd64, run the canonical isolated Compose API/worker/datastore path, observe genuine DB polls, stop worker with Docker SIGTERM and require exit 0 plus observed cleanup. No init override or test-only launch shim.
