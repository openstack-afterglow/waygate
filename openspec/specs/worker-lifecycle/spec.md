# worker-lifecycle Specification

## Purpose
Define canonical CLI signal shutdown, awaited resource cleanup and preservation of durable interrupted-job recovery state.

## Requirements
### Requirement: Worker process terminates through resource cleanup
The canonical worker CLI SHALL handle SIGTERM and SIGINT by cancelling and awaiting its serve task, SHALL execute existing database cleanup, and SHALL exit successfully for those requested shutdowns. It SHALL preserve durable interrupted-job leases and attempts for existing recovery, not treat shutdown cancellation as a new cloud-operation failure.

#### Scenario: Shutdown during pending database connection
- **WHEN** the worker has connected to a loopback database listener which has not supplied its handshake and receives SIGTERM or SIGINT
- **THEN** the process exits with status 0 and its database connection closes rather than requiring SIGKILL

#### Scenario: Interrupted claimed job
- **WHEN** shutdown cancellation interrupts a claimed job
- **THEN** its existing durable lease and attempt state remain available to the unchanged recovery path

