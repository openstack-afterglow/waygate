## Why
Native APIs currently accept any project token for sensitive client credentials and mutations. Enforce the exact Waygate grade/action contract independently of any BFF.

## What Changes
Explicit capability checks for inventory, connect, client/gateway editing, destructive/key administration and routing. Persist and validate client owner_user_id with additive migration 005. Ordinary connect users receive only their assigned profile. Global policies retain verified Keystone system-admin authority; agent callbacks remain separate.

## Impact
Waygate auth, native routes, models/store, migration bundles and regression tests. No Afterglow, real cloud role mutation, production deployment or publication. Parent-reported selected regressions and the subsequent isolated arm64/amd64 image/SDK HTTP/real MariaDB migration acceptance are recorded in design.md; full release gates remain separate.
