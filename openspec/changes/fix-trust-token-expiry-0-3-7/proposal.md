## Why

A real0.3.6 member create returned403. Matching grant timestamps, native Keystone token expiration86400 and installed password issuance strongly support a native-token/operation-expiry mismatch; the failed token itself was not retained. Existing synthetic issuance incorrectly clamped token expiry and hid that compatibility failure.

## What Changes

- Accept a still-valid native Trust token beyond the independent two-hour grant deadline only while current Trust, actor/project authority, exact delegated role closure and SQL send fences remain valid.
- Inspect/use the exact original scoped credential without token reissue; resolve native v3 authentication endpoints for both versioned and unversioned configuration.
- Add scoped installed-SDK HTTP regressions and actual Uvicorn/worker loopback smoke.
- Prepare0.3.7 metadata/docs from released0.3.6/current dev; exclude shared unrelated WIP. No publishing/deployment, schema/dependency/IAM or agent change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `isolated-tenant-execution`: independently enforce token and grant expiry, exact original credential ceiling and discovered v3 endpoint.

## Impact

Runtime change is limited to `waygate/services/execution.py`; fixture/regressions and release metadata/docs change alongside it. API/worker must use the same qualified source. Immutable001–007 schema, SDK0.2.0, policy, gateway agents and prebuilt images remain unchanged. Source implementation/local qualification is not live lifecycle or release acceptance.
