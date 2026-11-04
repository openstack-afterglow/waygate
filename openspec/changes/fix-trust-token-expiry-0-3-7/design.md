## Context

Released0.3.6/current dev is8a62fd9f1e8deabebb0d78a39720675992940569. A synthetic fixture incorrectly expiry-clamped password Trust tokens. The clean six-path scope patch corrects that and exact original-token/role inference behavior. Shared primary contains unrelated untracked executor and test WIP; it is not the release source and remains untouched.

## Goals / Non-Goals

**Goals:** fix genuine native token compatibility without extending any grant; preserve original issuance ceiling; qualify installed-SDK HTTP and separate processes; prepare minimum unreserved patch version0.3.7.

**Non-Goals:** no publication, deployment, live resource mutation, executor activation, schema/dependency/IAM change, agent upgrade or prebuilt gateway-image rebuild.

## Decisions

1. Check token validity and two-hour Trust/operation deadline independently, including final sends. Do not shorten native Keystone token lifetime or weaken revocation/current-authority checks.
2. Inspect exact original token data through the service directory, require its issued role-ID/name closure and identity/method/expiry constraints, and send that same token using fixed-token authentication. Reissuing it could acquire newly granted authority.
3. Discover configured identity authentication endpoints using `AUTH_INTERFACE` with v3 bounds; never guess `/v3` or send Trust writes to an unversioned path. Native API: https://github.com/openstack/keystoneauth/blob/master/doc/source/api/keystoneauth1.identity.base.md .
4. Bound cached Trust token exact ID/name pairs by current delegated native closure. Classify higher-core implications case-insensitively to match oslo.policy, while keeping exact token ID/name matching and exact delegated core identity. Unique `Manager`/`ADMIN` implications must reject, not bypass the ceiling.
5. Reuse0.3.6 immutable001–007 migrations and Kolla behavior; update only registry default/package/runtime/lock version. Source-mode pin remains explicitly stale and must be overridden by the release owner.

## Risks / Trade-offs

- Failed production token was not retained: root-cause mechanism is strongly supported by timestamp/config/installed-source evidence and reproduced synthetically, not directly captured.
- Native discovery/role catalog outages remain fail-closed. Additional authority reads prioritize revocation correctness; no cache/retry workaround is introduced.
- Scratch SQLite and synthetic providers do not qualify MariaDB failover, actual native cloud policy, published image architecture, guest readiness or VPN data plane.
- API and worker correction must reach one qualified cohort after lifecycle quiescence/drain. Preserve prior immutable images/config and ledger before separately approved rollout.
