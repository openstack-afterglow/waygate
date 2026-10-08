## MODIFIED Requirements

### Requirement: Migrations and operator trust are explicit

Applied migration identities and checksums SHALL remain immutable; additive migrations and manifest entries SHALL be maintained together. New API/worker processes SHALL start only after the candidate's complete schema is applied. Existing records, encrypted credentials and earlier ledger entries SHALL remain preserved. Kolla migration executes in deploy bootstrap; reconfigure is not evidence of schema application. Operators SHALL preserve previous image/config and DB backup before a separately authorized rollout.

Callback endpoints SHALL be explicit VM-reachable public HTTP(S) URLs, never a loopback or internal fallback. The configured service identity SHALL stay in its own service project and SHALL NOT require tenant membership. Tenant cloud work SHALL use the current user's bounded delegation. Zero-root-disk flavors SHALL use member-compatible volume-backed root boot, with Cinder policy, image minimum size and project quota qualified separately; Nova's admin-only image-backed zero-disk policy SHALL remain unchanged. Trusted proxy settings SHALL be limited to actual proxies and ingress SHALL discard caller-supplied forwarded scheme. Native build TLS verification SHALL remain enabled, with OS_CACERT for private CAs.

#### Scenario: Operator reconfigures an old schema
- **WHEN** a candidate rollout uses reconfigure without applying its additive migrations
- **THEN** this is not treated as migration completion, and new API/worker startup requires backup and deploy/bootstrap schema verification

#### Scenario: Tenant service roles remain from an old deployment
- **WHEN** the isolated execution candidate is locally implemented
- **THEN** no production role is automatically removed; operators separately qualify fresh delegated create/delete/routing and verify old assignments are unused before scoped retirement
