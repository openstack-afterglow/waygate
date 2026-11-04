# Native service grades

## Purpose
Separate Waygate project inventory, assigned-profile use, editing and destructive/security authority using current Keystone roles without granting OpenStack or platform administration.

## Requirements

### Requirement: Standard project authority
Native endpoints SHALL authorize current effective project `member`, `manager` or `admin` for owned resource management and `reader` for nonsecret inventory, without dedicated Waygate roles. Fresh complete global Keystone role definitions, the role-ID implication DAG and effective project assignments remain authoritative, including custom/group/domain-inherited implications; no local aliases or legacy-root filters substitute for native authority. Unknown, malformed, domain-specific or ambiguous effective authority and incomplete directory data SHALL fail closed.

Per-operation oslo.policy rules SHALL apply after mandatory project/core-role/credential ceilings. Operator overrides may narrow authority but SHALL NOT upgrade reader, retired-service-only, restricted global-admin or foreign-project credentials. Authenticated `/v1/policy/capabilities` SHALL use the same rules and return `Cache-Control: no-store`.

#### Scenario: Plain standard roles
- **WHEN** an enabled current project member, manager or admin invokes owned metadata or client management
- **THEN** management succeeds without Waygate role assignments or implied member requirements.
- **WHEN** a reader requests inventory
- **THEN** only nonsecret inventory is returned; config/download/write remain denied.

#### Scenario: Native provider delegation
- **WHEN** an unrestricted caller creates a provider operation
- **THEN** a two-hour operation Trust delegates exactly one actually effective canonical core role, preferring member, then manager, then admin.
- **AND** persisted role ID, token role-ID/name ceiling, current actor/project/domain/action, Trust and job ownership are rechecked; no missing member is manufactured.

#### Scenario: Original credential attenuation
- **WHEN** an original restricted credential has reader while current user membership has member
- **THEN** discovery/inventory remain reader-only and provider execution, private downloads and global administration are denied.

### Requirement: Assigned profile access
Connect users SHALL download only their own assigned client profile. Nullable persisted owner_user_id SHALL be upgraded additively; assignment SHALL validate current enabled project membership. Unknown-owner legacy and imported clients SHALL fail closed for ordinary users. Metadata SHALL contain no private key, PSK, token or profile text.

#### Scenario: Foreign or unassigned profile
- **WHEN** a connect user requests another user's or an unassigned profile
- **THEN** the request is denied before decrypting credentials.

#### Scenario: Creation does not bypass private ownership
- **WHEN** management permits client creation but the profile belongs to another user or is unassigned
- **THEN** the create response has tunnel_conf null.
- **WHEN** current management authority exists, the persisted owner is the caller and the client is enabled
- **THEN** the create response may include the private profile under no-store.

### Requirement: Owner-scoped credential export
Credential export SHALL require clients-admin and routing-admin but SHALL never decrypt or wrap a known foreign owner's private key or PSK. It SHALL include caller-owned and unassigned administrative profiles plus ordinary server/routing state and SHALL report export_scope, excluded_assigned_client_count and nonsecret excluded_assigned_client_ids. The subset SHALL NOT be represented as a complete project backup. Imports SHALL leave owner_user_id NULL.

#### Scenario: Export exclusion happens before decryption
- **WHEN** an admin exports a project containing a different member's decryptable profile
- **THEN** that profile's ciphertext never reaches the decrypt operation and its nonsecret ID/count appear in the exclusion metadata.

### Requirement: Separate platform and machine authority
Only verified Keystone system-admin SHALL access global resource policies; tenant service admin SHALL NOT. Machine callbacks SHALL keep existing server-bound durable bearer checks and SHALL NOT accept tenant grade roles as authority.

#### Scenario: Tenant authority does not authorize platform or callbacks
- **WHEN** a tenant service administrator requests global resource policy or a machine callback without the independent verified system or server-bound bearer authority
- **THEN** tenant role leaves do not authorize the operation.
