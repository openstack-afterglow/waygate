# Native service grades

## Purpose
Separate Waygate project inventory, assigned-profile use, editing and destructive/security authority using current Keystone roles without granting OpenStack or platform administration.

## Requirements

### Requirement: Explicit tenant capabilities
Native endpoints SHALL authorize exact Waygate action leaves using current uncached Keystone global role definitions, implication DAG and effective project assignments. Runtime SHALL NOT restore missing edges from a static parent bundle or issuance-time token roles. Unknown/malformed/domain/ambiguous/dangerous graph resolution and provider lookup failure SHALL fail closed. Plain project roles SHALL NOT imply service entitlement; all resources SHALL remain token-project-bound.

Nonreader use/write capabilities SHALL also require effective native member. Inventory SHALL require native reader or member. Unverified raw admin/manager SHALL fail closed; caller-supplied role headers SHALL NOT authorize. Exact leaf-only grants SHALL remain narrow.

#### Scenario: Grade restriction
- **WHEN** a plain member or project administrator invokes service APIs
- **THEN** inventory and privileged operations are denied without explicit service roles.
- **WHEN** an editor deletes, rotates credentials, changes routing or imports/exports credentials
- **THEN** authorization is denied.

#### Scenario: Removed implication invalidates old token authority
- **WHEN** an old token names waygate_admin but the current DAG no longer reaches the needed action leaf
- **THEN** that action is denied; a static bundle must not restore it.

### Requirement: Assigned profile access
Connect users SHALL download only their own assigned client profile. Nullable persisted owner_user_id SHALL be upgraded additively; assignment SHALL validate current enabled project membership. Unknown-owner legacy and imported clients SHALL fail closed for ordinary users. Metadata SHALL contain no private key, PSK, token or profile text.

#### Scenario: Foreign or unassigned profile
- **WHEN** a connect user requests another user's or an unassigned profile
- **THEN** the request is denied before decrypting credentials.

#### Scenario: Editor-only creation does not grant connection credentials
- **WHEN** clients-editor permits metadata creation but current connect-user authority is absent or its implication was removed
- **THEN** the create response has tunnel_conf null, even for the caller's own new profile.
- **WHEN** current connect-user authority exists, the persisted owner is the caller and the client is enabled
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
