## MODIFIED Requirements

### Requirement: Standard project authority
Native actions SHALL admit current effective member/manager/admin for owned resource management and reader for nonsecret inventory without dedicated service roles. Native per-operation oslo.policy and authenticated `/v1/policy/capabilities` SHALL describe the same ceilings.

#### Scenario: Plain manager
- **WHEN** a manager has no Waygate role or implied member
- **THEN** owned metadata management succeeds without role assignment changes
- **AND** provider execution delegates the actually effective manager role, never a missing member role.

#### Scenario: Attenuated reader
- **WHEN** the original machine credential has reader while current user membership is member
- **THEN** inventory is readable but write, private config and global admin remain denied.

#### Scenario: Credentials remain private
- **WHEN** a member manages another user’s profile or invokes a machine callback
- **THEN** private-key download and server bearer bypass remain denied.
