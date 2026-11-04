## ADDED Requirements

### Requirement: Token validity and operation deadlines are independent

The service SHALL accept a currently valid native password Trust token even if its nominal expiration exceeds the independently enforced finite operation/Trust deadline. Before each native send, it SHALL recheck current actor/project authority, exact Trust identity and scope, grant deadline, token validity, current delegated role-ID/name closure and SQL claim where applicable. Token lifetime SHALL NOT extend an operation or revive revoked authority. Higher core-role implications SHALL be classified case-insensitively consistently with native oslo.policy; token role IDs/names SHALL retain exact matching.

#### Scenario: Native24-hour password token and two-hour Trust
- **WHEN** an authorized member has a valid exact-scope24-hour Trust token and an active two-hour operation
- **THEN** execution proceeds until its independent deadline without a false403 solely because token expiry is later

#### Scenario: Long token survives revoked authority or expired operation
- **WHEN** the grant expires, Trust is revoked, current membership is removed, token expires or cached token roles leave the delegated closure
- **THEN** the next native send is denied with no service/admin fallback

#### Scenario: Higher core implication uses unique mixed case
- **WHEN** delegated member implies a unique Manager or ADMIN role even without its lowercase counterpart
- **THEN** execution is denied before provider writes

### Requirement: Original credential and discovered v3 endpoint are retained

Trust admission SHALL inspect and send the exact original valid project-scoped credential without reissue, requiring its original issued roles to include the delegated role's current exact native closure. It SHALL discover a native v3 authentication endpoint from the configured auth URL for both versioned and unversioned inputs. It SHALL reject foreign/restricted/expired credential scope and SHALL NOT exchange tokens to acquire later authority or guess an unversioned Trust write path.

#### Scenario: Original reader token after current member assignment
- **WHEN** the original credential lacks currently required delegated issuance roles
- **THEN** admission is denied without reissuing the token or writing provider resources

#### Scenario: Root or versioned authentication URL
- **WHEN** configuration uses an unversioned root URL or a v3 URL with native discovery
- **THEN** the exact original credential creates its Trust at the discovered v3 endpoint without token exchange
