# isolated-tenant-execution Specification

## Purpose
Execute tenant Nova/Neutron/Glance/Cinder work only through the requesting user's current, operation-bound Keystone Trust, so the Waygate service identity never needs tenant project membership and revoked user authority cannot outlive its operation.

## Requirements
### Requirement: Tenant execution uses current bounded delegation

The service SHALL authorize the current enabled requester and project with the exact native action capability and SHALL execute tenant OpenStack requests using an operation-bound, finite Keystone Trust containing only the requester's current global member role. The service identity SHALL NOT receive tenant role assignments or authenticate its password against a caller-selected tenant project.

#### Scenario: Authorized project member admits a gateway
- **WHEN** the requester currently has member and gateways-editor authority in the selected project
- **THEN** gateway resource validation and creation use an impersonating Trust in that exact project with the configured service identity as trustee, without tenant service membership

#### Scenario: Current authority is removed during an operation
- **WHEN** the actor, project, service capability, member assignment or Trust becomes disabled, revoked, expired or mismatched
- **THEN** the next cloud SDK request is denied without service-password or admin fallback

#### Scenario: Legacy job has only actor metadata
- **WHEN** a queued job has no admitted grant
- **THEN** the worker fails authorization without creating a new grant from a stored user ID

### Requirement: Durable grant cleanup does not repeat mutations

The service SHALL bind each deferred job to verified operation/project/server/actor grant metadata and SHALL revoke terminal or abandoned grants independently of job execution retries. A cleanup failure SHALL NOT repeat already committed cloud mutations. Unpersisted Trusts SHALL have a finite expiry.

#### Scenario: Mutation completes but revocation is unavailable
- **WHEN** the server is provisioned or durably deleted and Keystone Trust deletion fails
- **THEN** the mutation remains terminal and its grant remains eligible for cleanup without another VM creation or deletion attempt

#### Scenario: Original creator leaves the project
- **WHEN** another currently authorized gateways-admin submits deletion
- **THEN** deletion uses that requester's fresh delegation, not the original creator's grant

### Requirement: Member execution supports zero-disk flavor boot

A zero-disk flavor SHALL use image-to-volume root block-device mapping sized to at least the selected image's minimum and ten GiB with delete-on-termination. Positive-disk image-backed boot SHALL remain unchanged. The service SHALL NOT relax Nova policy or delegate an admin role to bypass zero-disk image-backed boot policy.

#### Scenario: A zero-disk flavor is selected
- **WHEN** a current member executes an admitted gateway provision operation
- **THEN** Nova receives a volume-backed root boot mapping and no image-backed zero-disk boot request

