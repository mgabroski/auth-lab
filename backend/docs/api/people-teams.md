# People & Teams API

**Status:** Backend foundation only  
**Surface:** Tenant admin API  
**Route prefix:** `/people-teams/*`

## Scope

This API is the tenant-level People & Teams group foundation. It supports the future Operational Access model by creating a clean place for reusable tenant groups and active tenant people selection.

This API is **not** Operational Access.

It does not implement:

- access grants
- scopes / Where rules
- Person Exceptions
- Managed People
- Effective Access Resolver
- Agent invite group requirements
- runtime role migration from `ADMIN | MEMBER`
- permissions UI

Current runtime membership roles remain `ADMIN | MEMBER`. Group levels are classification only: `ADMIN`, `AGENT`, `USER`.

## Security

All endpoints require a fully authenticated current `ADMIN` session:

- active session
- current tenant context
- email verified
- MFA verified
- membership role `ADMIN`

Current `MEMBER` sessions are denied. All reads are scoped to the authenticated tenant. No request parameter may widen tenant scope.

## GET `/people-teams/groups`

Returns active groups for the authenticated tenant.

Archived groups are excluded from this normal list. They remain persisted for history and future remediation behavior, but they are not returned by the foundation read surface.

### Response

```json
{
  "groups": [
    {
      "id": "uuid",
      "name": "HR Agents",
      "normalizedName": "hr agents",
      "description": "Tenant-local operational team",
      "level": "AGENT",
      "status": "ACTIVE",
      "memberCount": 0,
      "createdAt": "2026-05-14T00:00:00.000Z",
      "updatedAt": "2026-05-14T00:00:00.000Z",
      "archivedAt": null
    }
  ]
}
```

## GET `/people-teams/people`

Returns safe identifying data for active tenant memberships. This endpoint exists to support a future group member picker. It is not a full People/Profile module and does not expose sensitive Personal fields.

Only `ACTIVE` memberships for the authenticated tenant are returned.

### Response

```json
{
  "people": [
    {
      "membershipId": "uuid",
      "userId": "uuid",
      "email": "person@example.com",
      "name": "Person Name",
      "role": "MEMBER",
      "status": "ACTIVE"
    }
  ]
}
```

## Data lifecycle notes

- Groups are tenant-scoped.
- Group names are normalized and unique per tenant.
- Group membership anchors to tenant membership, not global user alone.
- Archive is the MVP lifecycle path; hard delete is not part of this foundation.
- Archived groups must later fail closed when Operational Access consumes them.
