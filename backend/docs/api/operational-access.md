# Operational Access API

**Surface:** Tenant admin API and Settings UI (`/admin/settings/operational-access`)  
**Route prefix:** `/operational-access/*`  
**Status:** Step 3 configuration foundation only

## Current boundary

Operational Access is now capability-gated and has a configuration foundation for active Agent groups, but it is **not** a full runtime authorization system yet.

Shipped in this API:

- product-defined action catalog: **What this group can do**
- Primary Where catalog: **Where this group normally works**
- Which Records catalog: **Which records**
- active Agent-group grant configuration
- Responsible For exact-person coverage using active tenant membership IDs
- backend validation and audit for configuration writes

Not shipped in this API:

- Effective Access Resolver
- runtime Agent visibility
- Assigned Areas coverage table or employer/location target assignments
- Oversight
- Temporary Coverage
- Special Access / Person Exceptions
- search/export/notification visibility changes
- module consumer integration

People & Teams group membership remains provisioning-only by itself. A group member does not receive runtime visibility merely because they are in a group or because this configuration exists.

`/admin/settings/access` remains Access & Security. It is not Operational Access.

## Auth and tenant scope

All routes require a fully authenticated tenant Admin session:

- role: `ADMIN`
- MFA complete
- email verified
- tenant-scoped session

`AGENT` and `USER` sessions are rejected. Legacy `MEMBER` normalizes to `USER` and is rejected. Every read/write uses the authenticated tenant context; request parameters cannot widen tenant scope.

If `tenants.operational_access_enabled = false`, Operational Access configuration routes fail closed as not found.

## Product-defined catalog

### GET `/operational-access/catalog`

Returns the product-owned configuration choices. Tenant admins cannot create arbitrary action strings, Primary Where strings, or Which Records strings.

Response shape:

```ts
{
  catalog: {
    actions: Array<{
      key: 'tasks.view' | 'tasks.manage' | 'documents.review' | 'checklists.manage' | 'personal_cards.view';
      label: string;
      description: string;
      category: string;
      allowedPrimaryWhere: Array<'TENANT_WIDE' | 'ASSIGNED_AREAS' | 'RESPONSIBLE_FOR' | 'REVIEW_QUEUE'>;
      allowedWhichRecords: Array<
        'all_tasks' |
        'open_tasks' |
        'documents_requiring_review' |
        'active_checklists' |
        'personal_cards_requiring_attention'
      >;
    }>;
    primaryWhere: Array<{
      key: 'TENANT_WIDE' | 'ASSIGNED_AREAS' | 'RESPONSIBLE_FOR' | 'REVIEW_QUEUE';
      label: string;
      description: string;
    }>;
    whichRecords: Array<{
      key: string;
      label: string;
      description: string;
      category: string;
    }>;
    coverage: {
      assignedAreas: {
        available: false;
        reason: string;
      };
      responsibleFor: {
        available: true;
        targetType: 'tenant_membership';
        reason: string;
      };
    };
    deferred: string[];
  };
}
```

Important catalog rule: Oversight, Temporary Coverage, and Special Access are **not** Primary Where options.

## Groups

### GET `/operational-access/groups`

Lists active Agent groups only. Admin and User groups are intentionally excluded from this Operational Access foundation.

Response shape:

```ts
{
  groups: Array<{
    id: string;
    name: string;
    description: string | null;
    level: 'AGENT';
    status: 'ACTIVE';
    memberCount: number;
    grantCount: number;
    responsibleForAssignmentCount: number;
  }>;
}
```

### GET `/operational-access/groups/:groupId`

Returns one active Agent group configuration for the authenticated tenant.

Cross-tenant group IDs fail closed as not found. Archived groups and non-Agent groups cannot be configured.

Response shape:

```ts
{
  groupConfiguration: {
    group: {
      id: string;
      name: string;
      description: string | null;
      level: 'AGENT';
      status: 'ACTIVE';
      memberCount: number;
      grantCount: number;
      responsibleForAssignmentCount: number;
    };
    grants: Array<{
      id: string;
      actionKey: string;
      actionLabel: string;
      primaryWhere: string;
      primaryWhereLabel: string;
      whichRecordsKey: string;
      whichRecordsLabel: string;
      createdAt: string;
      updatedAt: string;
    }>;
    responsibleFor: Array<{
      agentMembershipId: string;
      agentUserId: string;
      agentEmail: string;
      agentName: string | null;
      targetMembershipId: string;
      targetUserId: string;
      targetEmail: string;
      targetName: string | null;
      createdAt: string;
    }>;
    safety: {
      runtimeVisibilityChanged: false;
      effectiveAccessResolverShipped: false;
      notes: string[];
    };
  };
}
```

## Group grants

### PUT `/operational-access/groups/:groupId/grants`

Full-replacement save for one active Agent group’s grants.

Request body:

```ts
{
  grants: Array<{
    actionKey: string;
    primaryWhere: 'TENANT_WIDE' | 'ASSIGNED_AREAS' | 'RESPONSIBLE_FOR' | 'REVIEW_QUEUE';
    whichRecordsKey: string;
  }>;
}
```

Validation:

- group must exist in the authenticated tenant
- group must be active
- group must be level `AGENT`
- `actionKey` must be product-defined
- `primaryWhere` must be product-defined
- `whichRecordsKey` must be product-defined
- action + Primary Where + Which Records combination must be allowed by the catalog
- duplicate action grants in one request are rejected
- Oversight / Temporary Coverage / Special Access are rejected because they are not Primary Where options

Response: same as `GET /operational-access/groups/:groupId`.

Audit action: `operational_access.group_grants_saved`.

## Responsible For coverage

### GET `/operational-access/people`

Lists active tenant memberships that can appear in Responsible For configuration. It marks which memberships are Agents.

Response shape:

```ts
{
  people: Array<{
    membershipId: string;
    userId: string;
    email: string;
    name: string | null;
    role: 'ADMIN' | 'AGENT' | 'USER';
    status: 'ACTIVE';
    isAgent: boolean;
  }>;
}
```

### PUT `/operational-access/groups/:groupId/responsible-for`

Full-replacement save for exact-person Responsible For coverage on one active Agent group.

Request body:

```ts
{
  assignments: Array<{
    agentMembershipId: string;
    targetMembershipId: string;
  }>;
}
```

Validation:

- group must exist in the authenticated tenant
- group must be active
- group must be level `AGENT`
- `agentMembershipId` must be an active `AGENT` membership in the same tenant
- the Agent must be a member of the selected group
- `targetMembershipId` must be an active membership in the same tenant
- cross-tenant membership IDs are rejected/fail closed
- self-responsibility is rejected
- duplicate assignments in one request are rejected

Response: same as `GET /operational-access/groups/:groupId`.

Audit action: `operational_access.responsible_for_saved`.

## Fail-closed behavior

- Missing capability: routes return not found.
- Missing/cross-tenant group: not found.
- Archived or non-Agent group: conflict.
- Missing/cross-tenant membership target: not found.
- Deleted group/membership targets are removed by foreign keys and therefore grant nothing.
- Archived group targets are not writable and should not be consumed by future runtime access.

## Runtime visibility boundary

This API stores configuration only. Until the Effective Access Resolver and a real module consumer are implemented, no Agent receives runtime access from these rows.
