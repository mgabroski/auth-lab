# Operational Access API

**Surface:** Tenant admin Operational Access configuration plus the first backend resolver proof surface  
**Route prefix:** `/operational-access/*`  
**Status:** Resolver proof shipped for one narrow people / Personal Card surface

## Current boundary

Operational Access is now capability-gated, configurable for active Agent groups, and consumed by one narrow backend-enforced proof surface.

Shipped in this API:

- product-defined action catalog: **What this group can do**
- Primary Where catalog: **Where this group normally works**
- Which Records catalog: **Which records**
- active Agent-group grant configuration
- Responsible For exact-person coverage using active tenant membership IDs
- Oversight, directed and single-hop in MVP
- Temporary Coverage with start/end window, reason, and audit metadata
- Special Access with reason, review date, expiry, and explicit target
- backend Effective Access Resolver v1 for `personal_cards.view`
- set-based runtime people filtering through `GET /operational-access/runtime/people`
- direct decision enforcement through `GET /operational-access/runtime/people/:membershipId`
- backend masking for the selected proof surface

Still not shipped:

- Assigned Areas coverage table or employer/location target assignments
- broad module integration beyond the selected runtime people proof surface
- search/export/notification/PDF/generated-output integrations
- full Personal Cards module UI
- tenant-facing Why UI beyond backend explanation fields in resolver responses
- operational repair/review queues for expired or review-due coverage

People & Teams group membership remains provisioning-only by itself. A group member receives runtime visibility only when the backend resolver finds a matching source path such as Admin level, own User record, an active Agent group grant plus matching coverage, active Temporary Coverage, or active Special Access.

`/admin/settings/access` remains Access & Security. It is not Operational Access.

## Auth and tenant scope

Configuration routes require a fully authenticated tenant Admin session:

- role: `ADMIN`
- MFA complete
- email verified
- tenant-scoped session

Runtime proof routes require an authenticated verified tenant session. If the actor is Admin, MFA must also be complete. The resolver then decides access for `ADMIN`, `AGENT`, and `USER` server-side.

Every read/write uses the authenticated tenant context. Request parameters cannot widen tenant scope. If `tenants.operational_access_enabled = false`, all Operational Access routes fail closed as not found.

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

## Admin configuration routes

### GET `/operational-access/groups`

Lists active Agent groups only. Admin and User groups are intentionally excluded from this Operational Access foundation.

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
      runtimeVisibilityChanged: boolean;
      effectiveAccessResolverShipped: boolean;
      notes: string[];
    };
  };
}
```

### PUT `/operational-access/groups/:groupId/grants`

Full-replacement save for one active Agent group's grants.

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

Audit action: `operational_access.group_grants_saved`.

### GET `/operational-access/people`

Lists active tenant memberships that can appear in Responsible For configuration. It marks which memberships are Agents.

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

Audit action: `operational_access.responsible_for_saved`.

## Advanced coverage configuration

### GET `/operational-access/advanced-coverage`

Returns current Oversight, Temporary Coverage, and Special Access configuration for the authenticated tenant. Admin-only.

### PUT `/operational-access/advanced-coverage/oversight`

Full-replacement save for directed Oversight.

Request body:

```ts
{
  entries: Array<{
    overseerMembershipId: string;
    targetMembershipId: string;
    includesResponsiblePeople: boolean;
    reason: string;
    reviewAt: string;
  }>;
}
```

Rules:

- overseer and target must be active Agent memberships in the same tenant
- self-oversight is rejected
- duplicates are rejected
- Oversight is directed, not reciprocal
- Oversight include-team behavior is explicit through `includesResponsiblePeople`
- MVP Oversight is single-hop; include-team collects only the target person's own base Responsible For set

Audit action: `operational_access.oversight_saved`.

### PUT `/operational-access/advanced-coverage/temporary-coverage`

Full-replacement save for time-bound Temporary Coverage.

Request body:

```ts
{
  entries: Array<{
    coveringMembershipId: string;
    coveredMembershipId: string;
    startsAt: string;
    expiresAt: string;
    reason: string;
    reviewAt?: string;
  }>;
}
```

Rules:

- covering and covered memberships must be active Agents in the same tenant
- `startsAt` must be before `expiresAt`
- optional `reviewAt` must not be after `expiresAt`
- expired Temporary Coverage grants nothing

Audit action: `operational_access.temporary_coverage_saved`.

### PUT `/operational-access/advanced-coverage/special-access`

Full-replacement save for rare one-person extra access.

Request body:

```ts
{
  entries: Array<{
    membershipId: string;
    targetMembershipId: string;
    actionKey: 'personal_cards.view';
    reason: string;
    reviewAt: string;
    expiresAt: string;
  }>;
}
```

Rules:

- `membershipId` must be an active Agent membership in the same tenant
- target must be an active membership in the same tenant
- reason is required
- review date is required and must not be after expiry
- expiry is required and must be in the future
- revoked or expired Special Access grants nothing

Audit action: `operational_access.special_access_saved`.

## Runtime resolver proof routes

### GET `/operational-access/runtime/people`

Returns the backend-resolved visible people set for the authenticated actor and action `personal_cards.view`.

This route is the first set-shape resolver consumer. It does not load all people in the frontend. The backend resolver returns either all tenant memberships for Admin or a tenant-scoped ID set for User/Agent, then the query filters server-side.

Response shape:

```ts
{
  actionKey: 'personal_cards.view';
  module: 'personal_cards';
  people: Array<{
    membershipId: string;
    name: string | null;
    email: string | null;
    fieldVisibility: Array<{
      fieldKey: 'name' | 'email';
      treatment: 'VISIBLE' | 'MASKED' | 'HIDDEN';
    }>;
    sourcePath: string[];
    explanation: string[];
  }>;
}
```

### GET `/operational-access/runtime/people/:membershipId`

Returns one backend decision and the masked person payload when allowed. Returns forbidden when denied.

Decision shape:

```ts
{
  actionKey: 'personal_cards.view';
  module: 'personal_cards';
  person: {
    membershipId: string;
    name: string | null;
    email: string | null;
    fieldVisibility: Array<{ fieldKey: string; treatment: string }>;
    sourcePath: string[];
    explanation: string[];
  };
  decision: {
    allowed: boolean;
    visible: boolean;
    editable: boolean;
    sourcePath: string[];
    explanation: string[];
    fields: Array<{ fieldKey: string; treatment: string }>;
  };
}
```

Resolver source-path rules:

- Admin: `ADMIN_LEVEL`
- User: `USER_OWN_DATA`
- Agent grant + Responsible For: `AGENT_GROUP_RESPONSIBLE_FOR`
- Oversight: `OVERSIGHT_DIRECT` and optionally `OVERSIGHT_RESPONSIBLE_PEOPLE`
- Temporary Coverage: `TEMPORARY_COVERAGE`
- Special Access: `SPECIAL_ACCESS`
- Denied: `DENIED`

The explanation strings contain source categories only. They must not include hidden field values or sensitive personal data.

## Fail-closed behavior

- Missing capability: routes return not found.
- Missing/cross-tenant group: not found.
- Archived or non-Agent group: conflict.
- Missing/cross-tenant membership target: not found.
- Deleted or inactive group/membership targets are pruned by active-target joins or rejected by validation.
- Expired Temporary Coverage and expired/revoked Special Access grant nothing.
- The runtime people proof masks email for Agents and never returns hidden target emails in explanations.

## Selected-consumer leak boundary

The selected consumer is the backend runtime people / Personal Card proof surface. It currently exposes no search, export, notification, PDF, email digest, or generated-output route. Those channels must not consume Operational Access until they use backend-resolved visibility and masking.
