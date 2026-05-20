# Operational Access API

**Surface:** Tenant admin Operational Access configuration plus the first Personal Cards module proof surface  
**Route prefixes:** `/operational-access/*`, `/personal/cards*`  
**Status:** Resolver proof shipped for `personal_cards.view`; first real module proof is Personal Cards

## Current boundary

Operational Access is now capability-gated, configurable for active Agent groups, and consumed by one narrow backend-enforced Personal Cards proof surface.

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
- first normal module API consumer through `GET /personal/cards` and `GET /personal/cards/:membershipId`
- backend masking for the selected proof surface

Still not shipped:

- Assigned Areas coverage table or employer/location target assignments
- broad module integration beyond the selected Personal Cards proof surface
- search/export/notification/PDF/generated-output integrations
- full Personal Cards module UI; only the backend read API proof is shipped
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

Runtime proof routes and Personal Cards module read routes require an authenticated verified tenant session. If the actor is Admin, MFA must also be complete. The resolver then decides access for `ADMIN`, `AGENT`, and `USER` server-side.

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

Returns current Oversight, Temporary Coverage, and Special Access configuration for the authenticated tenant. Admin-only. Response includes `version`, the required optimistic-concurrency value for the next advanced coverage write.

### PUT `/operational-access/advanced-coverage/oversight`

Subject-scoped replacement save for directed Oversight. By default the request replaces Oversight rows for the overseer memberships present in `entries`. `replaceForMembershipIds` may be supplied to explicitly clear or replace specific overseer subjects without wiping unrelated tenant rows.

Request body:

```ts
{
  expectedVersion: number;
  replaceForMembershipIds?: string[];
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
- save is subject-scoped and must not wipe unrelated overseer rows
- `expectedVersion` must match the current advanced coverage version or the write returns 409

Audit actions: `operational_access.oversight_saved`; rejected writes use `operational_access.oversight_save_failed` where failure audit is available. Success metadata includes before/after details, actor/tenant context, replace subjects, source service, and runtime-visibility impact.

### PUT `/operational-access/advanced-coverage/temporary-coverage`

Subject-scoped replacement save for time-bound Temporary Coverage. By default the request replaces Temporary Coverage rows for covering memberships present in `entries`. `replaceForMembershipIds` may be supplied to explicitly clear or replace specific covering subjects without wiping unrelated tenant rows.

Request body:

```ts
{
  expectedVersion: number;
  replaceForMembershipIds?: string[];
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
- save is subject-scoped and must not wipe unrelated covering rows
- `expectedVersion` must match the current advanced coverage version or the write returns 409

Audit actions: `operational_access.temporary_coverage_saved`; rejected writes use `operational_access.temporary_coverage_save_failed` where failure audit is available. Success metadata includes before/after details, actor/tenant context, replace subjects, source service, and runtime-visibility impact.

### PUT `/operational-access/advanced-coverage/special-access`

Subject-scoped replacement save for rare one-person extra access. By default the request replaces Special Access rows for memberships present in `entries`. `replaceForMembershipIds` may be supplied to explicitly clear or replace specific subjects without wiping unrelated tenant rows.

Request body:

```ts
{
  expectedVersion: number;
  replaceForMembershipIds?: string[];
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
- save is subject-scoped and must not wipe unrelated Special Access rows
- `expectedVersion` must match the current advanced coverage version or the write returns 409

Audit actions: `operational_access.special_access_saved`; rejected writes use `operational_access.special_access_save_failed` where failure audit is available. Success metadata includes before/after details, actor/tenant context, replace subjects, source service, exact target/action metadata, and runtime-visibility impact.

## Personal Cards module proof routes

These are normal module read APIs. They are not admin configuration APIs and they do not let the frontend compute access. The controller authenticates the tenant actor, delegates to the backend PersonalCardsService, and returns a server-built card read model. The service consumes Operational Access decisions, applies field-level masking/hiding, and returns only server-filtered/masked DTOs.

### GET `/personal/cards`

Returns the Personal Card list that the authenticated actor may see for `personal_cards.view`. The response uses `cards[]`, not raw people rows, and each card contains server-decided fields.

Response shape:

```ts
{
  actionKey: 'personal_cards.view';
  module: 'personal_cards';
  whichRecordsApplied: 'personal_cards_requiring_attention';
  cards: Array<{
    membershipId: string;
    title: string | null;
    fields: Array<{
      fieldKey: 'person.name' | 'person.work_email' | 'person.ssn' | 'person.date_of_birth';
      label: string;
      sensitivity: 'STANDARD' | 'SENSITIVE';
      treatment: 'VISIBLE' | 'MASKED' | 'HIDDEN';
      value: string | null;
    }>;
    sourcePath: string[];
    explanation: string[];
  }>;
}
```

Rules:

- Admin sees tenant people by Admin level.
- User sees only own/self-service record.
- Agent with only group membership sees an empty list.
- Agent with grant but no matching coverage sees an empty list.
- Agent with grant plus matching Responsible For / Oversight / Temporary Coverage / Special Access sees only matching records.
- List filtering happens in the backend query path; frontend filtering is not the enforcement boundary.
- Sensitive proof fields (`person.ssn`, `person.date_of_birth`) are masked or hidden by the server decision.
- Fields outside the shipped proof card are omitted from the DTO and fail closed for this proof surface.

### GET `/personal/cards/:membershipId`

Returns one Personal Card when the backend resolver allows it. Unauthorized direct detail access returns forbidden according to repo convention.

Rules:

- Direct detail bypass must not expose records omitted from the list.
- Why/sourcePath output may explain source categories, but must not include hidden values.
- This endpoint is the first real-module Operational Access integration proof.
- The current proof includes deterministic sensitive proof fields to verify masking/hiding without claiming full Personal Settings field-card runtime is complete.

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
      fieldKey: 'name' | 'email' | 'person.ssn' | 'person.date_of_birth';
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
- Current OA persistence uses tenant/membership foreign keys with cascade cleanup for hard-deleted tenants/memberships. This is intentional fail-closed behavior for the current foundation: deleted targets cannot keep granting access. Audit events preserve mutation history; later remediation/orphan-retention UI remains deferred.
- Expired Temporary Coverage and expired/revoked Special Access grant nothing.
- The runtime people proof masks email for Agents and never returns hidden target emails in explanations.

## Selected-consumer leak boundary

The selected consumers are the OA-owned runtime people proof routes and the backend Personal Cards module read routes. They currently expose no search, export, notification, PDF, email digest, or generated-output route. Those channels must not consume Operational Access until they use backend-resolved visibility and masking.
