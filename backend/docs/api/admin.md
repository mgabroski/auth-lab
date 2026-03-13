# Admin API Contract

This document describes the **current admin provisioning and audit API contract** implemented in this repository.

It is a contract file, not a roadmap.
That means:

- it describes the admin endpoints that actually exist now
- it must stay aligned with `backend/src/modules/invites/admin/*` and `backend/src/modules/audit/*`
- it must not describe planned admin UX as if it were already a different API surface

Read this after:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `backend/docs/engineering-rules.md`

---

## 1. Scope

This file covers the admin endpoints registered in:

- `backend/src/modules/invites/admin/admin-invite.routes.ts`
- `backend/src/modules/audit/admin-audit.routes.ts`

Current route surface:

- `POST /admin/invites`
- `GET /admin/invites`
- `POST /admin/invites/:inviteId/resend`
- `DELETE /admin/invites/:inviteId`
- `GET /admin/audit-events`

---

## 2. Shared admin guard assumptions

All endpoints in this file require a valid authenticated session with all of the following:

- role = `ADMIN`
- MFA verified
- email verified
- tenant-bound session matching the current host/subdomain

Without those guards, the endpoint returns an auth/permission error before business logic runs.

### Common auth guard failures

| Situation          | Status | Code           | Message                        |
| ------------------ | ------ | -------------- | ------------------------------ |
| no valid session   | `401`  | `UNAUTHORIZED` | `Authentication required`      |
| wrong role         | `403`  | `FORBIDDEN`    | `Insufficient role.`           |
| email not verified | `403`  | `FORBIDDEN`    | `Email verification required.` |
| MFA not verified   | `403`  | `FORBIDDEN`    | `MFA verification required.`   |

---

## 3. Admin invite endpoints

## 3.1 `POST /admin/invites`

### Purpose

Creates a new tenant-scoped invite and queues invite email delivery.

### Request body

```ts
{
  email: string;
  role: 'ADMIN' | 'MEMBER';
}
```

Validation notes:

- `email` must be a valid email address
- `role` must be `ADMIN` or `MEMBER`
- invalid payloads return `400 VALIDATION_ERROR`

### Success response

Status: `201 Created`

```ts
{
  invite: {
    id: string;
    tenantId: string;
    email: string;
    role: 'ADMIN' | 'MEMBER';
    status: 'PENDING' | 'ACCEPTED' | 'CANCELLED' | 'EXPIRED';
    expiresAt: string;
    usedAt: string | null;
    createdAt: string;
    createdByUserId: string | null;
  }
}
```

### Notes

- email is normalized to lowercase
- response DTO never includes `tokenHash`
- success writes `invite.created` audit data
- success enqueues outbox delivery for the invite email

### Common business failures

| Situation                             | Status | Code               | Message                                                  |
| ------------------------------------- | ------ | ------------------ | -------------------------------------------------------- |
| already active member in this tenant  | `409`  | `CONFLICT`         | `This email already has an active membership.`           |
| suspended account in this tenant path | `403`  | `FORBIDDEN`        | `This user account has been suspended.`                  |
| active pending invite already exists  | `409`  | `CONFLICT`         | `An active invite already exists for this email.`        |
| email domain blocked by tenant policy | `400`  | `VALIDATION_ERROR` | `This email domain is not permitted for this workspace.` |

---

## 3.2 `GET /admin/invites`

### Purpose

Lists tenant-scoped invites with pagination and optional status filter.

### Query params

```ts
{
  limit?: number;   // default 20, min 1, max 100
  offset?: number;  // default 0, min 0
  status?: 'PENDING' | 'ACCEPTED' | 'CANCELLED' | 'EXPIRED';
}
```

### Success response

Status: `200 OK`

```ts
{
  invites: Array<{
    id: string;
    tenantId: string;
    email: string;
    role: 'ADMIN' | 'MEMBER';
    status: 'PENDING' | 'ACCEPTED' | 'CANCELLED' | 'EXPIRED';
    expiresAt: string;
    usedAt: string | null;
    createdAt: string;
    createdByUserId: string | null;
  }>;
  total: number;
  limit: number;
  offset: number;
}
```

### Notes

- results are always scoped to the session tenant
- `tokenHash` is never returned
- invalid query params return `400 VALIDATION_ERROR`

---

## 3.3 `POST /admin/invites/:inviteId/resend`

### Purpose

Resends an invite by rotating the active link and re-queueing invite delivery.

### Route param

```ts
{
  inviteId: string; // UUID
}
```

### Success response

Status: `200 OK`

```ts
{
  invite: {
    id: string;
    tenantId: string;
    email: string;
    role: 'ADMIN' | 'MEMBER';
    status: 'PENDING' | 'ACCEPTED' | 'CANCELLED' | 'EXPIRED';
    expiresAt: string;
    usedAt: string | null;
    createdAt: string;
    createdByUserId: string | null;
  }
}
```

### Notes

- invalid `inviteId` format returns `400 VALIDATION_ERROR`
- the operation is tenant-scoped; cross-tenant lookups do not reveal existence
- success rotates the link rather than reusing the old token

### Common business failures

| Situation                                  | Status | Code        | Message                                |
| ------------------------------------------ | ------ | ----------- | -------------------------------------- |
| invite not found in this tenant            | `404`  | `NOT_FOUND` | `Invite not found.`                    |
| invite cannot be resent from current state | `409`  | `CONFLICT`  | `This invite can no longer be resent.` |

---

## 3.4 `DELETE /admin/invites/:inviteId`

### Purpose

Cancels an invite in the current tenant.

### Route param

```ts
{
  inviteId: string; // UUID
}
```

### Success response

Status: `200 OK`

```ts
{
  status: 'CANCELLED';
}
```

### Notes

- invalid `inviteId` format returns `400 VALIDATION_ERROR`
- this is a `DELETE` endpoint, not a `POST /cancel` endpoint
- cross-tenant lookups collapse to not-found behavior

### Common business failures

| Situation                                     | Status | Code        | Message                                   |
| --------------------------------------------- | ------ | ----------- | ----------------------------------------- |
| invite not found in this tenant               | `404`  | `NOT_FOUND` | `Invite not found.`                       |
| invite cannot be cancelled from current state | `409`  | `CONFLICT`  | `This invite can no longer be cancelled.` |

---

## 4. Admin audit endpoint

## 4.1 `GET /admin/audit-events`

### Purpose

Returns paginated, tenant-scoped audit events for admin forensic and operational review.

### Query params

```ts
{
  limit?: number;   // default 50, min 1, max 100
  offset?: number;  // default 0, min 0
  action?: string;
  userId?: string;  // UUID
  from?: string;    // ISO 8601 datetime
  to?: string;      // ISO 8601 datetime
}
```

### Success response

Status: `200 OK`

```ts
{
  events: Array<{
    id: string;
    action: string;
    userId: string | null;
    membershipId: string | null;
    requestId: string | null;
    ip: string | null;
    userAgent: string | null;
    metadata: Record<string, unknown>;
    createdAt: string;
  }>;
  total: number;
  limit: number;
  offset: number;
}
```

### Notes

- results are always scoped to the session tenant
- `tenantId` is intentionally omitted from response rows because the session tenant already defines scope
- metadata is sanitized before response; sensitive keys such as token/hash-like fields are removed
- `limit=101` is rejected with `400 VALIDATION_ERROR` rather than silently clamped

---

## 5. Privacy and tenant-isolation posture

All endpoints in this file are tenant-scoped by the current session and host context.

This means:

- cross-tenant reads do not become an existence oracle
- invite DTOs never expose `tokenHash`
- audit rows are filtered to the session tenant only
- admin responses do not expose raw secrets or token material

---

## 6. Frontend contract guidance

### Use same-origin browser paths

Browser code should call these endpoints through same-origin relative paths such as:

```text
/api/admin/invites
/api/admin/audit-events
```

### Treat DTOs as stable contract surfaces

The frontend should consume the returned DTOs directly rather than reconstructing invite or audit shapes from inferred backend internals.

### Respect strict validation

Do not rely on silent clamping or implicit coercion beyond what the documented Zod schemas already allow.

---

## 7. When to update this file

Update this file when any of the following change:

- admin invite route paths change
- request body/query/param validation changes
- invite DTO shape changes
- audit DTO shape changes
- auth guard requirements change
- privacy / tenant-scoping behavior changes
