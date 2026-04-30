# Invites API Contract

This document describes the **current backend invite-acceptance API contract** implemented in this repository.

It is a contract file, not a roadmap.
That means:

- it describes the endpoint that actually exists now
- it must stay aligned with `backend/src/modules/invites/*`
- it must not describe planned invite UX as if it were already a different API

Read this after:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `backend/docs/engineering-rules.md`

---

## 1. Scope

This file covers the invite-acceptance endpoint registered in:

- `backend/src/modules/invites/invite.routes.ts`

Current route surface:

- `POST /auth/invites/accept`

This contract does **not** cover admin invite management.
That surface is documented in `backend/docs/api/admin.md`.

---

## 2. Topology assumptions

### Browser path

Browser code should call this endpoint through same-origin relative paths:

```text
/api/auth/invites/accept
```

### SSR path

SSR/server-side frontend code may call the backend directly through `INTERNAL_API_URL`, but it must forward request identity headers correctly.

### Tenant routing

Tenant identity is derived from the request host/subdomain.
The caller does **not** provide tenant identity in the request body.

### Token transport rule

Invite tokens are accepted **only** in the POST body.
They must not be placed in:

- query params
- route params
- logs
- browser-visible redirect URLs after acceptance

---

## 3. Endpoint

## 3.1 `POST /auth/invites/accept`

### Purpose

Consumes an invite token for the current tenant and returns the next continuation step for the user.

### Auth requirement

Public endpoint.
No existing session is required.

### Request body

```ts
{
  token: string;
}
```

Validation notes:

- `token` is required
- `token` must be a string
- `token` must be at least 20 characters long
- malformed payloads return `400 VALIDATION_ERROR`

### Success response

```ts
{
  status: 'ACCEPTED';
  nextAction: 'SET_PASSWORD' | 'SIGN_IN' | 'MFA_SETUP_REQUIRED';
  email: string;
}
```

### `nextAction` meaning

- `SET_PASSWORD` — invite belongs to a user that does not yet have an existing account path ready for sign-in
- `SIGN_IN` — invite was accepted and the user should continue by signing in
- `MFA_SETUP_REQUIRED` — invite was accepted for an admin-path user who must set up MFA before normal continuation

### Notes

- acceptance is tenant-scoped by host/subdomain
- success consumes the invite inside a transaction
- success writes an `invite.accepted` audit event inside the same transaction
- the endpoint never returns the raw token or token hash
- acceptance does **not** expose whether a token existed in another tenant

---

## 4. Failure behavior

### Common error responses

| Situation                             | Status | Code               | Message               |
| ------------------------------------- | ------ | ------------------ | --------------------- |
| malformed request body                | `400`  | `VALIDATION_ERROR` | validation-driven     |
| token not found for this tenant       | `404`  | `NOT_FOUND`        | `Invite not found`    |
| token belongs to another tenant       | `404`  | `NOT_FOUND`        | `Invite not found`    |
| invite expired                        | `409`  | `CONFLICT`         | `Invite has expired`  |
| invite already consumed / not pending | `409`  | `CONFLICT`         | `Invite is not valid` |
| rate-limited invite acceptance        | `429`  | `RATE_LIMITED`     | rate-limit message    |

### Privacy / anti-enumeration posture

This endpoint intentionally does **not** reveal:

- whether an invite token exists in another tenant
- whether a token was ever valid in a different workspace
- raw token material

Cross-tenant token mismatch and token absence collapse to the same `404 Invite not found` shape.

---

## 5. Frontend contract guidance

### Use this endpoint only for token consumption

Invite links may arrive from email or external navigation, but the backend contract expects the token to be posted in the request body.
The frontend should extract the token from the incoming URL, then call:

```text
POST /api/auth/invites/accept
```

### Treat `nextAction` as authoritative

Do not invent a parallel frontend decision tree after invite acceptance.
Use the backend response to decide whether the user continues to:

- register/set password
- sign in
- set up MFA

### Do not persist tokens longer than needed

Once the token has been posted, remove it from active client-side flow state as soon as practical.

---

## 6. When to update this file

Update this file when any of the following change:

- invite acceptance route path changes
- request body shape changes
- response shape changes
- continuation vocabulary changes
- privacy/error behavior changes
