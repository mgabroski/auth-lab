# Frontend — Auth + User Provisioning Status and Guide

This frontend is the current **implemented Auth + User Provisioning surface** of the Hubins Auth-Lab repository.

It is no longer only a topology/foundation shell.
The repo now contains the real frontend routes and supporting wiring for the current auth and provisioning scope.

Read this file together with:

- `README.md`
- `docs/current-foundation-status.md`
- `ARCHITECTURE.md`
- `frontend/src/shared/engineering-rules.md`
- `backend/docs/api/auth.md`

---

## 1. Current frontend status

At the current repo phase, the frontend already implements:

- topology-aware Next.js App Router setup
- same-origin browser `/api/*` communication model
- SSR direct-backend communication model
- host-derived tenant handling
- root bootstrap handoff from `/`
- public auth entry routing
- login screen
- signup screen
- invite registration flow
- forgot-password screen
- reset-password screen
- accept-invite flow
- verify-email continuation flow
- MFA setup flow
- MFA verify flow
- SSO completion landing
- authenticated member landing route
- authenticated admin landing route
- admin invite management UI
- logout flow
- legacy compatibility handoff from `/dashboard`
- topology smoke-test page

This is the current implemented frontend module surface for Auth + User Provisioning.

---

## 2. What the frontend does not claim yet

The frontend should **not** currently be described as having:

- a broader member product application beyond the authenticated landing route
- a full admin dashboard beyond the current invite management surface
- broader non-auth product modules
- generalized product navigation outside the current auth/provisioning scope
- every future management screen that may belong to later modules

The frontend is functionally real for Auth + User Provisioning, but it is not yet the complete Hubins product UI.

---

## 3. Locked frontend rules

These rules remain load-bearing and should not be casually changed.

### 3.1 Same-origin browser rule

Browser code must call backend APIs through same-origin relative paths:

```text
/api/*
```

Browser code must not hardcode direct backend origins.

### 3.2 SSR is first-class

Because the system uses:

- tenant-aware routing
- cookie-based sessions
- backend-owned auth truth

SSR is part of the intended application model, not an optional optimization.

### 3.3 Backend truth is authoritative

The frontend must continue to use backend truth from endpoints such as:

- `GET /auth/config`
- `GET /auth/me`

The frontend must not invent its own tenant state, auth state, or continuation state when the backend already owns that truth.

### 3.4 Tenant identity is host-derived

The frontend must treat tenant identity as coming from the request host/subdomain.

It must not derive tenant identity from:

- query params
- local storage
- arbitrary UI state
- request body fields

---

## 4. Current frontend communication model

### 4.1 Browser requests

Browser code calls the backend through same-origin paths such as:

```text
/api/auth/config
/api/auth/me
/api/auth/login
/api/admin/invites
```

How those requests reach the backend depends on the runtime mode:

- **Host-run mode:** Next.js Route Handlers in `src/app/api/[...path]/route.ts` proxy `/api/*` to the backend while preserving host/cookie/forwarded-header context.
- **Full-stack / deployed topology:** the public reverse proxy routes `/api/*` directly to the backend.

The browser contract stays the same in both modes:

- always use relative same-origin `/api/*`
- never hardcode backend origins in browser code

### 4.2 SSR requests

Server-side frontend code may call the backend directly through `INTERNAL_API_URL`.

When doing so, it must forward the request identity headers needed by the backend, including:

- `Host`
- `Cookie`
- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`

This preserves:

- tenant resolution
- session continuity
- request fidelity

---

## 5. Current route surface

The current frontend route surface includes:

### Public and continuation routes

- `/`
- `/auth`
- `/auth/login`
- `/auth/signup`
- `/auth/register`
- `/auth/forgot-password`
- `/auth/reset-password`
- `/accept-invite`
- `/verify-email`
- `/auth/mfa/setup`
- `/auth/mfa/verify`
- `/auth/sso/done`
- `/auth/unavailable`
- `/auth/continue/[action]`

### Authenticated routes

- `/app`
- `/admin`
- `/admin/invites`

### Compatibility and validation routes

- `/dashboard`
- `/topology-check`

---

## 6. Important current frontend files

### `src/app/page.tsx`

Root bootstrap handoff page.
This is the entry point that resolves route outcome from backend/bootstrap truth.

### `src/app/auth/*`

Public auth and continuation pages.
These implement the main browser-facing auth and provisioning flows.

### `src/app/app/page.tsx`

Minimal authenticated member landing route.
This exists after backend truth resolves the user as an authenticated member with no remaining continuation requirement.

### `src/app/admin/page.tsx`

Minimal authenticated admin landing route.
This exists after backend truth resolves the user as an authenticated admin with no remaining continuation requirement.

### `src/app/admin/invites/page.tsx`

Admin invite management page.
This is the current implemented admin-facing provisioning surface.

### `src/app/dashboard/page.tsx`

Legacy compatibility handoff route.
It forwards to the correct modern landing route using backend truth.

### `src/app/api/[...path]/route.ts`

Host-run same-origin API proxy.
This exists so browser `/api/*` requests behave correctly even when Next.js is running directly on the host without the public reverse proxy in front of it.

### `src/shared/api-client.ts`

Browser-side API wrapper.
Used for same-origin browser communication with the backend.

### `src/shared/ssr-api-client.ts`

SSR/server-side API wrapper.
Used for direct backend communication from server-side frontend code.

### `src/shared/auth/*`

Shared auth contracts, redirect logic, bootstrap logic, route-state handling, SSO helpers, and current reusable auth UI pieces.

### `src/shared/engineering-rules.md`

Frontend implementation law.
This should still be read before changing the auth/bootstrap surface.

---

## 7. Backend capabilities this frontend currently depends on

The current frontend implementation is especially grounded in these backend areas:

- `GET /auth/config`
- `GET /auth/me`
- `POST /auth/login`
- `POST /auth/signup`
- `POST /auth/register`
- `POST /auth/forgot-password`
- `POST /auth/reset-password`
- `POST /auth/verify-email`
- `POST /auth/resend-verification`
- `POST /auth/invites/accept`
- `POST /auth/mfa/setup`
- `POST /auth/mfa/verify-setup`
- `POST /auth/mfa/verify`
- `POST /auth/mfa/recover`
- `POST /auth/logout`
- `POST /admin/invites`
- `GET /admin/invites`
- `POST /admin/invites/:inviteId/resend`
- `DELETE /admin/invites/:inviteId`

These are real load-bearing dependencies for the current frontend module.

---

## 8. Local development

### 8.1 Host-run mode

This is the normal daily development mode.

From the repo root:

```bash
yarn dev
```

What `yarn dev` does:

- starts Postgres + Redis in Docker
- auto-creates `backend/.env` from `backend/.env.example` if needed
- auto-creates `frontend/.env.local` from `frontend/.env.example` if needed
- runs migrations
- regenerates DB types
- starts backend on `http://localhost:3001`
- starts frontend on `http://goodwill-ca.localhost:3000`

Important browser URL for tenant-aware behavior:

```text
http://goodwill-ca.localhost:3000
```

Do **not** use plain `http://localhost:3000` when checking tenant-aware frontend behavior.

Important host-run details:

- browser `/api/*` is handled by the local Next Route Handler proxy
- SSR uses `INTERNAL_API_URL=http://localhost:3001`

### 8.2 Full-stack mode

Use this when validating real proxy behavior.

From the repo root:

```bash
yarn stack
```

Public entrypoint:

```text
http://goodwill-ca.lvh.me:3000
```

Run proxy conformance checks:

```bash
yarn stack:test
```

If a frontend change affects:

- same-origin assumptions
- cookies/session behavior through proxy
- SSR forwarding behavior
- host/subdomain assumptions

then full-stack validation is required.

---

## 9. Frontend commands

From `frontend/`:

```bash
yarn dev
yarn build
yarn start
yarn lint
yarn lint:fix
yarn typecheck
yarn test
yarn test:unit
yarn test:e2e
```

The frontend now ships dedicated test commands for the current auth/provisioning slice:

- `yarn test:unit` for route-state, bootstrap, and browser API discipline
- `yarn test:e2e` for the frontend auth-flow browser journeys

Do not claim a broader frontend test surface than what those scripts actually cover.

---

## 10. Practical smoke checks

When reviewing frontend changes in this module, at minimum verify:

- signed-out `/` resolves correctly
- member login ends at `/app`
- admin login ends at `/admin`
- continuation routes follow backend `nextAction`
- logout clears session and returns to public entry
- browser network calls stay on same-origin `/api/*`
- tenant behavior remains host-derived
- `/dashboard` still acts as a compatibility handoff
- admin invite management still works if the changed code touches that surface

---

## 11. Current truth for reviewers and future implementers

This frontend should currently be reviewed as:

- a real topology-aware auth and provisioning frontend
- a real SSR/browser integration layer
- a truthful implementation of the current Auth + User Provisioning scope

It should **not** currently be reviewed as:

- the full Hubins product frontend
- a complete admin control plane
- a complete member application beyond auth landing
- a finished surface for future non-auth modules

That distinction matters because future product modules should extend this frontend without breaking the locked topology and auth rules.

---

## 12. Final rule

If code, docs, prompts, or review notes describe this frontend as either _less implemented_ or _more implemented_ than it really is, repair the description before using it as planning truth.
