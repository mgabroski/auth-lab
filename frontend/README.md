# Frontend Surface Reference

This folder contains the Hubins frontend application.

It is a frontend surface reference.
It is not the repo entrypoint.

Start at the repo root first:

1. `../README.md`
2. `../docs/current-foundation-status.md`
3. `../ARCHITECTURE.md`
4. `../docs/quality-bar.md`
5. `../docs/decision-log.md`
6. `../docs/security-model.md`

For AI/review routing, use:

- `../AGENTS.md`
- `./AGENTS.md`

---

## What This Folder Owns

This frontend owns the current browser and SSR application surface for the shipped Auth + User Provisioning foundation.

That includes:

- public auth routes
- invite acceptance and registration routes
- email verification and password reset routes
- MFA setup and verify routes
- SSO completion route behavior
- admin and member post-auth landing behavior
- shared browser API client behavior
- shared SSR API client behavior
- authenticated shell and route composition for the current shipped surface

Use `../docs/current-foundation-status.md` before describing anything here as fully shipped.

---

## What This Folder Does Not Own

This frontend does **not** own:

- backend auth/session truth
- tenant identity truth
- membership truth
- API contract truth
- proxy or cookie policy truth
- architectural law for the whole repo

Those are defined in repo-level and backend-level authority docs.

---

## Read For Frontend Work

### Core frontend law

- `./AGENTS.md`
- `./src/shared/engineering-rules.md`
- `./docs/module-skeleton.md`

### Backend contracts the frontend depends on

- `../backend/docs/api/auth.md`
- `../backend/docs/api/invites.md`
- `../backend/docs/api/admin.md`

### Cross-cutting truth when relevant

- `../ARCHITECTURE.md`
- `../docs/decision-log.md`
- `../docs/security-model.md`

### Review expectations

- `../code_review.md`

---

## Frontend Operating Rules

### 1. Browser requests stay same-origin

Browser code must use relative `/api/*` paths.

Do not hardcode browser calls to backend origins.

### 2. SSR and browser calls are different

SSR/server-side code and browser code must follow their distinct request models.

Do not flatten them into one generic fetch path if that weakens topology truth.

### 3. Backend owns auth/session outcomes

The frontend renders from backend-owned outcomes.
It does not invent a parallel truth model for auth, membership, tenant, or next actions.

### 4. User-visible route behavior must stay truthful

Login, signup, invite, MFA, SSO, reset-password, verification, logout, admin/member landing, and setup-banner behavior must stay aligned with backend contracts and shipped docs.

### 5. Keep frontend state readable

Critical route behavior should be easy to follow in code.
Do not bury meaningful auth or redirect behavior in scattered abstractions.

---

## Folder Map

### App routes and route handlers

- `src/app/**`

Use this area for route composition, route-local UI, server components, and route handlers.

### Shared frontend logic

- `src/shared/**`

Use this for genuinely shared frontend code such as:

- API clients
- auth helpers
- redirect helpers
- shared UI primitives
- safe shared utilities

Do not turn shared code into a second source of product truth.

### Frontend docs

- `docs/module-skeleton.md`

Use this as the frontend structure reference when adding or reshaping frontend modules.

### Tests

- `test/unit/**`
- `test/e2e/**`

Use unit tests for focused behavior and E2E for route or stack-sensitive behavior.

---

## Local Development

Run normal local development from the repo root:

```bash
yarn dev
```

Run full topology-sensitive flows from the repo root when needed:

```bash
yarn stack
yarn stack:test
```

Do not treat frontend-only local behavior as sufficient proof for:

- auth/session behavior
- SSR/bootstrap behavior
- proxy-sensitive routing
- cookie-sensitive flows
- SSO callback paths

For deeper setup instructions, use:

- `../docs/developer-guide.md`

---

## Frontend Truth Order

When frontend-local materials seem to disagree, use this order:

1. active locked product/module source-of-truth docs
2. repo-level shipped-truth and architecture docs
3. backend contract docs
4. frontend engineering law
5. frontend implementation code
6. frontend tests
7. local reference docs like this one

If a lower source conflicts with a higher one, the lower source must be corrected or ignored.

---

## What This File Should Be

This file should stay small.

Its job is to:

- explain what the frontend folder owns
- point readers to the right higher-truth docs
- prevent this folder from becoming a second repo entrypoint

It should not become:

- a duplicate of root `README.md`
- a duplicate of `frontend/AGENTS.md`
- a long setup manual
- a substitute for backend contract docs
