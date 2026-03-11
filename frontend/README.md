# Frontend — Foundation Status and Guide

This frontend is the **current UI foundation layer** of the Hubins Auth Lab repository.

At the current repo phase, the frontend is intentionally focused on:

- proving the topology and FE/BE wiring
- establishing the correct frontend communication model
- locking SSR vs browser API behavior
- preparing the ground for the real auth/bootstrap implementation

It is **not** yet the finished Auth + User Provisioning product UI.

Read this file together with:

- `README.md`
- `docs/current-foundation-status.md`
- `ARCHITECTURE.md`
- `frontend/src/shared/engineering-rules.md`
- `backend/docs/api/auth.md`

---

## 1. What the frontend already implements

At the current phase, the frontend already provides:

- Next.js App Router foundation
- root app layout
- SSR API wrapper
- browser API wrapper
- host-run `/api/*` Route Handler proxy
- topology smoke-test page
- tenant-aware browser usage through subdomain-based local access
- frontend engineering rules for future implementation work

This is not trivial scaffolding.
These pieces are the required base for building the real auth UI correctly.

---

## 2. What is intentionally not implemented yet

The following are **not yet implemented** and should not be described as delivered:

- login screen
- signup screen
- forgot/reset password screens
- invite acceptance screen
- verify-email continuation screen
- MFA setup / verify continuation screens
- authenticated app shell
- admin shell
- frontend auth bootstrap state
- route guards for public/authenticated/continuation states

These are next-step frontend work.
The current frontend is a foundation, not a complete product surface.

---

## 3. Why the frontend is built this way

The frontend follows the backend and topology constraints of this repo.

### 3.1 Same-origin browser rule

Browser code must call backend APIs through same-origin relative paths:

```text
/api/*
```

The browser must not hardcode direct backend origins.

### 3.2 SSR is first-class

Because the system uses:

- tenant-aware routing
- server-side sessions
- cookie-based auth

SSR is part of the intended application flow, not an optional optimization.

### 3.3 Backend bootstrap is authoritative

The future frontend auth/bootstrap flow must be built around backend truth from:

- `GET /auth/config`
- `GET /auth/me`

The frontend must not independently invent tenant/auth continuation state when the backend already owns that truth.

---

## 4. Current frontend communication model

## 4.1 Browser requests

Browser code should call the backend via same-origin paths such as:

```text
/api/auth/config
/api/auth/me
/api/auth/login
```

How those requests reach the backend depends on the current local/runtime mode:

- **Host-run mode:** Next.js Route Handlers in `src/app/api/[...path]/route.ts` proxy `/api/*` to the backend while preserving host/cookie/forwarded-header context.
- **Full-stack / deployed topology:** the public reverse proxy routes `/api/*` directly to the backend.

The browser contract stays the same in both cases:

- always use relative same-origin `/api/*`
- never hardcode backend origins in browser code

## 4.2 SSR requests

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

## 4.3 Tenant identity

The frontend must treat tenant identity as host/subdomain-derived.

It must not invent tenant identity from:

- local storage
- query params
- UI state
- request body fields

The host is the current tenant context.

---

## 5. Current important frontend files

### `src/app/layout.tsx`

Root application layout.

### `src/app/page.tsx`

Current topology smoke page.
This file is intentionally simple and should be understood as a foundation proof page, not as the final app shell.

### `src/app/api/[...path]/route.ts`

Host-run same-origin API proxy.
This exists so browser `/api/*` requests behave correctly even when Next.js is running directly on the host without the public reverse proxy in front of it.

### `src/shared/api-client.ts`

Browser-side API wrapper.
Used for same-origin browser communication with the backend.

### `src/shared/ssr-api-client.ts`

SSR/server-side API wrapper.
Used for direct backend communication from server-side frontend code.

### `src/shared/engineering-rules.md`

Frontend implementation law.
This file must be read before building the real auth/bootstrap UI layer.

---

## 6. Backend endpoints the frontend foundation depends on

The current frontend foundation is especially aligned with these backend endpoints:

### `GET /auth/config`

Used for public/bootstrap UI truth such as:

- tenant availability
- whether public signup is enabled
- which SSO providers should be shown

### `GET /auth/me`

Used for authenticated/bootstrap truth such as:

- current user
- current tenant
- current membership role
- current session continuation state
- `nextAction`

These are load-bearing frontend dependencies.
Future frontend auth flows must be designed around them.

---

## 7. Local development

## 7.1 Host-run mode

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

Important host-run detail:

- browser `/api/*` is handled by the local Next Route Handler proxy
- SSR uses `INTERNAL_API_URL=http://localhost:3001`

---

## 7.2 Full stack mode

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

then full stack validation is required.

---

## 8. Frontend commands

From `frontend/`:

```bash
yarn dev
yarn build
yarn start
yarn lint
yarn lint:fix
yarn typecheck
```

At the current repo phase, there is **no separate frontend test suite documented as a locked repo gate yet**.
Do not claim `yarn test` exists for the frontend unless that script is actually added.

---

## 9. Current frontend truth for reviewers and future implementers

This frontend should currently be reviewed as:

- a strong topology-aware foundation
- a real SSR/browser integration layer
- a preparatory shell for auth/bootstrap UI work

It should **not** currently be reviewed as:

- complete auth application
- complete tenant admin UI
- complete user provisioning UI
- complete shell for broader Hubins modules

That distinction matters because the next implementation phase will build on this foundation.

---

## 10. What should happen next

The next frontend work should build on the current foundation in this order:

1. use `/auth/config` and `/auth/me` as the bootstrap truth sources
2. implement frontend auth/bootstrap state
3. implement public/authenticated/continuation route handling
4. implement real auth screens
5. implement authenticated app shell and admin entry points

The goal is to expand from the current foundation without violating the locked topology and backend contract.

---

## 11. Final rule

This frontend README must remain truthful about one thing above all else:

**the frontend foundation is real, but the real auth product UI is still next-step work**

If this file starts describing planned frontend behavior as already shipped, it has become misleading and must be corrected.
