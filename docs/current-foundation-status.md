# Current Foundation Status

This document is the truth source for what this repository version actually implements **today**.

Its purpose is simple:

- stop false confidence
- separate current shipped scope from broader platform vision
- make future implementation sessions start from reality

If a broader architecture document and this file appear to conflict, read them like this:

- `ARCHITECTURE.md` = broader system direction + locked architecture law
- `current-foundation-status.md` = what is concretely implemented right now in this repo

---

## 1. Repo phase

This repo is currently in the:

**Topology + FE/BE wiring + Auth/User Provisioning foundation phase**

That means the foundation is intentionally front-loaded around:

- topology correctness
- tenant-aware request behavior
- session/cookie correctness
- frontend/backend contract correctness
- backend module structure discipline
- the first real backend module set needed to support auth and provisioning

It is not yet a fully built product frontend.

---

## 2. What is implemented today

## 2.1 Topology foundation

Implemented:

- reverse-proxy-first architecture
- same-origin browser API model
- backend behind trusted proxy assumption
- host/subdomain-driven tenant resolution
- SSR direct backend calls through `INTERNAL_API_URL`
- forwarded-header propagation from SSR to backend
- full-stack proxy validation via Docker + proxy conformance tests

## 2.2 Backend foundation

Implemented:

- Fastify bootstrap and DI structure
- route registration layer
- shared request context
- real `/health` endpoint with DB + Redis liveness checks
- session middleware
- tenant-aware auth context loading
- bounded-context module organization

## 2.3 Auth + User Provisioning backend

Implemented:

- register
- login
- logout
- `/auth/me`
- `/auth/config`
- forgot password
- reset password
- public signup
- verify email
- resend verification
- MFA setup / verify / recovery
- Google + Microsoft SSO start/callback
- invite provisioning flows
- admin invite lifecycle
- audit event viewing
- outbox-backed email delivery

## 2.4 Frontend foundation

Implemented:

- Next.js App Router application shell
- SSR API wrapper (`ssr-api-client.ts`)
- browser API wrapper (`api-client.ts`)
- topology smoke-test page proving SSR → backend contract
- tenant-aware local browser usage via subdomain host

## 2.5 Local workflow / infra

Implemented:

- host-run development mode
- full Docker stack mode
- proxy conformance script
- root convenience scripts for starting/stopping/status/reset

---

## 3. What is intentionally not implemented yet

These are not “missing by accident.”
They are **next-step work**, not current shipped scope.

## 3.1 Frontend product flows

Not yet implemented:

- real login screen
- real signup screen
- real forgot/reset password screens
- real invite acceptance screens
- real verification/continuation screens
- real authenticated app shell
- real admin shell
- route guards / frontend bootstrap state

## 3.2 Broader platform modules

Not yet implemented in this repo phase:

- broader Hubins business modules beyond Auth + User Provisioning
- the larger workflow/business surfaces referenced in long-term platform docs

## 3.3 Current root quality gates

Current root command truth:

- root `yarn typecheck` covers backend + frontend
- root `yarn test` currently represents backend tests
- root `yarn verify` now adds a real frontend production build before backend tests

---

## 4. What is already strong enough to build on

These parts should be treated as foundation law unless intentionally changed:

### 4.1 Same-origin browser contract

Browser code talks to the backend through relative `/api/*` paths.

- In host-run mode, a local Next.js Route Handler proxies those requests to the backend while preserving the original host/cookie context.
- In full-stack / deployed topologies, the public reverse proxy routes `/api/*` directly to the backend.

### 4.2 SSR direct backend contract

SSR code may call the backend directly through `INTERNAL_API_URL`, but it must forward request identity headers correctly.

### 4.3 Tenant routing rule

Tenant identity comes from host/subdomain, not client payload.

### 4.4 Session-tenant binding

Sessions are not portable across tenants.

### 4.5 Two-mode local workflow

Host-run mode and full-stack mode serve different purposes and are both intentional.

---

## 5. Current frontend truth

The frontend currently proves the topology and wiring.
It does **not** yet represent a finished auth application.

That means:

- current frontend files are valid as foundation
- they should not be described as “auth app complete”
- the frontend-readiness brief is still a **next implementation brief**, not a statement of completed UI delivery

---

## 6. Current documentation truth

The repo intentionally contains two documentation layers:

### Layer A — broader architecture direction

Examples:

- `ARCHITECTURE.md`

### Layer B — current shipped truth

Examples:

- this file
- `README.md`
- `docs/decision-log.md`

The repo must keep those layers aligned, but not collapse them into one thing.

A broader platform description is allowed.
A broader platform description pretending to be fully implemented is not.

---

## 7. When to update this file

Update this file whenever any of these change:

- a previously planned piece becomes actually implemented
- a current foundation capability is removed or changed
- the frontend crosses from “foundation shell” to “real auth UI”
- root quality gates change meaningfully
- current repo scope expands beyond Auth + User Provisioning foundation

---

## 8. Current next-step expectation

The next implementation work should build on this foundation in this order:

1. keep docs truthful and authority clean
2. tighten repo law and quality gates
3. implement the real frontend auth/bootstrap flow on top of `/auth/me` and `/auth/config`
4. then move into the next module or next frontend slice

This order protects the foundation from avoidable drift.
