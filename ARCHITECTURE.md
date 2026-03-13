# Hubins — Architecture

## How to read this document

This document is intentionally broader than the code currently implemented in this repo.

It describes:

1. the **Hubins platform architectural direction**
2. the **locked topology and engineering decisions that already apply today**
3. the **current implementation status of this repository**

That distinction matters.

This file is allowed to describe the wider platform vision.
It is **not** allowed to blur the line between:

- what Hubins is intended to become
- and what this repo version already ships now

For the exact shipped state, read `docs/current-foundation-status.md`.

---

## 1. Executive recommendation

Build Hubins as a disciplined modular monolith first.

That is the correct decision for the current stage because:

- topology and system contracts must be locked before module explosion
- tenant isolation must be enforced centrally and consistently
- Auth + User Provisioning is foundational and cross-cutting
- premature service extraction would raise complexity before domain boundaries and operational needs are mature

This repo therefore prioritizes:

- clean module boundaries
- topology correctness
- strict request/tenant/session rules
- reproducible local development
- documentation discipline
- future-safe expansion from a strong core

---

## 2. Current implementation status in this repository

Today this repository concretely implements:

### Foundation that is already real

- frontend ↔ backend topology and wiring
- same-origin browser API model
- SSR direct-to-backend model using forwarded request context
- reverse proxy contract
- tenant resolution via subdomain / host
- Redis-backed server-side session model
- backend bootstrap / DI / route registration foundation
- backend Auth + User Provisioning surface
- frontend Auth + User Provisioning route/UI surface for the current module scope

### Broader product work that is intentionally not complete yet

- broader member product modules beyond the current auth/provisioning landing surface
- broader admin product modules beyond the current invite-management surface
- non-auth business modules beyond Auth + User Provisioning
- later confidence/test hardening phases for the already-shipped auth/provisioning slice

So this repo is not “the whole Hubins platform.”
It is the **foundation plus Auth + User Provisioning slice** that must be correct before the rest of Hubins expands.

---

## 3. System architecture shape

### Recommended shape

Hubins should evolve as a **modular monolith with explicit boundaries**.

That means:

- one deployable system for now
- well-defined modules
- private internals inside each module
- shared infrastructure only where truly cross-cutting
- deliberate async boundaries only when justified

This gives us:

- lower operational overhead
- easier local development
- simpler transactional consistency
- faster iteration while the product surface is still forming
- a clean path to later extraction if real scaling triggers appear

---

## 4. What Hubins is intended to become

Hubins is intended to grow into a multi-tenant SaaS platform with multiple business domains.

Examples of broader platform concerns may include:

- authentication and identity
- user provisioning
- tenancy and access control
- workflow/process features
- auditability and compliance
- notifications and email delivery
- future business modules beyond this foundation

This broader direction is real, but the current repo phase implements only the foundation and the first real module boundary set needed to support future growth safely.

---

## 5. Architecture principles for this repo

### 5.1 Topology is load-bearing

The proxy layer is not a convenience.
It is part of the architecture.

Browser traffic is designed to behave like this:

```text
Browser
  -> public origin
  -> reverse proxy
  -> frontend or backend
```

The backend is designed with the assumption that:

- it sits behind a trusted proxy boundary
- forwarded headers are meaningful
- tenant resolution depends on the public host/subdomain
- browser requests remain same-origin

### 5.2 Tenant identity comes from topology, not payload

Tenant identity is derived from the request host/subdomain.

It must never come from:

- request body
- query parameter
- local storage
- client-selected tenant headers

This keeps tenant isolation anchored to routing, not user-controlled payload.

### 5.3 Sessions are server-side

Hubins uses server-side sessions backed by Redis.

The browser does not own an auth token in local storage.
The browser sends cookies.
The backend resolves session state centrally.

This improves:

- revocation
- session invalidation
- MFA transitions
- security posture for auth-heavy flows

### 5.4 SSR is first-class

Because auth is cookie/session based and tenant-aware, SSR is not an optional optimization.
It is part of the correct UX and control flow.

Server-rendered code can:

- read request headers
- forward cookies
- resolve tenant safely
- call backend auth/bootstrap endpoints before client hydration

### 5.5 Foundation first, expansion second

Before adding more product modules, the following must be trustworthy:

- proxy behavior
- FE/BE contract
- session rules
- tenant isolation
- backend module boundaries
- docs and engineering law

This repo exists to lock those first.

---

## 6. Current topology model

### Browser path

Client-side frontend code calls backend APIs through relative same-origin URLs:

```text
/api/*
```

The browser must not hardcode direct backend URLs.

### SSR path

SSR code calls the backend directly through `INTERNAL_API_URL` and explicitly forwards:

- `Host`
- `Cookie`
- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`

This preserves:

- tenant resolution
- session continuity
- request-shape fidelity

### Local modes

Two local modes are intentional:

#### Host-run

Best for daily feature development:

- backend and frontend run on the host
- Postgres + Redis run in Docker

#### Full stack

Best for topology validation:

- proxy + frontend + backend + infra run in Docker
- validates proxy behavior that host-run mode cannot prove

Neither mode replaces the other.

---

## 7. Backend architectural shape

The backend is organized around three layers of concern:

### 7.1 App/bootstrap layer

Located under `backend/src/app/`.

Responsibilities:

- config loading
- dependency assembly
- server creation
- route registration
- plugin / middleware setup

### 7.2 Module layer

Located under `backend/src/modules/`.

Responsibilities:

- own business behavior for a bounded context
- expose a public module surface
- keep internal layers private where possible

Examples currently present in the repo:

- `auth`
- `invites`
- `memberships`
- `tenants`
- `users`
- `audit`

### 7.3 Shared infrastructure layer

Located under `backend/src/shared/`.

Responsibilities:

- HTTP/request infrastructure
- session infrastructure
- DB infrastructure
- cache infrastructure
- logging
- cross-cutting utilities that are not owned by a single business module

This layer must not become a dumping ground for business logic.

---

## 8. Frontend architectural shape

The frontend is a Next.js App Router application.

### What is already established

- root app shell
- SSR fetch layer
- browser fetch layer
- topology smoke page
- frontend engineering rules file

### What the frontend is expected to become next

- auth bootstrap based on `/auth/me` and `/auth/config`
- public/authenticated/continuation route handling
- login/signup/invite/reset screens
- admin shell entry points
- tenant-aware UI behavior without client-side tenant guessing

The frontend must preserve the same topology law as the backend:

- same-origin browser calls
- SSR direct backend calls only from server-side code
- no direct browser-to-backend URL coupling

---

## 9. Bounded contexts in the current foundation

### Auth

Owns:

- login
- logout
- register
- signup
- password reset
- email verification
- MFA
- SSO bootstrap and callback orchestration
- auth-facing read models like `/auth/me` and `/auth/config`

### Invites

Owns:

- invite creation
- resend/cancel/list
- invite acceptance and provisioning coordination

### Memberships

Owns:

- tenant membership persistence and membership-related query/write logic

### Users

Owns:

- user persistence and user-related query/write logic

### Tenants

Owns:

- tenant lookup
- tenant policy inputs
- tenant activation / configuration state used by auth-facing endpoints

### Audit

Owns:

- audit persistence
- audit event retrieval / admin viewer behavior

These boundaries can evolve, but any change should be deliberate and documented.

---

## 10. Integration rules that are already locked

### 10.1 Same-origin browser rule

Browser code talks to the backend through the proxy on the same origin.

### 10.2 No client-chosen tenant

The frontend must not choose tenant identity from application state.
Tenant comes from host/subdomain.

### 10.3 Trusted-proxy rule

Forwarded headers are trusted because the backend is designed to sit behind the reverse proxy boundary.

### 10.4 Session-tenant binding

A valid session from tenant A must not authenticate on tenant B.

### 10.5 Topology validation rule

Changes affecting proxy, cookies, request context, or SSO callback assumptions must be validated in the full stack, not only in host-run mode.

---

## 11. Documentation law

This repository relies on documents as engineering control surfaces, not decoration.

The minimum authority chain is:

1. `README.md` — repo entry and scope framing
2. `docs/current-foundation-status.md` — what is actually implemented now
3. `ARCHITECTURE.md` — broader system shape + locked architecture direction
4. `docs/decision-log.md` — non-obvious decisions and their consequences
5. backend/frontend engineering rules — implementation law

A document that overclaims readiness is a bug.
A document that contradicts the code without saying so is a bug.
A document that blurs target vision with current implementation is a bug.

---

## 12. What this architecture explicitly avoids right now

The current foundation intentionally avoids:

- premature microservices
- client-side tenant selection
- browser-managed auth tokens in local storage
- direct browser coupling to backend internal URLs
- mixing topology assumptions with ad hoc exceptions
- pretending planned frontend flows are already built

These are not omissions by accident.
They are deliberate constraints to keep the foundation reliable.

---

## 13. Expansion rule

New modules should only be added on top of this foundation if they preserve:

- tenant isolation
- same-origin FE/BE contract
- backend layer discipline
- explicit request/session behavior
- documentation truthfulness
- repeatable local validation

Hubins should grow from a stable foundation, not from accumulating assumptions.
