# Hubins Auth-Lab — Current Foundation and Frontend Module Status

## Purpose

This document is the truthful snapshot of what currently exists in the repository.

It exists to prevent drift between:

- what the repo actually implements
- what contributors think is implemented
- what future prompts and reviews assume is implemented

This file should be updated whenever the practical status of the foundation or frontend Auth + User Provisioning module changes in a meaningful way.

---

## 1. High-level status

The repository is past pure foundation stage.

The platform topology and wiring foundation are implemented, and the frontend Auth + User Provisioning module is fully implemented for its intended scope.

That means the repo should no longer be described as only:

- infra planning
- topology planning
- backend-only auth groundwork
- frontend shell/foundation only

Those descriptions are now incomplete.

---

## 2. What is implemented at foundation level

The following core foundation areas are implemented and load-bearing:

### Repository and infrastructure foundation

- monorepo/workspace structure
- frontend application
- backend application
- Docker-based local infrastructure
- Postgres and Redis integration for local/dev topology
- local development commands for host-run and stack-run workflows

### Topology foundation

- single public-origin frontend model
- same-origin browser API model using `/api/*`
- SSR direct-backend model using internal backend connectivity
- tenant-aware request handling
- host-derived tenant identity model
- proxy-compatible routing model
- compatibility between local host-run mode and full-stack/proxy-aware mode

### Auth/backend truth foundation

- backend-owned session truth
- backend-owned continuation truth through `nextAction`
- backend config endpoint for tenant auth state
- backend `me` endpoint for authenticated session/bootstrap truth
- invite and provisioning backend surface
- password auth backend surface
- MFA backend surface
- SSO callback/backend handling surface

These are not speculative anymore. They are part of the current implemented system shape.

---

## 3. What is implemented in the frontend Auth + User Provisioning module

The current frontend includes the real route and UI surface for the Auth + User Provisioning scope.

### Implemented frontend route surface

#### Public/bootstrap routes

- `/`
- `/auth`
- `/auth/unavailable`
- `/topology-check`

#### Public auth routes

- `/auth/login`
- `/auth/signup`
- `/auth/register`
- `/auth/forgot-password`
- `/auth/reset-password`

#### Invite and continuation routes

- `/accept-invite`
- `/verify-email`
- `/auth/mfa/setup`
- `/auth/mfa/verify`
- `/auth/sso/done`
- `/auth/continue/[action]`

#### Authenticated routes

- `/app`
- `/admin`
- `/admin/invites`

#### Compatibility route

- `/dashboard`

### Implemented frontend auth/provisioning capabilities

- root bootstrap handoff
- public auth entry routing
- login flow
- public signup flow
- invite registration flow
- forgot-password flow
- reset-password flow
- invite acceptance flow
- verify-email continuation flow
- MFA setup flow
- MFA verify flow
- SSO completion landing
- authenticated member landing
- authenticated admin landing
- admin invite management UI
- logout flow
- legacy dashboard compatibility handoff

This means the frontend Auth + User Provisioning module is complete for its intended scope.

---

## 4. Scope boundary for this completed module

This repo snapshot should not be described as containing the full Hubins product frontend.

That does not mean this module is incomplete.
It means the Hubins product contains other future modules that are separate from Auth + User Provisioning.

The following areas are intentionally outside the scope of this completed module:

- broader member product modules beyond the authenticated landing surface
- full admin control-plane/product dashboard beyond current invite management
- non-auth product modules
- broader product navigation across future modules
- future management screens unrelated to current auth/provisioning needs

This distinction matters.

The Auth + User Provisioning frontend module is complete.
Broader Hubins product UI belongs to separate future modules.

---

## 5. Current frontend truth that reviewers must respect

When reviewing or extending this repository, contributors should assume the following are already true:

### 5.1 Browser-side API rule

Browser code must use same-origin relative requests:

```text
/api/*
```

Browser code must not hardcode backend origins.

### 5.2 SSR rule

SSR/server-side frontend code may call the backend directly using the internal backend URL.

When it does so, it must preserve the forwarded request identity context required for:

- tenant resolution
- cookie continuity
- request fidelity

### 5.3 Tenant rule

Tenant identity is host-derived.

It must not be moved into:

- query params
- local storage
- arbitrary frontend state
- request bodies as a replacement for host-derived truth

### 5.4 Session and continuation rule

The backend owns:

- session truth
- continuation truth
- `nextAction`

The frontend must consume that truth, not replace it with frontend-only decision logic.

---

## 6. Current practical repo status

A truthful current summary is:

> The topology/foundation layer is implemented, and the frontend Auth + User Provisioning module is fully implemented for its intended scope.

A misleading summary would be any statement that says either:

> The repo is still only foundation-level with no real frontend auth UI.

or:

> The full Hubins product frontend is already implemented.

Both are false.

---

## 7. Current known boundaries

The following boundaries should remain explicit:

### Complete for current scope

- topology-aware frontend/backend integration model
- auth/provisioning route-state model
- real frontend auth/provisioning screens
- continuation flows
- authenticated landing handoff
- admin invite management surface
- logout flow

### Separate future module work

- broader post-auth product experience
- additional admin modules beyond invite management
- non-auth domain modules
- future UX/system surfaces outside auth/provisioning

---

## 8. How to use this document in future prompts and reviews

When creating future implementation or review prompts:

- treat topology as already locked and implemented
- treat same-origin browser `/api/*` behavior as already locked
- treat SSR direct-backend behavior as already locked
- treat the frontend Auth + User Provisioning module as complete for its intended scope
- do not ask future prompts to rebuild already completed auth/provisioning foundation work

Future prompts should build on this state, not regress the repository narrative backward.

---

## 9. Truthfulness rule

This file is a status document, not a roadmap.

It must describe:

- what exists now
- what is outside this module’s scope now
- what belongs to separate future modules now

It must not:

- advertise future work as already complete
- describe already-implemented frontend auth/provisioning surfaces as if they do not exist
- blur the boundary between current module completion and future module work

---

## 10. Current one-paragraph status statement

Use the following paragraph when a concise repo status summary is needed:

> Hubins Auth-Lab currently has its topology and foundation layer implemented, and the frontend Auth + User Provisioning module is fully implemented for its intended scope, including bootstrap, public auth, invite and continuation flows, authenticated member and admin landing routes, admin invite management, and logout. Any broader Hubins product UI belongs to separate future modules and is outside the scope of this completed module.
