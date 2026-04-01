# Hubins — Auth Lab

Hubins Auth Lab is the foundation repository for the wider Hubins platform.

This repo exists to do a small number of important things well before broader platform expansion:

- lock the **topology**
- lock the **frontend ↔ backend communication model**
- lock the **tenant-aware request model**
- lock the **session/cookie contract**
- ship the first real module: **Auth + User Provisioning**

It is intentionally broader in long-term vision than what is implemented today, but it must stay explicit about what is already shipped versus what is still future work.

---

## How to read this repo correctly

There are two truths that must stay separate.

### 1. The broader platform direction

Hubins is intended to grow into a larger multi-tenant SaaS platform.
That broader direction is described in `ARCHITECTURE.md`.

### 2. The current shipped foundation

Today, this repository concretely implements:

- the topology foundation
- frontend ↔ backend wiring
- same-origin browser API model
- SSR direct-to-backend model with forwarded headers
- tenant resolution via host/subdomain
- session-aware request flow
- the current Auth + User Provisioning backend + frontend surface

Read `docs/current-foundation-status.md` before assuming a broader product area already exists.

---

## Current implemented scope

### Topology and FE/BE communication

- reverse-proxy-first architecture
- browser uses same-origin relative `/api/*`
- in host-run mode, browser `/api/*` first reaches Next.js Route Handlers, which proxy to the backend
- in full-stack mode, the public proxy routes `/api/*` to the backend
- SSR uses `INTERNAL_API_URL` and forwards `Host`, `Cookie`, and `X-Forwarded-*`
- backend trusts forwarded headers only because it sits behind the trusted proxy boundary
- local topology proof exists through the Docker stack and proxy conformance tests

### Backend foundation

- Fastify backend with explicit bootstrap / DI / route registration
- shared request context
- tenant resolution from subdomain / host
- Redis-backed server-side sessions
- health endpoint with real DB + Redis liveness checks
- bounded-context module structure under `backend/src/modules`

### Auth + User Provisioning

- register
- login
- logout
- `/auth/me`
- `/auth/config`
- forgot/reset password
- public signup
- email verification + resend verification
- MFA setup / verify / recovery
- Google + Microsoft SSO
- invite-based provisioning flow
- admin invite lifecycle
- audit event viewing
- outbox-backed email delivery

### Frontend Auth + User Provisioning surface

- Next.js App Router frontend for the current auth/provisioning slice
- root bootstrap handoff and public auth entry routing
- login, signup, invite registration, forgot-password, and reset-password screens
- accept-invite, verify-email, MFA setup, MFA verify, and SSO completion flows
- authenticated member landing, authenticated admin landing, and admin invite management UI
- logout flow and legacy dashboard compatibility handoff
- SSR fetch wrapper + browser fetch wrapper
- host-run `/api/*` Route Handler proxy
- topology smoke-test page proving SSR → backend path works
- tenant-aware frontend host usage in local development

---

## What is intentionally not built yet

This repository now includes the real Auth + User Provisioning frontend surface for the current module scope.

What is still intentionally not built yet:

- broader member product modules beyond the authenticated auth/provisioning landing surface
- broader admin product modules beyond the current invite-management surface
- additional business modules beyond Auth + User Provisioning
- broader Hubins platform workflows described in the long-term architecture vision
- later roadmap stages such as deeper release engineering, broader performance work, and later module expansion

That is intentional.
The current foundation phase is:

**lock the foundation, ship the auth/provisioning slice, then expand into broader product modules and later hardening stages**.

---

## Tech stack

| Layer            | Technology            |
| ---------------- | --------------------- |
| Runtime          | Node.js + TypeScript  |
| Backend HTTP     | Fastify               |
| Database         | PostgreSQL + Kysely   |
| Cache / sessions | Redis                 |
| Validation       | Zod                   |
| Logging          | Winston               |
| Error tracking   | Sentry                |
| Frontend         | Next.js 15 App Router |
| Local proxy      | Caddy                 |
| Testing          | Vitest + Playwright   |
| Package manager  | Yarn 4 workspaces     |
| Local infra      | Docker Compose        |

---

## Prerequisites

- Docker
- Node.js 20+
- Corepack

Enable Corepack once after installing Node:

```bash
corepack enable
```

The repo is pinned to Yarn 4 through `packageManager` in `package.json`.

---

## Local development modes

There are intentionally two local modes.

### Mode 1 — host-run (daily development)

Use this for normal feature work.

```bash
yarn dev
```

What `yarn dev` actually does:

- ensures `infra/.env.stack` exists
- starts Postgres, Redis, Mailpit, and the local OIDC server in Docker
- installs workspace dependencies
- ensures `backend/.env` exists
- ensures `frontend/.env.local` exists
- runs backend migrations
- regenerates DB types
- starts backend on the host
- starts frontend on the host

Current host-run entrypoints:

- Public app: `http://goodwill-ca.lvh.me:3000`
- Backend health: `http://localhost:3001/health`
- Mailpit UI: `http://localhost:8025`
- Local OIDC JWKS: `http://localhost:9998/.well-known/jwks.json`

Use this browser URL for tenant-aware behavior:

```text
http://goodwill-ca.lvh.me:3000
```

Do **not** use plain `localhost:3000` when testing tenant-aware behavior.

In host-run mode:

- browser `/api/*` goes to Next.js first
- the frontend Route Handlers proxy those requests to the backend
- SSR uses `INTERNAL_API_URL=http://localhost:3001`
- infra stays in Docker, but backend/frontend run on the host

### Mode 2 — full Docker stack (topology validation)

Use this when validating the real proxy topology.

You have two entry paths:

#### A. Minimal full stack

```bash
yarn stack
```

This starts the full Docker topology defined in `infra/docker-compose.yml`.

#### B. Full stack plus local OIDC helper

```bash
yarn dev:stack
```

This starts the full Docker topology plus `infra/docker-compose-ci-oidc.yml`.
Use this when you need the local OIDC helper in the full-stack path.

Public full-stack entrypoint:

```text
http://goodwill-ca.lvh.me:3000
```

Run topology validation:

```bash
yarn stack:test
```

Use full-stack mode before merging changes that affect:

- `infra/`
- proxy behavior
- request context
- session/cookie policy
- SSO callback behavior
- host / forwarded-header assumptions

See `infra/README.md` for details.

---

## First-time setup

For most contributors, first-time setup is simply:

```bash
yarn dev
```

If the local env files do not exist yet, `scripts/dev.sh` creates them from the committed example templates.

That means these files are auto-created when missing:

- `infra/.env.stack` from `infra/.env.stack.example`
- `backend/.env` from `backend/.env.example`
- `frontend/.env.local` from `frontend/.env.example`

---

## Useful root commands

### Start normal local development

```bash
yarn dev
```

### Start full Docker topology

```bash
yarn stack
```

### Start full Docker topology plus local OIDC helper

```bash
yarn dev:stack
```

### Stop Docker-backed local modes

```bash
yarn stop
```

### Check local topology status

```bash
yarn status
```

### Reset local DB/Redis Docker volumes

```bash
yarn reset-db
```

### Run repo verification

```bash
yarn verify
```

What `yarn verify` actually runs:

- `yarn fmt:check`
- `yarn lint`
- `yarn typecheck`
- `yarn test`

It does **not** run a frontend production build.
If you specifically need that proof, run:

```bash
yarn build:frontend
```

### Run tests directly

```bash
yarn test
```

What `yarn test` actually does:

- creates/migrates `auth_lab_test`
- runs backend tests against that isolated test DB
- runs frontend unit tests
- runs Playwright E2E only when the canonical app health endpoint is already reachable

If the stack is not reachable at `http://goodwill-ca.lvh.me:3000/api/health`, E2E is skipped.

---

## Seed and bootstrap commands

The repo contains explicit seed/bootstrap commands.
They are **not** automatically run by `yarn dev`.

### Dev seed

```bash
yarn seed:dev
```

### E2E fixture seed

```bash
yarn seed:e2e
```

### Tenant bootstrap helper

```bash
yarn bootstrap:tenant
```

Use these intentionally when you need known personas, test fixtures, or operator-style tenant bootstrap behavior.

---

## Recommended local workflow

### Daily feature loop

```bash
yarn dev
```

### Before pushing or opening a PR

```bash
yarn verify
```

### Before merging topology-sensitive changes

```bash
yarn stack
yarn stack:test
```

Use all three layers appropriately:

- `yarn dev` for normal iteration
- `yarn verify` for format/lint/typecheck/test proof
- `yarn stack:test` for topology-sensitive proof

---

## Where to look next

- `docs/current-foundation-status.md` — current repo truth
- `infra/README.md` — local topology modes and infra details
- `ARCHITECTURE.md` — longer-term architectural direction
- `docs/decision-log.md` — locked architectural/security decisions
- `docs/quality-bar.md` — quality and completion rules
- `docs/ops/runbooks.md` — operator/runbook guidance

---

## Important truth rules

- Do not describe Stage 3 as a fully mature ops system. The repo currently has an operability baseline.
- Do not describe Stage 4 as a fully mature security program. The repo currently has a security-system baseline.
- Do not assume `yarn verify` performs build proof. It currently does not.
- Do not assume `yarn dev` auto-seeds data. It currently does not.
- Do not test tenant-aware browser behavior on plain `localhost:3000`.

Those distinctions matter because this repo is designed to be truthful about what is implemented today.
