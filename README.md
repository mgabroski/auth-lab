# Hubins — Auth Lab

Hubins Auth Lab is the foundation repository for the wider Hubins platform.

This repo exists to prove and protect a small number of critical things before broader expansion:

- multi-tenant topology
- browser and SSR request contracts
- host-derived tenant resolution
- session and cookie behavior
- the first shipped module: Auth + User Provisioning

This file is the single human entrypoint for the repo.

---

## Read First

If you are new to the repo, read these in order:

1. `docs/current-foundation-status.md`
2. `ARCHITECTURE.md`
3. `docs/quality-bar.md`
4. `docs/decision-log.md`
5. `docs/security-model.md`

Then route by area:

- local setup and commands → `docs/developer-guide.md`
- contribution rules → `CONTRIBUTING.md`
- review expectations → `code_review.md`
- backend implementation law → `backend/docs/engineering-rules.md`
- frontend implementation law → `frontend/src/shared/engineering-rules.md`

For AI/review agents, the entrypoint is `AGENTS.md`, not this file.

---

## What This Repo Is

Today, this repository is the working foundation for:

- reverse-proxy-aware multi-tenant application behavior
- same-origin browser API usage
- SSR direct-to-backend calls with forwarded tenant/session headers
- backend session-aware auth and tenant resolution
- frontend auth/provisioning flows
- Auth + User Provisioning as the first real module

It is not the full future Hubins product.

Use `docs/current-foundation-status.md` before describing anything as shipped.

---

## Current Shipped Scope

### Foundation

- reverse-proxy-first topology
- host-derived tenant identity
- browser `/api/*` request contract
- SSR internal API contract
- session and cookie contract
- proxy conformance proof
- baseline operability, security, and release discipline

### Backend

- Fastify backend
- PostgreSQL + Kysely
- Redis-backed server-side sessions
- shared request context
- bounded module structure
- health checks and core observability baseline

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
- Google SSO
- Microsoft SSO
- invite-based provisioning
- admin invite lifecycle
- audit viewing
- outbox-backed email delivery

### Frontend

- Next.js App Router frontend for the current auth/provisioning surface
- public auth entry routes
- invite registration and acceptance flows
- password reset and email verification flows
- MFA setup and verify flows
- SSO completion flow
- member landing
- admin landing
- admin invite management
- SSR fetch wrapper
- browser API wrapper
- host-run `/api/*` proxy path

---

## What Is Not Shipped Yet

This repo does **not** yet claim broader product completion.

Examples of intentionally unshipped scope:

- broader tenant product modules beyond the current auth/provisioning slice
- broader admin product areas beyond the current invite-management/admin landing surface
- later-stage platform capabilities that are documented as future work in architecture or roadmap materials
- full production-maturity claims beyond the current proven baseline

Do not collapse architecture vision into shipped truth.

---

## Tech Stack

- Node.js + TypeScript
- Fastify
- PostgreSQL + Kysely
- Redis
- Next.js 15 App Router
- Caddy for local proxy topology
- Vitest + Playwright
- Yarn 4 workspaces
- Docker Compose for local infra

---

## Quick Start

### Prerequisites

- Docker
- Node.js 20+
- Corepack

Enable Corepack once:

```bash
corepack enable
```

### Daily local development

```bash
yarn dev
```

Primary local tenant URL:

```text
http://goodwill-ca.lvh.me:3000
```

Do **not** use plain `localhost:3000` for tenant-aware browser behavior.

### Full topology validation

```bash
yarn stack
yarn stack:test
```

Use this for proxy, cookie, host-header, SSR, SSO callback, and other topology-sensitive work.

---

## Useful Commands

### Start normal development

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

### Stop local stack

```bash
yarn stop
```

### Check stack status

```bash
yarn status
```

### Reset local DB/Redis volumes

```bash
yarn reset-db
```

### Run repo verification

```bash
yarn verify
```

### Run tests directly

```bash
yarn test
```

### Run frontend production build explicitly

```bash
yarn build:frontend
```

For setup details, env behavior, seeding, reset flows, and deeper local workflow guidance, use `docs/developer-guide.md`.

---

## Canonical Repo Map

### Repo truth

- `docs/current-foundation-status.md`
- `ARCHITECTURE.md`
- `docs/quality-bar.md`
- `docs/quality-exceptions.md`
- `docs/decision-log.md`
- `docs/security-model.md`

### Working rules

- `CONTRIBUTING.md`
- `code_review.md`
- `AGENTS.md`

### Local execution and support

- `docs/developer-guide.md`
- `docs/ops/runbooks.md`
- `docs/ops/observability.md`
- `docs/ops/release-engineering.md`

### Backend

- `backend/AGENTS.md`
- `backend/docs/engineering-rules.md`
- `backend/docs/module-skeleton.md`
- `backend/docs/api/*.md`

### Frontend

- `frontend/AGENTS.md`
- `frontend/src/shared/engineering-rules.md`
- `frontend/docs/module-skeleton.md`

### Prompt assets

- `docs/prompts/catalog.md`

---

## Repo Truth Rules

- `docs/current-foundation-status.md` is the current shipped-truth snapshot.
- `ARCHITECTURE.md` is architecture law, not a promise that every described module already exists.
- `docs/developer-guide.md` owns detailed local setup and workflow instructions.
- `AGENTS.md` is the AI entrypoint.
- Do not create a second source of truth when an existing canonical doc can be updated instead.

---

## Final Position

Start here as a human.

If you need deeper execution details, go to `docs/developer-guide.md`.
If you need repo law, go to the canonical docs listed above.
If you are an AI agent, switch to `AGENTS.md`.
