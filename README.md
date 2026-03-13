# Hubins — Auth Lab

Hubins Auth Lab is the foundation repository for the wider Hubins platform.

This repo exists to do one thing first and do it well:

- lock the **topology**
- lock the **frontend ↔ backend communication model**
- lock the **tenant-aware request model**
- lock the **session/cookie contract**
- ship the first real module: **Auth + User Provisioning**

It is intentionally broader in vision than what is implemented today, but it must always be explicit about what is already shipped versus what is still future work.

---

## How to read this repo correctly

There are **two truths** that must be kept separate:

### 1. The broader platform vision

Hubins is intended to grow into a larger multi-tenant SaaS platform. That broader direction is described in `ARCHITECTURE.md`.

### 2. The current shipped foundation

Today, this repository concretely implements:

- the topology foundation
- FE/BE wiring
- same-origin browser API model
- SSR direct-to-backend model
- tenant resolution via host/subdomain
- session-aware request flow
- Auth + User Provisioning backend + frontend surface for the current module scope

Read `docs/current-foundation-status.md` before making assumptions about what is already built.

---

## Current implemented scope

### Topology and FE/BE communication

- reverse-proxy-first topology
- browser uses same-origin relative `/api/*`
- in host-run mode, Next.js Route Handlers proxy browser `/api/*` calls to the backend
- in full-stack / deployed topologies, the public reverse proxy routes `/api/*` to the backend
- SSR uses `INTERNAL_API_URL` and forwards `Host`, `Cookie`, and `X-Forwarded-*`
- backend trusts forwarded headers only because it sits behind the trusted proxy boundary
- full local topology validation exists through the Docker stack and proxy conformance tests

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

This repository now includes the **real Auth + User Provisioning frontend surface** for the current module scope.

What is still intentionally not built yet:

- broader member product modules beyond the authenticated auth/provisioning landing surface
- broader admin product modules beyond the current invite-management surface
- additional business modules beyond Auth + User Provisioning
- broader Hubins platform workflows described in the long-term architecture vision
- later confidence/test hardening work that is tracked separately from the already-shipped auth/provisioning UI surface

That is intentional. The current phase is:

**lock the foundation, ship the auth/provisioning slice, then expand into broader product modules and later hardening phases.**

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
| Testing          | Vitest                |
| Package manager  | Yarn 4 workspaces     |
| Local infra      | Docker Compose        |

---

## Dev modes

There are intentionally **two** local modes.

### Mode 1 — host-run (daily development)

Use this for normal feature work.

```bash
yarn dev
```

What it does:

- starts Postgres + Redis in Docker
- auto-creates `backend/.env` from `backend/.env.example` if needed
- auto-creates `frontend/.env.local` from `frontend/.env.example` if needed
- runs migrations
- regenerates DB types
- starts backend on `http://localhost:3001`
- starts frontend on `http://goodwill-ca.localhost:3000`

Use this browser URL for tenant-aware frontend behavior:

```bash
http://goodwill-ca.localhost:3000
```

Do **not** use plain `localhost:3000` when testing tenant-aware behavior.

In host-run mode:

- browser `/api/*` goes to Next.js first
- the frontend Route Handler proxies those requests to the backend
- SSR uses `INTERNAL_API_URL=http://localhost:3001`

---

### Mode 2 — full Docker stack (topology validation)

Use this when validating real proxy wiring.

```bash
yarn stack
```

Public entrypoint:

```bash
http://goodwill-ca.lvh.me:3000
```

Run proxy conformance tests:

```bash
yarn stack:test
```

Use full stack mode before merging changes that affect:

- `infra/`
- proxy behavior
- request context
- session/cookie policy
- SSO callback behavior
- host / forwarded-header assumptions

See `infra/README.md` for details.

---

## Prerequisites

- Docker
- Node.js 20+
- Corepack / Yarn 4

```bash
corepack enable
```

---

## First-time setup

```bash
yarn dev
```

If the local env files do not exist yet, `scripts/dev.sh` creates them from the committed example templates:

- `backend/.env.example` → `backend/.env`
- `frontend/.env.example` → `frontend/.env.local`

With `SEED_ON_START=true`, the seed creates the `goodwill-ca` tenant and logs a one-time admin invite token for bootstrapping.

Useful health endpoints:

- host-run backend: `http://localhost:3001/health`
- full stack via proxy: `http://goodwill-ca.lvh.me:3000/api/health`

---

## Useful commands

### Root

```bash
yarn dev
yarn stack
yarn stack:down
yarn stack:test
yarn stop
yarn status
yarn reset-db
yarn lint
yarn lint:fix
yarn fmt
yarn fmt:check
yarn verify
```

### Important note about current root gates

At this foundation stage:

- `yarn typecheck` currently runs **backend + frontend** typecheck
- `yarn test` currently runs the **backend** test suite

That is truthful to the repo as it exists today:

- `yarn typecheck` covers backend + frontend
- `yarn test` still represents the backend suite
- `yarn verify` is the root verification command for format + lint + typecheck + **frontend build** + backend tests

### Backend

```bash
cd backend
yarn dev
yarn typecheck
yarn test
yarn test:watch
yarn db:migrate
yarn db:make <description>
yarn db:types
```

### Frontend

```bash
cd frontend
yarn dev
yarn build
yarn start
yarn lint
yarn lint:fix
yarn typecheck
```

---

## Project structure

```text
/
├── README.md
├── ARCHITECTURE.md
├── CONTRIBUTING.md
├── docs/
│   ├── current-foundation-status.md
│   └── decision-log.md
├── backend/
│   ├── src/
│   │   ├── app/                 # bootstrap, config, DI, route registration
│   │   ├── modules/             # bounded contexts
│   │   └── shared/              # infrastructure primitives
│   ├── test/
│   └── docs/
├── frontend/
│   ├── src/app/                 # App Router pages/layouts + host-run api proxy
│   └── src/shared/              # api clients, frontend rules
├── infra/
│   ├── caddy/
│   ├── nginx/
│   ├── docker-compose.yml
│   └── docker-compose-infra.yml
└── scripts/
    ├── dev.sh
    ├── stack.sh
    ├── proxy-conformance.sh
    ├── stop.sh
    ├── status.sh
    └── reset-db.sh
```

---

## Documentation order

Read in this order:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `backend/docs/README.md`
6. `backend/docs/engineering-rules.md`
7. `backend/docs/module-skeleton.md`
8. `frontend/src/shared/engineering-rules.md`
9. `infra/README.md`

Why this order:

- first understand the repo and current shipped scope
- then understand the broader architecture direction
- then move into backend/frontend implementation law

---

## Testing philosophy

Tests are intended to validate behavior against real infrastructure, not mocks pretending to be infrastructure.

Backend tests cover:

- unit tests for pure logic
- DAL tests against real Postgres
- E2E tests through Fastify inject using real DB + Redis-backed app dependencies

The proxy conformance script validates the load-bearing topology assumptions that normal host-run development does not prove.

---

## Important topology rule

In the full topology, the backend is treated as **internal-only behind the proxy**.

That is why forwarded headers such as:

- `X-Forwarded-Host`
- `X-Forwarded-Proto`
- `X-Forwarded-For`

are meaningful and trusted inside the backend request context.

This is not accidental. It is a locked architecture assumption of this foundation.

---

## Repo discipline

This repository should never overclaim readiness.

If a feature is:

- planned
- partially wired
- documented as next work
- or only represented by a brief/spec

it must not be described as already fully implemented.

Use `docs/current-foundation-status.md` to keep that line explicit as the system grows.
