# Insynctive — Auth Lab

The first implemented backend module of the Insynctive platform. Auth Lab is the foundation service: multi-tenant authentication and user provisioning, built to production quality before any other module ships.

---

## What this module does

- **Tenant resolution** — every request is scoped to a tenant resolved from the URL subdomain
- **Invite provisioning** — admin creates invite → user accepts → registers
- **Password registration** — invite-based, creates user + membership + auth identity
- **Public signup** — self-service with email verification
- **Email verification** — token-based, required for public signup only
- **Password login** — server-side Redis sessions, bcrypt, rate-limited
- **Password reset** — silent rate limit, one-time token, session destruction on complete
- **MFA (TOTP)** — mandatory for admins, setup / verify / recovery, secrets encrypted at rest
- **SSO** — Google + Microsoft OAuth2/OIDC, nonce/state AES-encrypted, subject drift protection
- **Admin invite lifecycle** — create / resend / cancel / list with full audit trail
- **Admin audit viewer** — paginated, tenant-scoped, filterable audit event log
- **Durable email delivery** — DB outbox with claim-lease worker, no lock held during send
- **Audit events** — append-only, two-phase (success inside tx, failure outside tx)
- **Rate limiting** — every mutation endpoint

---

## Stack

| Layer            | Technology                      |
| ---------------- | ------------------------------- |
| Runtime          | Node.js + TypeScript (strict)   |
| HTTP             | Fastify                         |
| Database         | PostgreSQL + Kysely (typed SQL) |
| Cache / sessions | Redis                           |
| Validation       | Zod                             |
| Logging          | Winston JSON (CloudWatch-ready) |
| Error tracking   | Sentry (unhandled 500s only)    |
| Testing          | Vitest                          |
| Package manager  | Yarn 4 workspaces               |
| Local infra      | Docker Compose                  |

---

## Quick start

### Prerequisites

- Docker and Docker Compose
- Node.js ≥ 20
- Yarn 4 (`corepack enable`)

### Setup

```bash
# 1. Copy the example env file (run from repo root)
cp backend/.env.example backend/.env

# 2. Start local infrastructure — Postgres + Redis (run from repo root)
yarn dev

# 3. Run migrations and generate DB types (run from backend/)
cd backend
yarn db:migrate
yarn db:types

# 4. Start the backend in watch mode (run from backend/)
yarn dev
```

The server starts on `http://localhost:3000`. Health check: `GET http://localhost:3000/health`.

On first start with `SEED_ON_START=true` in `.env`, the seed creates a tenant (`goodwill-ca` by default) and prints a one-time admin invite token to the logs.

---

## Environment variables

All variables are parsed and validated at startup via Zod. The server refuses to start if a required variable is missing or malformed.

| Variable                     | Required | Default               | Description                                                          |
| ---------------------------- | -------- | --------------------- | -------------------------------------------------------------------- |
| `DATABASE_URL`               | ✅       | —                     | PostgreSQL connection string                                         |
| `REDIS_URL`                  | ✅       | —                     | Redis connection string                                              |
| `MFA_ENCRYPTION_KEY_BASE64`  | ✅       | —                     | AES-256-GCM key for TOTP secret encryption (base64)                  |
| `MFA_HMAC_KEY_BASE64`        | ✅       | —                     | HMAC-SHA256 pepper for recovery code hashing (base64)                |
| `SSO_STATE_ENCRYPTION_KEY`   | ✅       | —                     | AES-256-GCM key for SSO state payload encryption (base64)            |
| `SSO_REDIRECT_BASE_URL`      | ✅       | —                     | Base URL for SSO callback redirects (e.g. `https://app.example.com`) |
| `GOOGLE_CLIENT_ID`           | ✅       | —                     | Google OAuth2 client ID                                              |
| `GOOGLE_CLIENT_SECRET`       | ✅       | —                     | Google OAuth2 client secret                                          |
| `MICROSOFT_CLIENT_ID`        | ✅       | —                     | Microsoft OAuth2 client ID                                           |
| `MICROSOFT_CLIENT_SECRET`    | ✅       | —                     | Microsoft OAuth2 client secret                                       |
| `OUTBOX_ENC_DEFAULT_VERSION` | ✅       | `v1`                  | Active outbox encryption key version (must have a matching key)      |
| `OUTBOX_ENC_KEY_V1`          | ✅       | —                     | AES-256-GCM key for outbox payload encryption, version 1 (base64)    |
| `PORT`                       | —        | `3000`                | HTTP port                                                            |
| `LOG_LEVEL`                  | —        | `info`                | Winston log level                                                    |
| `SERVICE_NAME`               | —        | `auth-lab-backend`    | Included in every structured log line                                |
| `BCRYPT_COST`                | —        | `12`                  | bcrypt work factor (10–15)                                           |
| `SESSION_TTL_SECONDS`        | —        | `86400`               | Session lifetime (5 min – 7 days)                                    |
| `MFA_ISSUER`                 | —        | `Hubins`              | Issuer name shown in authenticator apps                              |
| `OUTBOX_POLL_INTERVAL_MS`    | —        | `5000`                | How often the outbox worker polls for pending messages               |
| `OUTBOX_BATCH_SIZE`          | —        | `10`                  | Messages claimed per worker poll cycle                               |
| `OUTBOX_MAX_ATTEMPTS`        | —        | `5`                   | Max delivery attempts before a message is dead-lettered              |
| `OUTBOX_ENC_KEY_V2`          | —        | —                     | Optional second outbox key version (key rotation)                    |
| `OUTBOX_ENC_KEY_V3`          | —        | —                     | Optional third outbox key version (key rotation)                     |
| `SENTRY_DSN`                 | —        | —                     | Sentry DSN. Omit in dev/CI — Sentry stays uninitialised              |
| `SEED_ON_START`              | —        | `false`               | Run idempotent dev seed on startup                                   |
| `SEED_TENANT_KEY`            | —        | `goodwill-ca`         | Subdomain key for the seed tenant                                    |
| `SEED_TENANT_NAME`           | —        | `GoodWill California` | Display name for the seed tenant                                     |
| `SEED_ADMIN_EMAIL`           | —        | `admin@example.com`   | Email for the seed admin invite                                      |

See `backend/src/app/config.ts` for the complete Zod schema.

---

## Useful commands

```bash
# Infrastructure (run from repo root)
yarn dev               # start Postgres + Redis in Docker
yarn stop              # stop Docker containers
yarn status            # show running container status
yarn reset-db          # drop and recreate the local dev database

# Backend (run from backend/)
cd backend
yarn dev               # start backend in watch mode

# Database (run from backend/)
yarn db:migrate        # run pending migrations
yarn db:make <name>    # scaffold a new migration file
yarn db:types          # regenerate src/shared/db/database.types.ts from schema

# Code quality (run from repo root)
yarn lint              # ESLint
yarn lint:fix          # ESLint with auto-fix
yarn typecheck         # tsc --noEmit
yarn test              # all tests (unit + DAL + E2E)
yarn test:watch        # tests in watch mode
yarn fmt               # Prettier write
yarn fmt:check         # Prettier check
```

---

## Project structure

```
/
├── ARCHITECTURE.md          ← architecture law — read this first
├── CONTRIBUTING.md          ← how to contribute
└── backend/
    ├── src/
    │   ├── app/             ← server bootstrap, DI, config, routes
    │   ├── modules/         ← bounded context modules
    │   │   ├── auth/        ← authentication + MFA + SSO
    │   │   ├── invites/     ← invite provisioning + admin invite management
    │   │   ├── memberships/ ← membership DAL and public surface
    │   │   ├── tenants/     ← tenant resolution and policies
    │   │   ├── users/       ← user DAL and public surface
    │   │   ├── audit/       ← admin audit event viewer
    │   │   └── _shared/     ← cross-module use cases (stable, locked contracts)
    │   └── shared/          ← infrastructure primitives (DB, Redis, outbox, sessions, security)
    ├── test/
    │   ├── e2e/             ← endpoint tests using Fastify inject()
    │   ├── dal/             ← DAL tests against real Postgres
    │   └── unit/            ← pure unit tests (policies, encryption utilities)
    └── docs/                ← engineering rules, module skeleton, LLM prompts
```

---

## Documentation

Start here, in this order:

1. `ARCHITECTURE.md` — what Insynctive is, the bounded contexts, the architectural laws
2. `backend/docs/README.md` — the docs map for backend engineering
3. `backend/docs/engineering-rules.md` — the implementation law every PR is checked against
4. `backend/docs/module-skeleton.md` — the canonical structure every module must follow

---

## Tests

Tests run against real infrastructure (Postgres + Redis). There are no mocks for the database layer.

```bash
# Start infra first (run from repo root)
yarn dev

# Run all tests (run from backend/)
cd backend && yarn test
```

Test layers:

| Layer | Location     | Uses                                                          |
| ----- | ------------ | ------------------------------------------------------------- |
| Unit  | `test/unit/` | Pure functions, no infra. Policies and encryption utilities.  |
| DAL   | `test/dal/`  | Real Postgres, `resetDb()` between each test file.            |
| E2E   | `test/e2e/`  | Real Postgres + Redis, `buildTestApp()` + Fastify `inject()`. |

The E2E tests do not start an HTTP server. They use Fastify's `inject()` method to make in-process HTTP calls, which is faster and deterministic.
