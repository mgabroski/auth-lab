# Hubins Auth-Lab — Developer Guide

## Purpose

This guide is the repo's operational setup and repeatability document for the current Auth + User Provisioning module.

Use it to answer:

- how to start the current stack
- how to confirm health/status
- how to reset and reseed to a known state
- what canonical local fixtures exist today
- which personas are seed-backed versus later-phase/external
- which config and secrets each later phase depends on
- how to run the current backend, frontend, Playwright, and proxy checks

This guide is intentionally **scope-constrained**:

- it covers local setup, reset, test-running, and environment expectations
- it does **not** replace deployment or rollback runbooks
- production operator/runbook detail belongs in `docs/ops/runbooks.md`

---

## Locked topology reminders

Keep these invariants unchanged while using this guide:

- one public origin
- browser requests use same-origin `/api/*`
- SSR/server-side frontend code uses `INTERNAL_API_URL` and forwards `Host`, `Cookie`, and `X-Forwarded-*`
- backend owns session/auth truth
- tenant identity is host-derived

When testing tenant-aware behavior, always use the correct host, not plain `localhost`.

---

## Prerequisites

Install or confirm:

- Docker
- Node.js 20+
- Corepack / Yarn 4
- Playwright browsers for frontend E2E (`npx playwright install` if not already installed)
- `jq` for proxy conformance checks (`brew install jq` or equivalent)

Enable Corepack once:

```bash
corepack enable
```

---

## The two local modes

### 1. Host-run mode — daily development

Use this for normal feature work.

```bash
yarn dev
```

What it starts:

- Postgres in Docker
- Redis in Docker
- backend on the host (`http://localhost:3001`)
- frontend on the host (`http://goodwill-ca.localhost:3000`)

What it automatically does before boot:

- installs dependencies
- creates `backend/.env` from `backend/.env.example` if missing
- creates `frontend/.env.local` from `frontend/.env.example` if missing
- runs backend migrations
- regenerates Kysely DB types

Important browser URL:

```text
http://goodwill-ca.localhost:3000
```

Do **not** use `http://localhost:3000` for tenant-aware checks.

### 2. Full stack mode — topology validation

Use this when validating the actual proxy/public topology.

```bash
yarn stack
```

Public entrypoint:

```text
http://goodwill-ca.lvh.me:3000
```

This mode runs:

- Caddy proxy
- frontend in Docker
- backend in Docker
- Postgres
- Redis

Use this before merging changes that affect:

- `infra/`
- proxy rules
- forwarded headers
- session/cookie behavior
- host-derived tenant assumptions
- SSO start/callback topology

---

## Quick-start paths

### A. First-time daily development setup

```bash
yarn dev
```

Then confirm:

- frontend: `http://goodwill-ca.localhost:3000`
- backend health: `http://localhost:3001/health`
- status helper: `yarn status`

### B. First-time full topology setup

```bash
yarn stack
yarn stack:test
```

Then confirm:

- public root: `http://goodwill-ca.lvh.me:3000`
- public health: `http://goodwill-ca.lvh.me:3000/api/health`

---

## Health and status checks

### Fast status snapshot

```bash
yarn status
```

This checks:

- Docker container presence/health
- host-run frontend reachability
- host-run backend reachability
- full-stack public root reachability
- full-stack public `/api/health` reachability

### Direct health endpoints

Host-run backend:

```text
http://localhost:3001/health
```

Full-stack public health:

```text
http://goodwill-ca.lvh.me:3000/api/health
```

### Topology conformance

```bash
yarn stack:test
```

This runs the PT-01 to PT-08 proxy conformance checks against the live full stack.

---

## Canonical reset/reseed procedure

Use this exact sequence to turn a dirty local environment into a clean, seeded state.

### Safe default reset

```bash
yarn stop
yarn reset-db
```

That wipes both:

- infra-only host-run volumes
- full-stack volumes

### Reseed in host-run mode

```bash
yarn seed:dev
```

or, if you want the app running immediately after reset:

```bash
yarn dev
```

Because the committed host-run env template sets `SEED_ON_START=true`, backend startup also runs the canonical dev seed automatically.

---

### Reseed in full-stack mode

```bash
yarn stack
```

The full-stack compose file sets `SEED_ON_START=true`, so backend boot seeds automatically.

### When to prefer the explicit seed command

Use the explicit seed command when:

- infra is already running
- you do not want to start the full backend server yet
- you reset or migrated the DB and want fixtures restored immediately

### After reseed, verify these three checks

1. backend health is green
2. `goodwill-ca` resolves in the app/browser
3. the canonical fixtures below exist

---

## What the canonical local seed creates today

The repo now guarantees these local fixtures through `yarn seed:dev` and `SEED_ON_START=true` startup paths.

### Tenant 1 — admin bootstrap tenant

| Field               | Value                                     |
| ------------------- | ----------------------------------------- |
| Tenant key          | `goodwill-ca`                             |
| Tenant name         | `GoodWill California`                     |
| Public signup       | disabled                                  |
| Member MFA required | false                                     |
| Allowed SSO         | `google`, `microsoft`                     |
| Purpose             | canonical admin onboarding/bootstrap path |

### Tenant 2 — public signup variant tenant

| Field               | Value                                          |
| ------------------- | ---------------------------------------------- |
| Tenant key          | `goodwill-open`                                |
| Tenant name         | `GoodWill Open Signup`                         |
| Public signup       | enabled                                        |
| Member MFA required | false                                          |
| Allowed SSO         | `google`, `microsoft`                          |
| Purpose             | canonical public-signup-enabled policy variant |

### Seeded admin onboarding artifact

| Field          | Value                                |
| -------------- | ------------------------------------ |
| Email          | `system_admin@example.com`           |
| Tenant         | `goodwill-ca`                        |
| Role           | `ADMIN`                              |
| State          | pending invite                       |
| Delivery today | raw invite token logged locally only |
| Why            | local admin bootstrap proof path     |

Important:

- the raw invite token is logged locally for convenience
- that is acceptable only for local development
- shared staging/QA and production must not rely on raw token logging

### Seeded member login persona

| Field             | Value                          |
| ----------------- | ------------------------------ |
| Email             | `member@example.com`           |
| Password          | `Password123!`                 |
| Tenant            | `goodwill-open`                |
| Role              | `MEMBER`                       |
| Membership status | `ACTIVE`                       |
| Email verified    | true                           |
| Purpose           | canonical member login persona |

---

## Test persona matrix

This matrix is the practical Phase 1 truth.

| Persona / variant                  | Source today                                   | Host                                                                       | Credentials / artifact                                        | Use case                                          |
| ---------------------------------- | ---------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------- |
| Admin onboarding                   | canonical local seed                           | `goodwill-ca.localhost:3000` or `goodwill-ca.lvh.me:3000`                  | `system_admin@example.com` + raw invite token from local logs | invite acceptance, first admin onboarding chain   |
| Member login                       | canonical local seed                           | `goodwill-open.localhost:3000` or `goodwill-open.lvh.me:3000`              | `member@example.com` / `Password123!`                         | standard member login/logout                      |
| Public signup disabled tenant      | canonical local seed                           | `goodwill-ca.*`                                                            | n/a                                                           | confirm signup is blocked/hidden by tenant policy |
| Public signup enabled tenant       | canonical local seed                           | `goodwill-open.*`                                                          | n/a                                                           | confirm signup route/behavior on open tenant      |
| MFA proof persona                  | not seed-backed yet                            | created during MFA proof work or test helpers                              | depends on proof flow                                         | Phase 5 real authenticator/recovery validation    |
| Google/Microsoft SSO proof persona | not seed-backed and cannot be fully local-only | external provider sandbox/test account + staging/prod-like callback config | provider-managed credentials                                  | Phase 6/7 live-provider proof                     |

Important truth:

- Phase 1 makes the baseline admin/member/policy variants repeatable locally
- it does **not** claim that real MFA or real provider-backed SSO proof is already completed
- later phases still own real authenticator-app proof and real sandbox/provider round-trips

---

## Environment matrix

### Summary table

| Environment         | Email provider mode                          | Seed/bootstrap mechanism                                                         | Session cookie name                                                     | SSO credential source                                | Tenant/host routing expectation                                                                                    |
| ------------------- | -------------------------------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Local host-run      | `noop` by default; optional local SMTP later | `SEED_ON_START=true` or `yarn seed:dev`                                          | `sid` / `sso-state`                                                     | local placeholder/test values in env                 | use `*.localhost:3000`; browser still uses same-origin `/api/*`; Next Route Handler proxies `/api/*`               |
| Local full stack    | `noop` by default; optional local SMTP later | compose-backed `SEED_ON_START=true` on backend boot                              | `sid` / `sso-state`                                                     | local placeholder/test values in compose env         | use `*.lvh.me:3000`; Caddy is the public entrypoint                                                                |
| Shared staging / QA | sandbox SMTP required for later email phases | operator bootstrap / seed runbook; invite delivery must go through outbox + SMTP | production cookie policy: `__Host-sid` / `__Host-sso-state` under HTTPS | staging sandbox/provider credentials                 | one public origin, reverse proxy in front, same-origin browser `/api/*`, SSR direct backend with forwarded headers |
| Production          | real SMTP provider                           | operator bootstrap/runbook only; never raw token logging                         | `__Host-sid` / `__Host-sso-state` under HTTPS                           | production provider credentials managed outside repo | one public origin, host-derived tenant routing, HTTPS, strict production cookie rules                              |

### Notes that must stay true

- local HTTP environments use non-`__Host-` cookie names because Secure+HTTPS is not active there
- production/staging expectations use the locked `__Host-` cookie policy under HTTPS
- the browser never calls the backend directly by host/port in any environment
- SSR still calls the backend directly via `INTERNAL_API_URL`/internal service URL and forwards request headers

---

## Secrets and config checklist

This is the minimum practical checklist for current and upcoming auth phases.

| Dependency / purpose              | Variable(s)                                                                                            | Expected format                                                           | Where it must be set                               | First phase that depends on it       |
| --------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------ |
| Postgres                          | `DATABASE_URL`                                                                                         | Postgres connection string                                                | backend env / compose                              | current foundation                   |
| Redis                             | `REDIS_URL`                                                                                            | Redis connection string                                                   | backend env / compose                              | current foundation                   |
| Session TTL                       | `SESSION_TTL_SECONDS`                                                                                  | integer seconds                                                           | backend env / compose                              | current foundation                   |
| Password hashing                  | `BCRYPT_COST`                                                                                          | integer cost                                                              | backend env / compose                              | current foundation                   |
| MFA issuer                        | `MFA_ISSUER`                                                                                           | non-empty string                                                          | backend env / compose                              | current foundation                   |
| MFA secret encryption             | `MFA_ENCRYPTION_KEY_BASE64`                                                                            | base64 that decodes to exactly 32 bytes                                   | backend env / compose                              | current foundation / Phase 5 proof   |
| MFA recovery-code hashing         | `MFA_HMAC_KEY_BASE64`                                                                                  | base64 string                                                             | backend env / compose                              | current foundation / Phase 5 proof   |
| SSO state cookie encryption       | `SSO_STATE_ENCRYPTION_KEY`                                                                             | base64 that decodes to exactly 32 bytes                                   | backend env / compose                              | current foundation / Phase 6-7 proof |
| SSO redirect base fallback        | `SSO_REDIRECT_BASE_URL`                                                                                | absolute URL                                                              | backend env / compose                              | current foundation / later SSO proof |
| Google SSO                        | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`                                                             | provider credential strings                                               | backend env / compose / staging secret store       | Phase 6                              |
| Microsoft SSO                     | `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`                                                       | provider credential strings                                               | backend env / compose / staging secret store       | Phase 7                              |
| Outbox encryption                 | `OUTBOX_ENC_DEFAULT_VERSION`, `OUTBOX_ENC_KEY_V1` (+ optional future versions)                         | version string + 32-byte base64 key(s)                                    | backend env / compose                              | current foundation / email phases    |
| Email provider selection          | `EMAIL_PROVIDER`                                                                                       | `noop` or `smtp`                                                          | backend env / compose                              | current foundation / Phase 2         |
| SMTP transport                    | `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `SMTP_PUBLIC_BASE_URL` | host / integer / boolean / credential strings / from value / URL template | backend env / compose / staging secret store       | Phase 2                              |
| Sentry                            | `SENTRY_DSN`                                                                                           | URL                                                                       | backend env / deployment secret store              | later production hardening           |
| Canonical seed enablement         | `SEED_ON_START`                                                                                        | boolean                                                                   | backend env / compose                              | Phase 1                              |
| Canonical seed tenant/admin knobs | `SEED_TENANT_KEY`, `SEED_TENANT_NAME`, `SEED_ADMIN_EMAIL`, `SEED_INVITE_TTL_HOURS`                     | strings / integer hours                                                   | backend env / compose                              | Phase 1                              |
| Frontend SSR backend access       | `INTERNAL_API_URL`                                                                                     | absolute backend URL                                                      | frontend env / compose / Playwright web server env | current foundation                   |
| Frontend env marker               | `NEXT_PUBLIC_ENV`                                                                                      | string                                                                    | frontend env / compose                             | optional informational only          |

### Current repo truth

- committed host-run env templates exist for backend and frontend
- the full stack compose file carries its own local-safe dev values
- shared staging/QA and production secret storage are documented as expectations, not provisioned by this repo alone

---

## Running the seed

### Explicit seed command

From repo root:

```bash
yarn seed:dev
```

From `backend/` directly:

```bash
yarn db:seed:dev
```

### Startup-driven seed path

If `SEED_ON_START=true`, backend startup also runs the canonical seed.

That means all of these seed automatically:

```bash
yarn dev
yarn stack
```

### When seed output matters

For local admin onboarding, watch the backend logs for the raw invite token tied to `system_admin@example.com`.

That raw token logging is:

- allowed locally
- not the contract for shared staging/QA
- forbidden in production

---

## Running tests and checks

### Repo-wide verification

```bash
yarn verify
```

Current repo truth:

- format check
- lint
- backend + frontend typecheck
- frontend build
- backend tests
- frontend tests

### Backend tests

```bash
yarn test:backend
```

or:

```bash
cd backend
yarn test
```

### Frontend unit tests

```bash
yarn test:frontend:unit
```

or:

```bash
cd frontend
yarn test:unit
```

### Frontend Playwright locally

```bash
yarn test:frontend:e2e
```

or:

```bash
cd frontend
yarn test:e2e
```

Important:

- the current Playwright suite uses its own mock auth backend on port `3101`
- it validates frontend auth journeys and routing discipline
- it is **not** the same thing as the full real-stack/proxy proof path from later phases

### Proxy conformance checks

```bash
yarn stack
yarn stack:test
```

These validate the live Docker stack through the proxy path.

---

## Troubleshooting checklist

### `yarn dev` fails immediately with missing env example

Confirm these committed files exist:

- `backend/.env.example`
- `frontend/.env.example`

### Frontend loads but auth/SSR is broken

Check `frontend/.env.local`:

```env
INTERNAL_API_URL=http://localhost:3001
```

### Host-run app opens but tenant-aware behavior is wrong

Confirm the browser URL includes the subdomain:

```text
http://goodwill-ca.localhost:3000
```

not plain `localhost:3000`.

### Full stack is up but proxy tests fail

Run:

```bash
yarn status
yarn stack:test
```

and verify you are using `*.lvh.me:3000`, not plain `localhost:3000`.

### Local fixtures are missing after reset

Run:

```bash
yarn seed:dev
```

or restart via:

```bash
yarn dev
```

with `SEED_ON_START=true` in `backend/.env`.

---

## Truthful limitations at the end of Phase 1

Phase 1 after these updates means:

- a new engineer can start the local environment from committed examples
- local reset/reseed is explicit and repeatable
- the canonical admin/member/policy variants are present locally
- proxy conformance checks have an explicit local path
- config/secrets discovery for later phases is documented

It does **not** mean:

- real SMTP delivery is already proven
- real authenticator-app MFA proof is already done
- real Google/Microsoft provider round-trips are already done
- shared staging/QA bootstrap is already proven end to end

Those remain owned by later roadmap phases.
