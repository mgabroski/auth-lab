# Hubins Auth-Lab — Developer Guide

> **Document validation (Phase 10 requirement)**
> Last reviewed by: Engineering lead
> Review date: 2026-03
> Review method: Independent read-through against the running local stack, confirming
> all commands, paths, and environment instructions match the current repo state.
> This document was reviewed by someone other than its original author as required
> by the Phase 10 module lock exit criteria.

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

Install workspace dependencies:

```bash
yarn install
```

---

## Repository layout at a glance

Main working areas:

- `backend/` — Node/TypeScript backend
- `frontend/` — Next.js frontend
- `infra/` — Docker Compose topology and infra services
- `docs/` — active repo truth docs and runbooks

Important docs:

- `docs/current-foundation-status.md`
- `docs/ops/runbooks.md`
- this file

---

## Environment files

### Backend example env

Copy:

```bash
cp backend/.env.example backend/.env
```

Important defaults in the example:

- local Postgres on `localhost:5432`
- local Redis on `localhost:6379`
- local Mailpit SMTP on `localhost:1025`
- frontend public-base-url pattern: `http://{tenantKey}.localhost:3000`
- `SEED_ON_START=true`

Update values only as needed for your machine.

### Frontend example env

Copy:

```bash
cp frontend/.env.example frontend/.env.local
```

Default:

```env
INTERNAL_API_URL=http://localhost:3001
NEXT_PUBLIC_ENV=development
```

Do not point browser requests directly at backend public ports.
The browser must continue to use same-origin `/api/*`.

### Infra stack example env

If you are running the Docker/local-stack path that reads stack-level env, copy:

```bash
cp infra/.env.stack.example infra/.env.stack
```

This is the right place to wire backend/runtime secrets for the stack-driven environment when you are not using a host-run `backend/.env` directly.

---

## Phase 6 Google SSO config checklist

This is the repo-level secrets/config checklist for the Google live-provider proof.

### Backend env keys used by Google SSO

These keys belong in the backend environment only:

- `GOOGLE_CLIENT_ID` — Google OAuth web application client ID
- `GOOGLE_CLIENT_SECRET` — Google OAuth client secret
- `SSO_STATE_ENCRYPTION_KEY` — encrypts the short-lived `sso-state` cookie payload
- `SSO_REDIRECT_BASE_URL` — fallback only when the real public request origin is unavailable

### Frontend env keys

No Google OAuth client secret belongs in the frontend.
The frontend only needs:

- `INTERNAL_API_URL` for SSR/server-side backend calls
- `NEXT_PUBLIC_ENV` for environment display/behavior

### Staging Google app registration checklist

For the shared staging environment, document and confirm all of the following before attempting the live round-trip:

1. Google app type is **Web application**
2. the staging backend env contains the real `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`
3. the Google app has the exact authorized redirect URI for the staging tenant host you are proving, in the form:

```text
https://<tenant-host>/api/auth/sso/google/callback
```

4. the staging tenant has `google` in `allowed_sso`
5. the staging tenant host resolves through the real same-origin `/api/*` topology

### Provider key discovery reachability check

Before the live proof, confirm the staging network can reach Google's JWKS endpoint because backend token validation depends on it:

```bash
curl -fsS https://www.googleapis.com/oauth2/v3/certs > /dev/null
```

A zero-exit curl is the minimum pass signal for provider-key reachability.

---

## Phase 7 Microsoft SSO config checklist

This is the repo-level secrets/config checklist for the Microsoft live-provider proof.

### Exact env files used by this repo for Microsoft SSO wiring

Use these exact example files as the wiring source of truth:

- `backend/.env.example` → copy into `backend/.env` for host-run backend development
- `infra/.env.stack.example` → copy into `infra/.env.stack` for Docker/local-stack or staging-style stack wiring
- `frontend/.env.example` → copy into `frontend/.env.local` for frontend SSR wiring only

### Backend env keys used by Microsoft SSO

These keys belong in the backend environment only:

- `MICROSOFT_CLIENT_ID` — the Microsoft **Application (client) ID** from the app registration Overview page
- `MICROSOFT_CLIENT_SECRET` — the Microsoft client secret **Value** from **Certificates & secrets**
- `SSO_STATE_ENCRYPTION_KEY` — encrypts the short-lived `sso-state` cookie payload
- `SSO_REDIRECT_BASE_URL` — fallback only when the real public request origin is unavailable

Important repo-specific rule:

- this repo does **not** use a `MICROSOFT_TENANT_ID` env var
- the backend starts against Microsoft `/common` endpoints and resolves the final issuer from the token `tid` claim during verification

### Frontend env keys

No Microsoft OAuth client secret belongs in the frontend.
The frontend only needs:

- `INTERNAL_API_URL` for SSR/server-side backend calls
- `NEXT_PUBLIC_ENV` for environment display/behavior

### Microsoft claim fallback behavior confirmed in this repo

The Microsoft callback path resolves the user email in this exact order:

1. `email`
2. `preferred_username`
3. `upn`

The resolved value is normalized to lowercase before user lookup / identity linking.
If none of those claims contains an email-like value, the callback must fail.

### Staging Microsoft app registration checklist

For the shared staging environment, document and confirm all of the following before attempting the live round-trip:

1. Microsoft app platform is **Web**
2. Supported account types is **Accounts in any organizational directory and personal Microsoft accounts**
3. the staging backend env contains the real `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET`
4. the Microsoft app has the exact redirect URI for the staging tenant host you are proving, in the form:

```text
https://<tenant-host>/api/auth/sso/microsoft/callback
```

5. the staging tenant has `microsoft` in `allowed_sso`
6. the staging tenant host resolves through the real same-origin `/api/*` topology

### Exact value mapping from Microsoft into repo env

Use these exact mappings:

- Microsoft **Application (client) ID** → `MICROSOFT_CLIENT_ID`
- Microsoft client secret **Value** → `MICROSOFT_CLIENT_SECRET`
- Microsoft **Directory (tenant) ID** → operator reference only; do not try to wire it into backend env because this repo does not read a `MICROSOFT_TENANT_ID`

### Provider key discovery reachability check

Before the live proof, confirm the staging network can reach Microsoft's JWKS endpoint because backend token validation depends on it:

```bash
curl -fsS https://login.microsoftonline.com/common/discovery/v2.0/keys > /dev/null
```

A zero-exit curl is the minimum pass signal for provider-key reachability.

---

## Supported local run modes

The repo supports two main local paths.

### Mode A — Host-run app + infra services

Use this for fastest inner-loop development.

Infra only:

```bash
docker compose -f infra/docker-compose-infra.yml up -d
```

Then start backend:

```bash
yarn workspace @auth-lab/backend dev
```

Then start frontend:

```bash
yarn workspace @auth-lab/frontend dev
```

What runs in this mode:

- Postgres
- Redis
- Mailpit
- backend on host
- frontend on host

Recommended URL for tenant-aware testing:

- `http://goodwill-ca.localhost:3000`

Mailpit UI:

- `http://localhost:8025`

### Mode B — Full local stack via Docker Compose

Use this when you want the full proxy/topology path.

```bash
docker compose -f infra/docker-compose.yml up -d --build
```

This runs:

- proxy
- frontend
- backend
- Postgres
- Redis
- Mailpit

Use the committed proxy host contract from infra/docs or your local host mappings if already established in the repo.

---

## Health and basic verification

### Backend health

Check:

```bash
curl -s http://localhost:3001/health | jq
```

Expected:

- `ok: true`
- db check healthy
- redis check healthy

### Frontend availability

Open the tenant host in the browser, for example:

- `http://goodwill-ca.localhost:3000`

### Mailpit availability

Open:

- `http://localhost:8025`

You should see captured messages if the outbox poller and SMTP configuration are correct.

---

## Canonical seed behavior

The canonical seed now supports both identity/bootstrap data and local email proof.

Relevant example env keys:

```env
SEED_ON_START=true
SEED_TENANT_KEY=goodwill-ca
SEED_TENANT_NAME=GoodWill California
SEED_ADMIN_EMAIL=system_admin@example.com
SEED_INVITE_TTL_HOURS=168
```

### What the seed is expected to create

At minimum, the dev seed is expected to prepare:

- the seed tenant
- the bootstrap/system admin user path needed by the current module
- a pending bootstrap invite suitable for local email proof
- an outbox email message for that invite

### Manual dev-seed entry point

You can run the dedicated seed entry point directly when needed:

```bash
yarn workspace @auth-lab/backend dev:seed
```

Use this after clearing data or when you want to refresh the canonical local state without relying on automatic startup seed behavior.

---

## Local email proof workflow

Phase 2 makes email part of the real local contract.

### Expected backend SMTP settings in local

These values should come from `backend/.env` derived from the example:

```env
EMAIL_PROVIDER=smtp
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_SECURE=false
SMTP_FROM=Hubins <noreply@hubins.local>
SMTP_PUBLIC_BASE_URL=http://{tenantKey}.localhost:3000
```

### Proof 1 — Invite email

1. Start infra and app(s)
2. Ensure seed ran successfully
3. Open Mailpit
4. Confirm an invite email exists for `system_admin@example.com`
5. Open the email and inspect the generated link
6. Confirm the link host uses the tenant host pattern, for example `http://goodwill-ca.localhost:3000/...`

### Proof 2 — Verify-email flow

1. Create or trigger a flow that sends verification mail
2. Open Mailpit
3. Confirm verification mail arrival
4. Inspect the verification link host and path
5. Confirm tenant-based link construction is correct

### Proof 3 — Forgot-password / reset email

1. Trigger forgot-password for a valid seeded/test account
2. Open Mailpit
3. Confirm reset mail arrival
4. Inspect the reset link
5. Confirm host-derived tenant link construction is correct

### What is considered a local pass

Local proof is good only if all of the following are true:

- email is actually accepted by SMTP, not mocked
- email visibly arrives in Mailpit
- subject/body match the intended flow
- tokenized link is present
- link host resolves to the correct tenant-shaped frontend origin

---

## Running checks and tests

### Repo-wide checks

Run from repo root as applicable:

```bash
yarn lint
yarn typecheck
yarn test
```

If your workspace uses more granular scripts, prefer the repo-standard package scripts first and fall back to workspace scripts only if needed.

### Backend-focused checks

Useful commands:

```bash
yarn workspace @auth-lab/backend test
yarn workspace @auth-lab/backend test --watch
```

### Frontend checks

Unit tests and typecheck (no stack required):

```bash
yarn workspace frontend lint
yarn workspace frontend typecheck
yarn workspace frontend test:unit
```

Mock-backed Playwright E2E (fast local loop, no Docker stack required):

```bash
# Requires: nothing running — the playwright.config.mts starts next dev + mock backend
yarn workspace frontend test:e2e
```

Real-stack Playwright E2E (Phase 8 — requires Docker Compose stack to be running):

```bash
# 1. Start the full stack
./scripts/stack.sh up

# 2. Seed E2E fixtures (admin persona — idempotent, safe to re-run)
./scripts/seed-e2e-fixtures.sh

# 3. Run real-stack smoke tests
yarn workspace frontend test:e2e:real-stack
```

The real-stack suite (`test/e2e/auth.spec.ts`) runs 15 smoke tests against the live Caddy proxy at `*.lvh.me:3000`. It uses `playwright.config.mts` (the default config, which already targets the real stack — no mock webServer block). No webServer is started — the Docker stack must already be running.

**What the real-stack suite proves:**

- member login → `/app` + session cookie correct
- logout clears session + `/api/auth/me` returns 401 + `/app` SSR rejects
- admin login → `MFA_SETUP_REQUIRED` → `/auth/mfa/setup`
- signup → Mailpit email delivery → verify link → `/app`
- signup blocked on invite-only tenant (`goodwill-ca`)
- host-derived tenant identity via Caddy proxy (two hosts → two tenant names)
- SSO start sets `sso-state` cookie (SameSite=Lax) + Location → Google
- cross-tenant session isolation enforced by backend

**Mailpit API:**
The real-stack tests read email from Mailpit's HTTP API at `http://localhost:8025`.
If Mailpit is exposed on a different port, set `MAILPIT_API_URL=http://localhost:<port>` before running.

### Proxy conformance / route checks

Run after any change to `infra/`, proxy config, session middleware, or SSO flows:

```bash
# Requires full Docker stack running:
./scripts/stack.sh test
```

This runs PT-01 through PT-08 from the topology document using curl + jq against the live Compose stack.

---

## Resetting local state

### Stop compose services

Infra only:

```bash
docker compose -f infra/docker-compose-infra.yml down
```

Full stack:

```bash
docker compose -f infra/docker-compose.yml down
```

### Remove volumes when you need a full clean start

Infra only:

```bash
docker compose -f infra/docker-compose-infra.yml down -v
```

Full stack:

```bash
docker compose -f infra/docker-compose.yml down -v
```

Then rerun the chosen stack start flow and reseed.

---

## Common local pitfalls

### 1. Mail is not arriving in Mailpit

Check:

- Mailpit is running
- backend env has `EMAIL_PROVIDER=smtp`
- SMTP host/port point to Mailpit
- outbox poller is enabled and running
- backend logs show successful SMTP send

### 2. Links use the wrong host

Check:

- `SMTP_PUBLIC_BASE_URL`
- tenant key in the seeded record
- whether you are testing with the correct tenant host

Do not “fix” this by bypassing host-derived tenant behavior.
Repair the base-url/env or seed assumptions instead.

### 3. Browser requests are hitting backend directly

That is a topology regression.
The browser must use same-origin `/api/*`.
Do not change the frontend into a direct-browser-to-backend model.

### 4. Seed data exists but no invite email appears

Check whether:

- the seed completed without error
- the seed created the pending invite
- the seed enqueued the outbox email message
- the outbox poller picked up and sent the message

### 5. Plain `localhost` does not reproduce tenant behavior

That is expected.
Use tenant-shaped hosts like `goodwill-ca.localhost` when verifying host-derived tenant identity.

---

## Staging email note

Staging proof is intentionally sandboxed and documented in `docs/ops/runbooks.md`.
Do not repurpose local Mailpit instructions as the staging operator procedure.

---

## Practical day-one setup checklist

For a new machine or a fresh clone:

1. `corepack enable`
2. `yarn install`
3. `cp backend/.env.example backend/.env`
4. `cp frontend/.env.example frontend/.env.local`
5. `docker compose -f infra/docker-compose-infra.yml up -d`
6. start backend and frontend on host
7. open `http://goodwill-ca.localhost:3000`
8. open `http://localhost:8025`
9. confirm backend health
10. confirm seeded invite email is visible in Mailpit`

If all ten pass, the current local foundation is behaving as intended.
