# Hubins Auth-Lab — Developer Guide

**Status:** Active local-development truth
**Scope:** Current repo only
**Audience:** Engineers working in the repo today
**Last Updated:** 2026-04-01

---

## Purpose

This guide is the repo's practical setup and repeatability document for the current foundation.

Use it to answer:

- how to start the current local stack
- which URLs are canonical today
- how to confirm health/status
- how to stop or reset local state safely
- how to run checks and tests
- how to seed or bootstrap known local data intentionally
- which env files are used in each local mode
- what staging-only proof still depends on external credentials or infrastructure

This guide is intentionally scoped to:

- local development
- local topology validation
- current test-running truth
- current seed/bootstrap truth
- current repo env/config truth

It does **not** replace:

- release engineering rules
- deployment / rollback process
- incident response policy
- full operator runbooks

Those belong in:

- `docs/ops/release-engineering.md`
- `docs/ops/runbooks.md`

---

## Locked topology reminders

Keep these invariants unchanged while using this guide:

- browser requests use same-origin `/api/*`
- SSR/server-side frontend code uses `INTERNAL_API_URL`
- SSR forwards `Host`, `Cookie`, and `X-Forwarded-*`
- backend owns auth/session truth
- tenant identity is host-derived
- tenant-aware browser behavior must be tested on the correct tenant host, not plain `localhost`

---

## Prerequisites

Install or confirm:

- Docker
- Node.js 20+
- Corepack
- Playwright browsers
- `jq` for proxy conformance checks

Enable Corepack once:

```bash
corepack enable
```

Install dependencies:

```bash
yarn install
```

Install Playwright browsers if needed:

```bash
npx playwright install
```

Install `jq` if needed:

```bash
brew install jq
```

or your platform equivalent.

---

## Repo layout at a glance

Main working areas:

- `backend/` — Fastify backend, DB migrations, seed/bootstraps, auth logic
- `frontend/` — Next.js App Router frontend, browser proxy handlers, auth UI, Playwright tests
- `infra/` — Docker Compose files, Caddy config, reference nginx config
- `docs/` — active repo truth, quality docs, ops/security docs
- `scripts/` — startup, verify, stack, reset, and repo utility scripts

Important docs:

- `docs/current-foundation-status.md`
- `README.md`
- `infra/README.md`
- `docs/ops/runbooks.md`
- `docs/ops/release-engineering.md`
- `docs/security/threat-model.md`

---

## Local development modes

The repo intentionally supports two different local modes.

## Mode 1 — host-run (daily development)

Use this for the normal inner loop.

```bash
yarn dev
```

### What `yarn dev` actually does

It:

- ensures `infra/.env.stack` exists
- starts Docker infra from `infra/docker-compose-infra.yml`
- waits for Postgres and the local OIDC helper to be ready
- installs dependencies
- ensures `backend/.env` exists
- ensures `frontend/.env.local` exists
- runs backend migrations
- generates DB types
- starts backend on the host
- starts frontend on the host

### What runs in host-run mode

- Postgres in Docker
- Redis in Docker
- Mailpit in Docker
- local OIDC helper in Docker
- backend on the host
- frontend on the host

### Canonical URLs in host-run mode

Use these exact URLs:

- Public app: `http://goodwill-ca.lvh.me:3000`
- Proxy-style health check: `http://goodwill-ca.lvh.me:3000/api/health`
- Backend health directly: `http://localhost:3001/health`
- Mailpit UI: `http://localhost:8025`
- Local OIDC JWKS: `http://localhost:9998/.well-known/jwks.json`

### Important truth for host-run mode

In host-run mode:

- browser `/api/*` first hits Next.js Route Handlers
- those Route Handlers proxy to the backend
- SSR uses `INTERNAL_API_URL=http://localhost:3001`
- tenant-aware browser behavior still requires the tenant host, not plain `localhost:3000`

Do **not** test tenant-aware browser behavior on plain `localhost:3000`.
Use `goodwill-ca.lvh.me:3000` or another intended tenant host.

### What host-run mode proves well

- normal daily frontend/backend iteration
- local auth/provisioning feature work
- Mailpit local email capture
- SSR direct-backend behavior
- browser same-origin behavior through the Route Handler proxy

### What host-run mode does not prove fully

- real Caddy proxy behavior
- real `/api` prefix stripping through the public proxy layer
- final proxy header behavior
- final full-topology cookie/proxy behavior

---

## Mode 2 — full Docker topology

Use this when the actual proxy/topology path matters.

You have two entry paths.

### A. Standard full topology

```bash
yarn stack
```

This uses `infra/docker-compose.yml`.

### B. Full topology plus local OIDC helper

```bash
yarn dev:stack
```

This uses:

- `infra/docker-compose.yml`
- `infra/docker-compose-ci-oidc.yml`

Use `yarn dev:stack` when you need the full Docker topology and also want the local OIDC helper available in that stack.

### Canonical URL in full-stack mode

- Public app: `http://goodwill-ca.lvh.me:3000`
- Health via proxy: `http://goodwill-ca.lvh.me:3000/api/health`

### What full-stack mode proves

- Caddy proxy routing
- `/api/*` public-origin routing
- `/api` prefix stripping
- host-derived tenant routing through the proxy
- forwarded-header behavior through the proxy path
- real proxy conformance checks

### What full-stack mode still does not prove

The local full stack is HTTP-only.
It does **not** fully prove:

- production HTTPS
- browser-enforced `__Host-` cookie behavior
- final production TLS termination

That is expected.

---

## Environment files

The repo uses committed example env files as the safe source of truth.

## Backend env

Primary example file:

- `backend/.env.example`

Local working file:

- `backend/.env`

In normal local work, `yarn dev` auto-creates `backend/.env` from the example if it is missing.

### Important backend env notes

- host-run backend uses `localhost` endpoints for Postgres and Redis
- Mailpit SMTP is local
- backend env contains sensitive values in real usage
- never share real env files in screenshots, zips, or chat threads

## Frontend env

Primary example file:

- `frontend/.env.example`

Local working file:

- `frontend/.env.local`

In normal local work, `yarn dev` auto-creates `frontend/.env.local` from the example if it is missing.

### Important frontend env notes

Frontend env should not contain OAuth secrets.
Its main job is SSR/backend wiring, for example:

- `INTERNAL_API_URL`
- `NEXT_PUBLIC_ENV`

## Infra stack env

Primary example file:

- `infra/.env.stack.example`

Local working file:

- `infra/.env.stack`

`yarn dev`, `yarn stack`, and `yarn dev:stack` rely on this file for Docker-backed local modes.

---

## Secrets hygiene

`backend/.env`, `frontend/.env.local`, and `infra/.env.stack` are gitignored for a reason.

Never share these files in:

- review bundles or zips
- screenshots or recordings
- issue attachments
- chat messages
- email threads

If real credentials were shared accidentally:

1. assume they are compromised
2. rotate them immediately
3. update your local files with the rotated values

Safe sharing rule:

- share env var names
- share `.env.example` files
- do **not** share real values

---

## Health and status checks

## Quick status command

```bash
yarn status
```

This shows:

- Docker container state for local auth-lab/hubins containers
- health probes for the canonical tenant host
- `/api/health`
- direct backend health
- Mailpit UI reachability

## Manual health checks

### Canonical public health check

```bash
curl -fsS http://goodwill-ca.lvh.me:3000/api/health
```

### Direct backend health check

```bash
curl -fsS http://localhost:3001/health
```

### Mailpit UI

Open:

- `http://localhost:8025`

### Local OIDC JWKS

```bash
curl -fsS http://localhost:9998/.well-known/jwks.json
```

---

## Stop and reset commands

## Stop Docker-backed local modes

```bash
yarn stop
```

This stops:

- full-stack Docker mode
- infra-only Docker mode

If backend/frontend were started manually in separate host terminals, stop those terminals yourself.

## Reset local DB/Redis volumes

```bash
yarn reset-db
```

This wipes local Docker volumes for the supported local modes.
Use it when you need a clean local state.

Warning:

- this deletes local development data
- after reset, restart the relevant mode and rerun any intentional seed/bootstrap command you need

---

## Seed and bootstrap truth

This is important because old assumptions easily drift here.

## What `yarn dev` does **not** do

`yarn dev` does **not** automatically run repo seed commands.
It prepares env files, infra, migrations, DB types, and host-run app processes.

Do **not** assume `yarn dev` gives you seeded personas automatically.

## Available seed/bootstrap commands

### Dev seed

```bash
yarn seed:dev
```

### E2E fixtures seed

```bash
yarn seed:e2e
```

### Tenant bootstrap helper

```bash
yarn bootstrap:tenant
```

Use these intentionally when you need:

- canonical dev fixtures
- E2E fixture accounts/data
- operator-style tenant bootstrap flow

## Recommended seed usage

- use `yarn seed:dev` when you want known local development fixtures
- use `yarn seed:e2e` when preparing Playwright-compatible local fixtures
- use `yarn bootstrap:tenant` when you need the bootstrap operator path

---

## Local email proof

Mailpit is part of the real local proof contract.
The repo does not treat auth email as purely mocked behavior in local work.

## Mailpit URL

- `http://localhost:8025`

## Typical local email proof flows

- invite email
- verify-email
- forgot-password / reset-password

Local proof is considered real only if:

- the backend actually accepts the email for delivery via SMTP
- the email visibly arrives in Mailpit
- the expected tokenized link is present
- the link points to the correct tenant-shaped host contract for the tested flow

---

## Running checks and tests

## Repo-wide verification

```bash
yarn verify
```

What `yarn verify` actually runs:

- `yarn fmt:check`
- `yarn lint`
- `yarn typecheck`
- `yarn test`

Important truth:

`yarn verify` does **not** run a frontend production build.
If you need explicit frontend build proof, run:

```bash
yarn build:frontend
```

## Main test command

```bash
yarn test
```

What `yarn test` actually does:

1. ensures `auth_lab_test` exists
2. runs migrations against `auth_lab_test`
3. runs backend tests against that isolated test DB
4. runs frontend unit tests
5. runs Playwright E2E **only if** the canonical app health endpoint is already reachable

If the stack is not reachable at `http://goodwill-ca.lvh.me:3000/api/health`, E2E is skipped.

## Backend-only tests

```bash
yarn test:backend
```

or directly:

```bash
yarn workspace @auth-lab/backend test
```

## Frontend unit tests

```bash
yarn test:frontend:unit
```

or directly:

```bash
yarn workspace frontend test:unit
```

## Playwright E2E

```bash
yarn test:e2e
```

Important truth for Playwright in this repo today:

- Playwright targets the **real running stack**
- the config does **not** start its own mock server or its own Next server
- the stack must already be running before E2E begins
- the canonical base URL is `http://goodwill-open.lvh.me:3000`

That means current E2E is **not** a mock-backed no-Docker path.

## Recommended local test flow

### Daily feature work

```bash
yarn dev
```

### Before push / PR

```bash
yarn verify
```

### Before merging topology-sensitive changes

```bash
yarn stack
yarn stack:test
```

---

## Proxy and topology validation

If the change affects any of the following, run the full-stack proof path:

- `infra/`
- proxy config
- request context / tenant resolution
- session/cookie behavior
- SSR forwarded-header behavior
- SSO callback assumptions
- browser vs SSR request routing assumptions
- public-origin `/api/*` handling

Use:

```bash
yarn stack
yarn stack:test
```

or, if you need the local OIDC helper in the full stack:

```bash
yarn dev:stack
yarn stack:test
```

---

## Staging-only proof boundaries

Some proof cannot be honestly completed only on a local machine.
These remain staging / externally-managed environment concerns.

Examples:

- live Google SSO provider proof
- live Microsoft SSO provider proof
- real non-local SMTP provider proof
- any environment-specific provider/network rule that local Mailpit/local OIDC does not cover

Do not call those flows fully proven from local-only testing.

---

## Google SSO config checklist

Use this for staging/live-provider proof preparation.

### Backend env keys used by Google SSO

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `SSO_STATE_ENCRYPTION_KEY`
- `SSO_REDIRECT_BASE_URL` (fallback only)

### Frontend env keys

No Google client secret belongs in the frontend.
Frontend only needs normal SSR wiring such as:

- `INTERNAL_API_URL`
- `NEXT_PUBLIC_ENV`

### Staging Google app registration checklist

Before live proof, confirm:

1. Google app type is **Web application**
2. staging backend env contains the real `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`
3. the exact redirect URI exists in Google in the form:

```text
https://<tenant-host>/api/auth/sso/google/callback
```

4. the staging tenant allows `google`
5. the staging tenant host resolves through the real same-origin `/api/*` topology

### Provider key reachability check

```bash
curl -fsS https://www.googleapis.com/oauth2/v3/certs > /dev/null
```

---

## Microsoft SSO config checklist

Use this for staging/live-provider proof preparation.

### Backend env keys used by Microsoft SSO

- `MICROSOFT_CLIENT_ID`
- `MICROSOFT_CLIENT_SECRET`
- `SSO_STATE_ENCRYPTION_KEY`
- `SSO_REDIRECT_BASE_URL` (fallback only)

Repo-specific note:

- this repo does **not** use `MICROSOFT_TENANT_ID`
- the backend starts at `/common` and resolves issuer from the token `tid` claim

### Frontend env keys

No Microsoft client secret belongs in the frontend.
Frontend only needs SSR/runtime wiring such as:

- `INTERNAL_API_URL`
- `NEXT_PUBLIC_ENV`

### Microsoft claim fallback behavior in this repo

The callback resolves user email in this order:

1. `email`
2. `preferred_username`
3. `upn`

The result is normalized to lowercase.
If no email-like value exists, the callback must fail.

### Staging Microsoft app registration checklist

Before live proof, confirm:

1. Microsoft app platform is **Web**
2. Supported account types is **Accounts in any organizational directory and personal Microsoft accounts**
3. staging backend env contains real `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET`
4. the exact redirect URI exists in the form:

```text
https://<tenant-host>/api/auth/sso/microsoft/callback
```

5. the staging tenant allows `microsoft`
6. the staging tenant host resolves through the real same-origin `/api/*` topology

### Exact Microsoft value mapping

- Application (client) ID → `MICROSOFT_CLIENT_ID`
- client secret **Value** → `MICROSOFT_CLIENT_SECRET`
- Directory (tenant) ID → operator reference only, not backend env wiring in this repo

### Provider key reachability check

```bash
curl -fsS https://login.microsoftonline.com/common/discovery/v2.0/keys > /dev/null
```

---

## Recommended daily workflow

1. start normal local mode:

```bash
yarn dev
```

2. open the canonical tenant host:

```text
http://goodwill-ca.lvh.me:3000
```

3. run intentional seed/bootstrap commands only when needed
4. run `yarn verify` before push / PR
5. run `yarn stack:test` when the change touches topology-sensitive behavior

---

## Where to look next

- `docs/current-foundation-status.md` — current repo truth
- `README.md` — top-level entry and command summary
- `infra/README.md` — local topology modes and infra truth
- `docs/ops/release-engineering.md` — release gates, migration safety, rollback, hotfix rules
- `docs/ops/runbooks.md` — operator and incident-facing procedures

---

## Practical truth rules

- do not describe `yarn verify` as if it includes build proof; it does not
- do not describe Playwright in this repo as mock-backed-by-default; it is not
- do not assume `yarn dev` auto-seeds data; it does not
- do not test tenant-aware browser behavior on plain `localhost`
- do not call local HTTP proof equivalent to production HTTPS proof
- do not claim local-only proof is enough for live-provider SSO or real external SMTP proof

Those distinctions are part of repo truth, not optional wording.
