# Developer Guide

## Purpose

This file is the developer setup and daily-work guide for the repository.

Use it for:

- local environment setup
- daily start / stop / restart / reset commands
- health verification
- test execution entrypoints
- environment expectations
- secrets/config checklist
- seeded persona awareness

This file is not the canonical QA execution document.
For step-by-step QA proof and expected tester evidence, use `docs/qa/qa-execution-pack.md`.

---

## Read This After

Before using this file, read:

1. `docs/current-foundation-status.md`
2. `ARCHITECTURE.md`
3. `docs/security-model.md`

Then use this guide for workflow execution.

---

## Prerequisites

Install these first:

- Docker Desktop
- Node.js 24.14.1 LTS
- Corepack

Use the repo-pinned runtime:

```bash
nvm install
nvm use
corepack enable
```

Use Yarn only.
Do not switch package managers.

---

## One-Time Setup

From the repo root:

```bash
cp backend/.env.example backend/.env
cp infra/.env.stack.example infra/.env.stack
yarn install
```

If a new environment file or variable is introduced later, document it in the environment matrix and secrets/config checklist below.

---

## Daily Commands

### Start the local stack

```bash
yarn dev
```

Expected result:

- Postgres starts
- Redis starts
- Mailpit starts
- local OIDC starts
- backend starts
- frontend starts
- Control Plane starts
- local seed/bootstrap runs as defined by the current repo state

### Stop the local stack

```bash
yarn stop
```

### Restart the local stack

```bash
yarn restart
```

### Check status

```bash
yarn status
```

### Reset local database and restore seed state

```bash
yarn reset-db
```

Use reset when:

- a test changed auth data
- seeded personas are no longer in the expected state
- a failed flow left the environment dirty

---

## Local URLs

### Primary tenant URLs

- invite-only workspace: `http://goodwill-ca.lvh.me:3000`
- public-signup workspace: `http://goodwill-open.lvh.me:3000`

### Support URLs

- Control Plane direct dev server (default `yarn dev` browser entry): `http://localhost:3002`
- Control Plane proxy-routed host (full Docker stack via `yarn dev:stack`): `http://cp.lvh.me:3000`
- Mailpit: `http://localhost:8025`
- tenant health: `http://goodwill-ca.lvh.me:3000/api/health`
- backend direct health: `http://localhost:3001/health`
- local OIDC discovery: `http://localhost:9998/.well-known/openid-configuration`
- local OIDC JWKS: `http://localhost:9998/.well-known/jwks.json`

Do not use plain `localhost:3000` as the main tenant-aware browser URL.
Tenant-aware browser behavior depends on the `*.lvh.me` host pattern.

Do not treat `http://localhost:9998/` as a browser homepage.
The local OIDC server is a test/provider surface, not a UI.
The root path may return `{ "error": "not_found", "path": "/" }` by design.

---

## Green-Light Health Check

Run this before serious local work or handing the stack to QA.

### 1. Tenant health

Open:

```text
http://goodwill-ca.lvh.me:3000/api/health
```

Expected result:

```json
{
  "ok": true,
  "env": "development",
  "service": "auth-lab-backend",
  "checks": {
    "db": true,
    "redis": true
  },
  "requestId": "...",
  "tenantKey": "goodwill-ca"
}
```

The exact non-production shape may include different `requestId` values, but `ok: true` and healthy dependency checks are the load-bearing signals.

### 2. Invite-only login page

Open:

```text
http://goodwill-ca.lvh.me:3000/auth/login
```

Expected result:

- login page loads
- no blank page
- no 500

### 3. Public-signup login page

Open:

```text
http://goodwill-open.lvh.me:3000/auth/login
```

Expected result:

- login page loads

### 4. Control Plane shell

Default `yarn dev` host-run mode:

```text
http://localhost:3002
```

Expected result:

- redirects into the create-account flow
- Control Plane shell loads
- no auth screen is expected in current scope

Proxy-routed CP proof path (only when using `yarn dev:stack`):

```text
http://cp.lvh.me:3000
```

Use the proxy-routed host for topology-sensitive CP testing. Under the default host-run mode, `cp.lvh.me:3000` is not the active public entrypoint.

### 5. Mailpit

Open:

```text
http://localhost:8025
```

Expected result:

- inbox loads

### 6. Local OIDC discovery

Open:

```text
http://localhost:9998/.well-known/openid-configuration
```

Expected result:

- JSON discovery document loads

Optional direct key check:

```text
http://localhost:9998/.well-known/jwks.json
```

Expected result:

- JWKS JSON loads

### 7. Baseline seeded member login

Use the seeded member account on GoodWill Open.
Expected result:

- login succeeds
- role-aware landing works

If any of these fail, stop and fix the environment before deeper testing.

---

## Canonical Seeded Personas

The repo must always keep these easy to find and easy to re-create.

### Baseline personas

- one member login persona
- one admin onboarding persona
- one invite-only tenant
- one public-signup tenant

### Typical local examples

- `member@example.com` -> seeded member on GoodWill Open
- `e2e-admin@example.com` -> seeded admin on GoodWill Open, MFA setup path expected on first admin login
- `system_admin@example.com` -> bootstrap/admin path for the invite-only workspace, when present in current seed/bootstrap flow

If the actual seed changes, update this section and the QA pack in the same change.

---

## Environment Matrix

## Local development

- tenant browser origin: local `*.lvh.me` through the dev proxy
- Control Plane browser origin: preferred proof path `http://cp.lvh.me:3000`; direct `http://localhost:3002` is host-run UI iteration only
- backend routing: same-origin browser `/api/*`
- SSR routing: internal backend path with forwarded headers
- email mode: Mailpit / local capture
- local OIDC: Docker-backed local provider for dev/CI proof
- seed/bootstrap: developer-friendly local mode
- session cookie: local dev cookie policy
- SSO credentials: local environment only if intentionally configured
- primary use: engineering development and local proof

## Shared staging / QA

- browser origin: staging tenant host through the real or staging-equivalent proxy
- email mode: non-production real SMTP sandbox
- seed/bootstrap: real outbox + SMTP path, not raw local convenience behavior
- session cookie: staging policy
- SSO credentials: real Google and Microsoft staging credentials
- primary use: live-provider proof, staging QA, realistic browser validation

## Production

- browser origin: production tenant host through production proxy
- email mode: production provider path
- seed/bootstrap: operator-run production-safe mechanism
- raw local bootstrap convenience behavior: forbidden
- session cookie: production policy
- SSO credentials: production-managed
- primary use: real users, real tenant operations

When any environment rule changes, update this matrix and the relevant runbooks in the same PR.

---

## Secrets / Config Checklist

Document every external dependency that blocks local, staging, or production execution.

At minimum, keep this checklist current:

### Database

- `DATABASE_URL`
- where set: backend environment
- needed for: backend boot, migrations, tests, seed/reset

### Redis

- `REDIS_URL`
- where set: backend environment
- needed for: session state, rate limiting, backend runtime behavior

### Internal SSR API routing

- `INTERNAL_API_URL`
- where set: frontend environment
- needed for: SSR/server-side backend calls

### SMTP / email

Document the active variables used by the repo for:

- SMTP host
- SMTP port
- SMTP username
- SMTP password
- sender/from identity

Needed for:

- invite emails
- verification emails
- reset-password emails
- staging/production proof beyond local Mailpit

### Google SSO

Document the active variables used by the repo for:

- Google client ID
- Google client secret
- redirect-base or callback-related config if applicable

Needed for:

- live Google SSO proof outside purely local non-provider work

### Microsoft SSO

Document the active variables used by the repo for:

- Microsoft client ID
- Microsoft client secret
- tenant/authority or callback-related config if applicable

Needed for:

- live Microsoft SSO proof outside purely local non-provider work

### Local OIDC

Document the active variables used by the repo for:

- `LOCAL_OIDC_ENABLED`
- `LOCAL_OIDC_ISSUER`
- `LOCAL_OIDC_CLIENT_ID`

Needed for:

- local SSO test proof
- local callback validation
- local provider-backed auth testing without a real external IdP

### Important rule

Do not duplicate secret values in docs.
Document names, purpose, where they are set, and what they unblock.

---

## Reset / Reseed Procedure

Use this when the environment is dirty and you need a known baseline.

### Standard reset

1. stop the stack if needed
2. run `yarn reset-db`
3. run `yarn dev`
4. re-run the Green-Light Health Check
5. verify seeded personas and tenant URLs still match the documented expectations

### Reset after auth-flow mutation

Use reset after flows that intentionally mutate seed state, including:

- password reset on seeded users
- MFA enrollment on seeded admin personas when a clean pre-MFA state is needed again
- invite acceptance that consumes a one-time seeded invite
- any DB-assisted QA scenario that changes membership state

### Rule

If the seed model changes, update:

- this file
- `docs/qa/qa-execution-pack.md`
- any user-visible QA or setup reference that depends on the old seed assumptions

---

## Validation Entry Points

Use the smallest meaningful proof for the task.

### Repository baseline

```bash
yarn fmt:check
yarn lint
yarn typecheck
```

### Backend-focused work

Run the relevant backend tests for the touched area.

### Frontend-focused work

Run the relevant frontend tests for the touched area.

If the touched area is the Control Plane, apply the same rule to `cp/` and verify the route/shell surface you changed. Use `http://cp.lvh.me:3000` for topology-sensitive browser proof and `http://localhost:3002` only for isolated host-run UI iteration.

### Playwright / browser proof

Run local Playwright when the task needs route, redirect, or end-to-end browser confidence.

### Proxy / topology proof

Use the stack-level topology checks when the task touches:

- proxy behavior
- tenant host behavior
- browser `/api/*` routing
- SSR header forwarding
- cookies or session flow
- auth bootstrap behavior
- SSO start/callback behavior

Do not claim full-flow proof if you only ran static checks.

---

## Documentation Coupling Rule

When developer workflow truth changes, update this file in the same PR.

Examples:

- command changes
- environment file changes
- new required variables
- seed/reset behavior changes
- persona changes
- local URL changes
- primary validation entrypoint changes

If the change is tester-facing rather than developer-facing, update `docs/qa/qa-execution-pack.md` as well.

---

## What This File Intentionally Does Not Do

This file does not:

- act as the QA execution script
- duplicate the API contracts
- restate architecture law
- restate security law in full
- act as a release runbook
- act as a decision log

For those, route to the correct authority doc.

---

## Final Position

Use this file to get the repo running, keep local execution reproducible, and keep environment/setup knowledge out of chat memory and tribal knowledge.

For tester steps, expected results, screenshots, and signoff evidence, use `docs/qa/qa-execution-pack.md`.
