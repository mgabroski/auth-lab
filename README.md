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
3. `docs/security-model.md`

Then route by need:

- local setup and commands -> `docs/developer-guide.md`
- contribution rules -> `CONTRIBUTING.md`
- review expectations -> `code_review.md`
- backend implementation law -> `backend/docs/engineering-rules.md`
- frontend implementation law -> `frontend/src/shared/engineering-rules.md`
- prompt selection only -> `docs/prompts/catalog.md`

Read `docs/quality-bar.md` only when the task is about readiness, signoff, or release-quality judgment.
Read `docs/decision-log.md` only when the task is about architecture decisions, recorded conflicts, or decision history.

For AI and review agents, the entrypoint is `AGENTS.md`, not this file.

---

## What This Repo Is

Today, this repository is the working foundation for:

- reverse-proxy-aware multi-tenant application behavior
- same-origin browser API usage
- SSR direct-to-backend calls with forwarded tenant and session headers
- backend session-aware auth and tenant resolution
- frontend auth and provisioning flows
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

### Auth + User Provisioning

- register
- login
- logout
- `/auth/me`
- `/auth/config`
- forgot/reset password
- public signup
- email verification and resend verification
- MFA setup, verify, and recovery
- Google SSO
- Microsoft SSO
- invite-based provisioning
- admin invite lifecycle
- audit viewing
- outbox-backed email delivery

### Frontend Surface

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

Do not collapse broader architecture vision into shipped truth.

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

Do not use plain `localhost:3000` for tenant-aware browser behavior.

### Full topology validation

```bash
yarn stack
yarn stack:test
```

Use this for proxy, cookie, host-header, SSR, and full-flow topology proof.

For more setup, environment, reset, QA execution, and local workflow detail, use `docs/developer-guide.md`.

---

## How To Navigate The Repo

### Backend

Start with:

1. `backend/AGENTS.md`
2. `backend/docs/engineering-rules.md`
3. relevant `backend/docs/api/*.md`

### Frontend

Start with:

1. `frontend/AGENTS.md`
2. `frontend/src/shared/engineering-rules.md`
3. relevant backend API docs

### Review or audit work

Start with:

1. `code_review.md`
2. relevant authority docs for the touched area

### Prompt selection only

Start with:

1. `docs/prompts/catalog.md`

---

## Documentation Position

- `README.md` is the human router.
- `AGENTS.md` is the AI router.
- `docs/current-foundation-status.md` is the current shipped-truth snapshot.
- `ARCHITECTURE.md` is broader system law, not the same thing as shipped scope.
- `docs/security-model.md` is the trust-boundary and security law.

Do not start from QA docs, ops docs, or prompt docs when a higher-truth file already answers the question.

---

## Final Position

Keep this file short.
Use it to orient humans quickly.
Then route to the smallest authoritative document set that actually matches the task.
