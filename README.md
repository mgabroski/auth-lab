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
- designing a new module -> `docs/module-design-framework.md`
- backend module planning after the design is locked -> `backend/docs/module-skeleton.md`
- frontend module planning after the design is locked -> `frontend/docs/module-skeleton.md`
- AI-assisted full-stack module planning -> `docs/prompts/module-generation-fullstack.md`
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

## Designing a New Module

Use this sequence whenever a new Hubins module is being introduced.

### Step 1 — Design the module correctly

Start with:

- `docs/module-design-framework.md`

This is the reusable project-level source for future-module thinking.
It forces the team to answer the full design cycle before implementation planning begins, including:

- module truth
- module settings implications
- permission and policy implications
- workspace experience implications
- communications implications
- fail-closed, removal, and orphan behavior

Do not skip this step.
A module is not ready for implementation planning until this file says the design is complete enough.

### Step 2 — Move into surface planning

Only after Step 1 is complete, move to the surface-specific skeletons:

- backend planning -> `backend/docs/module-skeleton.md`
- frontend planning -> `frontend/docs/module-skeleton.md`

These files are implementation skeletons.
They are not module-design documents.

### Step 3 — Use the full-stack planning prompt only when needed

If you need one integrated AI-driven planning session across backend, frontend, docs, and proof:

- `docs/prompts/module-generation-fullstack.md`

That prompt now assumes the module-design framework is part of the required source bundle.

Do not jump straight from a business idea into route, DTO, page, and file generation.
That is exactly the failure mode the new framework is meant to prevent.

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

Primary local tenant URLs:

- `http://goodwill-ca.lvh.me:3000`
- `http://goodwill-open.lvh.me:3000`

Mailpit:

- `http://localhost:8025`

### Common commands

```bash
yarn dev
yarn stop
yarn status
yarn reset-db
yarn test
yarn verify
```

Use `docs/developer-guide.md` for setup detail, environment expectations, and routine workflows.

---

## Repo Structure

Top-level shape:

```text
backend/    Fastify backend, DB, auth flows, API contracts, backend docs
frontend/   Next.js frontend, SSR/browser boundary, frontend docs
infra/      Docker, proxy, local stack, infra docs
docs/       shared truth, quality, QA, ops, prompts, reusable design docs
scripts/    local stack and verification helpers
```

Use the closest authority doc before editing a surface.
Do not infer repo law from folder names alone.

---

## Human Routing Guide

### I need local setup help

Read:

- `docs/developer-guide.md`
- `infra/README.md`

### I need to understand what is truly shipped

Read:

- `docs/current-foundation-status.md`

### I need to understand architecture or security law

Read:

- `ARCHITECTURE.md`
- `docs/security-model.md`

### I need backend implementation rules

Read:

- `backend/docs/engineering-rules.md`
- `backend/docs/module-skeleton.md`

### I need frontend implementation rules

Read:

- `frontend/src/shared/engineering-rules.md`
- `frontend/docs/module-skeleton.md`

### I need to introduce or design a brand-new module

Read in this order:

1. `docs/module-design-framework.md`
2. `backend/docs/module-skeleton.md` when backend work is in scope
3. `frontend/docs/module-skeleton.md` when frontend work is in scope
4. `docs/prompts/module-generation-fullstack.md` when using an LLM to prepare a single full-stack module plan

### I need operational or QA guidance

Read:

- `docs/ops/*`
- `docs/qa/*`

### I need prompt selection only

Read:

- `docs/prompts/catalog.md`

---

## Working Rules

- Do not treat support docs as higher truth than shipped-truth, architecture, security, or API contracts.
- Do not describe future work as shipped.
- Do not create duplicate docs for things already owned elsewhere.
- Do not skip documentation updates when code or durable behavior changes.
- Do not invent new module structure without first checking the reusable module-design framework.
- Do not use backend or frontend skeleton docs as a substitute for unfinished module thinking.

---

## Contribution and Review

For contribution expectations, read:

- `CONTRIBUTING.md`

For review expectations, read:

- `code_review.md`
- `docs/quality-bar.md` when readiness or signoff is in scope

For AI/review-agent routing, use:

- `AGENTS.md`

---

## Final Position

This repo is intentionally strict.

It is designed so that humans and AI can find the real truth quickly, keep module work aligned with the current foundation, and avoid fake progress caused by duplicate docs, guessed architecture, or skipped proof.

The new durable addition to that system is `docs/module-design-framework.md`.
Use it first for every future module.
