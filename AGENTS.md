# AGENTS.md

## Scope

Applies at the repository root.

## Purpose

This is the single AI entrypoint for the repo.

Use it to route work correctly, load the right authority first, and avoid generic or conflicting answers.

This file is a router.
It is not a second architecture doc, not a product brief, and not a replacement for area-specific law.

---

## Read First

Before any non-trivial implementation, review, or audit work, load these in this order:

1. `docs/current-foundation-status.md`
2. `ARCHITECTURE.md`
3. `docs/quality-bar.md`
4. `docs/decision-log.md`
5. `docs/security-model.md`

Then route by area:

- backend work → `backend/AGENTS.md`
- frontend work → `frontend/AGENTS.md`
- review / audit work → `code_review.md`
- prompt selection only → `docs/prompts/catalog.md`

Do not start with QA docs, prompt docs, or support docs when a higher-truth file already answers the question.

---

## Truth Order

When sources disagree, use this order:

1. active locked product or module source-of-truth docs
2. current shipped-truth docs
3. architecture and decision records
4. security and trust-boundary docs
5. area engineering law and contract docs
6. implementation code
7. tests and CI workflows
8. runbooks, QA docs, and developer guides
9. prompts, temporary notes, and chat summaries

### Required behavior

- Call out real conflicts explicitly.
- Do not smooth over contradictions.
- Do not let polished wording outrank repo evidence.

---

## Repo-Wide Hard Rules

### 1. Do not improvise repo truth

If the repo already defines architecture, topology, security, product behavior, or quality gates, use that definition.

### 2. Keep scope tight

Do not turn a focused task into a cleanup campaign unless the task explicitly asks for cleanup.

### 3. Keep code and docs coupled

If a change affects architecture, contracts, trust boundaries, review behavior, runbooks, or user-visible workflow truth, update the matching docs in the same change.

### 4. AI output is not proof

Reasoning is not the same as tests, CI, topology checks, QA, or runtime evidence.

### 5. Respect boundary-sensitive work

Auth, session, tenant, SSR, proxy, SSO, and cookie behavior require stricter reasoning and stronger validation than normal changes.

### 6. Use Yarn only

Do not switch package managers.

### 7. Do not casually edit env or secret-bearing config

Only change environment or secret-related files when the task explicitly requires it.

---

## Routing By Work Type

### Backend work

Load:

1. `backend/AGENTS.md`
2. `backend/docs/engineering-rules.md`
3. `backend/docs/module-skeleton.md`
4. relevant `backend/docs/api/*.md`
5. relevant backend module docs or ADRs when needed

### Frontend work

Load:

1. `frontend/AGENTS.md`
2. `frontend/src/shared/engineering-rules.md`
3. `frontend/docs/module-skeleton.md`
4. relevant backend API docs
5. relevant frontend route or shared files

### Topology, auth, trust-boundary, or security work

Also load, when relevant:

- `docs/ops/runbooks.md`
- `docs/ops/observability.md`
- `docs/ops/release-engineering.md`
- relevant ADRs under `backend/docs/adr/`

### Review or audit work

Load:

1. `code_review.md`
2. relevant authority docs for the changed area
3. `docs/prompts/catalog.md` only if you need a reusable prompt asset

---

## Documentation Coupling Rules

Review or update the matching docs when code changes affect:

- architecture or cross-cutting behavior → `ARCHITECTURE.md`, `docs/decision-log.md`
- security, sessions, cookies, tenant rules, or trust boundaries → `docs/security-model.md`
- request/response or behavioral contracts → relevant `backend/docs/api/*.md`
- shipped capability or repo truth snapshot → `docs/current-foundation-status.md`
- operational recovery, release behavior, or support flow → relevant files under `docs/ops/`
- QA-visible messages or flow behavior → relevant files under `docs/qa/`
- contribution or review behavior → `AGENTS.md`, `CONTRIBUTING.md`, `code_review.md`, `docs/prompts/catalog.md`

Do not create silent documentation drift.

---

## Topology-Sensitive Change Rules

Treat a change as topology-sensitive if it touches any of the following:

- proxy behavior
- browser `/api/*` routing
- SSR direct-backend calls
- `INTERNAL_API_URL`
- forwarded headers
- host-derived tenant behavior
- cookie or session behavior
- auth bootstrap behavior
- SSO start/callback behavior

### Required behavior for topology-sensitive work

- Do not treat browser and SSR requests as interchangeable.
- Do not hardcode browser calls to backend origins.
- Do not weaken host-derived tenant routing.
- Do not weaken tenant/session isolation.
- Do not replace navigation-based auth flows with inappropriate `fetch()` flows.

---

## Validation Routing

Run the smallest meaningful proof that actually matches the risk.

### Baseline

Use the relevant subset of:

- `yarn fmt:check`
- `yarn lint`
- `yarn typecheck`

### Backend-focused changes

Run backend tests or stronger proof for the affected area.

### Frontend-focused changes

Run frontend unit tests, E2E, or stronger proof for the affected area.

### Auth, session, topology, or proxy-sensitive changes

Use stack-level or end-to-end proof when the behavior only becomes real through the full flow.

### Required behavior

When reporting validation, state what was actually run.
Do not imply runtime proof if you only reviewed code.

---

## What Not To Do

- Do not start from prompt files when repo law already answers the question.
- Do not treat support docs as stronger than architecture or shipped-truth docs.
- Do not invent missing behavior because a lower doc sounds confident.
- Do not claim completion without the proof level the task actually needs.
- Do not add parallel explanation docs when an existing canonical doc can be tightened instead.

---

## Final Position

Use this file as the root AI router.

For humans, `README.md` is the entrypoint.
For AI, this file is the entrypoint.

Everything else should stay below those two surfaces instead of competing with them.