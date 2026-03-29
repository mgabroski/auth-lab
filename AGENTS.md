# AGENTS.md

## Scope

Applies to the repository root.

## Purpose

This file is the **root repo instruction layer** for AI-assisted work and repo-aware engineering support.

Its job is to keep work in this repository:

* grounded in repo truth
* aligned with documentation
* aware of tenant, session, and topology boundaries
* coupled to the right validation
* resistant to generic or persuasive-but-ungrounded output

This file is the **root router**, not the full backend guide, frontend guide, or review contract.

---

## Read This First

Before doing any non-trivial task, review these in this order when present:

1. `docs/ai/repo-ai-adoption-roadmap.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `docs/security-model.md`
6. `docs/prompts/usage-guide.md`

Then route by area:

* backend work → `backend/AGENTS.md`
* frontend work → `frontend/AGENTS.md`
* review / audit / risk work → `code_review.md`
* prompt selection questions → `docs/prompts/catalog.md` and `docs/prompts/usage-guide.md`

If one of these files does not exist yet, do not invent it. Continue with the files that do exist.

---

## Truth Ladder

When sources disagree, use this order:

1. active locked product/module source-of-truth documents
2. current foundation / shipped-scope truth docs
3. architecture and decision records
4. security model and topology law
5. contract and API docs
6. implementation code
7. tests and CI workflows
8. runbooks, QA docs, and developer guides
9. temporary notes, chat summaries, and scratch prompts

### Required behavior

* If a lower-truth source conflicts with a higher-truth source, call it out explicitly.
* Do not silently smooth over contradictions.
* Do not let polished wording override repo evidence.

---

## Repo-Wide Hard Rules

### 1. Do not improvise system truth

If the repo already defines architecture, topology, security, or product behavior, use that definition.

### 2. Keep diffs minimal

Do not rename, reorganize, or “clean up” unrelated files unless explicitly asked.

### 3. Use Yarn only

Do not switch package managers.

### 4. Do not modify environment files casually

Do not edit `.env` files, secrets, or secret-bearing config unless the task explicitly requires it.

### 5. Keep code and docs coupled

If a change affects architecture, contracts, runbooks, review behavior, or user-visible workflows, update or review the matching docs in the same change.

### 6. AI output is not proof

Reasoning, summaries, and reviews do not replace tests, CI, topology checks, QA, or runtime evidence.

### 7. Keep AI repo-aware

Prefer repo-specific review and guidance over generic best-practice commentary when the repo can answer the question more precisely.

---

## Documentation Coupling Rules

Review or update the matching docs when code changes affect:

* architecture or cross-cutting behavior → `ARCHITECTURE.md`, `docs/decision-log.md`
* security, sessions, tenant rules, trust boundaries → `docs/security-model.md`
* request/response or behavioral contracts → relevant API/contract docs
* operational recovery, setup, deployment, or support behavior → `docs/ops/runbooks.md`
* QA-visible flows, redirects, user messages, or test behavior → relevant QA docs
* AI/review operating behavior → `AGENTS.md`, `code_review.md`, `docs/ai/repo-ai-adoption-roadmap.md`, `docs/prompts/usage-guide.md`, `docs/prompts/catalog.md`

Do not create silent documentation drift.

---

## Topology-Sensitive Change Rules

Treat a change as topology-sensitive if it touches any of the following:

* reverse proxy behavior
* host-derived tenant behavior
* browser `/api/*` routing
* SSR/backend calling path
* `INTERNAL_API_URL`
* forwarded header behavior
* cookie/session behavior
* auth bootstrap behavior
* SSO start/callback behavior

### Required behavior for topology-sensitive changes

* Do not treat browser and SSR requests as interchangeable.
* Do not hardcode direct browser calls to backend origins.
* Do not weaken host-derived tenant routing.
* Do not weaken tenant/session isolation assumptions.
* Do not replace navigation-based auth flows with inappropriate `fetch()` flows.

If a task touches one of these areas, use stricter review and stronger validation than usual.

---

## Frontend / SSR Boundary Rules

These rules are repo-wide because they affect correctness across the stack:

* browser API calls must stay same-origin through `/api/*`
* SSR/server-side code may use direct backend access only through the approved internal path and with the correct forwarded headers
* tenant identity must remain host-derived, not client-selected
* auth/bootstrap truth must remain backend-authoritative
* session and setup state must not become frontend-only truth

If a task changes frontend auth/bootstrap, SSR fetch wrappers, SSO flows, or protected routing, assume it is boundary-sensitive.

---

## Validation Routing

Run the smallest meaningful checks that actually prove the area you changed.

### Repo-wide baseline

* `yarn fmt:check`
* `yarn lint`
* `yarn typecheck`

### Backend-focused changes

Run the backend-focused checks relevant to the affected area.

### Frontend-focused changes

Run the frontend-focused checks relevant to the affected area.

### Topology/auth/session/proxy-sensitive changes

Run the higher-confidence stack or end-to-end proof relevant to the change.

### Required behavior

When reporting results, say what was actually run. Do not imply runtime proof if you only reasoned about the change.

---

## How To Work In This Repo

### For implementation work

* start from repo truth
* keep scope narrow
* avoid hidden side effects
* preserve architecture and documentation boundaries

### For review work

* ground the review in actual files and docs
* distinguish facts from assumptions
* separate blocker-level issues from advisory commentary

### For planning work

* do not mix product truth, implementation planning, and AI/review governance into one blob
* keep each file and discussion at the correct layer

---

## When To Consult Other Repo AI Files

### Consult `backend/AGENTS.md` when:

* backend modules, transactions, migrations, queries, audit, or outbox behavior are involved

### Consult `frontend/AGENTS.md` when:

* SSR, browser routing, auth flows, protected routes, UI shell boundaries, or frontend topology-sensitive work are involved

### Consult `code_review.md` when:

* the task is review, audit, risk assessment, or merge/release evaluation

### Consult `docs/prompts/catalog.md` and `docs/prompts/usage-guide.md` when:

* you need to choose the right prompt or review mode for the stage of work

---

## What Not To Do

* Do not use this file as a product roadmap.
* Do not use this file as a replacement for backend or frontend instructions.
* Do not use this file as a dumping ground for temporary chat guidance.
* Do not overfit the repo to AI tooling at the expense of clarity.
* Do not treat missing docs as permission to invent system truth.

---

## Final Position

This file is the root repo law for AI routing and repo-aware engineering assistance.

Its job is to keep work:

* grounded in repo truth
* aligned with documentation
* aware of topology and tenant boundaries
* coupled to validation
* resistant to generic drift
