# AGENTS.md

## Scope

Applies to the repository root.

## Mission

This repository is a multi-tenant Hubins/Auth-Lab codebase with a strong documentation and proof discipline.

The current repo focus is not generic product sprawl. It is a controlled foundation with locked topology, locked tenant/session boundaries, and a repo-native documentation model where architecture, security, contracts, QA, and review behavior must stay aligned.

Use AI to improve engineering quality, review quality, and decision quality — never to bypass repo truth.

---

## Read This First

Before doing any non-trivial work, read these in this order:

1. `docs/ai/repo-ai-adoption-roadmap.md`
2. `ARCHITECTURE.md` if present
3. `docs/current-foundation-status.md` if present
4. `docs/decision-log.md` if present
5. `docs/security-model.md` if present
6. `docs/prompts/usage-guide.md` if present

Then route by area:

* backend work → read `backend/AGENTS.md` when it exists
* frontend work → read `frontend/AGENTS.md` when it exists
* review/audit work → read `code_review.md` when it exists

If one of the files above does not exist yet, do not invent its content. Continue with the files that do exist.

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
9. chat summaries, temporary prompts, and scratch notes

### Required Behavior

* If a lower-truth source conflicts with a higher-truth source, call it out explicitly.
* Do not silently resolve contradictions.
* Do not let polished wording override repo evidence.

---

## Repo-Wide Hard Rules

### 1. Do not improvise architecture truth

If the repo already has architecture, topology, security, or product-law documentation, use it.

### 2. Keep diffs minimal

Do not rename, reorganize, or “clean up” unrelated files unless explicitly asked.

### 3. Use Yarn only

Do not switch package managers.

### 4. Do not modify environment files casually

Do not edit `.env` files or secret-bearing config unless the task explicitly requires it.

### 5. Code changes and doc changes must stay coupled

If a change affects architecture, contracts, runbooks, or review law, update the matching doc in the same change or call out the missing update.

### 6. AI output is not proof

Tests, CI, runtime validation, QA, and operational evidence still matter.

### 7. Keep AI repo-aware

Do not produce generic reviews or generic architecture advice when the repo can answer the question more precisely.

---

## Documentation Coupling Rules

Update or review the relevant docs when code changes affect these areas:

* architecture or cross-cutting system rules → `ARCHITECTURE.md`, `docs/decision-log.md`
* security/session/tenant rules → `docs/security-model.md`
* API behavior or request/response contracts → relevant `docs/api/*.md`
* operational behavior or recovery procedures → `docs/ops/runbooks.md`
* QA-visible behavior or manual test flows → relevant QA docs
* AI/review operating model → `docs/ai/repo-ai-adoption-roadmap.md`, `docs/prompts/usage-guide.md`, `code_review.md`, `AGENTS.md`

Do not duplicate the same rule into many files unless that duplication is intentional and justified.

---

## Topology-Sensitive Change Rules

This repo has load-bearing topology and tenant-boundary rules.

Treat a change as topology-sensitive if it touches any of the following:

* reverse proxy behavior
* host-derived tenant behavior
* `/api/*` browser routing
* SSR backend calling path
* `INTERNAL_API_URL`
* forwarded header behavior
* cookie/session behavior
* auth bootstrap behavior
* SSO start/callback behavior

### Required Behavior For Topology-Sensitive Changes

* Do not treat browser and SSR calls as interchangeable.
* Do not hardcode direct browser calls to backend origins.
* Do not break host-derived tenant routing.
* Do not weaken tenant/session isolation assumptions.
* Do not replace browser-native SSO navigation with `fetch()` flows.

If you are touching one of these areas, be stricter than usual about validation and review.

---

## Frontend / SSR Boundary Rules

These rules are repo-wide because they affect correctness across the stack:

* browser calls must stay same-origin through `/api/*`
* SSR/server-side calls may use direct backend access only through the internal backend path and only with the correct forwarded headers
* tenant identity must remain host-derived, not client-selected
* auth/bootstrap truth must remain backend-authoritative
* session and setup state must not become frontend-only truth

If a task changes frontend auth/bootstrap, SSR fetch wrappers, SSO flows, or protected routing, assume it is boundary-sensitive.

---

## Validation Routing

Run the smallest meaningful checks for the area you changed.

### Repo-wide

* `yarn fmt:check`
* `yarn lint`
* `yarn typecheck`

### Backend-focused changes

Use backend-focused typecheck and tests.

### Frontend-focused changes

Use frontend-focused typecheck and unit tests.

### Topology/auth/session/proxy-sensitive changes

Run the higher-confidence stack or end-to-end proof relevant to the change.

### Important Rule

Do not claim a change is proven if you only reasoned about it. Say what was actually run.

---

## How To Work In This Repo

### For implementation work

* start from repo truth
* keep the scope narrow
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

### Consult `docs/prompts/usage-guide.md` when:

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
