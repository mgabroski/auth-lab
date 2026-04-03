# AGENTS.md

## Scope

Applies at the repository root.

## Purpose

This is the single AI entrypoint for the repo.

Use it to load the right authority first, keep answers tied to repo truth, and avoid duplicate or lower-value context.

This file is a router.
It is not a second architecture doc, not a product brief, and not a substitute for area-specific law.

---

## Canonical Truth Order

When sources disagree, use this order:

1. module-specific highest-truth docs explicitly declared as authoritative for the target module
2. current shipped-truth docs
3. architecture and security law
4. area engineering law and API contract docs
5. implementation code
6. tests and CI workflows
7. developer, ops, and QA support docs
8. prompts, temporary notes, and chat summaries

### Required behavior

* Call out real conflicts explicitly.
* Do not smooth over contradictions.
* Do not let polished wording outrank repo evidence.
* Do not let support docs overrule architecture, security, contracts, or shipped-truth docs.

### Off-repo truth rule

An off-repo document may outrank repo docs only when all of the following are true:

* it is module-specific
* it explicitly declares source-of-truth priority
* it is still active, not historical
* the current task is about that module

Example: a locked master spec for Settings may outrank repo docs for Settings work only.
It does not become the default truth source for unrelated backend, frontend, auth, or topology work.

---

## Canonical AI Read Order

Before non-trivial implementation, debugging, review, or audit work, load these first:

1. `docs/current-foundation-status.md`
2. `ARCHITECTURE.md`
3. `docs/security-model.md`

Then route by task:

* backend work -> `backend/AGENTS.md`
* frontend work -> `frontend/AGENTS.md`
* review / audit work -> `code_review.md`
* prompt selection only -> `docs/prompts/catalog.md`

### Task-gated docs

Load these only when the task actually needs them:

* `docs/quality-bar.md` -> review, signoff, readiness, or release-quality questions
* `docs/decision-log.md` -> architectural decisions, open conflicts, or decision-history questions
* `docs/developer-guide.md` -> local setup, commands, environment, or workflow execution
* `docs/ops/*` -> operability, release, incident, topology-proof, or recovery work
* `docs/qa/*` -> QA execution, user-visible flow proof, or message-audit work

Do not start with QA docs, prompt docs, runbooks, or support docs when a higher-truth file already answers the question.

---

## Actual Repo Tier Map

This repo uses three documentation tiers.
The tier decides how a document is used, how often it should change, and whether it is allowed to compete for truth.

### Tier 1 — Canonical active routing and law

These are the highest-value active docs for repo navigation, shipped truth, and engineering law.
Load these first when relevant.

* `AGENTS.md`
* `README.md`
* `docs/current-foundation-status.md`
* `ARCHITECTURE.md`
* `docs/security-model.md`
* `backend/AGENTS.md`
* `frontend/AGENTS.md`
* `backend/docs/engineering-rules.md`
* `frontend/src/shared/engineering-rules.md`
* `backend/docs/module-skeleton.md`
* `frontend/docs/module-skeleton.md`

### Tier 2 — Canonical growing domain and decision surfaces

These are active and important, but they are not the first router layer.
They grow as the repo evolves.

* `docs/decision-log.md`
* `backend/docs/api/auth.md`
* `backend/docs/api/invites.md`
* `backend/docs/api/admin.md`
* `code_review.md`

### Tier 3 — Support, execution, and secondary reference

These are useful, but they must never compete with Tier 1 or Tier 2 for repo truth.
They are loaded only when the task needs them.

* `docs/developer-guide.md`
* `docs/qa/*`
* `docs/ops/*`
* `docs/prompts/catalog.md`
* other prompt docs under `docs/prompts/`
* folder-map docs such as `backend/docs/README.md`, `frontend/README.md`, and `infra/README.md`
* `CONTRIBUTING.md`
* `CHANGELOG.md`
* module-local docs that are explicitly secondary and scoped to genuine local complexity only

### Tier rules

* No Tier 3 doc may restate or re-own shipped truth already owned by Tier 1.
* No Tier 3 doc may restate API or behavioral contract truth already owned by Tier 2.
* If two active docs compete for the same job, tighten, demote, or remove one.
* Historical docs are not active tiers. They are reference-only or should be removed from active use.

---

## Continuation Chat Attachment Rules

### Default attachment bundle

Use this by default:

1. the latest repo/codebase snapshot
2. `AGENTS.md`
3. `docs/current-foundation-status.md`
4. `ARCHITECTURE.md`
5. `docs/security-model.md`

### Add one area bundle only when needed

#### Backend task

Attach or load:

* `backend/AGENTS.md`
* `backend/docs/engineering-rules.md`
* `backend/docs/module-skeleton.md`
* relevant `backend/docs/api/*.md`
* relevant module-local docs only if they exist, are still active, and add genuine non-obvious value

#### Frontend task

Attach or load:

* `frontend/AGENTS.md`
* `frontend/src/shared/engineering-rules.md`
* `frontend/docs/module-skeleton.md`
* relevant backend API docs

#### Review or release task

Attach or load:

* `code_review.md`
* `docs/quality-bar.md`
* relevant `docs/ops/*` only if release, rollback, readiness, or recovery is in scope

#### QA task

Attach or load:

* relevant files under `docs/qa/`
* `docs/developer-guide.md` only if setup or environment execution is part of the task

### Do not attach by default

Do not attach these unless the task explicitly needs them:

* `docs/decision-log.md`
* `docs/developer-guide.md`
* `docs/ops/*`
* `docs/qa/*`
* `CONTRIBUTING.md`
* `CHANGELOG.md`
* prompt docs other than `docs/prompts/catalog.md`
* ADR indexes or folder-map docs
* historical inventories, brainstorm notes, or raw cleanup inputs

### Historical-doc rule

If a master module spec explicitly bans certain historical docs from continuation chats, do not attach them.
They are treated as regression sources, not helpful context.

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

* `docs/decision-log.md`
* relevant `docs/ops/*`
* relevant ADRs

### Review or audit work

Load:

1. `code_review.md`
2. relevant authority docs for the changed area
3. `docs/quality-bar.md` when the task is about readiness or signoff
4. `docs/prompts/catalog.md` only if you need a reusable prompt asset

---

## Documentation Coupling Rules

Review or update the matching docs when code changes affect:

* architecture or cross-cutting behavior -> `ARCHITECTURE.md`, `docs/decision-log.md`
* security, sessions, cookies, tenant rules, or trust boundaries -> `docs/security-model.md`
* request/response or behavioral contracts -> relevant `backend/docs/api/*.md`
* shipped capability or repo truth snapshot -> `docs/current-foundation-status.md`
* operational recovery, release behavior, or support flow -> relevant files under `docs/ops/`
* QA-visible messages or flow behavior -> relevant files under `docs/qa/`
* routing or repo-usage behavior -> `AGENTS.md`, `README.md`, `code_review.md`, `docs/prompts/catalog.md`

Do not create silent documentation drift.

---

## Topology-Sensitive Change Rules

Treat a change as topology-sensitive if it touches any of the following:

* proxy behavior
* browser `/api/*` routing
* SSR direct-backend calls
* `INTERNAL_API_URL`
* forwarded headers
* host-derived tenant behavior
* cookie or session behavior
* auth bootstrap behavior
* SSO start/callback behavior

### Required behavior for topology-sensitive work

* Do not treat browser and SSR requests as interchangeable.
* Do not hardcode browser calls to backend origins.
* Do not weaken host-derived tenant routing.
* Do not weaken tenant/session isolation.
* Do not replace navigation-based auth flows with inappropriate `fetch()` flows.
