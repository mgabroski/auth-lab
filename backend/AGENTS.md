# AGENTS.md

Read `../AGENTS.md` first.

## Scope

Applies to all work under `backend/`.

## Purpose

This is the backend-specific AI and review router.

It narrows root repo law into backend execution rules so backend work stays:

* contract-correct
* tenant-aware
* auth-aware
* transaction-safe
* audit-aware
* topology-safe

It does not replace the root `AGENTS.md`.
It does not replace backend engineering law.
It routes backend work to the right authority and helps prevent contract, state, and boundary drift.

---

## Read After Root Instructions

After reading `../AGENTS.md`, load backend authority in this order:

1. `backend/docs/engineering-rules.md`
2. `backend/docs/module-skeleton.md`
3. relevant `backend/docs/api/*.md`
4. relevant backend module docs or ADRs only when needed
5. relevant backend code, tests, migrations, and workflows

### Task-gated re-checks

Load these only when the task actually needs them:

* `docs/current-foundation-status.md` -> shipped scope or current truth questions
* `ARCHITECTURE.md` -> cross-cutting design or boundary questions
* `docs/security-model.md` -> session, cookie, tenant, trust-boundary, or security-sensitive work
* `docs/decision-log.md` -> decision-history or architecture-decision questions
* `docs/ops/*` -> recovery, release, operability, or topology-proof work
* `docs/qa/*` -> QA-visible backend behavior or user-visible message proof

Do not invent backend truth from assumptions, screenshots, or chat memory when the repo already defines it.

---

## Backend Truth Order

When backend sources disagree, use this order:

1. module-specific highest-truth docs explicitly declared authoritative for the target module
2. current shipped-truth and architecture/security law
3. backend API contract docs
4. backend engineering law
5. backend implementation code
6. backend tests, migrations, and CI workflows
7. runbooks, QA docs, and developer guides
8. prompts, temporary notes, and chat summaries

### Required behavior

* Call out real conflicts explicitly.
* Do not let code convenience overrule API, security, or shipped truth.
* Do not let support docs become backend law.

---

## Backend Attachment Rules

### Default backend bundle

For most backend tasks, use:

1. repo snapshot
2. `../AGENTS.md`
3. `backend/AGENTS.md`
4. `backend/docs/engineering-rules.md`
5. `backend/docs/module-skeleton.md`
6. relevant `backend/docs/api/*.md`

### Add only when needed

* `docs/security-model.md` -> auth, session, tenant, cookie, proxy, or trust-boundary work
* `ARCHITECTURE.md` -> cross-cutting design or structural boundary work
* `docs/current-foundation-status.md` -> shipped-scope or current-state questions
* `docs/decision-log.md` -> decision-history questions
* `docs/ops/*` -> release, support, recovery, topology-proof, or incident work
* `docs/qa/*` -> QA-visible flows or message-audit work

### Do not attach by default

Do not attach by default:

* prompt docs
* QA docs
* ops docs
* `docs/decision-log.md`
* folder-map docs
* historical inventories or raw notes
* backend prompt docs when root prompt routing already covers the need

---

## Backend Hard Rules

### 1. Backend owns contract truth

Request validation, status codes, response shape, session truth, membership truth, and next-action truth are backend-owned.

Do not push contract meaning into frontend guesswork.

### 2. Keep module boundaries real

Do not bypass the established backend structure without a repo-level reason.

### 3. Tenant and session behavior must fail closed

If tenant resolution, membership state, auth state, cookie state, or trust-boundary behavior becomes uncertain, the safer behavior wins.

### 4. Do not weaken audit and side-effect discipline

Invites, verification, reset, MFA, SSO, outbox, and admin actions often require coupled behavior.
Do not change one part casually and assume the rest is unaffected.

### 5. Treat auth and topology work as high-risk

Auth, session, SSR-related backend behavior, proxy assumptions, tenant resolution, and forwarded-header behavior require stronger proof than ordinary CRUD changes.

### 6. Keep migrations and data-shape changes explicit

Do not bury schema changes inside unrelated backend work.

### 7. Use Yarn only

Do not switch package managers.

---

## Backend Review Focus

When reviewing backend work, check these explicitly when relevant:

### Boundary correctness

* Is the change in the right module and layer?
* Is shared code introduced in the right place?
* Is backend truth still server-owned?

### Contract correctness

* Does implementation still match the API doc?
* Are response shapes, codes, and continuation semantics still correct?

### Audit and side-effect behavior

* Are required audit events preserved?
* Are emails, invites, resets, or other side effects still triggered in the right situations?
* Could retries or sequencing changes break expected behavior?

### Migration and rollout risk

* Does the change alter schema, data meaning, or rollout assumptions?
* Does it require migration safety thinking, test fixture updates, or runbook changes?

---

## High-Risk Backend Change Triggers

Treat backend work as high-risk when it touches any of the following:

* authentication
* authorization
* session creation, validation, or invalidation
* tenant resolution
* request context
* membership activation, suspension, or gating
* invites
* email verification
* password reset
* MFA
* SSO start/callback behavior
* audit flow behavior
* outbox or email delivery behavior
* migrations or data-shape changes
* forwarded-header assumptions
* proxy-sensitive backend behavior

For these changes, be stricter than normal about docs, review, and validation.

---

## Documentation Coupling For Backend Changes

Review or update the relevant docs when backend code changes affect:

* request/response contract -> relevant `backend/docs/api/*.md`
* backend engineering law or structure expectations -> `backend/docs/engineering-rules.md`, `backend/docs/module-skeleton.md`
* architecture or cross-cutting design -> `ARCHITECTURE.md`, `docs/decision-log.md`, relevant ADRs
* session, security, tenant, or trust boundaries -> `docs/security-model.md`, relevant ADRs
* operational recovery or supportability -> `docs/ops/runbooks.md`, `docs/ops/observability.md`, `docs/ops/release-engineering.md`
* QA-visible backend behavior -> relevant docs under `docs/qa/`
* shipped capability or repo truth snapshot -> `docs/current-foundation-status.md`

Do not create silent backend documentation drift.

---

## Validation Routing For Backend Work

Run the smallest meaningful proof that actually matches the changed backend risk.

### Typical backend proof

Use the relevant subset of:

* backend typecheck
* backend unit tests
* backend DAL or integration tests
* backend E2E tests

### For schema or migration changes

Also use the smallest meaningful migration or fixture proof.

### For auth, session, tenant, proxy, or trust-boundary changes

Use stronger proof than unit tests alone when the behavior becomes real only through:

* cookies or sessions
* forwarded headers
* real redirects or callbacks
* proxy routing
* full stack behavior

### Required behavior

When reporting validation, state what was actually run.
Do not imply stack-proof if you only reviewed code.

---

## What Not To Do

* Do not treat controller changes as isolated if they alter service, audit, or side-effect meaning.
* Do not weaken fail-closed auth or tenant behavior to make local flows feel easier.
* Do not let stale notes, prompt docs, or support docs overrule backend law.
* Do not add parallel backend explainer docs when the right fix is to update the canonical contract or law doc.

---

## Final Position

Use this file to route backend work after reading the root `AGENTS.md`.

If the task is backend-specific, load only the backend authority you actually need.
Less context is better than duplicated context when the truth path is already clear.
