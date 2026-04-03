# AGENTS.md

Read `../AGENTS.md` first.

## Scope

Applies to all work under `backend/`.

## Purpose

This is the backend-specific AI/review router.

It narrows root repo law into backend execution rules so backend work stays:

- structurally correct
- tenant-safe
- contract-aware
- transaction-aware
- audit-aware
- validation-coupled

It does not replace the root `AGENTS.md`.
It does not replace `backend/docs/engineering-rules.md`.
It routes backend work to the right law and keeps backend changes from drifting.

---

## Read After Root Instructions

After reading `../AGENTS.md`, load backend authority in this order:

1. `backend/docs/engineering-rules.md`
2. `backend/docs/module-skeleton.md`
3. relevant `backend/docs/api/*.md`
4. relevant ADRs under `backend/docs/adr/`
5. relevant module docs under `backend/docs/modules/`
6. backend code and tests for the changed path

Also re-check these when the task touches cross-cutting behavior:

- `docs/current-foundation-status.md`
- `ARCHITECTURE.md`
- `docs/decision-log.md`
- `docs/security-model.md`
- `docs/ops/runbooks.md`

Do not invent backend law from memory when these files already answer it.

---

## Backend Truth Order

When backend sources disagree, use this order:

1. active locked product/module source-of-truth docs
2. repo shipped-truth and architecture law
3. backend engineering law
4. backend API/contract docs
5. ADRs and module docs
6. backend implementation code
7. backend tests and CI workflows
8. runbooks, QA docs, and developer guides
9. temporary notes and chat summaries

### Required behavior

- Call out real conflicts explicitly.
- Do not let tests silently overrule architecture, security, or contract truth.
- Do not let lower-value notes become backend law.

---

## Backend Hard Rules

### 1. Keep business logic inside modules

Business behavior belongs in `backend/src/modules/**`.

Do not move domain logic into generic helpers or cross-cutting folders just to reduce imports.

### 2. Keep `shared/` truly shared

`shared/` is for cross-cutting infrastructure and broadly reusable technical utilities.

It is not a shortcut for bypassing module boundaries.

### 3. Preserve the module skeleton

Default backend flow should remain recognizable and explicit:

- route
- controller
- service
- flow / use-case
- queries / repositories / policies / helpers

Do not collapse layers casually because a task looks small.

### 4. Put transactions in the correct place

Transactions belong in the flow / use-case layer.

Do not start transactions in controllers.
Do not scatter write coordination across unrelated helpers.

### 5. Keep request truth server-side

Tenant identity, session state, membership state, and security-sensitive continuation truth must come from backend request context and backend-owned rules.

Do not trust client-declared payload truth where the backend must decide.

### 6. Preserve tenant isolation

Any change touching tenant resolution, membership lookup, invite acceptance, session checks, or protected resource access is boundary-sensitive by default.

Fail closed when tenant/session truth does not line up.

### 7. Do not weaken audit behavior

If a backend flow requires audit evidence, preserve it deliberately.

Do not let refactors, transaction changes, or rollback behavior silently remove required success-path or failure-path audit coverage.

### 8. Be careful with side-effect sequencing

Invite, verification, password reset, SSO, MFA, and outbox-backed email flows are sequencing-sensitive.

Do not move side effects earlier or later without checking commit boundaries, retries, idempotency, and documented behavior.

### 9. Do not hide contract changes

If request/response behavior, status codes, redirect semantics, or user-visible backend outcomes change, review and update the matching API docs.

### 10. Keep backend claims honest

A clean explanation is not proof.
A passing unit test is not automatically enough for a high-risk backend change.

---

## Backend Review Focus

When reviewing backend work, check these explicitly when relevant:

### Module ownership

- Is the behavior in the correct module?
- Is `shared/` being used correctly?
- Is one module leaking business rules into another?

### Layer ownership

- Is the responsibility in the right layer?
- Is the flow still easy to reason about end to end?
- Has a refactor hidden important behavior in the wrong place?

### Transaction placement

- Is the transaction boundary in the flow / use-case layer?
- Is it too broad or too narrow?
- Could partial failure produce inconsistent state?

### Request-context correctness

- Is tenant identity derived correctly?
- Is membership/access enforced in the right place?
- Is backend truth still server-owned?

### Contract correctness

- Does implementation still match the API doc?
- Are response shapes, codes, and continuation semantics still correct?

### Audit / side-effect behavior

- Are required audit events preserved?
- Are emails, invites, resets, or other side effects still triggered in the right situations?
- Could retries or sequencing changes break expected behavior?

### Migration / rollout risk

- Does the change alter schema, data meaning, or rollout assumptions?
- Does it require migration safety thinking, test fixture updates, or runbook changes?

---

## High-Risk Backend Change Triggers

Treat backend work as high-risk when it touches any of the following:

- authentication
- authorization
- session creation, validation, or invalidation
- tenant resolution
- request context
- membership activation, suspension, or gating
- invites
- email verification
- password reset
- MFA
- SSO start/callback behavior
- audit flow behavior
- outbox or email delivery behavior
- migrations or data-shape changes
- forwarded-header assumptions
- proxy-sensitive backend behavior

For these changes, be stricter than normal about docs, review, and validation.

---

## Documentation Coupling For Backend Changes

Review or update the relevant docs when backend code changes affect:

- request/response contract → relevant `backend/docs/api/*.md`
- backend engineering law or structure expectations → `backend/docs/engineering-rules.md`, `backend/docs/module-skeleton.md`
- architecture or cross-cutting design → `ARCHITECTURE.md`, `docs/decision-log.md`, relevant ADRs
- session, security, tenant, or trust boundaries → `docs/security-model.md`, relevant ADRs
- operational recovery or supportability → `docs/ops/runbooks.md`, `docs/ops/observability.md`, `docs/ops/release-engineering.md`
- QA-visible backend behavior → relevant docs under `docs/qa/`

Do not create silent backend documentation drift.

---

## Validation Routing For Backend Work

Run the smallest meaningful proof that actually matches the changed backend risk.

### Typical backend proof

Use the relevant subset of:

- backend typecheck
- backend unit tests
- backend DAL/integration tests
- backend E2E tests

### For schema or migration changes

Also run:

- migration-related checks
- affected fixtures/seeds/tests
- rollback-sensitive or data-shape-sensitive validation where available

### For auth/session/tenant/topology-sensitive changes

Use stronger proof than unit tests alone when the behavior only becomes real through the full stack or proxy path.

### Required behavior

When reporting validation:

- state what was actually run
- state what was not run
- do not imply runtime proof if you only reviewed code

---

## How To Work On Backend Tasks

### For implementation

- start from the owning module
- read the backend law before changing structure
- prefer narrow, explicit changes
- keep important behavior visible

### For review

- read the real code path end to end
- check tenant, contract, transaction, and audit implications
- separate blocker-level issues from cleanup advice

### For refactor

- preserve behavior first
- preserve boundaries second
- improve readability without erasing sequencing, validation, or audit truth

---

## What Not To Do

- Do not use this file as a second root router.
- Do not duplicate all repo-wide rules here.
- Do not move business logic into `shared/` for convenience.
- Do not trust client input where backend request context should decide.
- Do not treat API docs as optional when behavior changes.
- Do not declare a backend flow safe because one shallow test passed.
- Do not let refactor language hide contract, tenant, or audit risk.

---

## Final Position

Use this file after the root `AGENTS.md`.

Its job is to keep backend work:

- aligned with backend law
- structurally clean
- safe around tenant/session boundaries
- coupled to the right docs
- validated at the right proof level