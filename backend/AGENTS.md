# AGENTS.md

Read `../AGENTS.md` first.

## Scope

Applies to all work under `backend/`.

## Purpose

This file defines the **backend-specific AI/review rules** for this repository.

It exists to keep backend work:

* aligned with repo truth
* structurally clean
* safe for tenant/session boundaries
* disciplined around transactions, audits, and contracts
* coupled to the right validation and documentation

This file does **not** replace the root `AGENTS.md`. It narrows and extends it for backend work.

---

## Read These After Root Instructions

After reading `../AGENTS.md`, review the backend-governing docs that exist for the area you are changing.

Prioritize these when present:

1. `backend/docs/engineering-rules.md`
2. `backend/docs/module-skeleton.md`
3. relevant `backend/docs/api/*.md`
4. `docs/decision-log.md`
5. `docs/security-model.md`
6. backend code and tests for the affected module

If one of these files does not exist yet, do not invent it. Continue with the files that do exist.

---

## Backend Source-of-Truth Order

Use this backend-oriented truth order when sources disagree:

1. active locked product/module source-of-truth documents
2. repo-wide current foundation / shipped-scope truth docs
3. architecture and decision records
4. security model and topology law
5. backend API/contract docs
6. backend implementation code
7. backend tests and CI workflows
8. runbooks, QA docs, and developer guides
9. temporary notes or chat summaries

### Required Behavior

* If a lower-truth source conflicts with a higher-truth source, call it out explicitly.
* Do not silently resolve backend behavior based on assumption.
* Do not let tests alone overrule architecture, security, or contract truth.

---

## Backend Hard Rules

### 1. Keep business logic in modules

Business behavior belongs in `backend/src/modules/**`, not in random shared helpers.

### 2. Keep `shared/` truly shared

`shared/` is for cross-cutting infrastructure and broadly reusable technical utilities, not for leaking business rules out of modules.

### 3. Preserve clean flow boundaries

Default backend dependency direction should stay structurally clean:

* routes
* controller
* service
* flow / use-case
* queries / repositories / policies / helpers

Do not collapse layers casually just because a change looks small.

### 4. Put transactions in the correct place

Transactions belong in the flow / use-case layer, not in controllers and not scattered across unrelated helpers.

### 5. Keep request truth server-side

Tenant identity, membership context, session state, and security-sensitive routing truth must come from backend request context — never from client-declared payload assumptions.

### 6. Preserve tenant isolation

Any change affecting membership lookup, tenant resolution, invites, sessions, or protected resources must be treated as tenant-boundary-sensitive.

### 7. Do not weaken audit behavior

If a flow requires audit behavior, keep success-path and failure-path expectations clear. Do not let rollback or refactor changes silently remove required audit evidence.

### 8. Be careful with outbox/email side effects

Changes that affect invite, verification, reset, notification, or other delivery-triggering flows must preserve the intended sequencing and side-effect behavior.

### 9. Do not hide contract changes

If backend request/response behavior changes, update or review the matching API docs.

### 10. AI is not proof

A clean explanation of a backend flow is not proof that the flow is safe, correct, or releasable.

---

## Backend Review Focus Areas

When reviewing or changing backend code, check these areas explicitly when relevant:

### Module ownership

* Is the behavior in the correct module?
* Is a shared utility being used appropriately?
* Is the change leaking one module’s business rules into another?

### Transaction placement

* Is the transaction boundary in the right layer?
* Is it too broad or too narrow?
* Could partial failure create inconsistent state?

### Tenant / request-context correctness

* Is tenant identity derived correctly?
* Is membership/access being checked in the right place?
* Is anything trusting the client when the server should decide?

### Contract correctness

* Does the implementation still match the API/contract docs?
* Are user-visible status codes and response shapes still correct?

### Audit / side-effect behavior

* Are audit events preserved?
* Are emails, invites, resets, or similar side effects still triggered in the correct situations?
* Could retries or refactors break expected behavior?

### Migration / rollout risk

* Does the change alter schema, data meaning, or rollout assumptions?
* Does it require rollback thinking, fixture updates, or QA/runbook updates?

---

## Documentation Coupling For Backend Changes

Review or update the relevant docs when backend code changes affect:

* request/response contract → relevant `backend/docs/api/*.md`
* module structure or backend engineering law → `backend/docs/engineering-rules.md`, `backend/docs/module-skeleton.md`
* architecture or cross-cutting design decisions → `docs/decision-log.md`, `ARCHITECTURE.md`
* session, security, tenant, or trust boundaries → `docs/security-model.md`
* operational recovery or backend supportability → `docs/ops/runbooks.md`
* QA-visible backend behavior → relevant QA docs

Do not create documentation drift by changing backend behavior silently.

---

## High-Risk Backend Change Triggers

Treat backend changes as high-risk when they touch any of the following:

* authentication
* authorization
* session creation or invalidation
* tenant resolution
* membership activation/suspension rules
* invites
* email verification
* password reset
* MFA
* SSO callback behavior
* audit flow behavior
* outbox / delivery behavior
* migrations or data-shape changes
* request-context propagation

For these changes, be stricter than usual about review, docs, and validation.

---

## Validation Routing For Backend Work

Run the smallest meaningful checks that prove the backend area you changed.

### Typical backend checks

* backend typecheck
* backend tests
* affected integration/e2e/backend flow checks when relevant

### For schema or migration changes

Also run:

* migration-related checks
* affected fixtures/seeds/tests
* any data-shape-sensitive validations available

### For auth/session/tenant/proxy-sensitive backend changes

Also run the higher-confidence proof relevant to the flow, especially when the backend behavior only becomes meaningful through the full stack.

### Required Behavior

When reporting results, say what was actually run. Do not imply runtime proof if you only reasoned about the change.

---

## How To Work On Backend Tasks

### For implementation

* start from the owning module and its rules
* keep boundaries explicit
* prefer narrow, understandable changes
* do not bury important behavior in generic helpers

### For review

* read the real code path end to end
* check transaction, contract, tenant, and audit implications
* distinguish blocker-level risk from cleanup advice

### For refactor

* preserve behavior first
* protect boundaries
* do not let “cleanup” erase important sequencing, auditing, or validation behavior

---

## When To Escalate Review

Use stricter review when the backend change affects:

* auth/session/tenant boundaries
* migration or rollback risk
* audit/outbox side effects
* user provisioning flows
* production-support diagnostics
* performance-sensitive data access patterns

If the change is high-risk, a generic code skim is not enough.

---

## What Not To Do

* Do not treat this file as a general architecture doc.
* Do not duplicate the entire root `AGENTS.md` here.
* Do not move business logic into `shared/` just to reduce imports.
* Do not trust client-side state when the backend should decide.
* Do not treat API docs as optional when behavior changes.
* Do not claim a backend flow is safe just because unit tests pass.

---

## Final Position

This file is the backend-specific instruction layer for repo-aware AI assistance and review.

Its job is to keep backend work:

* structurally correct
* tenant-safe
* contract-aware
* transaction-aware
* audit-aware
* validation-coupled
