# Backend Module Skeleton

This document defines the required backend planning shape for a new or expanded backend module in Hubins.

It is a backend implementation skeleton.
It is not a product-design document.
It is not a substitute for architecture law.
It is not a substitute for the reusable module-design framework.

---

## Mandatory Prerequisite

Before using this file, the module must already be analyzed through:

- `docs/module-design-framework.md`

That framework decides whether module thinking is actually complete enough to move into implementation planning.

This backend skeleton starts only after the following are already clear:

- what the module is
- what it owns
- what actions and lifecycle it contains
- what settings implications it has
- what permission and policy implications it has
- what fail-closed and removal behavior it requires
- what adjacent module boundaries exist

If those questions are still open, stop and return to `docs/module-design-framework.md`.

---

## Required Source Bundle

Before backend planning begins, load:

1. `docs/current-foundation-status.md`
2. `ARCHITECTURE.md`
3. `docs/security-model.md`
4. `backend/docs/engineering-rules.md`
5. relevant `backend/docs/api/*.md`
6. relevant adjacent backend modules
7. this file

If the task touches auth, tenant, proxy, cookies, session, SSO, or SSR-trust behavior, also load the relevant decision and ops docs.

---

## Purpose

Use this file to turn an already-designed module into a clean backend work package.

The goal is not to guess files.
The goal is to define the correct backend surfaces, ownership, contracts, data changes, and proof requirements before coding begins.

---

## Backend Planning Order

Follow this order.
Do not skip steps.

### Step 1 — Restate backend ownership

Answer:

- what backend bounded area owns this module
- what it is allowed to own
- what it must not own
- what existing modules it touches
- what trust boundaries it crosses

### Step 2 — Define backend behavior

Answer:

- read-only behavior
- mutating behavior
- transaction boundaries
- policy checks
- async/outbox behavior
- audit behavior
- fail-closed behavior

### Step 3 — Define the contract surface

Answer before planning files:

- new endpoints
- changed endpoints
- request shape
- response shape
- role/auth requirements
- status/error behavior
- anti-enumeration behavior
- admin/member differences where applicable

### Step 4 — Define persistence and state changes

Answer:

- entities or tables touched
- migrations needed or not
- indexes needed or not
- state transitions
- uniqueness constraints
- orphan-retention behavior where applicable

### Step 5 — Generate file plan

Only now generate the backend file plan.

---

## Backend File Plan Output Shape

For every planned file, use this structure:

```text
Path:
Action: create | modify
Layer:
Role:
Why needed:
Depends on:
```

### Expected backend layers

Use only when actually needed:

- route
- controller
- service
- flow / use-case
- policy / authorization helper
- query
- repository / DAL
- model / schema / types
- migration
- tests
- docs

Do not create layers that the module does not need.
Do not collapse multiple responsibilities into the wrong layer.

---

## Backend Work Package Checklist

Every backend module plan must explicitly answer these.

### 1. Contract package

- Which API docs must be created or updated?
- Does the module introduce a new domain contract file or extend an existing one?
- What response shapes become stable contract?

### 2. Data package

- What persistence changes are required?
- Are migrations required?
- Are indexes required?
- Are there uniqueness, retention, or lifecycle rules?

### 3. Logic package

- Which service owns orchestration?
- Are flows or use-cases needed?
- Are policy checks simple or layered?
- Is fail-closed behavior explicit?

### 4. Async/audit package

- Does the module emit audit actions?
- Does it require outbox events or background work?
- What happens if a downstream dependency is unavailable?

### 5. Proof package

- What backend tests are required?
- What contract tests are required?
- What integration or E2E proof is required?

---

## Anti-Drift Rules

### 1. Do not use this file to finish product design

If the module is still vague at product or settings-adapter level, go back to `docs/module-design-framework.md`.

### 2. Do not generate files before defining the contract

Undefined contract first, file planning second, coding third.
Not the other way around.

### 3. Do not skip fail-closed behavior

If the module can lose targets, mappings, dependencies, or permissions, backend behavior must say what fails closed, what is retained, and what requires review.

### 4. Do not hide data-model impact

If a module changes storage, state transitions, or constraints, call it out explicitly.
Do not bury this in a service description.

### 5. Do not claim readiness from structure alone

A set of backend files is not proof.
Tests, contracts, and runtime behavior still decide readiness.

---

## Fast Routing

### I am still defining what the module is

Go to:

- `docs/module-design-framework.md`

### I need backend implementation law

Read:

- `backend/docs/engineering-rules.md`

### I need backend file planning

Use:

- this file

### I need full-stack planning in one session

Use:

- `docs/prompts/module-generation-fullstack.md`

But only after the module-design framework has been applied.

---

## Final Position

This file is the backend execution bridge.
It exists to make backend module work structured, explicit, and provable.

It starts after module design is complete.
It does not replace that design step.
