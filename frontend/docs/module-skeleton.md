# Frontend Module Skeleton

This document defines the required frontend planning shape for a new or expanded frontend module surface in Hubins.

It is a frontend implementation skeleton.
It is not a product-design document.
It is not a substitute for architecture law.
It is not a substitute for the reusable module-design framework.

---

## Mandatory Prerequisite

Before using this file, the module must already be analyzed through:

- `docs/module-design-framework.md`

That framework decides whether module thinking is actually complete enough to move into implementation planning.

This frontend skeleton starts only after the following are already clear:

- what the module is
- what objects and actions it exposes to users
- what workspace experience implications it has
- what settings implications it has
- what permission and policy implications it has
- what communications touchpoints it creates or depends on
- what fail-closed and removal behavior must be visible or enforced in the UI

If those questions are still open, stop and return to `docs/module-design-framework.md`.

---

## Required Source Bundle

Before frontend planning begins, load:

1. `docs/current-foundation-status.md`
2. `ARCHITECTURE.md`
3. `docs/security-model.md`
4. `frontend/src/shared/engineering-rules.md`
5. relevant backend API docs
6. relevant adjacent frontend routes or features
7. this file

If the task touches auth, session, SSR bootstrap, `/api/*` behavior, tenant routing, or protected-route behavior, also load the relevant decision and ops docs.

---

## Purpose

Use this file to turn an already-designed module into a clean frontend work package.

The goal is not to guess components.
The goal is to define the correct routes, data-flow boundaries, SSR/client responsibilities, user-visible behavior, and proof expectations before coding begins.

---

## Frontend Planning Order

Follow this order.
Do not skip steps.

### Step 1 — Restate frontend ownership

Answer:

- what routes or surfaces this module owns
- what shell or layout it lives inside
- what existing frontend areas it touches
- what it must not own
- what role, tenant, or setup state affects visibility

### Step 2 — Define frontend behavior

Answer:

- SSR behavior
- client-only behavior
- navigation behavior
- setup or management mode differences where applicable
- permission-sensitive behavior
- fail-closed UI behavior
- loading, empty, error, and blocked states

### Step 3 — Define the data and contract usage

Answer before planning files:

- what API calls are needed
- browser vs SSR call path
- bootstrap dependencies
- request sequencing
- response-driven rendering states
- error and redirect behavior

### Step 4 — Define component and route structure

Answer:

- new pages or routes
- shared components required
- local components required
- whether new hooks or helpers are needed
- what should stay route-level vs reusable component-level

### Step 5 — Generate file plan

Only now generate the frontend file plan.

---

## Frontend File Plan Output Shape

For every planned file, use this structure:

```text
Path:
Action: create | modify
Layer:
Role:
Why needed:
Depends on:
```

### Expected frontend layers

Use only when actually needed:

- route / page
- layout
- view / screen component
- feature component
- shared component
- hook
- API client wrapper use
- types / mapping helper
- tests
- docs

Do not invent components that duplicate route responsibility.
Do not hide route logic in the wrong shared layer.

---

## Frontend Work Package Checklist

Every frontend module plan must explicitly answer these.

### 1. Route package

- What routes are new?
- Which are SSR-gated?
- Which are role-gated or setup-gated?
- Which routes are placeholders vs real surfaces?

### 2. Rendering package

- What is rendered on the server?
- What is rendered on the client?
- What loading, empty, blocked, and review-needed states exist?
- What fail-closed states must be visible?

### 3. Data package

- What data comes from bootstrap?
- What data comes from direct page fetches?
- What browser `/api/*` calls are needed?
- What SSR direct-backend fetches are needed?

### 4. UX contract package

- What headings, cards, actions, and status states exist?
- What is hidden vs visible vs read-only?
- What is role-specific?
- What is tenant-configuration-specific?

### 5. Proof package

- What frontend tests are required?
- What browser E2E flows are required?
- What message or copy expectations are important enough for QA?

---

## Anti-Drift Rules

### 1. Do not use this file to finish product design

If the module is still vague at product or settings-adapter level, go back to `docs/module-design-framework.md`.

### 2. Do not plan routes before defining rendering and data boundaries

A route tree without SSR/client/data rules will drift fast.

### 3. Do not blur browser and SSR behavior

If the module needs both, say exactly what happens in each path.
Do not plan frontend work as if all fetches are interchangeable.

### 4. Do not skip fail-closed UI behavior

If access, targets, configuration, or dependencies disappear, the frontend plan must say what becomes hidden, blocked, or review-needed.

### 5. Do not claim readiness from screens alone

Pages and components are not proof.
Tests, browser flows, and correct state handling still decide readiness.

---

## Fast Routing

### I am still defining what the module is

Go to:

- `docs/module-design-framework.md`

### I need frontend implementation law

Read:

- `frontend/src/shared/engineering-rules.md`

### I need frontend file planning

Use:

- this file

### I need full-stack planning in one session

Use:

- `docs/prompts/module-generation-fullstack.md`

But only after the module-design framework has been applied.

---

## Final Position

This file is the frontend execution bridge.
It exists to make frontend module work structured, explicit, and provable.

It starts after module design is complete.
It does not replace that design step.
