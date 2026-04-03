# AGENTS.md

Read `../AGENTS.md` first.

## Scope

Applies to all work under `frontend/`.

## Purpose

This is the frontend-specific AI and review router.

It narrows root repo law into frontend execution rules so frontend work stays:

* route-correct
* contract-correct
* SSR-aware
* tenant-aware
* auth-aware
* UX-truthful

It does not replace the root `AGENTS.md`.
It does not replace frontend engineering law.
It routes frontend work to the right authority and helps prevent contract and state drift.

---

## Read After Root Instructions

After reading `../AGENTS.md`, load frontend authority in this order:

1. `frontend/src/shared/engineering-rules.md`
2. `frontend/docs/module-skeleton.md`
3. relevant `backend/docs/api/*.md`
4. relevant frontend routes, shared utilities, components, and tests
5. relevant ADRs or backend docs only when the frontend behavior depends on them

### Task-gated re-checks

Load these only when the task actually needs them:

* `docs/current-foundation-status.md` -> shipped scope or current truth questions
* `ARCHITECTURE.md` -> cross-cutting design or boundary questions
* `docs/security-model.md` -> auth, session, tenant, cookie, SSR, or trust-boundary work
* `docs/decision-log.md` -> decision-history or architecture-decision questions
* `docs/ops/*` -> full-flow proof, release, recovery, or topology behavior
* `docs/qa/*` -> QA-visible flow behavior or message-audit work

Do not invent frontend truth from screenshots, assumptions, or chat memory when the repo already defines it.

---

## Frontend Truth Order

When frontend sources disagree, use this order:

1. module-specific highest-truth docs explicitly declared authoritative for the target module
2. current shipped-truth and architecture/security law
3. backend API and behavior contract docs
4. frontend engineering law
5. frontend implementation code
6. frontend tests and E2E flows
7. runbooks, QA docs, and developer guides
8. prompts, temporary notes, and chat summaries

### Required behavior

* Call out real conflicts explicitly.
* Do not let UI convenience overrule backend truth.
* Do not let screenshots or temporary behavior become frontend law.

---

## Frontend Attachment Rules

### Default frontend bundle

For most frontend tasks, use:

1. repo snapshot
2. `../AGENTS.md`
3. `frontend/AGENTS.md`
4. `frontend/src/shared/engineering-rules.md`
5. `frontend/docs/module-skeleton.md`
6. relevant `backend/docs/api/*.md`

### Add only when needed

* `docs/security-model.md` -> auth, session, tenant, cookie, SSR, or trust-boundary work
* `ARCHITECTURE.md` -> route-model, boundary, or cross-cutting behavior changes
* `docs/current-foundation-status.md` -> shipped-scope or current-state questions
* `docs/decision-log.md` -> decision-history questions
* `docs/ops/*` -> topology-proof, release, or incident-sensitive flows
* `docs/qa/*` -> user-visible flows, message audit, or QA execution questions

### Do not attach by default

Do not attach by default:

* prompt docs
* ops docs
* QA docs
* `docs/decision-log.md`
* folder-map docs
* screenshots as primary truth
* historical inventories or raw notes

---

## Frontend Hard Rules

### 1. Browser requests stay same-origin

Browser-side requests must use relative `/api/*` paths.

Do not hardcode browser calls to backend origins.
Do not bypass the host-run proxy path in browser code.

### 2. SSR and browser flows are different

Server-rendered calls and browser calls are not interchangeable.

Use the correct SSR or server path for server-side data loading.
Use the correct browser path for client-side requests.
Do not flatten both models into one generic approach if that weakens topology truth.

### 3. Backend owns auth and session truth

The frontend does not decide final auth state, membership state, tenant truth, or next-action truth.

The frontend renders and routes from backend-owned outcomes.
It does not invent parallel state machines for those decisions.

### 4. Keep tenant awareness intact

The current tenant comes from host-derived behavior and backend truth.

Do not introduce frontend shortcuts that weaken tenant isolation, tenant-sensitive routing, or tenant/session fail-closed behavior.

### 5. Preserve route-state clarity

Public auth pages, admin pages, member pages, setup pages, and transition pages should remain easy to reason about.

Do not hide important route behavior inside scattered helpers or UI-only abstractions.

### 6. Do not blur UI state with contract state

Loading, success, error, and redirect behavior must reflect actual backend contract behavior.

Do not make the UI feel nicer by masking real contract states or inventing optimistic states the backend did not authorize.

### 7. Keep user-visible text deliberate

Auth, invite, MFA, reset, verification, and setup flows are sensitive.

Do not casually rewrite user-visible messages if those messages are contract-meaningful, QA-audited, or security-sensitive.

### 8. Do not casually redesign auth flow behavior

Login, logout, signup, invite acceptance, MFA, reset-password, verification, SSO initiation, SSO completion, and admin/member landing behavior are not generic UX playgrounds.

Treat them as behaviorally coupled to backend truth and documented flow rules.

### 9. Respect shared frontend patterns

Use established frontend route, shell, shared-client, and state patterns unless the task explicitly requires a change.

Do not introduce one-off architectural patterns without a clear repo-level reason.

### 10. Keep frontend claims honest

A visually correct page is not automatically contract-correct.
A passing component test is not enough for high-risk route behavior.

---

## Frontend Review Focus

When reviewing frontend work, check these explicitly when relevant:

### Route correctness

* Is the page using the correct route model?
* Is auth gating or redirect behavior still correct?
* Are admin and member landing paths still aligned with backend truth?

### Contract correctness

* Does the UI match backend response and error behavior?
* Are redirects, next actions, and status handling still correct?
* Is any frontend logic silently overriding backend semantics?

### SSR vs browser correctness

* Is server-side data loading using the correct SSR path?
* Are browser requests still same-origin through `/api/*`?
* Has any change weakened forwarded-header or session behavior indirectly?

### State clarity

* Are loading, error, empty, and success states deterministic?
* Is any critical behavior hidden in a way that makes debugging harder?
* Does the component tree make the route behavior easier or harder to reason about?

### UX truthfulness

* Are messages, actions, and CTAs aligned with real system behavior?
* Is a setup banner, warning, or auth continuation shown only when backend truth warrants it?
* Has a cosmetic cleanup changed product meaning?

### Drift risk

* Does the frontend now assume behavior that only existed in mocks?
* Has a shared utility become a second source of truth?
* Does the current UI still match shipped repo law?

---

## High-Risk Frontend Change Triggers

Treat frontend work as high-risk when it touches any of the following:

* auth pages and auth routing
* admin/member landing behavior
* protected route gating
* SSR bootstrap or SSR API client behavior
* browser API client behavior
* invite flows
* email verification flows
* password reset flows
* MFA setup, verify, or recovery flows
* SSO initiation or completion flows
* workspace setup banner behavior
* settings bootstrap behavior
* tenant-derived behavior from host or forwarded headers
* logout and session invalidation behavior

For these changes, be stricter than normal about contracts, proof, and doc coupling.

---

## Documentation Coupling For Frontend Changes

Review or update the relevant docs when frontend code changes affect:

* user-visible flow behavior or page semantics -> relevant API docs, QA docs, and shipped-truth docs
* route or cross-cutting behavior -> `ARCHITECTURE.md`, `docs/decision-log.md`, relevant ADRs
* session, security, tenant, or trust-boundary behavior -> `docs/security-model.md`
* frontend structure expectations -> `frontend/src/shared/engineering-rules.md`, `frontend/docs/module-skeleton.md`
* operational or support expectations -> relevant docs under `docs/ops/`
* current shipped capability or behavior snapshot -> `docs/current-foundation-status.md`

Do not let frontend behavior drift away from the docs that users, QA, and reviewers depend on.

---

## Validation Routing For Frontend Work

Run the smallest meaningful proof that actually matches the changed frontend risk.

### Typical frontend proof

Use the relevant subset of:

* frontend lint and typecheck
* frontend unit tests
* route-level tests
* Playwright E2E

### For route, auth, or topology-sensitive changes

Use stronger proof than unit tests alone when the behavior only becomes real through:

* real redirects
* SSR and browser interaction
* session cookies
* protected route behavior
* full stack or proxy topology

### Required behavior

When reporting validation, state what was actually run.
Do not imply full-flow proof if you only reviewed code or ran shallow tests.

---

## What Not To Do

* Do not treat screenshots as stronger than shipped docs or backend contracts.
* Do not weaken backend-owned flow meaning for visual convenience.
* Do not create frontend-only state machines for auth, membership, tenant, or setup truth.
* Do not add parallel explainer docs when the correct fix is to update the canonical contract or law doc.

---

## Final Position

Use this file to route frontend work after reading the root `AGENTS.md`.

If the task is frontend-specific, load only the frontend authority you actually need.
Smaller, cleaner context is better than duplicated context.
