# AGENTS.md

Read `../AGENTS.md` first.

## Scope

Applies to all work under `frontend/`.

## Purpose

This file defines the **frontend-specific AI/review rules** for this repository.

It exists to keep frontend work:

* aligned with repo truth
* correct across browser and SSR boundaries
* safe for tenant/session behavior
* coupled to the right contracts and validation
* resistant to topology and auth drift

This file does **not** replace the root `AGENTS.md`. It narrows and extends it for frontend work.

---

## Read These After Root Instructions

After reading `../AGENTS.md`, review the frontend-governing docs that exist for the area you are changing.

Prioritize these when present:

1. `frontend/src/shared/engineering-rules.md`
2. relevant frontend auth/bootstrap/shared files
3. relevant `backend/docs/api/*.md`
4. `docs/decision-log.md`
5. `docs/security-model.md`
6. frontend code and tests for the affected route or component

If one of these files does not exist yet, do not invent it. Continue with the files that do exist.

---

## Frontend Source-of-Truth Order

Use this frontend-oriented truth order when sources disagree:

1. active locked product/module source-of-truth documents
2. repo-wide current foundation / shipped-scope truth docs
3. architecture and decision records
4. security model and topology law
5. backend API/contract docs and frontend shared contracts
6. frontend implementation code
7. frontend tests and CI workflows
8. runbooks, QA docs, and developer guides
9. temporary notes or chat summaries

### Required Behavior

* If a lower-truth source conflicts with a higher-truth source, call it out explicitly.
* Do not silently resolve frontend behavior based on assumption.
* Do not let temporary UI behavior overrule auth, topology, or contract truth.

---

## Frontend Hard Rules

### 1. Keep browser and SSR behavior distinct

Browser code and SSR/server-side code do not have the same routing, cookie, or header behavior. Do not treat them as interchangeable.

### 2. Browser calls must stay same-origin

Browser-side API calls must stay on the same origin through `/api/*`.

Do not hardcode direct browser calls to backend origins.

### 3. SSR backend access must stay explicit

SSR/server-side code may call the backend directly only through the approved internal backend path and only with the correct forwarded headers.

### 4. Tenant identity stays host-derived

Do not introduce frontend behavior that lets the client choose tenant identity independently of the host-derived model.

### 5. Auth/bootstrap truth stays backend-authoritative

The frontend may display, route, and react, but it must not become the source of truth for auth state, setup state, or security-sensitive workflow state.

### 6. Do not break protected-route assumptions

Changes to routing, layout loading, auth bootstrap, or redirects must preserve the protected-route model.

### 7. Do not weaken SSO flow correctness

Do not replace browser-native navigation flows with inappropriate fetch-based flows when the feature depends on real navigation behavior.

### 8. Do not let placeholder UI become system truth

Interim or placeholder screens must not redefine product or security behavior.

### 9. Keep contract changes visible

If frontend behavior depends on changed response shapes, new bootstrap fields, or changed auth/setup semantics, review or update the matching contract/docs.

### 10. AI is not proof

A clean explanation of a frontend/auth flow is not proof that routing, cookies, SSR behavior, or topology actually work.

---

## Frontend Review Focus Areas

When reviewing or changing frontend code, check these areas explicitly when relevant:

### Browser vs SSR boundary correctness

* Is this code running in the browser, on the server, or both?
* Is the chosen request path correct for that execution context?
* Are forwarded headers handled where SSR requires them?

### Auth/bootstrap correctness

* Is frontend routing still aligned with backend-authored auth truth?
* Are setup or redirect decisions still coming from the right source?
* Has any frontend-only interpretation started to drift from backend truth?

### Contract correctness

* Does the frontend still match backend request/response expectations?
* Are user-visible states and error messages still aligned with contract and QA truth?

### Tenant/topology correctness

* Does the change preserve host-derived tenant behavior?
* Could this route/component accidentally weaken tenant isolation or mix workspace contexts?

### UI shell and route ownership

* Is this behavior in the right route, layout, or shared layer?
* Is a temporary convenience layer being mistaken for architecture?

### QA-visible behavior

* Does the change alter screens, redirects, messages, or flows that QA docs rely on?

---

## Documentation Coupling For Frontend Changes

Review or update the relevant docs when frontend code changes affect:

* user-visible flow or screen behavior → relevant QA docs
* request/response contract assumptions → relevant `backend/docs/api/*.md`
* auth/bootstrap/setup semantics → `docs/decision-log.md`, `docs/security-model.md`, current foundation docs
* AI/review operating guidance → `docs/prompts/usage-guide.md`, `AGENTS.md`, `code_review.md`
* operational/recovery expectations for the UI flow → relevant runbooks or support docs

Do not let frontend behavior drift away from the docs that describe the flow.

---

## High-Risk Frontend Change Triggers

Treat frontend changes as high-risk when they touch any of the following:

* login/logout flows
* signup/invite acceptance flows
* email verification
* forgot/reset password
* MFA setup/verify/recovery
* SSO start/callback/done flows
* session/bootstrap logic
* protected routes
* admin vs member landing logic
* settings/setup banners or setup-completion behavior
* SSR fetch wrappers
* `/api/*` route handling
* topology-sensitive or proxy-sensitive behavior

For these changes, be stricter than usual about review, docs, and validation.

---

## Topology-Sensitive Frontend Rules

This repo has load-bearing frontend topology rules.

Treat a frontend change as topology-sensitive if it affects:

* same-origin `/api/*` behavior
* SSR direct backend calls
* `INTERNAL_API_URL`
* forwarded `Host`, `Cookie`, or `X-Forwarded-*` behavior
* browser vs SSR cookie/session handling
* host-derived tenant assumptions
* auth callback or redirect flows

### Required Behavior For Topology-Sensitive Frontend Changes

* Do not treat browser requests and SSR requests as equivalent.
* Do not break forwarded-header expectations for SSR.
* Do not hardcode backend origins into browser code.
* Do not weaken host-derived tenant routing.
* Do not turn navigation-based auth flows into fetch-based approximations.

If you are touching one of these areas, use stricter review and stronger validation than usual.

---

## Validation Routing For Frontend Work

Run the smallest meaningful checks that prove the frontend area you changed.

### Typical frontend checks

* frontend typecheck
* frontend unit tests
* affected route/component checks

### For auth/session/topology-sensitive frontend changes

Also run the higher-confidence proof relevant to the flow, including stack or end-to-end validation when needed.

### For SSR-boundary changes

Be especially careful to validate the path that actually runs on the server, not only client-side behavior.

### Required Behavior

When reporting results, say what was actually run. Do not imply full-stack proof if you only reasoned about the UI.

---

## How To Work On Frontend Tasks

### For implementation

* start from the real route, layout, or shared boundary that owns the behavior
* preserve browser vs SSR correctness
* keep changes narrow and understandable
* avoid spreading auth/topology logic across many unrelated components

### For review

* inspect the real flow, not only the visible screen
* check routing, bootstrap, contract, and tenant implications
* distinguish blocker-level risk from cleanup advice

### For refactor

* preserve behavior first
* do not let convenience abstractions hide important route or topology assumptions
* be careful when moving logic between client and server contexts

---

## When To Escalate Review

Use stricter review when the frontend change affects:

* auth flows
* SSR/bootstrap behavior
* tenant or workspace context
* topology or proxy assumptions
* protected routes or session behavior
* settings/setup-state presentation that influences user routing or expectations
* operationally sensitive user journeys

If the change is high-risk, a generic UI skim is not enough.

---

## What Not To Do

* Do not treat this file as a general architecture doc.
* Do not duplicate the entire root `AGENTS.md` here.
* Do not hardcode backend origins in browser code.
* Do not let client-side state replace backend truth for auth or setup decisions.
* Do not treat placeholder UI as permanent system behavior.
* Do not claim frontend flow safety just because the screen renders.

---

## Final Position

This file is the frontend-specific instruction layer for repo-aware AI assistance and review.

Its job is to keep frontend work:

* correct across browser and SSR contexts
* aligned with backend truth
* topology-aware
* tenant-safe
* contract-aware
* validation-coupled
