# Hubins Frontend — Engineering Rules

_Tier 1 — Frontend implementation law_  
_Applies to frontend code in this repository._

This file defines the canonical frontend implementation rules for Hubins Auth Lab.

It exists to keep frontend work aligned with:

- the locked topology
- the backend bootstrap/auth contract
- tenant-aware routing
- the current foundation-first phase of the repo

This file is not a product brief.
It is frontend implementation law.

Repo-level authority still sits above this file:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `frontend/src/shared/engineering-rules.md`

If another frontend-oriented document conflicts with this one, this file wins unless a higher repo-level document explicitly says otherwise.

---

## How to use this document

Every rule has a number.
Reference rule numbers in PR reviews, comments, planning notes, and LLM-assisted frontend sessions.

Example:

- `FER-07` — browser code must use same-origin `/api/*`
- `FER-18` — tenant identity must be host-derived

### Severity markers

- **[HARD]** = correctness/security/topology invariant. A violating PR is blocked.
- **[ARCH]** = architectural invariant. Overriding requires a deliberate architectural decision, not casual reviewer approval.
- unmarked = strong default rule. Exceptions are rare and must be explained.

---

## 1. Scope of these rules

These rules apply to frontend code under:

- `frontend/src/app/`
- `frontend/src/shared/`
- any future frontend feature/module directories added to this repo

They govern:

- browser vs SSR API access
- tenant handling
- auth/bootstrap behavior
- route/state responsibilities
- interaction with backend truth
- documentation alignment for frontend changes

These rules exist because this repo is not a generic frontend app.
It is a topology-aware, tenant-aware, session-based frontend foundation.

---

## 2. Core frontend principles

### FER-1 [ARCH] The frontend must preserve the locked topology model

The frontend exists inside a specific architecture:

- browser traffic uses same-origin public host access
- the reverse proxy routes to frontend/backend
- SSR/server-side frontend code may call backend directly
- tenant identity is derived from host/subdomain
- sessions are cookie-based and server-side

Frontend code must not weaken these assumptions.

### FER-2 [ARCH] The frontend must not invent a different auth model than the backend

The backend owns:

- session truth
- tenant truth
- continuation truth (`nextAction`)
- public-safe tenant auth bootstrap truth

The frontend must reflect and consume that truth.
It must not create a parallel auth rules engine in UI code.

### FER-3 [ARCH] Current repo phase matters

This repo is still in the frontend foundation phase.
That means:

- some real frontend infrastructure exists already
- many auth/product screens are still next-step work

Frontend code and docs must be truthful about that.
Do not describe planned UI behavior as shipped behavior.

### FER-4 Frontend structure should absorb complexity, not create ceremony

Do not add architecture theatre.
Only introduce frontend layers or abstractions when they clarify real responsibilities.

---

## 3. Browser vs SSR communication rules

### FER-5 [HARD] Browser code must call backend through same-origin relative paths

Browser-side code must use paths like:

```text
/api/*
```

Examples:

- `/api/auth/config`
- `/api/auth/me`
- `/api/auth/login`

Do not hardcode browser requests to a direct backend origin.

### FER-6 [HARD] Browser code must not bypass the proxy contract

Do not introduce:

- `http://localhost:3001/...` in browser code
- environment-variable-driven public backend origins in browser code
- frontend-side CORS-style architecture workarounds that bypass the intended topology

The browser path is same-origin through the proxy.

### FER-7 [ARCH] SSR/server-side code may call backend directly through `INTERNAL_API_URL`

This is allowed only from server-side frontend code.
It is not a browser pattern.

### FER-8 [HARD] SSR backend calls must forward request identity correctly

When server-side frontend code calls the backend directly, it must forward the request identity data needed by the backend to preserve:

- tenant resolution
- session continuity
- request fidelity

At minimum, this includes the relevant request headers such as:

- `Host`
- `Cookie`
- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`

### FER-9 SSR and browser access patterns must remain explicit

Do not blur browser and SSR access behind abstractions that make it unclear:

- where the code runs
- whether direct backend access is allowed
- whether forwarded request identity is required

A reviewer should be able to tell whether a fetch path is browser-side or server-side.

---

## 4. Tenant handling rules

### FER-10 [HARD] Tenant identity is host-derived

The frontend must treat the current host/subdomain as the tenant context.

### FER-11 [HARD] The frontend must not source tenant from app state or payload

Do not derive tenant identity from:

- local storage
- query params
- arbitrary client-side state
- request body fields
- user-selected headers

### FER-12 [ARCH] Tenant-aware behavior must follow the current host

UI decisions that depend on tenant context must use backend/bootstrap truth or current host-derived context.
The frontend must not try to become a tenant router independent of the URL.

### FER-13 Frontend docs and examples must use tenant-aware local URLs

When documenting local development or QA behavior, prefer tenant-aware examples like:

```text
http://goodwill-ca.localhost:3000
```

or in full-stack mode:

```text
http://goodwill-ca.lvh.me:3000
```

Avoid examples that accidentally hide the host-based tenant rule.

---

## 5. Auth/bootstrap rules

### FER-14 [ARCH] `/auth/config` is the public bootstrap truth source

Before authentication, the frontend should use backend truth from `GET /auth/config` for decisions such as:

- whether the tenant is effectively available
- whether public signup should be shown
- which SSO providers should be shown

Do not hardcode those assumptions in the frontend.

### FER-15 [ARCH] `/auth/me` is the authenticated bootstrap truth source

After a session exists, the frontend should use backend truth from `GET /auth/me` for decisions such as:

- current user identity
- current tenant identity
- membership role
- session continuation state
- `nextAction`

### FER-16 [HARD] The frontend must trust backend continuation truth

The frontend must not reimplement or guess continuation logic that the backend already returns.
Specifically, `nextAction` is authoritative for deciding whether the user must continue into:

- email verification
- MFA setup
- MFA verification
- or no continuation flow

### FER-17 [HARD] The frontend must not assume “session exists = app shell access”

A user may have a valid session and still need continuation work.
Frontend routing/UX must respect continuation state instead of assuming every authenticated session goes directly to the app shell.

### FER-18 Auth/bootstrap state belongs in explicit frontend state, not scattered heuristics

When the real auth/bootstrap layer is implemented, its state must be driven from backend truth and managed explicitly.
Do not spread auth rules across random components.

---

## 6. Route and screen responsibility rules

### FER-19 Routes should reflect user state categories clearly

As the frontend grows, routes/screens should clearly distinguish between:

- public pages
- authenticated pages
- continuation pages
- admin/privileged pages

Do not collapse all of those states into one ambiguous page flow.

### FER-20 A route guard is not a business rules engine

Future route guards may enforce coarse access categories such as:

- unauthenticated
- authenticated
- continuation required
- admin-only

They must not become the place where backend truth is re-derived from scratch.

### FER-21 Screens should consume backend truth, not own it

A screen may render the result of backend truth.
It should not become the origin of auth/tenant/security truth.

### FER-22 Temporary smoke-test pages must be treated as temporary

A foundation smoke-test page is acceptable during this phase.
It must not become a permanent justification for loose structure later.

---

## 7. API client rules

### FER-23 Browser and SSR clients should remain separate where execution model differs

It is correct for this repo to have distinct frontend wrappers for:

- browser API access
- SSR/server-side API access

Do not force them into one abstraction if doing so hides crucial execution differences.

### FER-24 Shared client utilities must stay honest about execution environment

If a utility works only on the server, its design and usage should make that obvious.
If a utility is browser-safe, it should not depend on server-only assumptions.

### FER-25 Frontend API wrappers must preserve backend contract clarity

The wrapper layer must not distort backend request/response meaning so heavily that reviewers can no longer tell what backend contract is being consumed.

---

## 8. UI state and data rules

### FER-26 Frontend state should be derived from authoritative backend truth when that truth exists

Do not create duplicate client-side sources of truth for:

- session/auth state
- tenant availability
- SSO availability
- continuation requirements

### FER-27 Client caching must not weaken correctness

As the frontend grows, avoid caching patterns that cause tenant/auth/bootstrap truth to become stale or misleading in sensitive flows.

### FER-28 Prefer explicit loading/error/empty states over hidden assumptions

When a frontend screen depends on backend bootstrap state, render that dependency explicitly instead of pretending state is already known.

---

## 9. Security and privacy rules

### FER-29 [HARD] The frontend must not expose or persist secrets that the backend intentionally protects

Do not move sensitive auth/session data into browser storage just to simplify UI logic.

### FER-30 [HARD] The frontend must preserve privacy/anti-enumeration posture

If the backend intentionally returns privacy-preserving generic shapes or messages, the frontend must not undermine that by adding side channels or contradictory UI assumptions.

Examples:

- tenant unavailable behavior
- forgot-password generic success
- resend-verification generic success

### FER-31 [HARD] The frontend must not leak tenant/security assumptions through shortcuts

Avoid UI patterns that effectively expose internal tenant rules that the backend deliberately keeps private.

---

## 10. Documentation and truthfulness rules

### FER-32 Frontend docs must distinguish current foundation from future UI work

If a frontend capability is:

- planned
- partially wired
- described in a readiness brief
- not actually built yet

then docs must say so clearly.

### FER-33 Frontend docs must stay aligned with backend bootstrap contract

If `/auth/config` or `/auth/me` behavior changes materially, frontend docs and implementation guidance must be updated.

### FER-34 Prompt/readiness docs are derived artifacts, not source authority

Files like the frontend readiness brief or future implementation prompts must reflect repo law.
They must not silently override it.

---

## 11. Review checklist for frontend PRs

When reviewing frontend changes, ask these in order:

1. Does this preserve the same-origin browser rule?
2. Does SSR-only backend access remain server-only and correctly forwarded?
3. Is tenant identity still host-derived?
4. Does the change trust backend bootstrap/auth truth instead of duplicating it?
5. Does it avoid weakening privacy/anti-enumeration posture?
6. Is the structure honest for the current repo phase?
7. Are docs updated if frontend behavior or contract assumptions changed?

If the answer to any of the first five is “no,” the PR is not ready.

---

## 12. Final rule

### FER-35 The frontend must stay easier to reason about than the auth flow it implements

If a frontend change makes auth/bootstrap/tenant behavior feel harder to understand than the business flow itself, step back.
That usually means:

- too much hidden state
- duplicated backend truth
- execution environment confusion
- or a broken boundary between browser and SSR responsibilities

The current frontend foundation is meant to make the real auth UI safer to build.
Keep it that way.

---

## 13. Module structure rules

### FER-36 [ARCH] New frontend modules follow the canonical module skeleton

Every new frontend module must follow the structure defined in `frontend/docs/module-skeleton.md`.

The skeleton defines:

- where server pages live (`frontend/src/app/<module>/`)
- where shared logic lives (`frontend/src/shared/<module>/`)
- what each file type is responsible for
- which concerns are server-only vs client-only

Do not invent a different structure for a new module without first updating the skeleton.

### FER-37 [HARD] Server pages own access gating. Client components do not.

Every authenticated route must call `loadAuthBootstrap()` in the server page and redirect if access is not allowed.

Client components must never gate access based on auth state they derive themselves.
A client component may display conditional UI based on props passed from the server page, but it must not own the redirect decision.

### FER-38 [HARD] Client components use browser-api.ts. Server pages use ssrFetch.

The execution environment determines the API layer:

- `browser-api.ts` → client components → same-origin `/api/*`
- `ssrFetch` → server pages/components → `INTERNAL_API_URL` with forwarded headers

Mixing these is always wrong. A client component that calls `ssrFetch` will fail at runtime.

### FER-39 contracts.ts must mirror backend shapes, not invent frontend shapes

`contracts.ts` in a frontend module must define TypeScript types that mirror actual backend response shapes.

Types must reference the backend source file they mirror (in a comment).
Do not add computed fields, defaults, or transformed shapes to `contracts.ts`.

---

## 14. Documentation coupling rules

These rules define when frontend documentation must be updated. They are as binding as the code rules above.

### FER-40 [ARCH] New routes must update docs/current-foundation-status.md

When a new frontend route or module surface ships and is real (not planned, not partially wired — actually shipped), `docs/current-foundation-status.md` must be updated in the same PR.

### FER-41 [ARCH] Changed frontend behavior must update frontend/README.md

When the frontend's implemented surface changes materially — new routes, removed routes, changed bootstrap behavior — `frontend/README.md` must reflect the new reality in the same PR.

### FER-42 New frontend API consumption must align with backend/docs/api/<domain>.md

When a frontend module begins consuming a backend domain's API, the corresponding `backend/docs/api/<domain>.md` must be accurate and up to date.

If a frontend change reveals a drift between the API doc and actual backend behavior, fix the API doc in the same PR.

### FER-43 New frontend modules require at least one E2E test

Every new frontend module with interactive flows must ship with at least one Playwright E2E test file in `frontend/test/e2e/`.

The E2E test must cover the happy path through the full browser → Next.js → mock backend flow.

If the module introduces new API routes, `frontend/test/e2e/mock-auth-backend.mjs` must be updated to handle them.

### FER-44 [ARCH] Frontend engineering rule changes must be propagated to module-generation prompts

If this file changes in a way that affects how new modules should be structured or reviewed, the relevant LLM prompts must be updated in the same PR:

- `docs/prompts/module-generation-fullstack.md`
- `frontend/docs/module-skeleton.md`

A rule change that silently obsoletes a prompt is a documentation defect.
