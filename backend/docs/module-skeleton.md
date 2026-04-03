# Backend Module Skeleton

## Purpose

This file defines the standard backend module shape for work in this repo.

Use it when creating or reviewing backend functionality so the result stays:

- boundary-correct
- contract-correct
- tenant-aware
- auth-aware
- transaction-safe
- audit-aware
- easy for engineers and AI to navigate

This file does not replace:

- `AGENTS.md`
- `backend/AGENTS.md`
- `backend/docs/engineering-rules.md`
- relevant backend API docs

Read those first.

---

## Core Rule

A normal backend module should follow the established backend pattern.

Do not invent a new backend architecture per module.
Do not create new layers, folders, or wiring conventions unless the repo-level architecture truly changed.

If a module needs a new cross-cutting pattern, that is an architecture decision, not a normal module-generation choice.

---

## Default Backend Shape

A normal backend module should use the existing backend structure and separate concerns cleanly.

Typical pieces may include:

- route registration
- controller or handler entry
- service-layer behavior
- repository / DAL behavior
- validators, schemas, or DTO shaping as needed
- tests at the correct level

Use the repo’s existing names and placement rules.
Do not add extra ceremony where the existing pattern already works.

---

## Ownership Rules

### Backend owns truth for:

- request validation
- response shape and status codes
- auth and session truth
- tenant and membership truth
- next-action truth
- audit side effects
- durable state transitions

### Frontend does not own these meanings

Frontend may render and route from backend outcomes, but it must not become the hidden owner of backend contract meaning.

---

## Contract Rules

If a backend module exposes HTTP behavior, it must be represented in the active domain contract system:

- `backend/docs/api/<domain>.md`

Do not create or reference a generic `docs/api/<module>.md` pattern.
The active contract pattern is domain-owned backend API docs under `backend/docs/api/`.

If the module changes an endpoint, request shape, response shape, behavior note, or status-code meaning, update the relevant backend API doc in the same PR.

---

## Backend Module Checklist

Before creating or changing a backend module, answer these:

1. Which bounded area or module should own this behavior?
2. Which existing module/layer should it live in?
3. Is the change synchronous, asynchronous, or both?
4. Does it affect auth, session, tenant, invite, MFA, SSO, or audit behavior?
5. What is the correct request/response contract?
6. What state change actually occurs?
7. What tests prove the behavior at the right level?
8. Which docs must be updated in the same PR?

If these answers are unclear, stop and reload the relevant repo law before coding.

---

## Recommended Backend Shape

Exact file names may vary by domain, but a normal backend feature should usually map to a shape like this:

```text
module/
  route registration
  handler/controller entry
  service logic
  repository / DAL logic
  schemas / validation if needed
  tests near the changed behavior or in the established backend test structure
```

Keep each file honest about what it owns.
Do not collapse all behavior into one oversized service file just because it feels faster.

---

## Shared Code Rules

Promote logic into shared backend code only when it is:

- genuinely cross-cutting
- stable enough to deserve shared ownership
- not carrying hidden assumptions from one feature

Good candidates:

- shared request context patterns
- shared auth/session helpers already part of repo law
- shared audit helpers
- stable validation or domain utilities

Bad candidates:

- feature-specific branching hidden as "helper" code
- DAL shortcuts that bypass module ownership
- shared abstractions built only to avoid writing one more explicit file

---

## Audit And Side-Effect Rules

Treat these with extra care:

- invite lifecycle
- email verification
- password reset
- MFA
- SSO
- admin actions
- outbox/email behavior
- membership activation/suspension

If a backend change affects any of these, check explicitly:

- contract meaning
- audit behavior
- side-effect timing
- retry or sequencing implications
- test coverage depth
- doc coupling

Do not assume a “small refactor” is small if it changes one of these flows.

---

## Data And Migration Rules

If a backend change affects persistence:

- keep schema meaning explicit
- keep migration behavior explicit
- update fixtures/tests that rely on old meaning
- do not bury data-shape change inside unrelated feature work

If a change affects current seeded assumptions, also update:

- `docs/developer-guide.md`
- `docs/qa/qa-execution-pack.md`

when those docs depend on the changed state.

---

## Testing Rules

Choose the smallest meaningful proof that matches the risk.

### Usually enough

- backend unit tests
- repository / integration tests
- API or E2E tests for changed endpoint behavior

### Stronger proof required

Use stronger proof when the change affects:

- auth/session behavior
- tenant resolution
- invites
- MFA
- SSO
- audit flow behavior
- outbox/email behavior
- proxy/header-sensitive behavior
- migrations or state transitions

Do not claim high confidence from isolated unit tests when the real behavior depends on the full flow.

---

## Documentation Coupling

A backend PR must update the right docs in the same change when it affects:

- endpoint contract -> relevant `backend/docs/api/*.md`
- backend law or generation pattern -> `backend/docs/engineering-rules.md` or this file
- shipped current-state truth -> `docs/current-foundation-status.md`
- operational recovery/support behavior -> relevant `docs/ops/*`
- QA-visible backend behavior -> relevant `docs/qa/*`
- architecture or cross-cutting design -> root law docs and decision log as needed

Do not create silent drift between backend code and backend truth.

---

## What Not To Create By Default

Do not create these unless the module genuinely needs them:

- per-feature README files
- feature-local architecture docs
- alternate API contract docs
- extra layers that repeat existing ones
- “shared” abstractions that only one feature uses
- background docs that duplicate file WHY headers or canonical law

If the module is normal, the code plus canonical docs are enough.

---

## Final Position

A backend module in this repo should be boring to place, explicit in ownership, and easy to review.

When in doubt:

- keep the structure aligned with repo law
- keep backend truth server-owned
- use domain API docs under `backend/docs/api/`
- update canonical docs instead of inventing side docs
