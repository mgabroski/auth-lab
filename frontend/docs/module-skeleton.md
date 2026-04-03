# Frontend Module Skeleton

## Purpose

This file defines the standard frontend module shape for work in this repo.

Use it when creating or reviewing new frontend functionality so the result stays:

- route-correct
- contract-correct
- SSR-aware
- same-origin browser-safe
- easy for engineers and AI to navigate

This file does not replace:

- `AGENTS.md`
- `frontend/AGENTS.md`
- `frontend/src/shared/engineering-rules.md`
- backend API contract docs

Read those first.

---

## Core Rule

Frontend modules do not invent their own architecture.
They fit into the existing repo structure and derive behavior from backend contracts and shared frontend law.

If a new frontend area requires a new architectural pattern, that is not a normal module-generation decision.
That is a repo-level design decision and must be documented in the right law docs.

---

## Default Frontend Shape

A normal frontend feature should be built from these kinds of pieces only when needed:

- route/page entrypoint
- feature-specific UI components
- feature-specific hooks or helpers
- contract-facing API client usage
- tests close to the behavior being proved

Prefer small, obvious files over large feature blobs.
Do not create extra folders just to look "enterprise."

---

## Routing Rules

### Browser-side calls

Browser requests must use relative `/api/*` paths.
Do not hardcode browser calls to backend origins.

### SSR / server-side calls

SSR and server-side fetches must use the established server-side path and forwarding model already defined by repo law.
Do not flatten SSR and browser behavior into one generic helper if that weakens topology truth.

### Auth and protected routes

Frontend route behavior must reflect backend-owned auth truth.
Do not create frontend-only auth state machines for:

- session truth
- tenant truth
- membership truth
- next-action truth
- admin/member landing truth

---

## Contract Rules

Every frontend module that talks to backend behavior must align with the relevant backend contract docs.

Use:

- `backend/docs/api/auth.md`
- `backend/docs/api/invites.md`
- `backend/docs/api/admin.md`
- future domain docs under `backend/docs/api/<domain>.md`

Do not create or reference `docs/api/<module>.md`.
The active contract pattern in this repo is backend-owned domain docs under:

- `backend/docs/api/<domain>.md`

If a module exposes or depends on HTTP behavior, the matching backend API doc must be created or updated in the same PR.

---

## Frontend Module Checklist

Before creating a new frontend feature, answer these:

1. Which existing route owns this behavior?
2. Is this browser behavior, SSR behavior, or both?
3. Which backend contract doc defines the API behavior?
4. Which shared frontend rules already cover the pattern?
5. What is the smallest file set needed?
6. Which tests prove the behavior at the right level?
7. Which docs must be updated in the same PR?

If you cannot answer these quickly, stop and load the canonical docs again.

---

## Recommended File Pattern

Exact paths can vary by feature, but normal frontend work should usually map to a shape like this:

```text
feature/
  page or route entry
  feature component(s)
  feature hook/helper(s) if needed
  tests near the changed behavior
```

Use shared code only when behavior is truly shared.
Do not prematurely extract abstractions just because two files look similar.

---

## What Belongs In Shared Frontend Code

Promote logic into shared frontend code only when it is:

- reused across multiple features
- stable enough to deserve shared ownership
- not carrying one feature's hidden assumptions

Good candidates:

- route-safe UI primitives
- API-client wrappers already established by repo law
- shared auth bootstrap helpers already proven by the repo

Bad candidates:

- feature-specific redirect hacks
- feature-specific response shaping
- one-off loading logic
- UI state that only makes sense for one page

---

## Testing Rules

Choose the smallest meaningful proof that matches the risk.

### Usually enough

- unit or route-level tests for isolated UI logic
- contract-aware component tests for visible state handling

### Stronger proof required

Use broader proof when the change affects:

- auth routing
- redirects
- SSR/browser interaction
- cookies/session behavior
- protected routes
- invite / reset / verification / MFA / SSO flows

Do not claim full-flow confidence from shallow component tests.

---

## Documentation Coupling

A frontend PR must update the right docs in the same change when it affects:

- route behavior -> relevant API docs, shipped-truth docs, or review docs
- auth/setup/provisioning user-visible flow -> relevant QA docs
- shared frontend pattern -> `frontend/src/shared/engineering-rules.md`
- frontend generation pattern -> this file
- broader architecture or boundary behavior -> root law docs and decision log as needed

Do not create silent drift between UI behavior and repo docs.

---

## What Not To Create By Default

Do not create these unless the feature genuinely needs them:

- feature README files
- feature-local architecture docs
- alternate API contract docs
- one-off design-system layers
- large service folders for trivial UI behavior
- duplicate route helpers that compete with shared patterns

If a feature is normal, the code plus canonical repo docs are enough.

---

## Final Position

A frontend module in this repo should be boring to place, easy to read, and hard to misunderstand.

When in doubt:

- keep the file set small
- use backend-owned contract truth
- preserve browser vs SSR correctness
- update the canonical docs instead of inventing side docs
