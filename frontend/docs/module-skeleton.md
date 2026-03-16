# Frontend Module Skeleton

_Tier 1 — Global Stable_
_Applies to new and refactored frontend modules in this repository._

This document defines the **default shape** of a frontend module in Hubins.

It is the canonical structure that future modules should follow unless there is a clear reason not to.

Use this file when:

- creating a new frontend module
- reviewing whether a frontend module is becoming structurally messy
- deciding where a new page, component, or file belongs
- deciding whether logic belongs in a server page, client component, browser API layer, or shared contracts

Read this together with:

- `ARCHITECTURE.md`
- `frontend/src/shared/engineering-rules.md`
- `backend/docs/module-skeleton.md` — the backend counterpart to this document
- `docs/current-foundation-status.md`

---

## 1. Purpose of this document

This file exists to prevent two common failures:

**Under-structured modules**

- server pages doing client-side logic
- client components fetching data on mount when SSR could have resolved it
- browser-only API calls happening in server components
- contracts/types scattered across page files

**Over-structured modules**

- unnecessary abstraction layers for simple read/render flows
- client components wrapping things that have no interactivity
- duplicating backend auth/session truth in frontend state

The correct goal is: **the minimal structure that makes the module reliable, testable, and consistent with the locked topology.**

---

## 2. Canonical module directory structure

A frontend module typically spans two locations:

### Route surface — `frontend/src/app/<module>/`

Owns the Next.js App Router pages for the module.

```text
frontend/src/app/<module>/
├── page.tsx                     ← SSR entry, bootstrap gate, redirect logic
├── <sub-route>/
│   └── page.tsx
└── layout.tsx                   ← optional, only when sub-routes share shell
```

### Shared logic — `frontend/src/shared/<module>/`

Owns everything reusable across the module's pages.

```text
frontend/src/shared/<module>/
├── contracts.ts                 ← TypeScript types mirroring backend contracts
├── browser-api.ts               ← Browser-side API calls (same-origin /api/*)
├── redirects.ts                 ← Route path constants and navigation helpers
├── components/
│   ├── <module>-shell.tsx       ← Page shell/layout for module pages (optional)
│   ├── <feature>-form.tsx       ← Client form components (use client)
│   ├── <feature>-flow.tsx       ← Multi-step client flows (use client)
│   └── <feature>-display.tsx   ← Read-only display components (server-safe or client)
└── url-tokens.ts                ← Query param parsing helpers (optional)
```

---

## 3. What each file is for

### `app/<module>/page.tsx` — SSR entry page

Responsibilities:

- `export const dynamic = 'force-dynamic'` — always
- call `loadAuthBootstrap()` to resolve session + tenant state
- gate access: if bootstrap fails or route state is wrong, redirect or render error
- pass resolved server-side truth (e.g., `me`, `config`, initial data) as props to client components
- keep this file server-only — no `'use client'`

Must not:

- call browser-only APIs
- import `useRouter`, `useState`, `useEffect`
- make direct fetch calls except through `ssrFetch`
- contain business logic that belongs in the backend

**Pattern:**

```tsx
export const dynamic = 'force-dynamic';

export default async function ModulePage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return <ErrorView />;
  }

  if (bootstrap.routeState.kind !== 'AUTHENTICATED_MEMBER') {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  return (
    <Shell me={bootstrap.routeState.me}>
      <ModuleClientComponent />
    </Shell>
  );
}
```

---

### `shared/<module>/contracts.ts` — TypeScript contracts

Responsibilities:

- mirror the backend request/response shapes the module consumes
- define the TypeScript types used by both pages and components
- reference the backend source files these types mirror (in the file header comment)

Must not:

- invent frontend-only state shapes for auth/session/tenant data
- duplicate types that already exist in `frontend/src/shared/auth/contracts.ts`
- add speculative types for unimplemented backend behavior

---

### `shared/<module>/browser-api.ts` — Browser API layer

Responsibilities:

- wrap all browser-side API calls for the module
- use `apiFetch` from `@/shared/api-client` (same-origin `/api/*`)
- return structured `{ ok: true, data }` / `{ ok: false, error }` results
- mirror the `BrowserAuthResult<T>` pattern from `shared/auth/browser-api.ts`

Must not:

- call `INTERNAL_API_URL` directly — that is SSR-only
- be used in server components or SSR pages
- contain business logic, redirect logic, or UI state

---

### `shared/<module>/redirects.ts` — Route constants

Responsibilities:

- define all path string constants for the module's routes
- export navigation helpers if redirect logic is non-trivial
- stay in sync with the actual `app/<module>/` page paths

Must not:

- contain business logic
- import from server-only modules

---

### `shared/<module>/components/` — UI components

**Server-safe components** (no `'use client'`):

- display read-only data passed from server pages as props
- render static or SSR-resolved UI
- can use server-only APIs if needed

**Client components** (`'use client'` at top):

- own interactivity, form state, and browser-side API calls
- must not call `ssrFetch` — use `browser-api.ts`
- must not replicate backend auth/session truth — use what the server page resolved
- access gating must happen in the server page, not in client components

---

## 4. SSR vs client execution — the key decision

Before writing any new frontend file, answer this question:

**Does this logic run on the server during the initial request, or does it run in the browser after hydration?**

| Concern                          | Where it belongs                                   |
| -------------------------------- | -------------------------------------------------- |
| Access gate (is user logged in?) | Server page — `loadAuthBootstrap()` + `redirect()` |
| Initial data fetch               | Server page — `ssrFetch()`                         |
| Tenant/session truth             | Server page — comes from `bootstrap.routeState`    |
| Form state and submission        | Client component — `useState`, `browser-api.ts`    |
| Navigation after form success    | Client component — `useRouter().replace()`         |
| Error display for API failures   | Client component — `useState` for error            |
| Static content rendering         | Server page or server-safe component               |

---

## 5. Documentation coupling rules

These rules determine when documentation must be updated as part of a frontend module change.

### When to update `frontend/src/shared/engineering-rules.md`

- when a new frontend implementation rule is established
- when an existing rule changes

### When to update `backend/docs/api/<domain>.md`

- when the frontend module consumes a new or changed backend endpoint
- when the frontend's expected request/response shape changes

### When to update `docs/current-foundation-status.md`

- when a new frontend route or module surface ships and is real

### When to update `frontend/README.md`

- when the frontend's implemented surface changes materially

### When to create `docs/api/<module>.md` (new domain API doc)

- when a new backend domain ships and the frontend module is the first consumer

### When to add a module doc (`docs/modules/<module>/README.md`)

- opt-in only — only when the module has non-obvious complexity a new engineer could not infer from the skeleton and file headers

If a frontend page, component, or API layer changes and no documentation was updated, treat the change as incomplete unless the change is trivially internal with no contract or behavior implications.

---

## 6. Test expectations for frontend modules

Every frontend module must have coverage at the appropriate layer.

### Unit tests — `frontend/test/unit/`

Test pure logic that does not require a browser or a server:

- `contracts.ts` type guards or transformations (if any)
- `redirects.ts` helper functions
- any pure utility functions in `shared/<module>/`

### Component / integration tests

Currently not formalized in this repo. Snapshot or interaction tests for complex client components are acceptable where the behavior is non-trivial.

### E2E tests — `frontend/test/e2e/`

Test the full user flow from browser through Next.js through mock backend:

- happy path for every main module flow
- continuation/redirect behavior for authenticated routes
- error states that users would actually encounter

**Every new module with interactive flows must add at least one E2E test file.**

The E2E tests run against the mock backend (`test/e2e/mock-auth-backend.mjs`). If the new module introduces new API calls, the mock backend must be updated to handle them.

**Critical:** `playwright.config.mts` uses `workers: 1` and `fullyParallel: false` because tests share a single `next dev` server. Do not change this without understanding the concurrency implications.

---

## 7. Anti-patterns this skeleton is designed to prevent

### Anti-pattern 1 — Client-side auth gate

Checking session state in a client component instead of a server page. The user sees a flash of unauthorized content before being redirected.

### Anti-pattern 2 — SSR fetch in a client component

Importing `ssrFetch` or `INTERNAL_API_URL` into a client component. It will fail at runtime because these are server-only.

### Anti-pattern 3 — Duplicate bootstrap

Calling `loadAuthBootstrap()` in multiple server components in the same render tree. Bootstrap should be called once per page entry.

### Anti-pattern 4 — Business logic in contracts.ts

Adding computed fields, defaults, or transformation logic to `contracts.ts`. It is a type-only file. Transformation belongs in the component or browser-api layer.

### Anti-pattern 5 — Frontend-owned auth truth

Storing auth/session/tenant state in `useState`, `localStorage`, or a React context that exists independently of the backend session. The backend session is the source of truth.

### Anti-pattern 6 — Unguarded authenticated routes

An authenticated page that does not call `loadAuthBootstrap()` and redirect on failure. Every authenticated route must gate with bootstrap or an explicit SSR session check.

---

## 8. Module documentation update checklist

When shipping a new frontend module or making a significant change to an existing one, verify:

```text
[ ] Server pages use loadAuthBootstrap() and redirect correctly
[ ] Client components use browser-api.ts, not ssrFetch
[ ] contracts.ts mirrors the actual backend response shapes
[ ] redirects.ts is up to date with actual app/* paths
[ ] Unit tests cover pure logic
[ ] E2E test covers at least the happy path
[ ] mock-auth-backend.mjs handles any new API routes the tests exercise
[ ] docs/current-foundation-status.md updated if new routes shipped
[ ] frontend/README.md updated if surface changed
[ ] backend/docs/api/<domain>.md accurate for the consumed API
```

---

## 9. Minimum viable module shape

For a simple authenticated module with one page and a few actions:

```text
frontend/src/app/<module>/
└── page.tsx                     ← SSR gate + bootstrap + render

frontend/src/shared/<module>/
├── contracts.ts                 ← backend response types
├── browser-api.ts               ← same-origin fetch wrappers
└── components/
    └── <module>-view.tsx        ← 'use client', owns interactivity
```

That is the minimum. Add `redirects.ts`, sub-routes, sub-components, and additional components only when the behavior genuinely requires them.

---

## 10. Final rule

The frontend skeleton exists to make building the next module predictable without making the codebase harder to reason about.

Structure should absorb genuine complexity.
Structure should not perform thoroughness theatre.
