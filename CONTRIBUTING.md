# CONTRIBUTING.md

This repository is strict on structure, scope clarity, and documentation truthfulness.

Do not treat this as a generic "open a PR and figure it out later" codebase.
The foundation is intentional, and future modules depend on that foundation staying clean.

---

## 1. Read these documents before changing code

Read them in this order:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `docs/security-model.md`
6. `backend/docs/README.md`
7. `backend/docs/engineering-rules.md`
8. `backend/docs/module-skeleton.md`

If you are working on frontend code, also read:

9. `frontend/src/shared/engineering-rules.md`
10. `frontend/docs/module-skeleton.md`
11. `frontend/README.md`

If you are using an LLM to help implement a module, also read:

For **backend-only** modules:

12. `backend/docs/prompts/module-generation.md`
13. `backend/docs/prompts/implement.md`
14. `backend/docs/prompts/review.md`

For **full-stack** modules (backend + frontend + docs):

12. `docs/prompts/module-generation-fullstack.md`
13. `backend/docs/prompts/implement.md`
14. `backend/docs/prompts/review.md`

When **refactoring** existing backend code:

- `backend/docs/prompts/refactor.md`

Do not skip `docs/current-foundation-status.md`.
That file exists specifically to prevent contributors from confusing broader platform direction with shipped implementation.

---

## 2. The rules that are never optional

### 2.1 Do not overclaim readiness

If something is:

- planned
- partially wired
- documented as next work
- or represented only by a brief/spec

do not document or describe it as fully implemented.

### 2.2 Preserve the topology law

This repo is built around a load-bearing topology:

- browser → same-origin public host
- proxy → frontend/backend
- SSR → direct backend via `INTERNAL_API_URL`
- tenant identity → host/subdomain
- sessions → server-side cookies + Redis

Do not introduce changes that bypass that model casually.

### 2.3 Tenant identity never comes from payload

Tenant must not come from:

- request body
- query parameter
- frontend local storage
- ad hoc client headers

Tenant identity is routing-derived.

### 2.4 Keep layer responsibilities clean

At a minimum, preserve this shape:

- route registration → wiring only
- controller → HTTP parsing / response mapping
- service → narrow module facade
- flow / use case → business orchestration / transactions
- DAL / queries → persistence logic

Do not hide business orchestration inside route files or controllers.

### 2.5 Keep docs aligned with code

If you change:

- architecture shape
- topology assumptions
- public contracts
- module boundaries
- engineering rules

you must update the relevant docs in the same change.

### 2.6 Small, explicit, reversible changes

Prefer changes that are:

- narrow in scope
- easy to review
- easy to revert
- easy to verify against docs and tests

---

## 3. What this repo is today

Before contributing, understand the current phase:

- this repo already implements the topology and FE/BE communication foundation
- this repo already implements the backend Auth + User Provisioning surface
- this repo already implements the frontend Auth + User Provisioning route/UI surface for the current module scope
- the broader Hubins product is still future work beyond the current auth/provisioning slice

That means:

- topology, session, tenant, and request-context assumptions are already real
- the auth/provisioning UI is real and must be treated as shipped scope
- broader product expansion and later confidence hardening are still next-step work

Contribute accordingly.

---

## 4. Before opening a PR

Run the checks that actually exist today.

### Root

```bash
yarn lint
yarn fmt:check
yarn typecheck
yarn test
```

### Backend

```bash
cd backend
yarn typecheck
yarn test
```

### Frontend

```bash
cd frontend
yarn lint
yarn typecheck
yarn test:unit
```

Important:

- root `yarn typecheck` covers backend + frontend
- root `yarn test` runs both backend and frontend unit/E2E test suites
- frontend E2E (`yarn test:e2e`) runs Playwright against a local Next.js dev server — it requires the dev server to start, so allow extra time
- do not pretend broader gates exist if they do not

If your change touches topology, also validate the full stack:

```bash
yarn stack
yarn stack:test
```

---

## 5. When full-stack topology validation is required

Run the full stack and proxy conformance tests before merge if you changed:

- `infra/`
- proxy config
- request context logic
- session middleware
- cookie behavior
- SSO callback assumptions
- anything relying on forwarded headers or host preservation

Host-run mode is not enough for those changes.

---

## 6. Adding or changing backend behavior

Use the existing repo shape as defined in `backend/docs/module-skeleton.md`.

Typical path:

1. route registration
2. controller handler
3. service facade
4. flow / use case
5. repo / query / policy additions
6. tests
7. doc updates if the behavior changes a contract or rule

Do not collapse those concerns into one file just because the change looks "small."

---

## 7. Adding or changing frontend behavior

Frontend changes must follow `frontend/docs/module-skeleton.md` and preserve these rules:

- browser calls backend through relative same-origin `/api/*`
- SSR/server components call backend directly through `INTERNAL_API_URL` with forwarded headers
- no direct browser hardcoding of backend origin
- no client-side tenant selection logic
- access gating happens in server pages via `loadAuthBootstrap()`, not in client components
- auth bootstrap is built around backend truth (`/auth/me`, `/auth/config`), not UI guesses

Both `frontend/src/shared/engineering-rules.md` and `frontend/docs/module-skeleton.md` are required reading for frontend work.

---

## 8. When docs must be updated

Update docs when you change:

| What changed                                                    | Update these docs                          |
| --------------------------------------------------------------- | ------------------------------------------ |
| Current delivered scope                                         | `docs/current-foundation-status.md`        |
| Broader architecture direction or locked topology law           | `ARCHITECTURE.md`                          |
| Non-obvious technical decisions                                 | `docs/decision-log.md`                     |
| Security model, crypto primitives, rate limits, isolation rules | `docs/security-model.md`                   |
| Backend implementation rules                                    | `backend/docs/engineering-rules.md`        |
| Canonical backend module structure                              | `backend/docs/module-skeleton.md`          |
| Frontend implementation rules                                   | `frontend/src/shared/engineering-rules.md` |
| Canonical frontend module structure                             | `frontend/docs/module-skeleton.md`         |
| Repo entrypoint / commands / current state framing              | `README.md`                                |
| New or changed backend API endpoint                             | `backend/docs/api/<domain>.md`             |
| New operational failure mode                                    | `docs/ops/runbooks.md`                     |

If the code changed and the docs stayed silent, assume the change is incomplete until proven otherwise.

---

## 9. Using LLMs on this repo

LLM-assisted implementation is allowed and expected, but only under repo law.

That means:

- do not let the model invent architecture that contradicts the repo
- do not let the model add files that break the documented structure casually
- do not let the model overclaim what is implemented
- always anchor the session in the current repo + relevant docs
- review generated code against architecture and rule docs, not only against "it compiles"

### Which prompt to load

| Work type                              | Primary prompt                                |
| -------------------------------------- | --------------------------------------------- |
| Backend-only new module                | `backend/docs/prompts/module-generation.md`   |
| Full-stack new module (BE + FE + docs) | `docs/prompts/module-generation-fullstack.md` |
| Backend implementation session         | `backend/docs/prompts/implement.md`           |
| Backend refactor session               | `backend/docs/prompts/refactor.md`            |
| Backend review session                 | `backend/docs/prompts/review.md`              |

Always also load `docs/security-model.md` for any module touching access control, tenant isolation, or sensitive data.

---

## 10. What a good PR looks like

A good PR in this repo is:

- **truthful** — no fake readiness claims
- **scoped** — does one logical thing
- **aligned** — respects topology and layer rules
- **tested** — against the real checks that exist
- **documented** — if it changes behavior, contract, or architecture
- **reviewable** — another engineer can understand the change without reverse-engineering intent

A passing test suite does not automatically mean the change is architecturally correct.

---

## 11. Do not use this repo as precedent for shortcuts

If you find:

- a temporary smoke-test page
- a phase-specific simplification
- an intentionally incomplete frontend surface

do not use it as justification to introduce additional shortcuts.

This repo is in a controlled foundation phase.
Temporary structure must not become permanent entropy.

---

## 12. Default contribution mindset

Contribute as if the next module depends on this foundation remaining stable.

Because it does.
