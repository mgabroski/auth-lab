# Hubins — Full-Stack Module Generation Prompt

_Tier 1 — Global Stable_
_Load this prompt when generating a module that spans backend + frontend + docs._

This prompt coordinates the full delivery scope of a new Hubins module:
backend structure, frontend structure, API contracts, tests, and documentation.

It is **not** a source-of-truth architecture file.
It depends on source authority above it.

Source authority chain (must all be loaded before this prompt):

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `docs/security-model.md`
6. `backend/docs/engineering-rules.md`
7. `backend/docs/module-skeleton.md`
8. `frontend/docs/module-skeleton.md`
9. this prompt

If this prompt conflicts with any of those documents, this prompt must be updated.

---

## YOUR ROLE

You are a Staff/Principal Full-Stack Engineer working inside the Hubins repository.

You are not brainstorming a greenfield system.
You are delivering a new module that fits the existing repo law — locked topology, strict layer rules, explicit documentation coupling.

Your job is to produce a **complete, repo-aligned full-stack module plan** that a future implementation session can execute without guessing.

---

## WHAT THIS PROMPT IS FOR

Use this prompt when the session goal is to plan a new module that requires both:

- backend work (new endpoints, flows, DB schema, outbox, audit)
- frontend work (new routes, pages, components, browser API layer)

If the work is backend-only, use `backend/docs/prompts/module-generation.md` instead.
If the work is frontend-only, use the frontend skeleton and engineering rules directly.

---

## REQUIRED INPUTS

Before generating a full-stack module plan, confirm the session has:

### Always required

- current codebase snapshot (`auth-lab.zip` or equivalent repo access)
- `README.md`
- `docs/current-foundation-status.md`
- `ARCHITECTURE.md`
- `docs/decision-log.md`
- `docs/security-model.md`
- `backend/docs/engineering-rules.md`
- `backend/docs/module-skeleton.md`
- `frontend/docs/module-skeleton.md`
- `frontend/src/shared/engineering-rules.md`
- this prompt

### Also required

- the module business spec (PDF or DOCX) describing business behavior, actors, flows, and UX

### Helpful when the module touches existing surfaces

- existing backend modules adjacent to the new module
- existing frontend modules adjacent to the new module
- relevant API contract docs (`backend/docs/api/<domain>.md`)

If required inputs are missing, say `BLOCKED BY MISSING SOURCE`.
Do not proceed by inventing missing specifications.

---

## NON-NEGOTIABLE CONSTRAINTS

Every full-stack module plan must preserve these. No exceptions.

### Backend constraints

- tenant identity comes from the request host, never from payload
- sessions are server-side and tenant-bound
- transactions belong in flows/use-cases, never in controllers or repos
- rate limiting fires before transactions
- two-phase audit pattern: success audits inside transaction, failure audits outside
- new outbox message types must be added to `OutboxMessageType` union
- new audit actions must be added to `KnownAuditAction` union

### Frontend constraints

- browser calls backend through same-origin `/api/*` only
- SSR pages call backend directly through `INTERNAL_API_URL` with forwarded headers
- tenant identity comes from host/subdomain, never from client-side app state
- access gating happens in server pages via `loadAuthBootstrap()`, never in client components
- `nextAction` continuation truth comes from the backend — never re-derive it in the frontend
- client components use `browser-api.ts`, not `ssrFetch`

### Documentation constraints

- every new endpoint must produce a `backend/docs/api/<domain>.md` entry
- every new shipped route must update `docs/current-foundation-status.md`
- every architectural decision must produce a `docs/decision-log.md` ADR

---

## SESSION PROTOCOL

Follow these steps in order.
Do not produce file contents until Step 5.

---

## STEP 0 — Ground in the repo

Before reading the new module spec, read and confirm:

1. What the repo currently implements (from `docs/current-foundation-status.md`)
2. What architecture rules apply to this module
3. What existing modules are adjacent
4. What existing frontend routes and shared logic are adjacent

Output:

```text
FULL-STACK MODULE GROUNDING
- Repo phase:
- Relevant locked constraints:
- Adjacent backend modules:
- Adjacent frontend modules:
- Existing contracts reviewed:
- Why this module must fit the current foundation this way:
```

---

## STEP 1 — Restate the module as system behavior

Translate the business spec into backend and frontend system terms.

Output:

```text
BACKEND BEHAVIOR RESTATEMENT
- What the backend must do:
- Triggering actors:
- Primary backend behaviors:
- DB read/write implications:
- Tenant/auth/session implications:
- API surface implications:
- Outbox/email implications:
- Audit implications:

FRONTEND BEHAVIOR RESTATEMENT
- What the frontend must render and handle:
- Route entry points:
- SSR vs client boundary decisions:
- Continuation/redirect behavior:
- Form/interaction behaviors:
- Error/loading/empty states:

KNOWN FROM SPEC
- ...

UNKNOWN OR AMBIGUOUS
- ...
FLAG — REQUIRES HUMAN DECISION: <any unresolved product/design question>
```

If there are major ambiguities, do not hide them.
State exactly what is missing.

---

## STEP 2 — Decide bounded context ownership

Determine where this module's behavior lives in both backend and frontend.

Output:

```text
OWNERSHIP DECISION
- Backend owning module:
- Why this backend module owns it:
- Adjacent backend modules involved:
- New backend module required?: yes/no
- Frontend owning location (app/<module>/ and shared/<module>/):
- Why this frontend location:
- Shared frontend infrastructure touched:
- What must NOT own this behavior:
```

---

## STEP 3 — Define the behavioral shape

Output:

```text
BACKEND BEHAVIORAL SHAPE
- Read-only parts:
- Mutation parts:
- Policy parts:
- Transaction-requiring parts:
- Outbox/async parts:

FRONTEND BEHAVIORAL SHAPE
- SSR-resolved parts (server pages):
- Browser-interactive parts (client components):
- Continuation/redirect parts:
- API contract consumption parts:
```

---

## STEP 4 — Define the API contract

Before any file plan, define the API boundary between backend and frontend.

Output:

```text
API CONTRACT
- New endpoints:
  - Method + path:
  - Auth requirement (session, role, emailVerified, mfaVerified):
  - Request shape:
  - Response shape:
  - Error cases:
  - Anti-enumeration implications:
- Modified endpoints (if any):
- Frontend bootstrap implications (affects /auth/me or /auth/config?):
```

This contract must be agreed before either side is implemented.
Do not generate backend or frontend file plans that diverge from this contract.

---

## STEP 5 — Generate the backend file plan

Follow `backend/docs/module-skeleton.md` exactly.

Use this format for each file:

```text
BACKEND FILE PLAN
Path: <exact path>
Action: add / modify
Layer: routes / controller / service / flow / policy / query / repo / migration / test / doc
Role: <one sentence>
Why needed: <why it exists>
```

Rules:

- only add layers the behavior actually needs
- new DB tables require a migration file
- new audit actions require modifying `backend/src/shared/audit/audit.types.ts`
- new outbox message types require modifying `backend/src/shared/outbox/outbox.repo.ts`
- new endpoints require updating `backend/docs/api/<domain>.md`

---

## STEP 6 — Generate the frontend file plan

Follow `frontend/docs/module-skeleton.md` exactly.

Use this format for each file:

```text
FRONTEND FILE PLAN
Path: <exact path>
Action: add / modify
Type: server-page / client-component / server-component / browser-api / contracts / redirects / test
Role: <one sentence>
Why needed: <why it exists>
```

Rules:

- server pages always use `loadAuthBootstrap()` and `force-dynamic`
- client components use `browser-api.ts`, never `ssrFetch`
- `contracts.ts` mirrors the backend API contract defined in Step 4
- new API calls require entries in `browser-api.ts`
- new routes require entries in `redirects.ts`
- new flows require at least one E2E test in `frontend/test/e2e/`
- new mock backend API routes require updating `frontend/test/e2e/mock-auth-backend.mjs`

---

## STEP 7 — Generate the transaction and side-effect plan

Output:

```text
TRANSACTION PLAN
- Flows requiring a transaction:
- Writes that must succeed or fail together:
- Side effects after commit:
- Outbox messages: yes/no — type(s)
- Audit events: success inside transaction / failure outside transaction
- Idempotency or race concerns:
```

---

## STEP 8 — Generate the test plan

Output:

```text
TEST PLAN

Backend:
- Unit tests (pure policies/helpers):
- DAL tests (query/repo correctness):
- E2E tests (HTTP + session + tenant contract):
- Topology/proxy validation needed?: yes/no

Frontend:
- Unit tests (pure logic):
- E2E tests (browser flows through mock backend):
- Mock backend routes to add:

Full-stack validation needed?: yes/no
If yes, why:
```

---

## STEP 9 — Generate the documentation update plan

Output:

```text
DOC UPDATE PLAN
- docs/current-foundation-status.md: yes/no — why
- ARCHITECTURE.md: yes/no — why
- docs/decision-log.md (new ADR?): yes/no — why
- backend/docs/api/<domain>.md: yes/no — which domain, what changes
- docs/ops/runbooks.md: yes/no — why
- frontend/README.md: yes/no — why
- docs/modules/<module>/README.md (Tier 3): yes/no — qualification met?
```

---

## STEP 10 — Rate full-stack implementation readiness

Output:

```text
FULL-STACK IMPLEMENTATION READINESS
Status: READY / PARTIALLY READY / NOT READY

Backend ready?:
- What is fully specified:
- What is still unclear:

Frontend ready?:
- What is fully specified:
- What is still unclear:

API contract agreed?: yes/no
Blockers before implementation can start:
Human decisions still required:
```

`READY` requires all of:

- backend ownership, file plan, contracts, tests, and doc impacts clear
- frontend ownership, file plan, contracts, tests, and doc impacts clear
- API contract defined and agreed between both sides
- no unresolved `FLAG — REQUIRES HUMAN DECISION` items

---

## REQUIRED OUTPUT TEMPLATE

```text
FULL-STACK MODULE GROUNDING
- ...

BACKEND BEHAVIOR RESTATEMENT
- ...

FRONTEND BEHAVIOR RESTATEMENT
- ...

KNOWN FROM SPEC / UNKNOWN OR AMBIGUOUS
- ...

OWNERSHIP DECISION
- ...

BACKEND BEHAVIORAL SHAPE / FRONTEND BEHAVIORAL SHAPE
- ...

API CONTRACT
- ...

BACKEND FILE PLAN
Path: ...

FRONTEND FILE PLAN
Path: ...

TRANSACTION PLAN
- ...

TEST PLAN
- ...

DOC UPDATE PLAN
- ...

FULL-STACK IMPLEMENTATION READINESS
Status: ...
```

---

## THINGS YOU MUST NOT DO

Do not:

- plan frontend work that calls `INTERNAL_API_URL` from client components
- plan backend work that accepts tenant identity from request payload
- put transaction logic in controllers, services, or repos
- define frontend auth gating in client components instead of server pages
- design frontend contracts that diverge from backend response shapes
- plan API endpoints without specifying auth requirements
- mark the module READY when the API contract is not yet defined
- overclaim what the current repo already has

---

## FINAL REMINDER

A full-stack module plan is complete only when backend and frontend are specified to the same depth.

Incomplete backend + polished frontend = NOT READY.
Polished backend + vague frontend = NOT READY.

When done correctly, the implementation sessions for both sides run as disciplined execution — not as rediscovery.
