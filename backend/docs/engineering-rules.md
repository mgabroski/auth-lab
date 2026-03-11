# Hubins Backend — Engineering Rules

_Tier 1 — Backend implementation law_  
_Applies to every backend bounded context in this repository._

This is the canonical backend implementation rules file.
If another backend-oriented document conflicts with this one, this file wins unless a higher repo-level document explicitly says otherwise.

Repo-level authority still sits above this file:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `backend/docs/engineering-rules.md`

Update this file when backend implementation law changes.
Do not update it for local exceptions or one-off preferences.

---

## How to use this document

Every rule has a number. Reference the number in PR reviews, comments, design discussions, and LLM sessions.

Example:

- `ER-19` — rate limiting must happen before opening the transaction
- `ER-41` — session mutations must happen after commit

Rules are grouped by concern.

### Severity markers

- **[HARD]** = correctness or security invariant. A violating PR is blocked.
- **[ARCH]** = architecture / boundary invariant. Overriding requires an ADR, not casual reviewer approval.
- unmarked = strong default rule. Exceptions are rare and must be explained in the affected file and review notes.

---

## 1. Scope of these rules

These rules apply to the backend code under:

- `backend/src/app/`
- `backend/src/modules/`
- `backend/src/shared/`

They govern:

- dependency direction
- module boundaries
- controller/service/flow responsibilities
- transaction ownership
- repo/query responsibilities
- request/session/tenant behavior
- testing expectations
- documentation alignment expectations for backend changes

These rules do **not** replace repo architecture docs.
They operationalize them.

---

## 2. Core principles

### ER-1 [ARCH] Backend code must preserve the locked topology model

The backend assumes:

- it sits behind a trusted reverse proxy boundary
- tenant identity is derived from host/subdomain
- browser traffic is same-origin via proxy
- SSR/server-side frontend code may call backend directly while forwarding request identity headers

No backend change may casually weaken these assumptions.

### ER-2 [ARCH] Tenant identity is routing-derived, never payload-derived

Tenant identity must not be sourced from:

- request body
- query string
- local storage assumptions
- ad hoc client-selected tenant headers

Backend logic must rely on request context / resolved tenant identity, not caller-provided tenant claims.

### ER-3 [ARCH] `src/shared/` is infrastructure-only

`backend/src/shared/` may contain:

- DB primitives
- HTTP/request primitives
- session primitives
- cache/redis primitives
- logging
- security infrastructure such as rate limiting
- generic utilities

It must not become a home for business logic that belongs to a bounded context.

### ER-4 [ARCH] Business behavior belongs to modules

Business logic must live under `backend/src/modules/<module>/`.
Do not hide module behavior in:

- `shared/`
- `app/`
- route registration files
- random utility files

### ER-5 Backend docs must stay truthful to the code

If backend behavior changes in a way that affects:

- implementation law
- module structure law
- auth API contract
- documented business/config behavior

then the corresponding backend docs must be updated in the same change.

---

## 3. Module boundary rules

### ER-6 [ARCH] Every bounded context lives under `src/modules/<module-name>/`

A backend module owns its:

- routes
- controller
- service
- flows/use-cases
- repo/query layer
- policies
- types
- errors
- tests associated with that module’s behavior

### ER-7 [ARCH] Module internals are private by default

Other modules must not reach into another module’s internals casually.
The default expectation is:

- behavior exposed for reuse should go through the target module’s public surface
- private helpers, internal flow functions, and internal persistence details stay private

### ER-8 [ARCH] Public module surfaces must be deliberate

If another module depends on a stable contract from a module, prefer exposing it through that module’s `index.ts` or another clearly intentional public surface.
Do not export everything “just in case.”

### ER-9 [ARCH] Pragmatic exception for narrow read-only contracts

This repo currently allows **narrow, read-only, explicitly justified cross-module imports** when all of the following are true:

- the import is not from a flow/service/controller
- it does not introduce behavioral coupling
- it is a stable type, error, or read-side contract
- exporting it through a public surface would add ceremony without improving clarity

This is an exception, not a default.
If such imports begin to spread or become unstable, elevate them to a public module surface or shared contract.

### ER-10 [ARCH] Cross-module writes and side effects must not bypass boundaries casually

Do not create hidden synchronous orchestration webs between modules.
If a module needs another module’s behavior:

- prefer the target module’s public surface
- or elevate the orchestration into a shared use case / explicit flow boundary
- or use async/outbox-based integration where appropriate

### ER-11 `modules/_shared/use-cases/` is for stable shared backend use cases only

A use case belongs there only when it is reused across multiple flows and represents a stable cross-module behavior worth centralizing.
Do not dump convenience code there.

---

## 4. Dependency direction rules

### ER-12 [ARCH] Dependency direction is strict

The intended dependency shape is:

```text
routes → controller → service → flow/use-case → queries/repos/policies
                                   ↓
                                shared/
```

Allowed notes:

- read-only services may delegate directly to query functions when no transaction or orchestration is needed
- any layer may import infrastructure from `shared/`

Forbidden:

- lower layers importing higher layers
- `shared/` importing from `modules/`
- queries importing services or flows
- repos importing controllers or services

### ER-13 [ARCH] `src/app/di.ts` owns concrete infrastructure wiring

Concrete class construction belongs in dependency assembly, not scattered through modules.
Modules receive dependencies; they do not construct infrastructure objects ad hoc.

### ER-14 `src/app/routes.ts` owns top-level route registration composition

Top-level app route composition belongs in app bootstrap.
Modules should expose route registration, not mutate app structure from random places.

### ER-15 No circular imports

If two modules or files need each other, the shared contract likely belongs in:

- a public module surface
- `modules/_shared/`
- or `shared/`

Do not “solve” circular imports with fragile runtime hacks.

### ER-16 No `any` to silence type problems

Do not use `any` as an escape hatch.
Use:

- `unknown`
- narrowing
- boundary parsing/validation
- carefully isolated casts with explanation when absolutely necessary

---

## 5. Layer responsibility rules

## 5.1 Routes

### ER-17 Routes register endpoints only

`<module>.routes.ts` files are wiring files.
They should:

- register paths
- bind controller handlers
- apply route-level metadata/config when needed

They must not own business logic.

### ER-18 Routes must not become hidden controllers

Do not place request parsing, conditional branching, or persistence logic in route registration files.
If the route file becomes “smart,” the layering is already slipping.

## 5.2 Controllers

### ER-19 Controllers are HTTP adapters

A controller’s responsibilities are:

- validate/parse request input
- enforce HTTP-context guards
- extract request metadata from request context
- call a service method
- map service results to HTTP responses

### ER-20 [HARD] Controllers must not own business orchestration

Controllers must not:

- access DB directly
- call query/repo functions directly
- write audit events directly
- hit rate limiters directly
- mutate sessions directly
- own transaction logic

### ER-21 Safe HTTP-context guards may live in controllers

Pure HTTP-context checks are allowed in controllers, such as:

- requiring tenant context to exist
- checking `returnTo` safety against open redirects
- asserting route param presence/shape when tied to HTTP behavior

These guards must remain:

- synchronous
- pure
- infrastructure-free

### ER-22 Controllers must not let raw validation library errors leak

Validation failures should be translated into the repo’s error model.
Do not expose raw Zod error payloads directly as your public error contract unless that is an intentional, documented API decision.

### ER-23 Controllers must pass request context explicitly

When backend behavior depends on request-derived values, controllers must pass them explicitly, such as:

- `tenantKey`
- `requestId`
- `ip`
- `userAgent`
- session/auth context identifiers

Do not let deeper layers “rediscover” HTTP state from globals or hidden imports.

## 5.3 Services

### ER-24 Services are module-facing facades

Services exist to provide a clean module-facing API to controllers and other approved callers.

### ER-25 Mutation services should stay thin

For mutation endpoints, the service should usually delegate to one flow/use case and return the result.
Do not make services a second orchestration layer when a flow already exists.

### ER-26 Read-only services may delegate directly to query functions

When a service method is purely read-only and does not require:

- transaction ownership
- audit coordination
- rate limiting
- multi-step orchestration

it may delegate directly to query functions.
This is a valid simplification, not a layering violation.

### ER-27 Services must not become persistence bags

If a service accumulates direct DB writes, transaction ownership, rate limiting, and audit behavior, it is no longer acting as a service facade. Extract a flow/use case.

## 5.4 Flows / use cases

### ER-28 [HARD] Flows own transactions

If a behavior needs a transaction, that transaction belongs in the flow/use-case layer.
Services, repos, and queries must not open transactions.

### ER-29 [HARD] Rate limiting happens before opening the transaction

Rejected requests must not open DB transactions first.

### ER-30 [HARD] Known transaction failures must be prepared for audit/failure handling

When the flow uses structured failure handling and audit trails, known domain failures inside the transaction should set the relevant failure context before throwing.
Do not rely on a generic catch block to guess what went wrong.

### ER-31 [HARD] Post-commit side effects happen after commit

Anything relying on committed DB truth must happen after the transaction commits, such as:

- session store mutations
- Redis/session/cache side effects that assume persisted state
- other external side effects that should not happen on rollback

### ER-32 Flows should end with explicit result integrity

If a flow expects a transaction result, guard against the impossible/null path explicitly rather than assuming it cannot happen.

## 5.5 Policies

### ER-33 Policies must be pure

Policy functions must be:

- synchronous
- side-effect free
- free of DB access
- free of HTTP access
- unit-testable without infrastructure

### ER-34 Policies decide logic, not data access

Policies operate on already-fetched input.
They do not fetch their own data.

### ER-35 Assertion and result variants are preferred for important policies

For important gatekeeping policies, prefer offering:

- a result/failure variant that helps structured flow handling
- an assertion variant when type narrowing or direct enforcement is useful

## 5.6 Queries

### ER-36 Queries are read-side functions

Queries shape database reads into backend/domain-friendly results.
They must not perform writes.

### ER-37 Queries return absence as data, not as transport error

If a record is not found, return `null` / empty result where appropriate.
Let flows/services decide what that absence means.

### ER-38 Queries accept a DB executor, not transaction ownership

Queries must work with either the root DB executor or a transaction executor passed in.
They do not start transactions.

## 5.7 Repos

### ER-39 Repos are write-side abstractions

Repo files should contain inserts, updates, deletes, and tightly related write helpers.
Do not mix large read models into repo files.

### ER-40 Repos must be transaction-friendly

Repo classes/functions must support being bound to a provided DB executor/transaction executor rather than secretly depending on one global connection.

### ER-41 Repos must not own business rules

Repos do persistence work.
They do not decide business policy, HTTP behavior, or audit meaning.

---

## 6. Transaction and side-effect rules

### ER-42 [HARD] Causally related writes belong in the same transaction

If two or more writes must succeed or fail together for correctness, they belong in the same transaction.

### ER-43 [HARD] External effects must not happen before transactional truth is secured

Do not send emails, mutate sessions, or perform external actions that assume success before the transaction commits, unless the design explicitly tolerates compensation and that decision is documented.

### ER-44 [HARD] Audit consistency matters

If a mutation flow is designed to write audit records for success/failure, the audit strategy must be explicit and ordered correctly relative to transaction boundaries.
Do not produce misleading success/failure trails.

### ER-45 Idempotency and race safety must be considered for write flows

Where flows may be retried, repeated, or raced, backend design must use the appropriate guard pattern:

- DB uniqueness constraints
- conditional updates
- atomic consume semantics
- explicit status transitions
- row-level locking only when truly justified

Do not trust happy-path sequencing alone.

---

## 7. Request, session, and tenant rules

### ER-46 [HARD] Request context is the source of request truth

Resolved host, tenant context, request ID, forwarded request info, and similar HTTP-derived truths belong in request context.
Do not recompute them differently in random modules.

### ER-47 [HARD] Session/auth context loading is shared infrastructure, not module trivia

Session resolution and auth context loading are load-bearing cross-cutting concerns.
Treat changes to them as architecture-sensitive.

### ER-48 [HARD] Session-tenant mismatch must fail closed

A valid session for tenant A must not authenticate the user on tenant B.
The default behavior is deny/ignore, not “try to make it work.”

### ER-49 Backend code must not trust caller-controlled tenant switching

Never let a request override resolved tenant identity through payload or convenience headers.

### ER-50 Trusted forwarded headers are only meaningful inside the locked topology

Backend code may rely on forwarded headers because this system is explicitly designed behind a trusted proxy boundary.
Do not cargo-cult that assumption into contexts where the proxy contract is absent.

---

## 8. Error and audit rules

### ER-51 Use the repo error model consistently

Backend code should raise and propagate errors through the repo’s established error model.
Do not invent ad hoc error payload styles per file.

### ER-52 Do not hide important failure reasons behind vague generic errors

Flows should preserve meaningful internal reason codes / contexts where the repo’s audit or reviewability depends on them.

### ER-53 Audit is part of behavioral correctness for sensitive flows

For sensitive backend behaviors such as auth, invite lifecycle, or admin actions, audit is not decorative logging.
It is part of the correctness story.

### ER-54 Logs are not audit records

Do not substitute ordinary logs for structured audit behavior.
They serve different purposes.

---

## 9. Testing rules

### ER-55 Every backend change must be proven at the right layer

Test at the layer where risk actually lives.
Examples:

- pure policy/helper logic → unit tests
- query/repo correctness → integration/DAL tests
- HTTP contract + middleware + request/session behavior → E2E tests

### ER-56 Topology-sensitive backend changes need topology-aware validation

If a backend change touches:

- forwarded-header assumptions
- request context
- session/cookie interaction through proxy
- SSO callback behavior

then host-run testing alone is insufficient. Full-stack/proxy validation is required.

### ER-57 Readability matters in tests

Tests are executable behavioral proof.
Do not make them so abstract or overly clever that they stop explaining intent.

---

## 10. Documentation alignment rules

### ER-58 Backend doc updates are part of backend completion

A backend change is incomplete if it changes backend law, contract, or documented behavior but leaves the relevant docs stale.

### ER-59 Prompt docs must be kept in sync with backend law

`backend/docs/prompts/*.md` are derived execution artifacts.
If backend engineering law or canonical module structure changes, prompt docs must be updated too.

### ER-60 Do not document future backend shape as present fact

If something is planned, partial, or next-step work, say so clearly.
This is especially important in a foundation-phase repo.

---

## 11. Review checklist for backend PRs

When reviewing backend code, ask these in order:

1. Does it preserve the locked topology and tenant model?
2. Does it respect module boundaries?
3. Is dependency direction clean?
4. Is the layer ownership correct?
5. If it writes, does the flow own the transaction?
6. Are side effects ordered correctly relative to commit?
7. Are audit and error behaviors coherent?
8. Are tests at the right layer?
9. Are docs updated if backend law/contract/behavior changed?
10. Is the implementation truthful, or is it hiding incompleteness behind polished wording?

If the answer to any of the first seven is “no,” the PR is not ready.

---

## 12. Final rule

### ER-61 The backend must stay easier to reason about than the business problem itself

If a change makes the backend feel harder to understand than the user or product behavior it implements, step back.
That usually means a boundary is wrong, a responsibility is misplaced, or hidden coupling is creeping in.

This repo is meant to grow from a stable foundation.
Keep it that way.
