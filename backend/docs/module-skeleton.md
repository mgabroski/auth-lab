# Backend Module Skeleton

_Tier 1 — Canonical backend module structure_  
_Applies to new and refactored backend modules in this repository._

This document defines the **default shape** of a backend bounded context in Hubins.
It is not a rigid requirement that every module must contain every possible file.
It is the canonical structure that future modules should follow unless there is a clear reason not to.

Use this file when:

- creating a new backend module
- reviewing whether a module is becoming structurally messy
- deciding where a new file belongs
- deciding whether logic belongs in a flow, policy, query, repo, or shared primitive

Read this together with:

- `backend/docs/engineering-rules.md`
- `docs/current-foundation-status.md`
- `ARCHITECTURE.md`

---

## 1. Purpose of this document

This file exists to prevent two common failures:

1. **Under-structured modules**
   - controllers doing business logic
   - services becoming giant bags of everything
   - DB logic spread randomly across files

2. **Over-structured modules**
   - boilerplate layers with no real responsibility
   - tiny wrapper files that add indirection but no clarity
   - ceremony copied from architecture diagrams instead of from actual needs

The correct goal is:

**deep modules with clear boundaries and minimal accidental complexity**

That means:

- every layer has a job
- not every module needs every layer immediately
- once complexity appears, structure should absorb it cleanly

---

## 2. Canonical module directory

The default module lives under:

```text
backend/src/modules/<module-name>/
```

A mature module may contain files like this:

```text
backend/src/modules/<module-name>/
├── index.ts
├── <module-name>.module.ts
├── <module-name>.routes.ts
├── <module-name>.controller.ts
├── <module-name>.service.ts
├── <module-name>.types.ts
├── <module-name>.errors.ts
├── flows/
│   └── *.flow.ts
├── use-cases/
│   └── *.usecase.ts
├── policies/
│   └── *.policy.ts
├── queries/
│   └── *.query.ts
├── repos/
│   └── *.repo.ts
├── helpers/
│   └── *.ts
├── dto/
│   └── *.ts
└── constants/
    └── *.ts
```

This is the **full shape**, not the minimum shape.

A smaller module may begin with only:

```text
backend/src/modules/<module-name>/
├── index.ts
├── <module-name>.module.ts
├── <module-name>.routes.ts
├── <module-name>.controller.ts
├── <module-name>.service.ts
└── queries/
    └── *.query.ts
```

That is acceptable **if it is still honest and clean**.

---

## 3. What each top-level file is for

### `index.ts`

Public surface of the module.

Use it to expose:

- route registration
- public service or module factory exports
- stable types/errors/contracts intentionally meant for other modules

Do **not** re-export the whole module casually.
Exports should be deliberate.

---

### `<module-name>.module.ts`

Dependency assembly for the module.

Responsibilities:

- construct the module’s controller/service with dependencies
- wire internal module components together
- expose a clean module surface to app bootstrap

This file is where the module is assembled.
It is **not** where business logic lives.

---

### `<module-name>.routes.ts`

HTTP route registration for the module.

Responsibilities:

- register paths
- bind handlers
- attach route-level metadata/config if needed

This file must stay thin.
No business branching, DB access, or orchestration here.

---

### `<module-name>.controller.ts`

HTTP adapter layer.

Responsibilities:

- parse/validate requests
- perform HTTP-context-only guards
- extract request context values
- call service methods
- translate service results into HTTP responses

Controllers must not:

- access DB directly
- own transactions
- own audit writes
- mutate sessions directly
- become orchestration centers

---

### `<module-name>.service.ts`

Module-facing facade.

Responsibilities:

- provide a clean API to the controller
- delegate mutations to flows/use cases
- delegate simple reads to queries when appropriate
- keep module entrypoints readable

Services should usually stay thin.
If a service becomes a large bag of orchestration and persistence, extract flows/use cases.

---

### `<module-name>.types.ts`

Module-scoped shared types.

Use for:

- service input/output shapes
- internal typed contracts reused across module files
- DTO/result shapes that belong to the module

Do not use this as a dumping ground for unrelated types.

---

### `<module-name>.errors.ts`

Module-specific error classes, codes, or error helpers.

Use for:

- meaningful domain error definitions
- reusable module-specific assertions/failure constructors

Do not scatter domain errors across random files.

---

## 4. Subdirectories and when to use them

## 4.1 `flows/`

Use for mutation orchestration that owns transactions and coordinates multiple steps.

Typical contents:

- `create-*.flow.ts`
- `update-*.flow.ts`
- `accept-*.flow.ts`
- `verify-*.flow.ts`

Use a flow when the behavior needs any of these:

- transaction ownership
- multiple writes
- side-effect ordering
- audit coordination
- rate-limit coordination
- multi-step decision making

If the behavior is truly simple and read-only, a flow is usually unnecessary.

---

## 4.2 `use-cases/`

Use for explicit application behaviors that deserve a named boundary but are not necessarily HTTP-specific.

In many modules, `flows/` and `use-cases/` overlap conceptually.
That is fine.
The repo may use either naming depending on which is clearer.

Guideline:

- prefer `flows/` when the emphasis is mutation orchestration / transaction ownership
- prefer `use-cases/` when the emphasis is a reusable application behavior boundary

Do not create both for the same behavior unless there is a real distinction.

---

## 4.3 `policies/`

Use for pure decision logic.

Policies must be:

- synchronous
- side-effect free
- DB-free
- HTTP-free

Examples:

- MFA required decision
- next-action decision
- invite eligibility decision
- safety checks over already-fetched data

Policies operate on inputs.
They do not fetch their own data.

---

## 4.4 `queries/`

Use for read-side DB access.

Queries should:

- read from the DB
- shape read models
- accept a DB executor/transaction executor
- return data or `null`/empty where appropriate

Queries must not:

- perform writes
- own business logic
- open transactions

Examples:

- `find-user-by-email.query.ts`
- `list-tenant-memberships.query.ts`
- `get-auth-config.query.ts`

---

## 4.5 `repos/`

Use for write-side persistence operations.

Repos should:

- insert/update/delete
- encapsulate write persistence details
- accept a DB executor/transaction executor

Repos must not:

- own business rules
- own transaction boundaries
- act as giant mixed read/write data bags

Examples:

- `create-invite.repo.ts`
- `consume-reset-token.repo.ts`
- `activate-membership.repo.ts`

---

## 4.6 `helpers/`

Use for small, local, non-domain-heavy helpers that do not justify their own layer.

Good uses:

- local value shaping
- tiny pure utilities only used by this module
- response builder helpers

Bad uses:

- hiding business logic that should be a policy
- hiding orchestration that should be a flow
- generic utilities that actually belong in `shared/`

If a helper becomes important enough that its name carries business meaning, promote it to a better layer.

---

## 4.7 `dto/`

Use only when DTOs are numerous or complex enough to deserve separation.

Small modules can keep DTO/result shapes in:

- controller file
- service file
- `<module-name>.types.ts`

Do not create a `dto/` folder just because a diagram says modules have DTOs.

---

## 4.8 `constants/`

Use for stable module-scoped constants.

Examples:

- event names
- limits that truly belong to the module
- reusable enum-like string sets that are not global/shared concerns

Do not move every string into constants just to look “organized.”

---

## 5. Required layering behavior

The default dependency shape is:

```text
routes → controller → service → flow/use-case → queries/repos/policies
                                   ↓
                                shared/
```

Allowed simplification:

```text
routes → controller → service → queries
```

That simplification is acceptable only when the behavior is:

- read-only
- non-transactional
- non-orchestrated
- simple enough that introducing a flow adds ceremony, not clarity

The moment mutation complexity or orchestration appears, add the proper layer.

---

## 6. What belongs in `shared/` vs what belongs in a module

## Belongs in `shared/`

Infrastructure or generic cross-cutting primitives such as:

- DB client / executor primitives
- Redis/session infrastructure
- HTTP/request context infrastructure
- logger setup
- rate limiter primitives
- generic crypto/time helpers if truly shared and non-domain-specific

## Belongs in a module

Anything that carries business meaning for a bounded context, such as:

- invite acceptance rules
- auth next-action logic
- tenant-specific auth config behavior
- provisioning behavior
- audit-facing business event meaning

If a function name sounds like business language, it probably belongs in a module.

---

## 7. When to split files

Split a file when one or more of these become true:

- it owns more than one clear responsibility
- reviewers struggle to explain what the file “is” in one sentence
- transaction logic and pure logic are mixed together
- read and write DB behavior are mixed in a way that obscures intent
- a service/controller starts accumulating condition trees and orchestration steps

Do **not** split a file just because it crossed an arbitrary line count.
The reason to split is clarity, not aesthetics.

---

## 8. Minimum viable module patterns

## 8.1 Read-only module pattern

Use when the module currently serves read-only behavior.

```text
backend/src/modules/<module-name>/
├── index.ts
├── <module-name>.module.ts
├── <module-name>.routes.ts
├── <module-name>.controller.ts
├── <module-name>.service.ts
└── queries/
    └── *.query.ts
```

That is enough **if** the module remains read-only and simple.

---

## 8.2 Simple mutation module pattern

Use when the module has writes but limited complexity.

```text
backend/src/modules/<module-name>/
├── index.ts
├── <module-name>.module.ts
├── <module-name>.routes.ts
├── <module-name>.controller.ts
├── <module-name>.service.ts
├── flows/
│   └── *.flow.ts
├── queries/
│   └── *.query.ts
├── repos/
│   └── *.repo.ts
└── <module-name>.errors.ts
```

---

## 8.3 Rich domain module pattern

Use when the module has multiple mutation flows, important business decisions, and multiple persistence concerns.

```text
backend/src/modules/<module-name>/
├── index.ts
├── <module-name>.module.ts
├── <module-name>.routes.ts
├── <module-name>.controller.ts
├── <module-name>.service.ts
├── <module-name>.types.ts
├── <module-name>.errors.ts
├── flows/
├── policies/
├── queries/
├── repos/
├── helpers/
└── constants/
```

This is close to the current Auth module shape and is appropriate when complexity is real.

---

## 9. Public surface guidance

A module’s `index.ts` should expose only what other parts of the backend truly need.

Typical exports:

- route registration function
- module factory
- intentionally shared service interface/class
- intentionally shared types/errors/contracts

Avoid:

- exporting all internals for convenience
- letting other modules depend on private helpers or private flow files

If another module repeatedly needs something stable, promote it intentionally.
Do not leak internals by habit.

---

## 10. Naming guidance

Use names that reveal role clearly.

### Good

- `auth.routes.ts`
- `auth.controller.ts`
- `auth.service.ts`
- `verify-mfa.flow.ts`
- `find-user-by-email.query.ts`
- `create-invite.repo.ts`
- `login-next-action.policy.ts`

### Avoid

- `auth.utils.ts`
- `auth.helpers.ts` for everything
- `common.ts`
- `misc.ts`
- `data.ts`
- `manager.ts`
- `processor.ts` unless it truly represents that concept

File names should tell the reviewer what kind of logic is inside before opening the file.

---

## 11. Testing alignment for modules

A module’s structure should make testing obvious.

Typical mapping:

- `policies/` → unit tests
- `helpers/` → unit tests if meaningful
- `queries/` / `repos/` → DB integration tests
- `flows/` / `use-cases/` → integration or focused module tests
- controller/route contract → E2E tests

If the structure makes testing awkward, the structure is probably wrong.

---

## 12. Anti-patterns this skeleton is designed to prevent

### Anti-pattern 1 — Controller orchestration

If the controller reads like a mini workflow engine, the module is slipping.

### Anti-pattern 2 — God service

If the service owns validation, persistence, policy, transaction, audit, and session mutation, the module is under-structured.

### Anti-pattern 3 — Fake layers

If a flow file just calls one repo method and adds no real boundary value, it may be unnecessary.

### Anti-pattern 4 — Shared dumping ground

If domain logic is being moved into `shared/` just because multiple modules use it, stop and check whether it is actually a stable shared use case or contract.

### Anti-pattern 5 — Leaky internals

If other modules import private helpers, random repo files, or internal flow functions, the module boundary is weak.

---

## 13. Decision guide: where should this logic go?

Ask these in order:

1. Is it infrastructure or generic cross-cutting?
   - yes → `shared/`
   - no → module

2. Is it HTTP adaptation?
   - yes → controller

3. Is it route registration?
   - yes → routes

4. Is it a module entrypoint/facade?
   - yes → service

5. Does it own transaction/orchestration/multi-step mutation?
   - yes → flow/use-case

6. Is it pure decision logic over already-fetched inputs?
   - yes → policy

7. Is it read-side DB access?
   - yes → query

8. Is it write-side DB access?
   - yes → repo

9. Is it a tiny module-local support function?
   - yes → helper

If none of those fit cleanly, step back and check whether the design is still too vague.

---

## 14. Final rule

The module skeleton exists to make the backend easier to extend without becoming harder to reason about.

Use structure to absorb complexity.
Do not use structure to perform architecture theatre.
