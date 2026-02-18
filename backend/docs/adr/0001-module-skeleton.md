# ADR 0001 — Module Skeleton & Cross-Module Boundaries

## Status

Accepted (Phase 0 — governance lock)

## Context

Auth-Lab is the authentication + user provisioning service for Hubins/Insynctive.

Primary constraints:

- Multi-tenant isolation (tenant/workspace boundaries are strict).
- Clean Architecture dependency direction must remain stable over time.
- Transactions may only be opened in the service/use-case orchestration layer.
- Modules must remain easy to navigate, test, and refactor without “repo entropy”.

We already have multiple modules (`auth`, `invites`, `tenants`, `memberships`, `users`) and a shared orchestration area (`_shared/use-cases`). Without a single structure standard, each module will drift and long-term change-cost will explode.

## Decision

We adopt one canonical module skeleton, with explicit rules about what goes where and what is optional.

### Canonical module layout (single source of truth)

src/modules/<module>/
<module>.module.ts # Composition + exports module public surface

<module>.types.ts # Domain/module types (no HTTP/DB/framework dependencies)
<module>.errors.ts # Module error factories (AppError builders)

queries/ # Read layer (DB → domain shaping)
<module>.queries.ts

dal/ # Data access (dumb SQL + write repos)
<module>.query-sql.ts # raw SQL builders / query helpers
<module>.repo.ts # write operations (insert/update/delete)

policies/ # PURE rules (no DB/HTTP/framework)
\*.policy.ts

helpers/ # Orchestration helpers (no hidden business rules)
\*.ts

flows/ # Deep modules for complex orchestration
<flowName>/
\*.ts

Optional — only if module exposes HTTP endpoints:
<module>.schemas.ts # Zod schemas (request/response boundary validation)
<module>.controller.ts # HTTP mapping only (no DB calls)
<module>.routes.ts # Fastify route wiring
<module>.service.ts # Orchestration + transaction ownership
<module>.audit.ts # Typed audit event builders

### What “optional” means

Modules without HTTP endpoints today (e.g. internal-only domains) may omit:

- `<module>.schemas.ts`
- `<module>.controller.ts`
- `<module>.routes.ts`
- `<module>.service.ts`
- `<module>.audit.ts`

But they must still follow the same internal boundaries (`queries/`, `dal/`, `policies/`) where applicable.

## Rules (enforced)

### Dependency direction (Clean Architecture)

- Controllers/Routes depend on Services.
- Services depend on Queries/Repos/Policies/Helpers.
- DAL depends on nothing above it (no service/controller imports).
- Policies must be pure (no DB/HTTP/framework imports).
- Shared utilities (logging, error types, security primitives) live in `src/shared/*`.

### Transactions

- Transactions are opened ONLY in:
  - `<module>.service.ts`, or
  - `_shared/use-cases/*` (if explicitly orchestrating cross-module work)

Never in:

- controllers
- routes
- queries
- dal

### DAL rules (“dumb SQL”)

- DAL must not throw `AppError` (it can throw raw DB errors or return results).
- DAL must not import HTTP types, controllers, or services.
- DAL should do minimal shaping; domain shaping belongs in queries/services.

### Queries rules (read model shaping)

- Queries may compose SQL and shape DB rows into module/domain models.
- Queries must not start transactions.
- Queries must not contain business decision logic (that goes into policies).

### Policies rules (pure logic)

- Policies are pure functions and deterministic.
- No DB reads/writes, no HTTP framework imports, no clocks unless injected.
- Policies must be unit-testable in isolation.

### Helpers rules

- Helpers may orchestrate small repeated steps, but must not hide core business rules.
- If a helper contains business decision logic, it must be promoted into `policies/`.

## Cross-module governance

### Only allowed cross-module orchestration surface

Cross-module orchestration is allowed ONLY in:

`src/modules/_shared/use-cases/*`

### Rules for `_shared/use-cases`

- No “random utilities” in `_shared`.
- Every use-case file MUST include a top comment header with:
  - Purpose
  - Invariants
  - Inputs/Outputs
  - Transaction ownership (yes/no)
  - Failure modes / idempotency notes
- Every shared use-case must have test coverage (at minimum: invariant tests).

## Consequences

- Repo becomes predictable: engineers can find code by convention.
- Modules stay aligned with Clean Architecture boundaries.
- Refactors become mechanical and safer.
- `_shared` stays a controlled boundary instead of turning into a dumping ground.

## Notes

This ADR does not require moving everything immediately. It defines the target structure and rules.
Refactors will apply this incrementally in small, test-gated batches.
