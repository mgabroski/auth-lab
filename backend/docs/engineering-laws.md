# Engineering Laws (Auth-Lab)

These are repo-level guardrails to keep the codebase production-grade as the system grows.

## 1) Clean Architecture boundaries (non-negotiable)

- **Domain / policies** do not import HTTP/DB/Redis/frameworks.
- **Use-cases / services / flows** orchestrate work and are the only place allowed to open transactions.
- **DAL / repositories / external clients** are implementation details and must depend on policies/use-cases, not the other way around.

## 2) File responsibility + size

- Prefer **small, cohesive files** with one reason to change.
- If a file exceeds **~350 LOC**, treat it as a refactor signal:
  - extract use-cases (one file per flow)
  - extract policies (pure decisions)
  - extract helpers only when they reduce duplication and stay explicit

## 3) Logging + PII safety

- Never log raw secrets (tokens, passwords, TOTP secrets, recovery codes).
- Avoid raw PII in operational logs and infra keys (e.g., Redis keys). Prefer hashed identifiers.
- Error meta must be treated as untrusted input and redacted before logging.

## 4) Module boundaries (public surfaces only)

- **No cross-module deep imports of implementation internals** (DAL, queries, helpers, policies, flows, etc.).
- Cross-module access must go through a module’s **public surface** (`backend/src/modules/<module>/index.ts`).
- `backend/src/shared/**` and `backend/src/_shared/**` are **shared layers** and may be imported by modules.
- Cross-module coordination should happen via:
  - a dedicated use-case in `backend/src/_shared/use-cases`, or
  - a narrow contract/port (interface) owned by the caller.
- If tooling enforcement is temporarily missing, this law is still mandatory in code review.

## 5) Safe change discipline

- Prefer small, reversible commits.
- Keep tests green frequently.
- Migrations must be backward compatible.
