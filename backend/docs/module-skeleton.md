# docs/module-skeleton.md

# Insynctive — Canonical Module Skeleton

_Tier 1 — Global Stable · Updated only on architectural change_
_Grounded in auth-lab codebase (v3, score 9.4/10)_

---

## 1. PURPOSE

This document is the canonical blueprint every new module must follow. It has two jobs:

**For engineers:** A concrete reference. When you build a new module, follow this shape exactly. Do not invent new layers, rename layers, or reorganise the folder structure because it looks cleaner to you in isolation. Consistency across modules is what makes the codebase navigable.

**For LLM sessions:** A binding contract. When generating or reviewing module code, this document — combined with `ARCHITECTURE.md` — defines what correct output looks like. Every generated file must be reconcilable against the patterns shown here.

The patterns in this document are extracted from `src/modules/auth/`, which is the most complete and complex module in the codebase. Where `auth` uses a sub-pattern not needed by simpler modules (e.g. `helpers/`, `sso/`), this is noted explicitly. The `src/modules/invites/` and `src/modules/memberships/` modules demonstrate the simpler variants.

---

## 2. CANONICAL MODULE SHAPE

Every module lives in `src/modules/<module-name>/` and follows this exact folder structure.

```
src/modules/<module-name>/
│
│   # Public surface — thin adapters
├── <module>.routes.ts          Routes only. No logic.
├── <module>.controller.ts      HTTP adapter. Zod parse → service call → reply.
├── <module>.service.ts         Facade. Delegates to flow functions. Zero logic.
├── <module>.module.ts          Wiring. Instantiates repos, service, controller.
│
│   # Domain types and contracts
├── <module>.types.ts           Domain types. No DB types. No HTTP types.
├── <module>.schemas.ts         Zod schemas for request validation.
├── <module>.errors.ts          AppError factories. Module-scoped error semantics.
├── <module>.constants.ts       (optional) Rate limit keys, expiry durations, enums.
│
│   # Business logic layers
├── flows/                      Orchestration. One subfolder per use case.
│   └── <use-case>/
│       └── execute-<use-case>-flow.ts   Owns transaction. Real unit of work.
│
├── policies/                   Pure business rules. No DB. No HTTP.
│   └── <rule-name>.policy.ts
│
│   # Audit helpers
├── <module>.audit.ts           Typed audit helpers. One function per action.
│
│   # Data access layer
├── queries/                    Read-only. Shapes DB rows → domain types.
│   └── <module>.queries.ts
│
└── dal/                        DB access primitives.
    ├── <module>.query-sql.ts   Raw Kysely SELECT queries. Returns raw rows.
    └── <module>.repo.ts        Write operations only. Supports withDb().
```

### The `flows/` convention

New modules use `flows/` sub-folders — one folder per use case:

```
flows/
  login/
    execute-login-flow.ts
  password-reset/
    request-password-reset-flow.ts
    reset-password-flow.ts
  mfa/
    setup-mfa-flow.ts
    verify-mfa-flow.ts
```

Older modules (`users/`, `tenants/`) use a `use-cases/` flat folder. That is a legacy pattern. All new modules use `flows/<use-case>/execute-<use-case>-flow.ts`.

### Optional folders (only when genuinely needed)

```
helpers/          Reusable internal helpers — only if ≥2 flow files share the same
                  logic and extraction is genuinely cleaner (not just DRY for its
                  own sake). Examples from auth: create-auth-session.ts,
                  build-auth-result.ts, has-verified-mfa-secret.ts.

<sub-domain>/     For a module with distinct sub-surface that warrants its own
                  controller/routes/service (e.g. invites/admin/ for admin-only
                  invite management endpoints). Do not create sub-surfaces
                  speculatively.
```

### The `index.ts` re-export

Modules that are consumed by other modules expose a public interface through `index.ts`:

```typescript
// src/modules/memberships/index.ts
export { MembershipModule, createMembershipModule } from './membership.module';
export type { MembershipRole, MembershipStatus } from './membership.types';
export { getMembershipByTenantAndUser } from './queries/membership.queries';
export { MembershipRepo } from './dal/membership.repo';
```

Only what other modules legitimately need is exported. Internal DAL types, policy functions, and flow functions are not exported unless another module explicitly needs them.

---

## 3. RESPONSIBILITY CONTRACT PER LAYER

Every layer has a single, non-negotiable job. Violations are caught in PR review.

### routes.ts

**Job:** Register HTTP endpoints. Nothing else.

- Calls `app.post(path, controller.method.bind(controller))`
- No `req`, no `reply`, no logic
- No imports from shared, no DB, no auth checks

```
ALLOWED:  app.post('/auth/login', controller.login.bind(controller))
FORBIDDEN: any if-statement, any import from shared/, any business condition
```

### controller.ts

**Job:** HTTP adapter. Parse request → call service → send reply.

- Parse request body with `schema.safeParse(req.body)`
- Throw `AppError.validationError(...)` on parse failure
- Extract session with `requireSession(req)` when authentication is required
- Extract `req.requestContext.tenantKey`, `req.ip`, `req.headers['user-agent']`
- Call exactly one service method
- Call `setSessionCookie` / `clearSessionCookie` when session must be set/cleared
- Return `reply.status(N).send(result)`

```
ALLOWED:  safeParse, requireSession, one service call, setSessionCookie, reply.send
FORBIDDEN: DB access, business rules, policy calls, direct repo calls, audit writes,
           session store access, any if-statement beyond parse error checking
```

### service.ts

**Job:** Thin facade. Dispatches to flow functions. Zero business logic.

- Holds a `deps` object passed in from the module constructor
- Every public method calls exactly one named flow function
- Passes the relevant subset of `deps` and the call params to the flow
- Contains no `if`, no `try/catch`, no direct DB calls, no audit writes

```
ALLOWED:  this.deps.someFlowFunction({ subset of deps }, params)
FORBIDDEN: transactions, business logic, DB access, audit writes, rate limit calls,
           any conditional logic
```

### flow file (flows/<use-case>/execute-<use-case>-flow.ts)

**Job:** Own the transaction. Real unit of orchestration.

This is the real unit of work. Everything important happens here.

**Mandatory execution order inside every flow:**

1. Rate limit check(s) — `hitOrThrow` or `hitOrSkip` — **before any DB work**
2. Open transaction: `await deps.db.transaction().execute(async (trx) => { ... })`
3. Inside transaction: resolve tenant → queries → policies → repo writes → success audit
4. Outside transaction: session/Redis operations, failure audit in catch block

```
ALLOWED:  rate limiter, db.transaction(), queries, repos.withDb(trx), policies,
          AuditWriter inside tx (success), AuditWriter outside tx (failure),
          session ops after tx commits
FORBIDDEN: opening a second nested transaction, HTTP concerns, calling other
           modules' services directly (use shared queries/repos), business logic
           that belongs in a policy
```

### policy file (policies/<rule-name>.policy.ts)

**Job:** Pure business rules. No DB. No HTTP. No side effects.

Two variants always exist for each rule:

- **Result variant** — `get<Rule>Failure(input) → failure | null` — lets the flow build `failureCtx` before throwing
- **Assertion variant** — `assert<Rule>(input): asserts input is Narrowed` — narrows the TypeScript type for the rest of the flow

```
ALLOWED:  pure computation, throw AppError, return failure payload
FORBIDDEN: DB access, repo imports, AppError HTTP codes (import those from errors.ts),
           any async operation, any side effects
```

### query file (queries/<module>.queries.ts)

**Job:** Read-only domain queries. Shape DB rows into domain types.

- Calls `<module>.query-sql.ts` functions
- Maps raw DB rows to domain types defined in `<module>.types.ts`
- Returns `null` when not found, never throws for missing records
- Usable in both transactional and non-transactional contexts (accepts `DbExecutor`)

```
ALLOWED:  call query-sql functions, map rows to domain types
FORBIDDEN: write operations, AppError, imports from service/controller/flow
```

### dal/query-sql.ts

**Job:** Raw Kysely SELECT queries. Returns typed raw rows directly.

- Accepts `db: DbExecutor` (works with both `db` and `trx`)
- Returns raw Kysely row shapes — no domain type mapping here
- One exported function per distinct query

```
ALLOWED:  Kysely .selectFrom().where().executeTakeFirst() etc.
FORBIDDEN: write operations (INSERT/UPDATE/DELETE), AppError, business logic
```

### dal/repo.ts

**Job:** Write operations only. Supports `withDb()` for transaction binding.

- `constructor(private readonly db: DbExecutor) {}`
- `withDb(db: DbExecutor): <Module>Repo { return new <Module>Repo(db); }`
- Methods are write-only: INSERT, UPDATE, DELETE
- No transactions opened here
- No AppError
- No policies
- Returns minimal shapes (e.g. `{ id: string }`) or `boolean` (update succeeded/failed)

### module.ts

**Job:** Wiring only. Instantiates module-owned repos, service, and controller.

- Receives all external deps as parameters (never creates infra)
- Instantiates repos: `const <x>Repo = new <X>Repo(deps.db)`
- Instantiates service with repos + deps
- Instantiates controller with service
- Returns `{ registerRoutes(app: FastifyInstance) { registerRoutes(app, controller); } }`
- Exports `create<Module>Module` function and `<Module>Module` type

```
ALLOWED:  new Repo(deps.db), new Service({ ...deps, repo }), new Controller(service),
          return { registerRoutes }
FORBIDDEN: infra creation (new Redis, createDb), business logic, global state
```

---

## 4. CANONICAL CODE PATTERNS

These are the exact patterns extracted from the codebase. Every new file must be consistent with these. Source paths are cited.

---

### Pattern 1 — Flow file (rate limit → tx → failureCtx → two-phase audit → post-tx session)

Source: `src/modules/auth/flows/login/execute-login-flow.ts`

```typescript
/**
 * src/modules/<module>/flows/<use-case>/execute-<use-case>-flow.ts
 *
 * WHY: [one sentence explaining the use case]
 * RULES:
 * - No HTTP concerns here (controller handles that).
 * - No raw SQL here (use queries/repos).
 * - Transactions are opened here.
 */

// ── Type definitions ────────────────────────────────────────────────────────
export type <UseCase>Params = { ... };

// Captures context for failure audit (built before throw so catch can use it)
type <UseCase>FailureContext = {
  tenantId: string;
  userId?: string;
  emailKey: string;     // hashed — never log raw email
  reason: string;
  error: Error;
};

type <UseCase>TxResult = { user: ...; membership: ...; tenant: ... };

export async function execute<UseCase>Flow(
  deps: { db: DbExecutor; rateLimiter: RateLimiter; auditRepo: AuditRepo; ... },
  params: <UseCase>Params,
): Promise<...> {

  // ── Step 1: Rate limit BEFORE any DB work ──────────────────────────────
  await deps.rateLimiter.hitOrThrow({
    key: `<module>.<action>:email:${emailKey}`,
    limit: RATE_LIMITS.<action>.perEmail.limit,
    windowSeconds: RATE_LIMITS.<action>.perEmail.windowSeconds,
  });

  // ── Step 2: Prepare failure context holder ────────────────────────────
  let failureCtx: <UseCase>FailureContext | null = null;
  let txResult: <UseCase>TxResult | null = null;

  try {
    txResult = await deps.db.transaction().execute(async (trx): Promise<<UseCase>TxResult> => {

      // ── Step 3: Build AuditWriter inside tx ──────────────────────────
      const audit = new AuditWriter(deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      });

      // ── Step 4: Resolve tenant ────────────────────────────────────────
      const tenant = await resolveTenantForAuth(trx, params.tenantKey);

      // ── Step 5: Queries → policies → repo writes ──────────────────────
      const entity = await getEntityByX(trx, ...);
      if (!entity) {
        failureCtx = { tenantId: tenant.id, reason: 'not_found', error: ModuleErrors.xxx() };
        throw failureCtx.error;
      }

      const failure = getPolicyFailure(entity);
      if (failure) {
        failureCtx = { ..., reason: failure.reason, error: failure.error };
        throw failureCtx.error;
      }
      assertPolicyAllowed(entity);  // narrows type

      // ── Step 6: Success audit INSIDE transaction ──────────────────────
      const fullAudit = audit
        .withContext({ tenantId: tenant.id })
        .withContext({ userId: user.id, membershipId: membership.id });

      await auditActionSuccess(fullAudit, { userId: user.id, ... });

      return { user, membership, tenant };
    });
  } catch (err) {

    // ── Step 7: Failure audit OUTSIDE transaction ─────────────────────
    if (failureCtx) {
      const ctx = failureCtx as <UseCase>FailureContext;
      const failAudit = new AuditWriter(deps.auditRepo, {  // NOTE: auditRepo, not withDb(trx)
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: ctx.tenantId, userId: ctx.userId ?? null, membershipId: null });

      await auditActionFailed(failAudit, { reason: ctx.reason });
    }

    throw err;
  }

  if (!txResult) throw new Error('<module>.<action>: transaction completed without result');

  // ── Step 8: Session/Redis operations AFTER transaction commits ────────
  const { sessionId } = await createAuthSession({ sessionStore: deps.sessionStore, ... });

  return { sessionId, result: buildAuthResult({ ... }) };
}
```

**Key invariants this pattern enforces:**

- Rate limit runs before the DB is touched — a rejected request never opens a transaction
- `failureCtx` is set before `throw` inside the tx — the catch block can audit it
- Success audit inside `db.transaction()` — commits atomically with data mutations
- Failure audit uses bare `deps.auditRepo` (not `.withDb(trx)`) — survives rollback
- Session store is touched only after the transaction commits successfully

---

### Pattern 2 — Repo file (writes only, withDb)

Source: `src/modules/auth/dal/auth.repo.ts` and `src/modules/memberships/dal/membership.repo.ts`

```typescript
/**
 * src/modules/<module>/dal/<module>.repo.ts
 *
 * WHY: DAL WRITES ONLY for <module> (mutations).
 * RULES:
 * - No transactions started here (flows own tx).
 * - No AppError.
 * - No policies.
 * - Supports withDb() for transaction binding.
 */

import type { DbExecutor } from '../../../shared/db/db';

export class <Module>Repo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): <Module>Repo {
    return new <Module>Repo(db);
  }

  async insert<Entity>(params: {
    tenantId: string;
    field: string;
  }): Promise<{ id: string }> {
    const row = await this.db
      .insertInto('<table>')
      .values({ tenant_id: params.tenantId, field: params.field })
      .returning(['id'])
      .executeTakeFirstOrThrow();

    return { id: row.id };
  }

  /**
   * Atomic conditional update — idempotency guard via WHERE clause.
   * Returns true if the row was updated; false if the guard condition was not met.
   */
  async activate<Entity>(params: { entityId: string; now: Date }): Promise<boolean> {
    const res = await this.db
      .updateTable('<table>')
      .set({ status: 'ACTIVE', accepted_at: params.now })
      .where('id', '=', params.entityId)
      .where('status', '=', 'INVITED')   // ← idempotency guard
      .executeTakeFirst();

    return Number(res?.numUpdatedRows ?? 0) > 0;
  }
}
```

**Key invariants:**

- `withDb(db)` returns a **new instance** — it does not mutate `this.db`
- Inside a flow, always call `repo.withDb(trx)` to bind the repo to the transaction
- Never call `repo.withDb(trx)` outside a flow — pass `trx` only inside `db.transaction().execute()`
- Write methods return minimal shapes (`{ id }`, `boolean`) — never full domain objects

---

### Pattern 3 — Policy file (pure function, result variant + assertion variant)

Source: `src/modules/auth/policies/login-membership-gating.policy.ts`

```typescript
/**
 * src/modules/<module>/policies/<rule>.policy.ts
 *
 * WHY: <Rule> is a business/security rule. Keep it pure + unit-testable.
 * RULES:
 * - Pure function — no DB, no async, no HTTP.
 * - Result variant gives flow control over failureCtx before throwing.
 * - Assertion variant narrows TypeScript type for the rest of the flow.
 */

import { <Module>Errors } from '../<module>.errors';

export type <Entity>Like = Readonly<{
  id: string;
  status: 'ACTIVE' | 'INVITED' | 'SUSPENDED';
  role: 'ADMIN' | 'MEMBER';
}>;

export type <Rule>Failure =
  | { reason: 'no_entity'; error: Error }
  | { reason: 'suspended'; error: Error };

/**
 * Returns null when the check passes.
 * Returns a failure payload when it fails — lets the flow set failureCtx before throwing.
 */
export function get<Rule>Failure(
  entity: <Entity>Like | undefined,
): <Rule>Failure | null {
  if (!entity) {
    return { reason: 'no_entity', error: <Module>Errors.notFound() };
  }
  if (entity.status === 'SUSPENDED') {
    return { reason: 'suspended', error: <Module>Errors.suspended() };
  }
  return null;
}

/**
 * Assertion variant — throws and narrows the type.
 * Use this after failureCtx is already set, to get TypeScript narrowing.
 */
export function assert<Rule>(
  entity: <Entity>Like | undefined,
): asserts entity is <Entity>Like {
  const failure = get<Rule>Failure(entity);
  if (failure) throw failure.error;
}
```

**Key invariants:**

- Both variants call the same underlying function — no logic duplication
- The result variant is called first in the flow to capture `failureCtx.reason`
- The assertion variant is called immediately after — its sole purpose is type narrowing
- No DB imports, no async, no side effects — policies must be synchronously unit-testable

---

### Pattern 4 — Errors file (AppError factory pattern)

Source: `src/modules/auth/auth.errors.ts`

```typescript
/**
 * src/modules/<module>/<module>.errors.ts
 *
 * WHY: <Module> owns its domain-specific error semantics.
 * RULES:
 * - Use AppError as the transport primitive.
 * - Error messages must be security-safe: never reveal whether a record exists.
 * - Never include passwords, tokens, or hashes in meta.
 */

import { AppError, type AppErrorMeta } from '../../shared/http/errors';

export const <Module>Errors = {
  /** Plain description in JSDoc — what triggers this error. */
  notFound(meta?: AppErrorMeta) {
    return AppError.notFound('Resource not found.', meta);
  },

  suspended(meta?: AppErrorMeta) {
    return AppError.forbidden('Your account has been suspended.', meta);
  },

  /**
   * SECURITY: a single error for token invalid/expired/used.
   * Separate errors would allow oracle attacks.
   */
  tokenInvalid(meta?: AppErrorMeta) {
    return AppError.validationError(
      'This link is invalid or has expired. Please request a new one.',
      meta,
    );
  },
} as const;
```

**Key invariants:**

- `as const` — prevents accidental mutation
- Every factory accepts optional `meta?: AppErrorMeta` — for structured debugging without leaking to the API
- Error messages use first-person-safe copy: never "email not found" (oracle), use "invalid credentials" instead
- Module error files never import from another module's error file

---

### Pattern 5 — Audit file (typed helpers, never raw writer.append in flows)

Source: `src/modules/auth/auth.audit.ts`

```typescript
/**
 * src/modules/<module>/<module>.audit.ts
 *
 * WHY: Typed audit helpers for the <Module> module.
 * RULES:
 * - Each function maps one domain action to one audit write.
 * - No DB access (delegates to AuditWriter).
 * - No business rules.
 * - Never include passwords, hashes, or tokens in metadata.
 * - New action strings must also be added to KnownAuditAction in audit.types.ts.
 */

import type { AuditWriter } from '../../shared/audit/audit.writer';

export function audit<ActionName>(
  writer: AuditWriter,
  data: { entityId: string; field: string },
): Promise<void> {
  return writer.append('<module>.<action>', {
    entityId: data.entityId,
    field: data.field,
  });
}

export function audit<ActionFailed>(
  writer: AuditWriter,
  data: { entityKey: string; reason: string }, // entityKey = hashed, never raw PII
): Promise<void> {
  return writer.append('<module>.<action>.failed', {
    entityKey: data.entityKey,
    reason: data.reason,
  });
}
```

**Key invariants:**

- Flow files never call `writer.append(...)` directly — always call the typed helper
- PII fields are hashed before entering metadata: use `emailKey` not `email`, `tokenHash` not `token`
- One function per action — no multi-action helpers
- The action string in `writer.append(...)` must match an entry in `KnownAuditAction` in `shared/audit/audit.types.ts`

---

### Pattern 6 — Service file (facade, zero logic)

Source: `src/modules/auth/auth.service.ts`

```typescript
/**
 * src/modules/<module>/<module>.service.ts
 *
 * WHY: Thin facade that dispatches to flow functions.
 * RULES:
 * - No transactions here; flows own orchestration boundaries.
 * - No business logic here; flows/policies own logic.
 */

import type { DbExecutor } from '../../shared/db/db';
import type { RateLimiter } from '../../shared/security/rate-limit';
// ... other infra type imports ...

import type { <Action>Params } from './flows/<use-case>/execute-<use-case>-flow';
import { execute<UseCase>Flow } from './flows/<use-case>/execute-<use-case>-flow';

export class <Module>Service {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      rateLimiter: RateLimiter;
      auditRepo: AuditRepo;
      // ... all deps the flows need ...
    },
  ) {}

  async <action>(params: <Action>Params): Promise<<Return>> {
    return execute<UseCase>Flow(
      {
        db: this.deps.db,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        // pass only what this flow needs — not all deps blindly
      },
      params,
    );
  }
}
```

**Key invariants:**

- Every public method is a one-liner that calls one flow function
- Pass only the subset of `deps` the flow actually needs — not all of `this.deps` blindly
- No `try/catch`, no `if`, no `await` on anything other than the flow call
- Service is the only file that knows which flow handles which action

---

### Pattern 7 — Controller file (HTTP adapter, Zod parse, no business logic)

Source: `src/modules/auth/auth.controller.ts`

```typescript
/**
 * src/modules/<module>/<module>.controller.ts
 *
 * WHY: Maps HTTP → service call.
 * RULES:
 * - No DB access here.
 * - No business rules here.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { <action>Schema } from './<module>.schemas';
import { AppError } from '../../shared/http/errors';
import type { <Module>Service } from './<module>.service';
import { requireSession } from '../../shared/http/require-auth-context';

export class <Module>Controller {
  constructor(private readonly <module>Service: <Module>Service) {}

  async <action>(req: FastifyRequest, reply: FastifyReply) {
    // 1. Parse + validate input (Zod)
    const parsed = <action>Schema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    // 2. Extract session if required
    const session = requireSession(req);   // throws 401 if no valid session

    // 3. Call service — one call only, no logic around it
    const result = await this.<module>Service.<action>({
      tenantKey: req.requestContext.tenantKey,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
      userId: session.userId,
      ...parsed.data,
    });

    // 4. Reply
    return reply.status(200).send(result);
  }
}
```

**Key invariants:**

- `safeParse` not `parse` — never let Zod throw raw errors from a controller
- `requireSession` is called in the controller, not the service or flow
- The controller passes `tenantKey`, `ip`, `userAgent`, `requestId` from request context to every service call — these are HTTP concerns, not business concerns
- Never call `reply.send` more than once per handler
- No `try/catch` in the controller — errors propagate to the global error handler in `shared/http/error-handler.ts`

---

### Pattern 8 — Module file (wiring only, no business logic)

Source: `src/modules/auth/auth.module.ts`

```typescript
/**
 * src/modules/<module>/<module>.module.ts
 *
 * WHY: Encapsulates <Module> module wiring.
 * RULES:
 * - No infra creation here (DI passes deps in).
 * - No globals or singletons.
 */

import type { FastifyInstance } from 'fastify';
import type { DbExecutor } from '../../shared/db/db';
import type { RateLimiter } from '../../shared/security/rate-limit';
// ... other infra type imports ...

import { <Module>Repo } from './dal/<module>.repo';
import { <Module>Service } from './<module>.service';
import { <Module>Controller } from './<module>.controller';
import { register<Module>Routes } from './<module>.routes';

export type <Module>Module = ReturnType<typeof create<Module>Module>;

export function create<Module>Module(deps: {
  db: DbExecutor;
  rateLimiter: RateLimiter;
  auditRepo: AuditRepo;
  // ... all deps the module needs ...
}) {
  // 1. Instantiate module-owned repos
  const <module>Repo = new <Module>Repo(deps.db);

  // 2. Instantiate service with repos + shared deps
  const <module>Service = new <Module>Service({
    db: deps.db,
    rateLimiter: deps.rateLimiter,
    auditRepo: deps.auditRepo,
    <module>Repo,
  });

  // 3. Instantiate controller
  const controller = new <Module>Controller(<module>Service);

  // 4. Expose registerRoutes
  return {
    <module>Service,
    registerRoutes(app: FastifyInstance) {
      register<Module>Routes(app, controller);
    },
  };
}
```

**Key invariants:**

- Module creates only its own repos — shared infra (`db`, `rateLimiter`, `auditRepo`) comes from DI
- `create<Module>Module` is the only exported constructor — no `new <Module>Module()`
- The return type is derived via `ReturnType<typeof create<Module>Module>` — no hand-written interface
- Module is the only place that wires repos → service → controller — this wiring never appears in `di.ts`

---

## 5. NAMING CONVENTIONS

### Files

| What               | Convention                    | Example                             |
| ------------------ | ----------------------------- | ----------------------------------- |
| Flow file          | `execute-<verb-noun>-flow.ts` | `execute-login-flow.ts`             |
| Policy file        | `<subject>-<rule>.policy.ts`  | `login-membership-gating.policy.ts` |
| Query-sql file     | `<module>.query-sql.ts`       | `auth.query-sql.ts`                 |
| Repo file          | `<module>.repo.ts`            | `auth.repo.ts`                      |
| Audit file         | `<module>.audit.ts`           | `auth.audit.ts`                     |
| Errors file        | `<module>.errors.ts`          | `auth.errors.ts`                    |
| Constants file     | `<module>.constants.ts`       | `auth.constants.ts`                 |
| Types file         | `<module>.types.ts`           | `auth.types.ts`                     |
| Schemas file       | `<module>.schemas.ts`         | `auth.schemas.ts`                   |
| Module wiring file | `<module>.module.ts`          | `auth.module.ts`                    |

### Classes and functions

| What                     | Convention               | Example                           |
| ------------------------ | ------------------------ | --------------------------------- |
| Service class            | `<Module>Service`        | `AuthService`                     |
| Repo class               | `<Module>Repo`           | `AuthRepo`                        |
| Controller class         | `<Module>Controller`     | `AuthController`                  |
| Module factory           | `create<Module>Module`   | `createAuthModule`                |
| Flow function            | `execute<UseCase>Flow`   | `executeLoginFlow`                |
| Policy result variant    | `get<Rule>Failure`       | `getLoginMembershipGatingFailure` |
| Policy assertion variant | `assert<Rule>`           | `assertLoginMembershipAllowed`    |
| Audit helper             | `audit<ActionName>`      | `auditLoginSuccess`               |
| Error factory object     | `<Module>Errors`         | `AuthErrors`                      |
| Routes registration      | `register<Module>Routes` | `registerAuthRoutes`              |

### Rate limit key format

```
<module>.<action>:<dimension>:<hashed-value>
```

Examples from `src/modules/auth/auth.constants.ts`:

```
login:email:<emailKey>
login:ip:<ipKey>
sso-start:ip:<ipKey>
```

The value in the key is always a hash — never a raw email, IP, or token. Use `deps.tokenHasher.hash(value)` before inserting into the key.

### Audit action string format

```
<module>.<noun>.<verb>         e.g. auth.login.success
<module>.<noun>.<verb>.failed  e.g. auth.login.failed
<module>.<noun>.<verb>.started e.g. auth.mfa.setup.started
```

After adding a new action string in `<module>.audit.ts`, add it to `KnownAuditAction` in `src/shared/audit/audit.types.ts`.

---

## 6. DECISION RULES

### When to create a helper vs a policy vs a query

**Create a helper** when:

- Two or more flow files share the same multi-step logic that is not a business rule
- Examples: `create-auth-session.ts` (builds and stores a session), `build-auth-result.ts` (constructs the HTTP response shape)
- Do not create helpers for single-use logic — keep it inline in the flow

**Create a policy** when:

- The logic is a business or security rule
- The logic can be tested without any async calls
- The logic needs a `reason` string for the failure audit context
- Examples: membership status gating, MFA requirement check, invite expiry check

**Create a query** when:

- Multiple flow files in the same module need to read the same entity in the same shape
- The shape combines multiple DB columns into a domain type
- Examples: `getUserByEmail`, `getMembershipByTenantAndUser`

**When logic belongs in the flow directly** (not extracted):

- It is used by only one flow
- It does not need to be independently tested
- Extracting it would require passing more dependencies than the flow already has

### When to add a `constants.ts` file

Add `<module>.constants.ts` when the module has:

- Rate limit configurations used in multiple flow files
- Token expiry durations referenced in more than one place
- Status/enum strings used in both flows and tests

If the module has only one flow and one constant, keep the constant inline in the flow file.

### When to open a transaction vs not

Open a transaction in the flow when any of these are true:

- The flow writes to the DB (always — all writes must be in a transaction)
- The flow reads then writes, and the read must be consistent with the write
- The flow writes a success audit (success audit must commit with the data write)

Do not open a transaction for read-only flows (audit viewers, list queries). They call `deps.db` directly without `.transaction()`.

---

## 7. REPO TRANSACTION-BINDING PATTERN

Every repo that participates in transactions must implement `withDb()`. This is the mechanism that binds a repo to a transaction scope.

**The pattern:**

```typescript
// src/modules/<module>/dal/<module>.repo.ts

export class <Module>Repo {
  constructor(private readonly db: DbExecutor) {}

  // Returns a NEW repo instance bound to the given DbExecutor (which may be a trx).
  withDb(db: DbExecutor): <Module>Repo {
    return new <Module>Repo(db);
  }

  async insert<Entity>(params: { ... }): Promise<{ id: string }> {
    return this.db
      .insertInto('<table>')
      .values({ ... })
      .returning(['id'])
      .executeTakeFirstOrThrow();
  }
}
```

**Usage inside a flow — always call `withDb(trx)` inside the transaction:**

```typescript
// Inside flows/<use-case>/execute-<use-case>-flow.ts

txResult = await deps.db.transaction().execute(async (trx) => {
  // Bind repos to the transaction scope — never pass bare deps.xRepo inside a tx
  const audit = new AuditWriter(deps.auditRepo.withDb(trx), { ... });

  await deps.<module>Repo.withDb(trx).insert<Entity>({ ... });
  await deps.membershipRepo.withDb(trx).activateMembership({ ... });

  await auditSuccess(audit.withContext({ tenantId }), { ... });

  return { ... };
});
```

**Two things that must never happen:**

- Calling `deps.xRepo.someWrite(...)` inside a transaction without `.withDb(trx)` — the write will run outside the transaction
- Calling `.withDb(trx)` on a repo outside a `db.transaction().execute()` callback — `trx` does not exist there

**The AuditWriter for failure audits uses bare `deps.auditRepo`, not `.withDb(trx)`:**

```typescript
catch (err) {
  if (failureCtx) {
    // Deliberately uses deps.auditRepo — not withDb(trx).
    // The transaction has been rolled back; we need the audit to persist anyway.
    const failAudit = new AuditWriter(deps.auditRepo, { requestId, ip, userAgent });
    await auditActionFailed(failAudit, { ... });
  }
  throw err;
}
```

---

## 8. PROGRESSIVE AUDITWRITER ENRICHMENT

The `AuditWriter` is built progressively as the flow resolves more context. Each call to `.withContext()` returns a new immutable writer — it never mutates the existing one.

Source: `src/shared/audit/audit.writer.ts`

**The three-stage enrichment:**

```typescript
// ── Stage 1: Start of request (inside transaction callback) ─────────────
const audit = new AuditWriter(deps.auditRepo.withDb(trx), {
  requestId: params.requestId,
  ip: params.ip,
  userAgent: params.userAgent,
  // tenantId, userId, membershipId are all null at this point
});

// ── Stage 2: After tenant is resolved ────────────────────────────────────
const tenantAudit = audit.withContext({ tenantId: tenant.id });
// `audit` is unchanged. `tenantAudit` has tenantId set.

// ── Stage 3: After user + membership are resolved ─────────────────────────
const fullAudit = tenantAudit.withContext({
  userId: user.id,
  membershipId: membership.id,
});
// `tenantAudit` is unchanged. `fullAudit` has all fields set.

// ── Write success audit using fully enriched writer ───────────────────────
await auditActionSuccess(fullAudit, { userId: user.id, role: membership.role });
```

**Rules:**

- Always use the most-enriched writer available for a given audit call
- Never pass a `tenantAudit` to an action that should have `userId` in context — enrich first
- Failure audit in the catch block always creates a fresh `new AuditWriter(deps.auditRepo, { ... })` and enriches it with whatever `failureCtx` captured before the throw
- Never call `writer.append(...)` directly in a flow file — always call the typed helper from `<module>.audit.ts`

---

## 9. FILE HEADER CONVENTION

Every file in every module must begin with a WHY/RULES header comment. This is not optional.

**The WHY block** answers: why does this file exist? What problem does it solve? What would break if it were deleted?

**The RULES block** answers: what are the constraints on this file's implementation? What is forbidden here?

**Template:**

```typescript
/**
 * src/modules/<module>/<path>/<file>.ts
 *
 * WHY:
 * - [One sentence: what this file does and why it belongs here.]
 * - [One sentence: what key design decision it embodies, if any.]
 *
 * RULES:
 * - [Constraint 1.]
 * - [Constraint 2.]
 * - [What is forbidden here (e.g. No DB access, No AppError, No business logic).]
 */
```

**Examples from the codebase:**

From `auth.repo.ts`:

```typescript
/**
 * src/modules/auth/dal/auth.repo.ts
 *
 * WHY:
 * - DAL WRITES ONLY for auth_identities and password_reset_tokens (mutations).
 * - Unique constraint (user_id, provider) enforced by DB on auth_identities.
 *
 * RULES:
 * - No transactions started here (service owns tx).
 * - No AppError.
 * - No policies.
 * - Supports withDb() for transaction binding.
 */
```

From `login-membership-gating.policy.ts`:

```typescript
/**
 * backend/src/modules/auth/policies/login-membership-gating.policy.ts
 *
 * WHY:
 * - Login membership gating is a business/security rule.
 * - Keep it pure + unit-testable (no DB, no HTTP).
 *
 * RULES:
 * - If membership is missing → no access.
 * - If membership is SUSPENDED → suspended.
 * - If membership is INVITED → invite not yet accepted.
 * - Otherwise OK.
 */
```

When a file is updated, add an update note to the header:

```typescript
 * BRICK 11 UPDATE:
 * - Added emailVerified field to login result (Decision 3).
```

---

## 10. WIRING CHECKLIST

Before marking a module complete, verify every item in this list:

### Module wiring (`<module>.module.ts` + `app/di.ts` + `app/routes.ts`)

- [ ] `create<Module>Module` creates only module-owned repos
- [ ] All shared infra (db, rateLimiter, auditRepo, sessionStore) passed in from DI — not created
- [ ] `create<Module>Module` is called in `app/di.ts` with correct deps
- [ ] `module.registerRoutes(app)` is called in `app/routes.ts`
- [ ] `<Module>Module` type is exported and used as a type in `AppDeps`

### Every flow file

- [ ] Rate limit called before `db.transaction()` opens
- [ ] `failureCtx` declared and set before every `throw` inside the transaction
- [ ] Success audit called inside `db.transaction().execute()` callback
- [ ] Failure audit called inside `catch` block using bare `deps.auditRepo` (not `.withDb(trx)`)
- [ ] All repo writes inside tx use `.withDb(trx)`
- [ ] Session store / Redis operations happen after transaction commits
- [ ] `txResult` guard: `if (!txResult) throw new Error('...: transaction completed without result')`

### Every repo file

- [ ] `withDb(db: DbExecutor): <Module>Repo` method exists and returns `new <Module>Repo(db)`
- [ ] No `db.transaction()` opened
- [ ] No `AppError` imported or thrown
- [ ] No policy functions called
- [ ] Methods return minimal shapes or `boolean`

### Every policy file

- [ ] No async functions
- [ ] No DB imports
- [ ] No `AppError` construction — uses `<Module>Errors.xxx()` instead
- [ ] Both variants exist: `get<Rule>Failure` (result) and `assert<Rule>` (assertion)

### Audit

- [ ] All new action strings added to `KnownAuditAction` in `src/shared/audit/audit.types.ts`
- [ ] No raw PII (email, token, password) in any audit metadata field
- [ ] No `writer.append(...)` calls in flow files — only in `<module>.audit.ts` helpers

### Tests

- [ ] E2E test covers at least: happy path, auth failure, business rule violation
- [ ] E2E test asserts DB state after happy path (not just HTTP status)
- [ ] E2E test asserts audit event was written on success
- [ ] DAL tests cover repo write methods and query-sql functions
- [ ] Unit tests cover every policy function (both pass and fail cases for every branch)

---

## 11. WHAT A MODULE MUST NOT DO

These are hard prohibitions. A PR that contains any of these is blocked.

| Prohibited pattern                                             | Why it is forbidden                                                                | Correct alternative                                             |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| Controller calls a repo directly                               | Bypasses the service/flow layer; untestable; no audit trail                        | Controller calls service only                                   |
| Service opens a `db.transaction()`                             | Transaction ownership belongs to flows; services stay thin                         | Flow owns the transaction                                       |
| Repo opens a `db.transaction()`                                | Repos are write primitives; they never own scope                                   | Flow owns the transaction                                       |
| Policy imports a repo or calls any async function              | Policies must be synchronously unit-testable; async kills that                     | Keep policies pure; move DB calls to queries                    |
| Flow calls another module's service                            | Creates hidden coupling; breaks layer boundaries                                   | Use the other module's exported query function or repo directly |
| Rate limit called inside `db.transaction()`                    | Rate limiter is Redis; calling it inside a DB tx couples two transactional systems | Call rate limiter before opening the transaction                |
| Success audit called outside `db.transaction()`                | Audit must commit atomically with data mutation                                    | Move audit write inside the transaction callback                |
| Failure audit uses `.withDb(trx)`                              | `trx` is rolled back on failure; the audit would never persist                     | Use bare `deps.auditRepo` in the catch block                    |
| Raw email, token, or password in logger call or audit metadata | Credential leakage; GDPR violation                                                 | Hash first: `emailKey = tokenHasher.hash(email)`                |
| Module creates infra (new Redis, createDb) in `module.ts`      | Infra is DI's job; module.ts is wiring only                                        | Pass infra from DI                                              |
| Import of one module's internal DAL from another module        | Cross-module table coupling; breaks bounded context                                | Use the exporting module's public `index.ts` interface          |
| `any` type cast to suppress TypeScript error                   | Masks real type bugs; `any` is tech debt at a boundary                             | Fix the type; use `unknown` + narrowing if needed               |
| Omitting WHY/RULES header comment                              | Future reader has no context for constraints                                       | Add the header before the first import                          |

---

_End of module-skeleton.md_
_Source: auth-lab codebase v3 (post-review, score 9.4/10)_
_Canonical primary reference: `src/modules/auth/flows/login/execute-login-flow.ts`_
