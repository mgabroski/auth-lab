# backend/docs/engineering-rules.md

# Insynctive Backend — Engineering Rules

_Tier 1 — Global Stable · The implementation law for all backend modules_
_Grounded in auth-lab codebase v3. Applies to every bounded context._
_Update only when ARCHITECTURE.md changes. Rules are numbered for citation in PRs and reviews._

---

## How to use this document

Every rule has a number. Use the number in PR comments: `ER-14: rate limit must precede the transaction`.

Rules are organized by concern. When reviewing a PR, work through each section that applies to the changed files. When writing code, check the relevant sections before opening a PR.

Rules marked **[HARD]** are security or correctness invariants. A PR that violates a [HARD] rule is blocked regardless of other merits.

Rules marked **[ARCH]** are architectural boundaries. Violations require an ADR to override — not a reviewer approval.

All other rules are enforced but may be discussed if a genuine edge case exists. The edge case must be documented in the file header comment of the affected file.

---

## 1. MODULE BOUNDARY RULES

**ER-1** [ARCH] Every module lives in `src/modules/<module-name>/`. No module logic lives in `src/shared/`. `shared/` is for infrastructure primitives only (DB executor, cache, rate limiter, session store, audit writer, outbox). Business logic of any kind does not belong in `shared/`.

**ER-2** [ARCH] A module's internal layers (`dal/`, `queries/`, `policies/`, `flows/`) are private to that module. Other modules MUST NOT import from these paths directly.

```
// FORBIDDEN — imports a module's internal DAL directly
import { findInviteByToken } from '../invites/dal/invite.query-sql';

// CORRECT — uses the module's public surface
import { getInviteByTenantAndTokenHash } from '../invites/queries/invite.queries';
// OR via index.ts if the module exports it there
import { getInviteByTenantAndTokenHash } from '../invites';
```

**ER-3** [ARCH] Every module that is consumed by other modules exposes a public surface via `index.ts`. The `index.ts` exports only what other modules legitimately need. Internal types, policy implementations, and flow functions are not exported unless explicitly required by another module.

Source: `src/modules/tenants/index.ts`, `src/modules/memberships/index.ts`.

**ER-4** Cross-module synchronous reads use the target module's exported query functions (via `index.ts`). Cross-module writes and side effects use the DB outbox. No module calls another module's service directly from inside a flow.

**ER-5** The `src/modules/_shared/use-cases/` folder holds cross-module use cases that are reused by three or more flows. A use case belongs there only when it is a stable, locked contract. Breaking changes to a `_shared` use case require an ADR. Example: `provision-user-to-tenant.usecase.ts`.

---

## 2. IMPORT AND DEPENDENCY RULES

**ER-6** [ARCH] Dependency direction is strictly enforced:

```
routes → controller → service → flow → queries / repos / policies / audit helpers
                                    ↓
                              shared/ (any layer may import shared/)
```

No layer imports from a layer above it. No `shared/` file imports from `modules/`. No `queries/` file imports from `service/` or `flow/`.

**ER-7** All infrastructure types are imported as TypeScript interfaces, not concrete classes. Flows receive `DbExecutor`, `RateLimiter`, `AuditRepo`, `SessionStore` — not `KyselyDatabase`, `RedisCache`, `RedisRateLimiter`.

```typescript
// CORRECT — depends on interface
import type { DbExecutor } from '../../../shared/db/db';
import type { RateLimiter } from '../../../shared/security/rate-limit';

// FORBIDDEN — depends on concrete implementation
import { RedisCache } from '../../../shared/cache/redis-cache';
```

**ER-8** `src/app/di.ts` is the only file that instantiates infrastructure classes. Modules receive deps, never construct them. `src/app/routes.ts` is the only file that calls `module.registerRoutes(app)`.

**ER-9** No `any` type cast to suppress a TypeScript error. Use `unknown` + type narrowing. If a third-party type is genuinely unsound, isolate the cast at the boundary with a comment explaining why.

**ER-10** Circular imports are forbidden. If two modules need to import from each other, the shared type or function belongs in `shared/` or `modules/_shared/`.

---

## 3. LAYER RESPONSIBILITY RULES

### Routes

**ER-11** `<module>.routes.ts` registers endpoints only. It contains zero logic, zero `if` statements, zero imports from `shared/`. Every line is a call to `app.get/post/put/patch/delete(path, controller.method.bind(controller))`.

### Controller

**ER-12** `<module>.controller.ts` is an HTTP adapter. Its responsibilities are exactly: parse input with Zod, extract session with `requireSession()` when auth is required, call one service method, send the reply. Nothing else.

```typescript
// CORRECT
async login(req: FastifyRequest, reply: FastifyReply) {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) throw AppError.validationError('Invalid request body', { issues: parsed.error.issues });

  const { result, sessionId } = await this.authService.login({
    tenantKey: req.requestContext.tenantKey,
    ip: req.ip,
    userAgent: req.headers['user-agent'] ?? null,
    requestId: req.requestContext.requestId,
    ...parsed.data,
  });

  setSessionCookie(reply, sessionId, this.isProduction, this.sessionTtlSeconds);
  return reply.status(200).send(result);
}
```

**ER-13** [HARD] Controllers MUST NOT: access the DB directly, call repos or queries, implement business rules, write audit events, call the session store, or access the rate limiter.

**ER-14** Controllers always use `safeParse`, never `parse`. Raw Zod errors must never propagate to the error handler — the controller catches parse failures and throws `AppError.validationError(...)`.

**ER-15** The controller passes `tenantKey`, `ip`, `userAgent`, and `requestId` from the request context to every service call. These are HTTP concerns — they must not be sourced from any other place.

### Service

**ER-16** `<module>.service.ts` is a thin facade. Every public method calls exactly one flow function and returns the result. No `if`, no `try/catch`, no DB access, no audit writes, no rate limit calls.

**ER-17** The service passes only the subset of `deps` that the flow actually needs. It does not pass `this.deps` blindly.

### Flow

**ER-18** [HARD] Flows own transactions. Services and repos MUST NOT call `db.transaction()`. The flow is the only layer that opens a `db.transaction().execute(async (trx) => { ... })`.

**ER-19** [HARD] Rate limit checks MUST be the first operation in a flow, before `db.transaction()` opens. A rejected request must never open a database transaction.

```typescript
// CORRECT
await deps.rateLimiter.hitOrThrow({ key: `login:email:${emailKey}`, ... });
// Only after rate limit passes:
txResult = await deps.db.transaction().execute(async (trx) => { ... });

// FORBIDDEN — rate limit inside transaction
txResult = await deps.db.transaction().execute(async (trx) => {
  await deps.rateLimiter.hitOrThrow(...); // ← wrong
  ...
});
```

**ER-20** [HARD] Every `throw` inside a `db.transaction().execute()` callback that represents a known failure MUST be preceded by setting `failureCtx`. The catch block uses `failureCtx` to write the failure audit. A throw without `failureCtx` is acceptable only for unexpected errors (infrastructure failures).

```typescript
// CORRECT — failureCtx set before throw
if (!user) {
  failureCtx = {
    tenantId: tenant.id,
    reason: 'user_not_found',
    error: AuthErrors.invalidCredentials(),
  };
  throw failureCtx.error;
}
```

**ER-21** Session store and Redis operations MUST happen after the transaction commits. They must never be called inside `db.transaction().execute()`.

**ER-22** Every flow that may succeed or fail in a domain-meaningful way ends with a guard:

```typescript
if (!txResult) throw new Error('<module>.<action>: transaction completed without result');
```

### Policy

**ER-23** Policy functions MUST be pure: no async operations, no DB imports, no HTTP imports, no side effects. They are synchronously unit-testable without any infrastructure.

**ER-24** Every policy implements two variants:

- Result variant: `get<Rule>Failure(input) → failure | null` — returns the failure payload so the flow can set `failureCtx.reason` before throwing
- Assertion variant: `assert<Rule>(input): asserts input is Narrowed` — throws and narrows the TypeScript type

Source: `src/modules/auth/policies/login-membership-gating.policy.ts`.

**ER-25** Policies import only from `<module>.errors.ts` and from TypeScript. No imports from repos, queries, services, or `shared/` infrastructure.

### Queries

**ER-26** `<module>.queries.ts` is read-only. It shapes DB rows into domain types defined in `<module>.types.ts`. It MUST NOT contain INSERT, UPDATE, or DELETE.

**ER-27** Query functions return `null` (or an empty array) when a record is not found. They never throw `AppError`. The flow or policy layer decides what a missing record means.

**ER-28** Query functions accept `DbExecutor` — they work with both `db` and `trx`. They never call `db.transaction()`.

### Repo

**ER-29** `<module>.repo.ts` contains write operations only: INSERT, UPDATE, DELETE. No SELECT queries belong in a repo file.

**ER-30** [HARD] Every repo class MUST implement `withDb(db: DbExecutor): <Module>Repo` that returns a new instance bound to the given executor. This is the transaction-binding mechanism.

```typescript
withDb(db: DbExecutor): AuthRepo {
  return new AuthRepo(db); // new instance — never mutates this.db
}
```

**ER-31** Repos MUST NOT open transactions, import `AppError`, or call policies.

**ER-32** Repo write methods return minimal shapes: `{ id: string }` for inserts, `boolean` for conditional updates (true = updated, false = guard condition not met). They do not return full domain objects.

---

## 4. TRANSACTION RULES

**ER-33** [HARD] All repo writes that are causally related MUST execute inside the same transaction. A flow that inserts two rows without a transaction has a correctness bug if either write can fail independently.

**ER-34** [HARD] Every repo write inside `db.transaction().execute()` MUST use `.withDb(trx)`. Calling a repo write without `.withDb(trx)` inside a transaction runs outside the transaction silently — this is a correctness bug with no compiler error.

```typescript
// CORRECT — bound to transaction
await deps.inviteRepo.withDb(trx).markAccepted({ inviteId: invite.id, usedAt: now });
await deps.auditRepo.withDb(trx).append({ ... });

// FORBIDDEN — runs outside transaction
await deps.inviteRepo.markAccepted({ inviteId: invite.id, usedAt: now });
```

**ER-35** Token consumption MUST be atomic. One-time-use tokens are consumed with a single `UPDATE ... WHERE used_at IS NULL AND expires_at > now() RETURNING`. Never check-then-update.

```typescript
// CORRECT — atomic consumption
const row = await this.db
  .updateTable('password_reset_tokens')
  .set({ used_at: params.now })
  .where('token_hash', '=', params.tokenHash)
  .where('used_at', 'is', null)
  .where('expires_at', '>', params.now)
  .returning(['user_id'])
  .executeTakeFirst();
if (!row) return null; // token missing, expired, or already used
```

Source: `src/modules/auth/dal/auth.repo.ts` — `consumeResetTokenAtomic`.

**ER-36** Idempotency guards on status transitions MUST use a `WHERE` condition on the current state:

```typescript
// CORRECT — guard prevents double-activation
.where('status', '=', 'INVITED')
.executeTakeFirst();
const updated = Number(res?.numUpdatedRows ?? 0) > 0;
```

Source: `src/modules/memberships/dal/membership.repo.ts` — `activateMembership`.

---

## 5. AUDIT RULES

**ER-37** [HARD] Every flow that mutates state MUST have both a success audit and a failure audit.

**ER-38** [HARD] Success audits MUST be written inside `db.transaction().execute()`. They commit atomically with the data mutation. A success audit written outside the transaction can persist even if the data mutation rolls back.

**ER-39** [HARD] Failure audits MUST be written in the `catch` block using the bare `deps.auditRepo` — NOT `deps.auditRepo.withDb(trx)`. The transaction has been rolled back when the catch block executes. Using `.withDb(trx)` would lose the audit.

```typescript
catch (err) {
  if (failureCtx) {
    const failAudit = new AuditWriter(deps.auditRepo, { // bare — not withDb(trx)
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    }).withContext({ tenantId: ctx.tenantId, userId: ctx.userId ?? null, membershipId: null });

    await auditActionFailed(failAudit, { reason: ctx.reason });
  }
  throw err;
}
```

**ER-40** [HARD] No raw PII in any audit metadata field or logger call. Always hash identifiers first.

```typescript
// FORBIDDEN
await writer.append('auth.login.failed', { email: params.email });

// CORRECT
const emailKey = deps.tokenHasher.hash(params.email.toLowerCase());
await auditLoginFailed(writer, { emailKey, reason: 'wrong_password' });
```

Hashed field naming convention: `email → emailKey`, `ip → ipKey`, `token → tokenHash`.

**ER-41** Flow files MUST NOT call `writer.append()` directly. All audit writes go through typed helper functions defined in `<module>.audit.ts`. This ensures consistent metadata shapes per action.

```typescript
// FORBIDDEN in a flow file
await audit.append('auth.login.success', { userId: user.id, membershipId: membership.id });

// CORRECT — typed helper
await auditLoginSuccess(audit, {
  userId: user.id,
  membershipId: membership.id,
  role: membership.role,
});
```

**ER-42** Every new audit action string used in `<module>.audit.ts` MUST be added to `KnownAuditAction` in `src/shared/audit/audit.types.ts`. The escape hatch `AuditAction = KnownAuditAction | (string & {})` is intentional and currently active — it prevents commits from being blocked during development. The convention is: new action strings are added to the union even with the hatch open.

**ER-43** The `AuditWriter` is enriched progressively in the flow:

```typescript
// Stage 1: start of request (inside tx callback)
const audit = new AuditWriter(deps.auditRepo.withDb(trx), { requestId, ip, userAgent });

// Stage 2: after tenant resolved
const tenantAudit = audit.withContext({ tenantId: tenant.id });

// Stage 3: after user + membership resolved
const fullAudit = tenantAudit.withContext({ userId: user.id, membershipId: membership.id });
```

Each `.withContext()` call returns a new immutable writer. Never mutate an existing writer.

---

## 6. RATE LIMIT RULES

**ER-44** [HARD] Rate limit checks MUST precede the first DB operation in every mutation flow. See ER-19.

**ER-45** Rate limit configurations are defined in `<module>.constants.ts` as a typed `as const` object. Inline numbers in flow files are forbidden.

```typescript
// CORRECT — single source of truth
export const AUTH_RATE_LIMITS = {
  login: {
    perEmail: { limit: 5, windowSeconds: 900 },
    perIp: { limit: 20, windowSeconds: 900 },
  },
} as const;
```

**ER-46** Rate limit key format: `<module>.<action>:<dimension>:<hashedValue>`. The value in the key is always a hash — never a raw email, IP, user ID, or token.

```typescript
// CORRECT
const emailKey = deps.tokenHasher.hash(email.toLowerCase());
await deps.rateLimiter.hitOrThrow({ key: `login:email:${emailKey}`, ...RATE_LIMITS.login.perEmail });

// FORBIDDEN — raw PII in key
await deps.rateLimiter.hitOrThrow({ key: `login:email:${email}`, ... });
```

**ER-47** Use `hitOrThrow` when a 429 response is the correct outcome (login, register, admin actions, MFA verify). Use `hitOrSkip` when the endpoint must always return 200 regardless of the rate limit state (forgot-password, resend-verification). With `hitOrSkip`, check the return value and skip the side-effecting work when it returns `false`.

Source: `src/shared/security/rate-limit.ts` — `hitOrThrow` vs `hitOrSkip` documentation.

**ER-48** The rate limiter is disabled in test environments via `disabled: config.nodeEnv === 'test'` in `src/app/di.ts`. Tests must not attempt to manually bypass rate limits. Do not add `nodeEnv` checks inside application code — the DI wiring handles environment-specific behavior at the composition root.

---

## 7. TENANT ISOLATION RULES

**ER-49** [HARD] Every DB query on tenant-owned data MUST include a `tenant_id` WHERE clause. There are no exceptions. A query that returns rows without scoping to a tenant is a tenant isolation violation.

```typescript
// CORRECT
.selectFrom('invites')
.where('tenant_id', '=', params.tenantId)
.where('id', '=', params.inviteId)

// FORBIDDEN — no tenant scope
.selectFrom('invites')
.where('id', '=', params.inviteId)
```

**ER-50** [HARD] Cross-tenant access returns 404, not 403. A 403 leaks the existence of a resource in another tenant. A 404 treats the resource as if it does not exist from the requester's perspective.

**ER-51** [HARD] Session tenant binding is enforced in `src/shared/session/session.middleware.ts`. The middleware silently rejects sessions where `session.tenantKey !== req.requestContext.tenantKey`. This is the second layer of tenant enforcement (the first being the `tenant_id` WHERE clause). Do not weaken or bypass either layer.

**ER-52** Tenant is always resolved from the URL subdomain via `req.requestContext.tenantKey`. Tenant identity must never be accepted from the request body, query string, or headers. The request context is set by `src/shared/http/request-context.ts` from the `Host` header — it is not user-controlled.

---

## 8. OUTBOX AND ASYNC RULES

**ER-53** [HARD] All side-effecting async operations (email sending, webhook delivery, external API calls) MUST use the DB outbox pattern. Fire-and-forget in-memory queues are forbidden for any operation where loss is unacceptable.

**ER-54** [HARD] Outbox messages MUST be enqueued inside the same transaction as the data mutation that triggers them. An outbox row enqueued outside the transaction can persist even if the triggering transaction rolls back — or be lost if the transaction commits but the enqueue fails.

```typescript
// CORRECT — enqueue inside transaction
txResult = await deps.db.transaction().execute(async (trx) => {
  const invite = await deps.inviteRepo.withDb(trx).insertInvite({ ... });
  await deps.outboxRepo.enqueueWithinTx(trx, { type: 'invite.created', payload: encryptedPayload });
  await auditInviteCreated(audit, { ... });
  return invite;
});
```

**ER-55** [HARD] Outbox payloads MUST NOT contain raw tokens, raw email addresses, or plaintext secrets. Encrypt before storing. The `OutboxEncryption` service handles payload encryption. The outbox worker decrypts at delivery time.

```typescript
// CORRECT — encrypt payload before enqueue
const encryptedPayload = deps.outboxEncryption.encryptPayload({
  token: rawToken,
  toEmail: email,
  tenantKey: params.tenantKey,
});
// payload in DB contains tokenEnc + toEmailEnc — never plaintext
```

**ER-56** The outbox worker (`src/shared/outbox/outbox.worker.ts`) claims a batch of rows, sends outside the transaction, and finalizes with an ownership guard (`locked_by = workerId`). The worker MUST NOT contain business logic. It is infrastructure only. All domain logic lives in the flow that enqueued the message.

**ER-57** `shared/messaging/` (in-memory queue) exists only as a test double and early prototype. It MUST NOT be used for any feature that has been moved to the outbox. Do not add new uses of the in-memory queue.

---

## 9. SECURITY RULES

**ER-58** [HARD] Passwords are hashed with bcrypt (cost ≥ 12) before storage. Raw passwords are never stored, never logged, never returned in responses.

**ER-59** [HARD] Invite tokens, password reset tokens, and email verification tokens are stored as SHA-256 hashes only. The raw token is sent once (in an email) and never stored.

**ER-60** [HARD] MFA recovery codes are stored as HMAC-SHA256 hashes with a server-side pepper key. Plain SHA-256 is insufficient for 82-bit entropy values.

**ER-61** [HARD] TOTP secrets and SSO state payloads are encrypted with AES-256-GCM. A random IV is generated per encryption. The auth tag is validated on decrypt. Key material lives in environment config — never in source code.

**ER-62** [HARD] Error messages for ambiguous conditions (wrong password, nonexistent user, SSO-only user trying password login) MUST use a single vague message. Separate error messages create oracle attacks.

```typescript
// CORRECT — one message for multiple conditions
invalidCredentials() { return AppError.unauthorized('Invalid email or password.'); }

// FORBIDDEN — separate messages reveal which condition triggered
userNotFound() { return AppError.notFound('No account with that email.'); }
wrongPassword() { return AppError.unauthorized('Incorrect password.'); }
```

**ER-63** The `src/shared/http/error-handler.ts` redacts sensitive meta keys before logging. Do not add raw token/password fields to `AppError` meta objects — but if you do, add the field name to `SENSITIVE_META_KEYS` in the error handler.

**ER-64** SSO return-to URLs are validated before use. Only relative paths starting with `/` (not `//`) are accepted. This prevents open-redirect attacks. See `isSafeReturnTo` in `src/modules/auth/auth.controller.ts`.

---

## 10. CROSS-MODULE INTERACTION RULES

**ER-65** [ARCH] A module's flow MUST NOT call another module's service. Cross-module synchronous reads use the target module's exported query functions.

```typescript
// CORRECT — use exported query
import { getMembershipByTenantAndUser } from '../../memberships';

// FORBIDDEN — calls another module's service from inside a flow
import { MembershipService } from '../../memberships/membership.service';
const membership = await this.deps.membershipService.getForTenant(...); // ← wrong
```

**ER-66** Cross-module async side effects use the DB outbox. A module that needs to trigger work in another bounded context enqueues an outbox message. The receiving module's worker (or a shared worker) processes it.

**ER-67** When a flow needs a cross-module write that must be transactionally consistent with its own write, the cross-module repo must accept a `trx`-bound executor via `.withDb(trx)`. This is only valid for repos belonging to modules in the same database. For future extracted modules, the outbox is the only option.

**ER-68** The `modules/_shared/use-cases/` pattern is for stable, widely reused cross-module orchestration. Before adding a use case there, confirm it is used by at minimum three different flows. Single-module use cases belong in `flows/` within that module.

---

## 11. TESTING RULES

**ER-69** Every mutation endpoint MUST have an E2E test that:

- Verifies the correct HTTP status and response body on the happy path
- Asserts DB state after the request (not just HTTP status)
- Asserts that an audit row was written with the correct `action` and meaningful metadata
- Tests at least one auth failure (missing session, wrong role) → 401/403
- Tests each business rule from the module spec → correct error status

**ER-70** Every policy function MUST have unit tests covering every branch: the pass case and each distinct fail reason.

**ER-71** Every repo write method and query-sql function MUST have a DAL test that inserts seed data and asserts the returned shape.

**ER-72** E2E tests use `buildTestApp()` from `test/helpers/build-test-app.ts`. They do not start a real HTTP server — they use Fastify's `inject()`. They do not mock the database — they use the test Postgres instance with `resetDb()` between tests.

**ER-73** Rate limits are disabled in the test environment (see ER-48). Tests MUST NOT attempt to re-enable them mid-test or call rate limit keys directly.

**ER-74** Tests that verify tenant isolation (session-cookie-from-tenant-A rejected on tenant-B) MUST exist for any module that involves sessions. These are security tests and are never optional. Source: `test/e2e/tenant-isolation.spec.ts`.

**ER-75** Test files MUST use UUID-keyed tenant seeds to prevent cross-test contamination. Never hardcode tenant keys like `'acme'` or `'test'` in test helpers — always `randomUUID().slice(0, 8)`.

---

## 12. FILE HEADER RULES

**ER-76** Every file in every module MUST begin with a WHY/RULES header comment. The WHY block states why this file exists. The RULES block states what is forbidden here.

```typescript
/**
 * src/modules/<module>/<path>/<file>.ts
 *
 * WHY:
 * - [what this file does and why it belongs here]
 *
 * RULES:
 * - [what is forbidden — not allowed to do X, Y, Z]
 */
```

**ER-77** When a file is changed by a later "brick" or PR to add new behavior, add an update note to the header:

```typescript
 * BRICK 11 UPDATE:
 * - Added emailVerified field to login result.
```

---

## 13. MIGRATION RULES

**ER-78** Migrations are immutable. A migration that has been applied to any environment (dev, staging, production) MUST NOT be edited. Add a new migration instead.

**ER-79** Every migration file has both `up()` and `down()`.

**ER-80** Migration files are numbered sequentially: `NNNN_<description>.ts`. The next number is one greater than the current highest. Never reuse a number.

**ER-81** After adding a migration, run `yarn db:migrate` then `yarn db:types` to regenerate `src/shared/db/database.types.ts`. Commit the regenerated types in the same PR as the migration.

---

## 14. PROHIBITED PATTERNS TABLE

| Pattern                                     | Rule         | Why forbidden                                          | Correct alternative                             |
| ------------------------------------------- | ------------ | ------------------------------------------------------ | ----------------------------------------------- |
| Controller calls repo directly              | ER-13        | Bypasses service/flow; no audit                        | Controller → service → flow → repo              |
| Service opens `db.transaction()`            | ER-18        | Transaction ownership belongs to flows                 | Flow opens the transaction                      |
| Repo opens `db.transaction()`               | ER-18        | Repos are write primitives                             | Flow opens the transaction                      |
| Rate limit inside transaction               | ER-19, ER-44 | Couples Redis and DB transactions                      | Rate limit before `db.transaction()`            |
| Success audit outside transaction           | ER-38        | Audit may persist if data rolls back                   | Move audit inside `db.transaction()`            |
| Failure audit uses `.withDb(trx)`           | ER-39        | `trx` is rolled back; audit lost                       | Use bare `deps.auditRepo` in catch              |
| Repo write without `.withDb(trx)` inside tx | ER-34        | Write silently escapes transaction                     | Always `.withDb(trx)` inside tx                 |
| Raw PII in logger or audit metadata         | ER-40        | GDPR + credential leakage                              | Hash first: `tokenHasher.hash(value)`           |
| `writer.append()` called in flow            | ER-41        | Inconsistent metadata shapes                           | Use typed helper in `<module>.audit.ts`         |
| Cross-module internal DAL import            | ER-2, ER-65  | Hidden coupling, boundary violation                    | Use target module's `index.ts`                  |
| Business logic in `shared/`                 | ER-1         | `shared/` is infrastructure only                       | Move to module `flows/` or `policies/`          |
| Outbox payload with raw token/email         | ER-55        | Credential leakage in DB                               | Encrypt with `OutboxEncryption` before enqueue  |
| Outbox enqueue outside transaction          | ER-54        | Message survives rollback or is lost on commit failure | Enqueue inside same transaction                 |
| Module creates infra in `module.ts`         | ER-8         | Infra creation belongs in `di.ts`                      | Pass infra from DI                              |
| `any` type cast to suppress error           | ER-9         | Masks real type bugs                                   | Fix the type; use `unknown` + narrowing         |
| Check-then-update token consumption         | ER-35        | Race condition allows replay                           | Atomic `UPDATE WHERE used_at IS NULL RETURNING` |
| Policy imports a repo or async call         | ER-23, ER-25 | Policies must be synchronously testable                | Keep policies pure; DB calls go in queries      |
| Hardcoded tenant key in test                | ER-75        | Cross-test contamination                               | `randomUUID().slice(0, 8)` for all seed keys    |
| Fire-and-forget in-memory queue for email   | ER-53        | Lost on restart, not multi-instance safe               | DB outbox pattern                               |

---

## 15. PR AND CI FITNESS CHECKS

Before marking a PR ready for review, the author verifies:

**Code correctness:**

- [ ] `yarn lint` passes with zero errors
- [ ] `yarn typecheck` passes with zero errors
- [ ] `yarn test` passes with zero failures

**Layer rules (check each changed file):**

- [ ] Routes file: zero logic, only `app.method(path, controller.method.bind(controller))`
- [ ] Controller: no DB access, no business rules, `safeParse` not `parse`
- [ ] Service: every method is a one-liner delegating to a flow
- [ ] Flow: rate limit before `db.transaction()`, `failureCtx` set before every failure throw
- [ ] Success audit inside transaction, failure audit in catch using bare `deps.auditRepo`
- [ ] All repo writes inside tx use `.withDb(trx)`
- [ ] Policy: no async, no DB imports, both variants (result + assertion) present

**Security:**

- [ ] No raw email/token/password in any log call or audit metadata
- [ ] Token consumption uses `UPDATE WHERE used_at IS NULL RETURNING` pattern
- [ ] Every tenant-scoped query includes `WHERE tenant_id = ...`
- [ ] Rate limit uses hashed key, not raw PII

**Audit completeness:**

- [ ] All new action strings added to `KnownAuditAction` in `src/shared/audit/audit.types.ts`
- [ ] Both success and failure audits exist for every mutation flow

**Outbox:**

- [ ] If this flow sends email: outbox enqueue is inside the transaction
- [ ] Outbox payload uses `OutboxEncryption` — no raw token or email in DB

**Tests:**

- [ ] E2E: happy path with DB assertion and audit assertion
- [ ] E2E: auth failure (401/403), each business rule violation
- [ ] Unit: every policy branch covered
- [ ] DAL: repo writes and query-sql functions covered

**Wiring:**

- [ ] New module registered in `src/app/di.ts`
- [ ] `module.registerRoutes(app)` called in `src/app/routes.ts`
- [ ] New audit actions in `KnownAuditAction`

---

_End of engineering-rules.md_
_Tier 1 — Global Stable. Cite rule numbers in PR comments. Update only on ARCHITECTURE.md change._
