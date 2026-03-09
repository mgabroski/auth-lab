# backend/docs/engineering-rules.md

# Insynctive Backend — Engineering Rules

_Tier 1 — Global Stable · The single source of truth for backend implementation law_
_Grounded in auth-lab codebase v3. Applies to every bounded context._
_This is the only authoritative implementation rules file. If any other document_
_conflicts with this one, this document wins._

_Update only when `ARCHITECTURE.md` changes. Rules are numbered for citation in PRs and reviews._

---

## How to use this document

Every rule has a number. Use the number in PR comments and review findings: `ER-14: rate limit must precede the transaction`.

Rules are organized by concern. When reviewing a PR, work through each section that applies to the changed files. When writing code, check the relevant sections before opening a PR.

Rules marked **[HARD]** are security or correctness invariants. A PR that violates a [HARD] rule is blocked regardless of other merits.

Rules marked **[ARCH]** are architectural boundaries. Violations require an ADR to override — not a reviewer approval.

All other rules are enforced but may be discussed if a genuine edge case exists. The edge case must be documented in the file header comment of the affected file.

**On known legacy violations:** The current auth/user-provisioning module contains violations of ER-2, ER-16, and ER-18 that predate this document. These are tracked and must be corrected before introducing new modules. New code must not add to these violations.

---

## 1. MODULE BOUNDARY RULES

**ER-1** [ARCH] Every module lives in `src/modules/<module-name>/`. No module logic lives in `src/shared/`. `shared/` is for infrastructure primitives only: DB executor, cache, rate limiter, session store, audit writer, outbox. Business logic of any kind does not belong in `shared/`.

**ER-2** [ARCH] A module's internal layers (`dal/`, `queries/`, `policies/`, `flows/`, `use-cases/`, `helpers/`) are private to that module. Other modules MUST NOT import from these paths directly.

```typescript
// FORBIDDEN — imports a module's internal DAL directly
import { findInviteByToken } from '../invites/dal/invite.query-sql';
import { getMfaSecretForUser } from '../auth/queries/mfa.queries';

// CORRECT — uses the module's public surface via index.ts
import { getInviteByTenantAndTokenHash } from '../invites';
import { getMfaStatusForUser } from '../auth';
```

**ER-3** [ARCH] Every module consumed by other modules exposes a public surface via `index.ts`. The `index.ts` exports only what other modules legitimately need. Internal types, policy implementations, dal functions, and flow functions are not exported unless explicitly required by another module.

Sources: `src/modules/tenants/index.ts`, `src/modules/memberships/index.ts`.

**ER-4** Cross-module synchronous reads use the target module's exported query functions via `index.ts`. Cross-module writes and side effects use the DB outbox. No module calls another module's service directly from inside a flow.

**ER-5** The `src/modules/_shared/use-cases/` folder holds cross-module use cases that are reused by three or more flows. A use case belongs there only when it is a stable, locked contract. Breaking changes to a `_shared` use case require an ADR.

> **Current exception:** `provision-user-to-tenant.usecase.ts` in `_shared` currently imports from internal DAL paths of `users/` and `memberships/`. This is a known legacy violation. New `_shared` use cases must not repeat this pattern — they must depend on stable `index.ts` exports only.

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

**ER-12** `<module>.controller.ts` is an HTTP adapter. Its core responsibilities are: validate the request with Zod, apply HTTP-context guards, extract session when auth is required, call one service method, send the reply.

**HTTP-context guards are allowed in controllers.** These are functions that enforce HTTP-layer invariants — not domain logic — such as:

- `requireTenantKey()` — asserts the subdomain resolved a tenant before the service is called
- `isSafeReturnTo()` — validates a redirect parameter stays on the same origin (open-redirect prevention)

These guards are correctly placed in the controller because they operate on HTTP request context, not on domain objects. They must remain pure, synchronous, and free of DB access.

```typescript
// CORRECT — HTTP-context guards in controller
function requireTenantKey(tenantKey: string | null | undefined): string {
  if (!tenantKey) throw AppError.validationError('Missing tenant context');
  return tenantKey;
}

function isSafeReturnTo(value: string): boolean {
  return value.startsWith('/') && !value.startsWith('//');
}
```

**ER-13** [HARD] Controllers MUST NOT: access the DB directly, call repos or queries, implement domain business rules, write audit events, call the session store, or call the rate limiter.

**ER-14** Controllers always use `safeParse`, never `parse`. Raw Zod errors must never propagate to the error handler — the controller catches parse failures and throws `AppError.validationError(...)`.

**ER-15** The controller passes `tenantKey`, `ip`, `userAgent`, and `requestId` from the request context to every service call. These are HTTP concerns — they must not be sourced from any other place.

### Service — mutation flows

**ER-16** For **mutation endpoints** (any endpoint that writes to the DB, writes an audit event, calls the rate limiter, or enqueues outbox messages), the service is a thin facade. Every public method for a mutation endpoint calls exactly one flow function and returns the result. No `if`, no `try/catch`, no DB access, no audit writes, no rate limit calls in the service body.

```typescript
// CORRECT — mutation service is a one-liner
async login(params: LoginParams): Promise<{ result: AuthResult; sessionId: string }> {
  return executeLoginFlow(
    { db: this.deps.db, rateLimiter: this.deps.rateLimiter, auditRepo: this.deps.auditRepo, ... },
    params,
  );
}

// FORBIDDEN for mutation endpoints — service owns the transaction
async acceptInvite(params: AcceptInviteParams) {
  await this.deps.rateLimiter.hitOrThrow(...); // ← belongs in the flow
  return this.deps.db.transaction().execute(async (trx) => { ... }); // ← belongs in the flow
}
```

### Service — read-only paths

**ER-16b** For **read-only service methods** (no DB writes, no audit events, no rate limiting, no outbox messages), the service may delegate directly to query functions without a flow layer. This is valid because there is no transaction boundary to manage and no two-phase audit to coordinate.

```typescript
// CORRECT — read-only service delegates to queries directly
async listEvents(params: ListAuditEventsParams): Promise<ListAuditEventsResult> {
  const [events, total] = await Promise.all([
    listAuditEvents(this.deps.db, { ...params }),
    countAuditEvents(this.deps.db, { ...params }),
  ]);
  return { events, total, limit: params.limit, offset: params.offset };
}
```

Source: `src/modules/audit/admin-audit.service.ts`.

**ER-17** The service passes only the subset of `deps` that the flow actually needs. It does not pass `this.deps` as a whole object.

### Flow

**ER-18** [HARD] Flows own transactions. Services and repos MUST NOT call `db.transaction()`. The flow file is the only layer that opens a `db.transaction().execute(async (trx) => { ... })`.

The definition of "flow" for this rule: any mutation that requires a transaction. If a service method owns rate limiting, a transaction, and audit writing, it is a flow that has not yet been extracted. Extract it.

> **Known violations:** `src/modules/invites/invite.service.ts` and `src/modules/invites/admin/admin-invite.service.ts` currently own their own transactions. These are tracked for correction. `src/modules/auth/auth.service.ts` (startSso and logout methods) similarly contains orchestration that belongs in flow files.

**ER-19** [HARD] Rate limit checks MUST be the first operation in a flow, before `db.transaction()` opens. A rejected request must never open a database transaction.

```typescript
// CORRECT
await deps.rateLimiter.hitOrThrow({ key: `login:email:${emailKey}`, ... });
txResult = await deps.db.transaction().execute(async (trx) => { ... });

// FORBIDDEN — rate limit inside transaction
txResult = await deps.db.transaction().execute(async (trx) => {
  await deps.rateLimiter.hitOrThrow(...); // ← wrong
});
```

**ER-20** [HARD] Every `throw` inside a `db.transaction().execute()` callback that represents a known domain failure MUST be preceded by setting `failureCtx`. The catch block uses `failureCtx` to write the failure audit.

```typescript
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

**ER-22** Every flow ends with a null result guard after the try/catch:

```typescript
if (!txResult) throw new Error('<module>.<action>: transaction completed without result');
```

### Policy

**ER-23** Policy functions MUST be pure: no async operations, no DB imports, no HTTP imports, no side effects. They are synchronously unit-testable without any infrastructure.

**ER-24** Every policy implements two variants:

- **Result variant:** `get<Rule>Failure(input) → failure | null` — returns the failure payload so the flow can set `failureCtx.reason` before throwing
- **Assertion variant:** `assert<Rule>(input): asserts input is Narrowed` — throws and narrows the TypeScript type

Source: `src/modules/auth/policies/login-membership-gating.policy.ts`.

**ER-25** Policies import only from `<module>.errors.ts`, from TypeScript built-ins, and from `src/shared/utils/`. No imports from repos, queries, services, or other modules.

> **Known violation:** `src/modules/tenants/policies/tenant-access.policy.ts` imports `emailDomain()` from `src/modules/auth/helpers/email-domain`. This violates ER-25 and contradicts its own file header. Fix: move `emailDomain()` to `src/shared/utils/email-domain.ts`. Tracked for correction.

### Queries

**ER-26** `<module>.queries.ts` is read-only. It shapes DB rows into domain types defined in `<module>.types.ts`. It MUST NOT contain INSERT, UPDATE, or DELETE.

**ER-27** Query functions return `null` (or an empty array) when a record is not found. They never throw `AppError`. The flow or policy layer decides what a missing record means.

**ER-28** Query functions accept `DbExecutor` — they work with both `db` and `trx`. They never call `db.transaction()`.

### Repo

**ER-29** `<module>.repo.ts` contains write operations only: INSERT, UPDATE, DELETE. No SELECT queries belong in a repo file.

**ER-30** [HARD] Every repo class MUST implement `withDb(db: DbExecutor): <Module>Repo` that returns a new instance bound to the given executor.

```typescript
withDb(db: DbExecutor): AuthRepo {
  return new AuthRepo(db); // new instance — never mutates this.db
}
```

**ER-31** Repos MUST NOT open transactions, import `AppError`, or call policies.

**ER-32** Repo write methods return minimal shapes: `{ id: string }` for inserts, `boolean` for conditional updates (true = updated, false = guard condition not met).

---

## 4. TRANSACTION RULES

**ER-33** [HARD] All repo writes that are causally related MUST execute inside the same transaction. A flow that inserts two rows without a transaction has a correctness bug if either write can fail independently.

**ER-34** [HARD] Every repo write inside `db.transaction().execute()` MUST use `.withDb(trx)`. Calling a repo write without `.withDb(trx)` inside a transaction runs outside the transaction silently — no compiler error, silent correctness bug.

```typescript
// CORRECT — bound to transaction
await deps.inviteRepo.withDb(trx).markAccepted({ inviteId: invite.id, usedAt: now });

// FORBIDDEN — runs outside transaction
await deps.inviteRepo.markAccepted({ inviteId: invite.id, usedAt: now });
```

**ER-35** Token consumption MUST be atomic. One-time-use tokens are consumed with a single `UPDATE ... WHERE used_at IS NULL AND expires_at > now() RETURNING`. Never check-then-update.

```typescript
// CORRECT — atomic consumption prevents replay
const row = await this.db
  .updateTable('password_reset_tokens')
  .set({ used_at: params.now })
  .where('token_hash', '=', params.tokenHash)
  .where('used_at', 'is', null)
  .where('expires_at', '>', params.now)
  .returning(['user_id'])
  .executeTakeFirst();
if (!row) return null;
```

**ER-36** State transition updates MUST use a `WHERE` condition on the current state as an idempotency guard:

```typescript
// CORRECT — guard prevents double-transition
.where('status', '=', 'INVITED')
.executeTakeFirst();
const updated = Number(res?.numUpdatedRows ?? 0) > 0;
```

---

## 5. AUDIT RULES

**ER-37** [HARD] Every flow that mutates state MUST have both a success audit and a failure audit.

**ER-38** [HARD] Success audits MUST be written inside `db.transaction().execute()`. They commit atomically with the data mutation.

**ER-39** [HARD] Failure audits MUST be written in the `catch` block using the bare `deps.auditRepo` — NOT `deps.auditRepo.withDb(trx)`. The transaction is rolled back when the catch block runs.

```typescript
catch (err) {
  if (failureCtx) {
    const failAudit = new AuditWriter(deps.auditRepo, { // bare — not .withDb(trx)
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    }).withContext({ tenantId: ctx.tenantId, userId: ctx.userId ?? null, membershipId: null });
    await auditActionFailed(failAudit, { reason: ctx.reason });
  }
  throw err;
}
```

**ER-40** [HARD] No raw PII in any audit metadata field or logger call. Always hash identifiers first. Convention: `email → emailKey`, `ip → ipKey`, `token → tokenHash`.

**ER-41** Flow files MUST NOT call `writer.append()` directly. All audit writes go through typed helper functions defined in `<module>.audit.ts`.

```typescript
// FORBIDDEN in a flow file
await audit.append('auth.login.success', { userId: user.id });

// CORRECT — typed helper
await auditLoginSuccess(audit, {
  userId: user.id,
  membershipId: membership.id,
  role: membership.role,
});
```

**ER-42** Every new audit action string used in `<module>.audit.ts` MUST be added to `KnownAuditAction` in `src/shared/audit/audit.types.ts`. The escape hatch `AuditAction = KnownAuditAction | (string & {})` is intentional and currently active. The convention remains: add every known action to the union even with the hatch open.

**ER-43** The `AuditWriter` is enriched progressively in the flow:

```typescript
// Stage 1 — inside tx, bound to trx
const audit = new AuditWriter(deps.auditRepo.withDb(trx), { requestId, ip, userAgent });

// Stage 2 — after tenant resolved
const tenantAudit = audit.withContext({ tenantId: tenant.id });

// Stage 3 — after user + membership resolved
const fullAudit = tenantAudit.withContext({ userId: user.id, membershipId: membership.id });
```

Each `.withContext()` returns a new immutable writer. Never mutate an existing writer.

---

## 6. RATE LIMIT RULES

**ER-44** [HARD] Rate limit checks MUST precede the first DB operation in every mutation flow. See ER-19.

**ER-45** Rate limit configurations are defined in `<module>.constants.ts` as a typed `as const` object. Inline numbers in flow files are forbidden.

```typescript
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

**ER-47** Use `hitOrThrow` when a 429 response is the correct outcome. Use `hitOrSkip` when the endpoint must always return 200 regardless of the rate limit (forgot-password, resend-verification patterns). With `hitOrSkip`, check the return value and skip the side-effecting work when it returns `false`.

**ER-48** The rate limiter is disabled in test environments via `disabled: config.nodeEnv === 'test'` in `src/app/di.ts`. Do not add `nodeEnv` checks inside application code. The DI wiring handles environment-specific behavior at the composition root.

---

## 7. TENANT ISOLATION RULES

**ER-49** [HARD] Every DB query on tenant-owned data MUST include a `tenant_id` WHERE clause. A query that returns rows without scoping to a tenant is a tenant isolation violation.

```typescript
// CORRECT
.selectFrom('invites')
.where('tenant_id', '=', params.tenantId)
.where('id', '=', params.inviteId)

// FORBIDDEN — no tenant scope
.selectFrom('invites')
.where('id', '=', params.inviteId)
```

**ER-50** [HARD] Cross-tenant access returns 404, not 403. A 403 leaks the existence of a resource in another tenant.

**ER-51** [HARD] Session tenant binding is enforced in `src/shared/session/session.middleware.ts`. The middleware silently rejects sessions where `session.tenantKey !== req.requestContext.tenantKey`. Do not weaken or bypass this check.

**ER-52** Tenant is always resolved from the URL subdomain via `req.requestContext.tenantKey`. Tenant identity must never be accepted from the request body, query string, or headers.

---

## 8. OUTBOX AND ASYNC RULES

**ER-53** [HARD] All side-effecting async operations (email sending, webhook delivery, external API calls) MUST use the DB outbox pattern. Fire-and-forget in-memory queues are forbidden for any operation where loss is unacceptable.

**ER-54** [HARD] Outbox messages MUST be enqueued inside the same transaction as the data mutation that triggers them.

```typescript
// CORRECT — enqueue inside transaction
txResult = await deps.db.transaction().execute(async (trx) => {
  const invite = await deps.inviteRepo.withDb(trx).insertInvite({ ... });
  await deps.outboxRepo.enqueueWithinTx(trx, { type: 'invite.created', payload: encryptedPayload });
  await auditInviteCreated(audit, { ... });
  return invite;
});
```

**ER-55** [HARD] Outbox payloads MUST NOT contain raw tokens, raw email addresses, or plaintext secrets. Encrypt before storing using `OutboxEncryption`. The worker decrypts at delivery time.

**ER-56** The outbox worker (`src/shared/outbox/outbox.worker.ts`) MUST NOT contain business logic. It is infrastructure only.

**ER-57** `shared/messaging/` (in-memory queue) MUST NOT be used for any feature that has been migrated to the outbox. Do not add new uses of the in-memory queue.

---

## 9. SECURITY RULES

**ER-58** [HARD] Passwords are hashed with bcrypt (cost ≥ 12) before storage. Raw passwords are never stored, logged, or returned.

**ER-59** [HARD] Invite tokens, password reset tokens, and email verification tokens are stored as SHA-256 hashes only.

**ER-60** [HARD] MFA recovery codes are stored as HMAC-SHA256 hashes with a server-side pepper key.

**ER-61** [HARD] TOTP secrets and SSO state payloads are encrypted with AES-256-GCM. A random IV is generated per encryption. The auth tag is validated on decrypt.

**ER-62** [HARD] Error messages for ambiguous conditions (wrong password, nonexistent user, SSO-only user trying password login) MUST use a single vague message.

```typescript
// CORRECT — one message covers all conditions
invalidCredentials() { return AppError.unauthorized('Invalid email or password.'); }

// FORBIDDEN — separate messages create oracle attacks
userNotFound() { return AppError.notFound('No account with that email.'); }
wrongPassword() { return AppError.unauthorized('Incorrect password.'); }
```

**ER-63** The `src/shared/http/error-handler.ts` redacts sensitive meta keys before logging. If you add sensitive data to `AppError` meta, add the field name to `SENSITIVE_META_KEYS` in the error handler.

**ER-64** SSO return-to URLs are validated before use. Only relative paths starting with `/` (not `//`) are accepted. Implemented via `isSafeReturnTo()` in the controller — see ER-12.

---

## 10. CROSS-MODULE INTERACTION RULES

**ER-65** [ARCH] A module's flow MUST NOT call another module's service. Cross-module synchronous reads use the target module's exported query functions via `index.ts`.

```typescript
// CORRECT — use exported query via index.ts
import { getMembershipByTenantAndUser } from '../../memberships';

// FORBIDDEN — calls another module's service from inside a flow
import { MembershipService } from '../../memberships/membership.service';
```

**ER-66** Cross-module async side effects use the DB outbox. A module that needs to trigger work in another bounded context enqueues an outbox message.

**ER-67** When a flow needs a cross-module write that must be transactionally consistent with its own write, the cross-module repo is passed as a dep and bound to the same transaction via `.withDb(trx)`. This is only valid for modules in the same database.

**ER-68** The `modules/_shared/use-cases/` pattern is for stable, widely reused cross-module orchestration. Confirm use by at minimum three different flows before placing something there. New `_shared` use cases must depend on stable `index.ts` exports — not internal `dal/` or `queries/` paths.

---

## 11. TESTING RULES

**ER-69** Every mutation endpoint MUST have an E2E test that:

- Verifies correct HTTP status and response body on the happy path
- Asserts DB state after the request (not just HTTP status)
- Asserts that an audit row was written with the correct `action` and meaningful metadata
- Tests at least one auth failure (missing session → 401, wrong role → 403)
- Tests each business rule from the module spec → correct error status

**ER-70** Every policy function MUST have unit tests covering every branch: the pass case and each distinct fail reason.

**ER-71** Every repo write method and query-sql function MUST have a DAL test that inserts seed data and asserts the returned shape.

**ER-72** E2E tests use `buildTestApp()` from `test/helpers/build-test-app.ts`. They do not start a real HTTP server — they use Fastify's `inject()`. They do not mock the database — they use the test Postgres instance with `resetDb()` between tests.

**ER-73** Rate limits are disabled in the test environment (see ER-48). Tests MUST NOT attempt to re-enable them mid-test or directly manipulate rate limit keys.

**ER-74** Tests that verify tenant isolation (session-cookie-from-tenant-A rejected on tenant-B) MUST exist for any module that involves sessions. These are security tests and are never optional.

Source: `test/e2e/tenant-isolation.spec.ts`.

**ER-75** Test files MUST use UUID-keyed tenant seeds. Never hardcode tenant keys like `'acme'` or `'test'` — always `randomUUID().slice(0, 8)` or equivalent.

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
 * - [what is forbidden in this file]
 */
```

**ER-77** When a file is changed by a later brick or PR to add new behavior, add an update note to the header.

**ER-78** If a file's RULES header contains a constraint that is violated by the current code (e.g. `"Does NOT import from auth"` but it does), fix the code. Do not remove the constraint from the header to paper over the violation.

---

## 13. MIGRATION RULES

**ER-79** Migrations are immutable. A migration that has been applied to any environment MUST NOT be edited. Add a new migration instead.

**ER-80** Every migration file has both `up()` and `down()`.

**ER-81** Migration files are numbered sequentially: `NNNN_<description>.ts`. Never reuse a number.

**ER-82** After adding a migration, run `yarn db:migrate` then `yarn db:types` to regenerate `src/shared/db/database.types.ts`. Commit the regenerated types in the same PR as the migration.

---

## 14. PROHIBITED PATTERNS TABLE

| #   | Pattern                                     | Violated rule | Why forbidden                            | Correct alternative                             |
| --- | ------------------------------------------- | ------------- | ---------------------------------------- | ----------------------------------------------- |
| 1   | Controller calls repo directly              | ER-13         | Bypasses service/flow; no audit          | Controller → service → flow → repo              |
| 2   | Mutation service opens `db.transaction()`   | ER-18         | Transaction ownership belongs to flows   | Extract a flow file                             |
| 3   | Repo opens `db.transaction()`               | ER-18         | Repos are write primitives               | Flow opens the transaction                      |
| 4   | Rate limit inside transaction               | ER-19, ER-44  | Couples Redis and DB transactions        | Rate limit before `db.transaction()`            |
| 5   | Success audit outside transaction           | ER-38         | Audit may persist if data rolls back     | Move audit inside `db.transaction()`            |
| 6   | Failure audit uses `.withDb(trx)` in catch  | ER-39         | `trx` is rolled back; audit is lost      | Use bare `deps.auditRepo` in catch              |
| 7   | Repo write without `.withDb(trx)` inside tx | ER-34         | Write silently escapes transaction       | Always `.withDb(trx)` inside tx                 |
| 8   | Raw PII in logger or audit metadata         | ER-40         | GDPR + credential leakage                | Hash first: `tokenHasher.hash(value)`           |
| 9   | `writer.append()` called directly in flow   | ER-41         | Inconsistent metadata shapes             | Use typed helper in `<module>.audit.ts`         |
| 10  | Cross-module internal DAL import            | ER-2, ER-65   | Hidden coupling, boundary violation      | Use target module's `index.ts`                  |
| 11  | Business logic in `shared/`                 | ER-1          | `shared/` is infrastructure only         | Move to module `flows/` or `policies/`          |
| 12  | Outbox payload with raw token/email         | ER-55         | Credential leakage in DB                 | Encrypt with `OutboxEncryption` before enqueue  |
| 13  | Outbox enqueue outside transaction          | ER-54         | Message lost or orphaned                 | Enqueue inside same transaction                 |
| 14  | Module creates infra in `module.ts`         | ER-8          | Infra creation belongs in `di.ts`        | Pass infra from DI                              |
| 15  | `any` cast to suppress type error           | ER-9          | Masks real type bugs                     | Fix the type; use `unknown` + narrowing         |
| 16  | Check-then-update token consumption         | ER-35         | Race condition allows replay             | Atomic `UPDATE WHERE used_at IS NULL RETURNING` |
| 17  | Policy imports a repo or async function     | ER-23, ER-25  | Policies must be synchronously testable  | Keep policies pure                              |
| 18  | Policy imports from another module          | ER-25         | Cross-module policy coupling             | Move shared utility to `src/shared/utils/`      |
| 19  | Hardcoded tenant key in test                | ER-75         | Cross-test contamination                 | `randomUUID().slice(0, 8)` for all seed keys    |
| 20  | Fire-and-forget in-memory queue for email   | ER-53         | Lost on restart; not multi-instance safe | DB outbox pattern                               |
| 21  | Mutation service method with logic          | ER-16         | Business logic belongs in flows          | Service calls one flow function, nothing else   |

---

## 15. PR AND CI FITNESS CHECKS

Before marking a PR ready for review, the author verifies:

**Code correctness:**

- [ ] `yarn lint` passes with zero errors
- [ ] `yarn typecheck` passes with zero errors
- [ ] `yarn test` passes with zero failures

**Layer rules (check each changed file):**

- [ ] Routes file: zero logic, only `app.method(path, controller.method.bind(controller))`
- [ ] Controller: no DB access, no domain business rules, `safeParse` not `parse`; HTTP-context guards (requireTenantKey, isSafeReturnTo) are allowed
- [ ] Service: mutation methods are one-liners delegating to a flow; read-only methods may query directly (ER-16b)
- [ ] Flow: rate limit before `db.transaction()`, `failureCtx` set before every failure throw
- [ ] Success audit inside transaction, failure audit in catch using bare `deps.auditRepo`
- [ ] All repo writes inside tx use `.withDb(trx)`
- [ ] Policy: no async, no DB imports, both variants present (result + assertion)

**Security:**

- [ ] No raw email/token/password in any log call or audit metadata
- [ ] Token consumption uses `UPDATE WHERE used_at IS NULL RETURNING` pattern
- [ ] Every tenant-scoped query includes `WHERE tenant_id = ...`
- [ ] Rate limit keys use hashed values, never raw PII

**Audit completeness:**

- [ ] All new action strings added to `KnownAuditAction` in `src/shared/audit/audit.types.ts`
- [ ] Both success and failure audits exist for every mutation flow

**Outbox:**

- [ ] If this flow sends email: outbox enqueue is inside the transaction
- [ ] Outbox payload uses `OutboxEncryption` — no raw token or email in DB

**Tests:**

- [ ] E2E: happy path with DB state assertion and audit row assertion
- [ ] E2E: auth failure (401/403), each business rule violation
- [ ] Unit: every policy branch covered
- [ ] DAL: repo writes and query-sql functions covered

**Wiring:**

- [ ] New module registered in `src/app/di.ts`
- [ ] `module.registerRoutes(app)` called in `src/app/routes.ts`
- [ ] New audit actions in `KnownAuditAction`

---

_End of engineering-rules.md_
_Tier 1 — Global Stable. This is the only authoritative implementation rules file._
_Cite rule numbers (ER-N) in PR comments. Update only on `ARCHITECTURE.md` change._
