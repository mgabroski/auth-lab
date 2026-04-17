# Hubins — Security Model

_Tier 1 — Global Stable_
_Applies to every module in this repository._

This document is the authoritative, consolidated source of truth for Hubins's security model.

It covers:

- tenant isolation
- session and cookie model
- token handling and hashing
- cryptographic primitives in use
- MFA model
- rate limiting posture
- anti-enumeration rules
- trust model for forwarded headers
- what future modules must preserve

This document is **not** a product brief.
It is a security engineering reference.

Read this together with:

- `ARCHITECTURE.md` — topology and session architecture
- `docs/decision-log.md` — ADRs for non-obvious security decisions
- `backend/docs/engineering-rules.md` — implementation rules that enforce this model
- `hubins-topology-plan.docx` — cookie contract and proxy trust specifics

If this document conflicts with a lower document, this document wins.

---

## 1. Tenant Isolation

### 1.1 Tenant identity is routing-derived

Tenant identity is always derived from the request host/subdomain.

It must **never** come from:

- request body fields
- query parameters
- client-chosen headers
- frontend application state
- local storage

This is enforced at the request context layer (`shared/http/request-context.ts`) on every incoming request, before any module logic runs.

**Why this matters for new modules:**
Any module that accepts a `tenantId` or `tenantKey` from a client-controlled input is a security defect. All tenant-aware module behavior must read tenant context from `req.requestContext.tenantKey`, which is set once from the host header and cannot be overridden by request payload.

### 1.2 Session-tenant binding is a hard equality check

The session middleware (`shared/session/session.middleware.ts`) enforces:

```
session.tenantKey === req.requestContext.tenantKey
```

This is an exact equality check with no conditional bypass. A session cookie from `acme.hubins.com` will never authenticate a request arriving at `techstart.hubins.com`. The check fails silently — the request becomes unauthenticated, not errored — to avoid leaking session existence to attackers.

**Test coverage:** `test/e2e/tenant-isolation.spec.ts` locks this behavior and must remain green.

### 1.3 New modules must not weaken tenant isolation

Any new module that introduces a route, an endpoint, or a shared behavior that could allow cross-tenant data access is a P0 defect. The engineering rule is ER-48 [HARD].

---

## 2. Session Model

### 2.1 Sessions are server-side

Sessions are stored in Redis, not in browser-managed tokens. The browser holds only a session cookie. The backend holds the session data.

This means:

- sessions can be revoked instantly by deleting the Redis key
- session state (e.g., `mfaVerified`, `emailVerified`) is owned by the backend and cannot be spoofed by the client
- session rotation is safe — the client simply receives a new cookie value

**What new modules must not do:** Issue JWTs or store auth state in local storage. All continuation state for authenticated users is owned by the session store.

### 2.2 Session data structure

The session carries:

| Field           | Type                | Meaning                                    |
| --------------- | ------------------- | ------------------------------------------ |
| `userId`        | string              | Global user ID                             |
| `tenantId`      | string              | Tenant this session is bound to            |
| `tenantKey`     | string              | Subdomain key (used for isolation check)   |
| `membershipId`  | string              | The specific membership for this tenant    |
| `role`          | `ADMIN` \| `MEMBER` | Role at this tenant                        |
| `mfaVerified`   | boolean             | Whether MFA has been verified this session |
| `emailVerified` | boolean             | Whether user's email is verified           |

**Note on `mfaVerified`:** This field is false after login if MFA is required but not yet completed. It is set to true only after a successful `POST /auth/mfa/verify` or `POST /auth/mfa/verify-setup` call, which also rotates the session ID.

### 2.3 Session ID rotation on privilege elevation

The session ID is rotated (new ID issued, old ID invalidated) at every privilege elevation event:

- MFA verification completed
- MFA setup completed
- MFA recovery completed

This prevents session fixation attacks where an attacker who observed a pre-MFA session ID retains access after the user completes MFA.

**Engineering rule:** ER-31 [HARD] — post-commit side effects (session store mutations) happen after transaction commit.

---

## 3. Cookie Contract

There are exactly two cookies in this system. They have different names, different SameSite values, and different lifecycle rules. They must never be confused.

### 3.1 Session cookie

| Property           | Value                                       |
| ------------------ | ------------------------------------------- |
| Name (production)  | `__Host-sid`                                |
| Name (development) | `sid`                                       |
| HttpOnly           | Always `true`                               |
| Secure             | `true` in production, `false` in dev (HTTP) |
| SameSite           | `Strict` — always                           |
| Domain             | **Not set** — host-only binding             |
| Path               | `/`                                         |
| Max-Age            | `SESSION_TTL_SECONDS` (default 86400 = 24h) |

**Why `SameSite=Strict`:** All session-authenticated API calls are same-origin fetch calls from the frontend. SSO callbacks do not need the session cookie — the session is created inside the callback handler. Strict provides maximum CSRF protection.

**Why no `Domain` attribute:** The `__Host-` cookie prefix enforces host-only binding. A cookie on `acme.hubins.com` must not be readable by `techstart.hubins.com`. Setting `Domain=.hubins.com` would break the `__Host-` invariant and weaken tenant isolation. **Never add a Domain attribute to either cookie.**

### 3.2 SSO state cookie

| Property           | Value                                |
| ------------------ | ------------------------------------ |
| Name (production)  | `__Host-sso-state`                   |
| Name (development) | `sso-state`                          |
| HttpOnly           | Always `true`                        |
| Secure             | `true` in production, `false` in dev |
| SameSite           | `Lax` — required                     |
| Domain             | **Not set** — host-only binding      |
| Path               | `/`                                  |
| Max-Age            | 600 seconds (10 minutes)             |

**Why `SameSite=Lax` for SSO state:** The OAuth provider redirects back to the callback URL as a cross-site top-level navigation. `Strict` would block this cookie during the OAuth redirect, breaking the SSO flow. `Lax` allows top-level navigations while still blocking cross-site POST and subresource requests.

**Why the SSO state cookie is safe at `Lax`:** The cookie contains only encrypted, short-lived OAuth state material (PKCE verifier, CSRF token, tenant redirect URI). It contains no user data and no session identity. It is cleared immediately after callback completion.

### 3.3 The `__Host-` prefix invariants (production)

The `__Host-` prefix is enforced by the browser and requires:

1. `Secure=true` must be present
2. `Path=/` must be set
3. `Domain` must **not** be set

Violating any of these causes the browser to silently reject the cookie. The session would not work. These invariants are currently maintained by `set-session-cookie.ts` and `set-sso-state-cookie.ts`. Changing either file is an architecture-sensitive change requiring full-stack validation.

---

## 4. Token Handling

### 4.1 Raw tokens are never stored

All security tokens (invite tokens, password reset tokens, email verification tokens) are generated as cryptographically random values and stored only as hashes.

- **Storage:** SHA-256 hash of the token (via `Sha256TokenHasher`)
- **Transport:** Raw token in email links only
- **Lookup:** Token is hashed at lookup time and compared to the stored hash

Raw tokens must never appear in:

- database rows
- logs
- audit events
- error messages
- response bodies (after generation)

**Engineering rule:** ER-44 [HARD] — audit consistency. Tokens must not appear in audit payloads.

### 4.2 Token generation

All tokens are generated with `generateSecureToken()` from `shared/security/token.ts` using `crypto.randomBytes(32)` encoded as URL-safe base64. This produces 256 bits of entropy, which is sufficient for all current use cases.

### 4.3 Rate-limit keys use hashed identifiers

Rate limiter keys embed hashed versions of PII (emails, IP addresses) rather than raw values. This prevents PII from appearing in Redis key scans, metrics, or logs.

```
login:email:<sha256(email)>
login:ip:<sha256(ip)>
```

New modules that implement rate limiting must follow this same pattern.

---

## 5. Cryptographic Primitives

### 5.1 Password hashing

Algorithm: **bcrypt** (via `BcryptPasswordHasher`)
Cost factor: 12 in production, 4 in tests (cost 4 is the minimum and is test-only)

Passwords are never stored in plaintext. Password hashes are never returned in API responses or logged.

### 5.2 TOTP secret encryption at rest

Algorithm: **AES-256-GCM** (via `EncryptionService`)
Key: 32-byte key from `MFA_ENCRYPTION_KEY_BASE64` environment variable
IV: 12 bytes, freshly generated for every encryption call (never reused)
Auth tag: 16 bytes (GCM mode, ensures integrity)
Format: `base64(iv || authTag || ciphertext)`

TOTP secrets are encrypted before being stored in `mfa_secrets`. An attacker who obtains the database rows cannot generate valid TOTP codes without the encryption key.

### 5.3 MFA recovery code hashing

Algorithm: **HMAC-SHA256** (via `HmacSha256KeyedHasher`)
Key: 32-byte key from `MFA_HMAC_KEY_BASE64` environment variable

Recovery codes are hashed before storage. Each code is single-use and consumed atomically.

Recovery code generation uses rejection sampling to avoid modulo bias (see X9 comment in `setup-mfa-flow.ts`).

### 5.4 Outbox payload encryption

Algorithm: **AES-256-GCM** (via `OutboxEncryption`)
Key: Per-version keys from `OUTBOX_ENC_KEY_V*` environment variables
Versioned format: `v1:<ciphertext>` — supports key rotation without downtime

Outbox messages encrypt both the token and the recipient email address before DB storage. Raw emails and tokens must not appear in the `outbox_messages` table.

### 5.5 SSO state encryption

Algorithm: **AES-256-GCM** (via `EncryptionService`)
Key: 32-byte key from `SSO_STATE_ENCRYPTION_KEY` environment variable

The SSO state cookie payload (provider, tenantKey, requestId, redirectUri, nonce) is encrypted before being written to the cookie.

### 5.6 Key segregation rule

Each cryptographic purpose must use an independently generated key. Reusing the same key value for multiple purposes (e.g., using the MFA key for outbox encryption) reduces the blast radius of a key compromise but creates an implicit coupling between subsystems. Production deployments must generate separate keys for each purpose.

See `infra/docker-compose.yml` for an example of correctly segregated dev keys with prominent "never reuse in production" warnings.

---

## 6. Rate Limiting

### 6.1 Rate limiting happens before DB access

Rate limits fire before any database transaction is opened. This prevents expensive queries from being triggered by brute-force or high-volume traffic.

**Engineering rule:** ER-29 [HARD].

### 6.2 Current rate limit table

| Operation           | Key type  | Limit | Window | Behavior on exceed             |
| ------------------- | --------- | ----- | ------ | ------------------------------ |
| Login               | Per email | 5     | 15 min | Hard 429 with lockout message  |
| Login               | Per IP    | 20    | 15 min | Hard 429 with lockout message  |
| Register            | Per email | 5     | 15 min | Hard 429                       |
| Register            | Per IP    | 20    | 15 min | Hard 429                       |
| Forgot password     | Per email | 3     | 1 hour | Silent — no 429, no email sent |
| Reset password      | Per IP    | 5     | 15 min | Hard 429                       |
| MFA verify          | Per user  | 5     | 15 min | Hard 429                       |
| MFA recover         | Per user  | 5     | 15 min | Hard 429                       |
| SSO start           | Per IP    | 20    | 15 min | Hard 429                       |
| SSO callback        | Per IP    | 20    | 15 min | Hard 429                       |
| Signup              | Per email | 5     | 15 min | Hard 429                       |
| Signup              | Per IP    | 20    | 15 min | Hard 429                       |
| Email verify        | Per IP    | 10    | 15 min | Hard 429                       |
| Resend verification | Per email | 3     | 1 hour | Silent                         |

### 6.3 Silent rate limiting (hitOrSkip)

The forgot-password and resend-verification flows use `hitOrSkip` rather than `hitOrThrow`. This means the endpoint always returns 200 even when the limit is exceeded. The email is simply not sent. This prevents an attacker from using 429 responses as an oracle to confirm that an email address exists in the system.

### 6.4 Rate limit key atomicity

The Redis `INCR` + `EXPIRE` operations are atomic via a Lua script (X4 fix in `redis-cache.ts`). This prevents a crash between `INCR` and `EXPIRE` from creating a key with no TTL that permanently rate-locks a user.

---

## 7. Anti-Enumeration Posture

Several endpoints are intentionally designed to prevent attackers from confirming whether an email address exists in the system.

| Situation                                   | What the endpoint returns                          |
| ------------------------------------------- | -------------------------------------------------- |
| Unknown tenant vs inactive tenant           | Identical `{ isActive: false }` shape — same bytes |
| Forgot password (email exists vs does not)  | Always `200` with generic message                  |
| Resend verification (email verified vs not) | Always `200` with generic message                  |
| Login with non-existent email               | Same `401` as wrong password                       |
| Login with SSO-only account trying password | Same `401` as wrong password                       |
| Invite token wrong tenant vs not found      | Same `404 Invite not found`                        |

**What new modules must preserve:** If an endpoint accepts an email, username, or other user-identifying input and returns different responses based on whether that identifier exists, it is leaking information. New modules that accept such inputs must be reviewed for enumeration risks before shipping.

---

## 8. Trust Model for Forwarded Headers

The backend trusts certain forwarded headers because it is explicitly designed to sit behind a trusted reverse proxy boundary.

**Trusted headers:**

| Header              | Used for                            | Why trusted                           |
| ------------------- | ----------------------------------- | ------------------------------------- |
| `Host`              | Tenant resolution                   | Proxy preserves original host exactly |
| `X-Forwarded-Host`  | Tenant fallback (SSR calls)         | Forwarded by both Caddy and nginx     |
| `X-Forwarded-For`   | Rate limiting client IP             | Caddy appends to chain (not collapse) |
| `X-Forwarded-Proto` | Cookie `Secure` flag, public origin | Set by proxy from incoming scheme     |

**What this trust boundary means:**
The backend assumes the proxy is trusted and the client cannot directly reach the backend without going through the proxy. If this changes (e.g., backend exposed directly to the internet), the trust model breaks and forwarded headers must be re-evaluated.

**Engineering rule:** ER-50 — forwarded headers are only meaningful inside the locked topology.

### 8.1 Control Plane dev-only no-auth deviation

The Control Plane (CP) is currently permitted to run without authentication **only in local development** as a bounded build-out exception for the prerequisite provisioning track. This is not a normalization of the platform security model.

The rule is strict:

- CP no-auth is local-dev-only
- CP must not be exposed publicly under this posture
- CP must not be exposed to shared staging or production until its own authentication boundary is implemented
- this temporary deviation does not change the tenant-app session, cookie, proxy, or forwarded-header trust model described in this document

**Why this note exists:** CP is a separate internal surface, not a tenant-facing app. The temporary dev-only shortcut is allowed to unblock prerequisite implementation work, but it must remain visibly exceptional and time-bounded.

---

## 9. MFA Model

### 9.1 MFA secrets are global per user

A user has one TOTP secret across the entire platform. See ADR-010 in `docs/decision-log.md` for the full rationale, multi-tenant consequences, and named re-evaluation trigger.

### 9.2 MFA is mandatory for admins, configurable for members

All admin users must complete MFA setup before accessing any authenticated admin surface. The `nextAction: 'MFA_SETUP_REQUIRED'` return value from login/register/SSO callback enforces this at the protocol level.

Member MFA is configurable per tenant via `tenant.memberMfaRequired`.

### 9.3 MFA-gated endpoints require email verification

All MFA endpoints (`/auth/mfa/setup`, `/auth/mfa/verify-setup`, `/auth/mfa/verify`, `/auth/mfa/recover`) require `emailVerified: true` in the session. A user cannot set up MFA before verifying their email.

### 9.4 TOTP replay prevention

Each TOTP code is valid for approximately 30 seconds but is cached in Redis for 120 seconds after first use. The same code cannot be replayed within that window. This is implemented via `cache.setIfAbsent()` with a 120-second TTL. Cache write failures are logged but treated as rejection (fail-closed).

---

## 10. What Future Modules Must Preserve

Every new module added to this repository must preserve the following invariants. Violating any of these is at minimum a P1 review finding; violating the HARD ones is a release blocker.

**Tenant isolation [HARD]:** Never accept a tenant identifier from request payload. Always read tenant context from `req.requestContext.tenantKey`.

**Session binding [HARD]:** If a module creates or modifies sessions, the session must remain tenant-bound. Cross-tenant session reuse must fail silently (not with an error).

**Cookie contract [HARD]:** Never add a `Domain` attribute to either cookie. Never change `SameSite=Strict` on the session cookie without a full topology review and proxy conformance validation.

**Token handling [HARD]:** Never store raw tokens in the database. Never log raw tokens. Always use the `TokenHasher` interface for storage and lookup.

**Rate limiting before DB [HARD]:** Any endpoint that accepts credentials, tokens, or identifiers must rate-limit before opening a transaction.

**Anti-enumeration:** Any endpoint that accepts a user-identifying input must not return different responses based on the existence or non-existence of that identifier, unless the difference is intentional and reviewed.

**Key segregation:** New features that require a new encryption or HMAC key must use a key dedicated to that purpose. Keys must be 32 bytes for AES-256. The `Base64KeySchema32` Zod schema enforces this at config-parse time.

---

## 11. When to Update This Document

Update this document when:

- the session model changes (new fields, new rotation rules)
- the cookie contract changes (new cookie, name change, SameSite change)
- a new cryptographic primitive is introduced
- a new rate limiting behavior is added
- the trust model for forwarded headers changes
- the anti-enumeration posture changes
- a security-relevant ADR is added that affects the overall model

A code change that alters any of the behaviors in this document without updating this document is a documentation defect.
