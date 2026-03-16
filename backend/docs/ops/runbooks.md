# Hubins — Operational Runbooks

_Tier 2 — Global Growing_
_Organized by operational concern, not by module._
_Add sections as new modules ship. Never split into per-module files._

This document is the single home for all Hubins operational procedures.

When something breaks in production, this document should be the second thing you open — after the logs.

Runbooks are organized by **symptom and response**, not by which module owns the underlying code. An on-call engineer responds to "the outbox is stalled," not "the invites module's outbox is stalled."

---

## How to use this document

1. Identify the symptom from alerts, logs, or user reports
2. Find the matching section below
3. Follow the investigation steps in order
4. Escalate or resolve based on findings
5. If this runbook did not help, add the missing steps after resolving the incident

---

## System Dependencies and Health Checks

### Health endpoint

The backend exposes a liveness/readiness probe at `GET /health`.

**What it checks:**

- `checks.db: true` — backend can reach Postgres with a trivial query
- `checks.redis: true` — backend can write to Redis

**What a 503 means:**
The process is alive but cannot reach a critical dependency. Traffic should not be routed to this instance.

**What a connection failure means:**
The process itself is unhealthy (crash, OOM, port not binding). Check process manager logs.

**Normal response shape (non-production):**

```json
{
  "ok": true,
  "env": "production",
  "service": "auth-lab-backend",
  "checks": { "db": true, "redis": true }
}
```

In production, `requestId` and `tenantKey` are intentionally omitted.

### Postgres

Postgres is required for all backend write and most read paths.

**Symptoms of Postgres failure:**

- `GET /health` returns `checks.db: false`
- All write endpoints return 500
- Logs show `ECONNREFUSED` or `connection refused` for the DB URL

**Investigation:**

1. Check if the Postgres process is running: `pg_isready -U auth_lab -d auth_lab`
2. Check connection pool exhaustion in logs (`too many clients`)
3. Check disk space — Postgres will reject writes if the data volume is full

### Redis

Redis is required for sessions, rate limiting, and the outbox worker claim lease.

**Symptoms of Redis failure:**

- `GET /health` returns `checks.redis: false`
- Login/session endpoints fail
- Rate limits stop enforcing (since `RateLimiter` fails open on Redis errors at the application level, depending on error handling)
- Outbox worker cannot claim messages

**Investigation:**

1. Check Redis process: `redis-cli ping` should return `PONG`
2. Check memory usage: `redis-cli INFO memory` — look for `used_memory` near `maxmemory`
3. Check eviction policy: if keys are being evicted, session data may be lost

---

## Outbox and Email Delivery

### Outbox message status reference

| Status    | Meaning                                  |
| --------- | ---------------------------------------- |
| `pending` | Waiting to be claimed by a worker        |
| `sent`    | Successfully delivered                   |
| `dead`    | Permanently failed — will not be retried |

### The outbox worker is not running

**Symptom:** Outbox messages accumulate in `pending` status. Users report not receiving emails. No `outbox.claimed` log lines for several minutes.

**Investigation:**

1. Confirm the backend process is running and healthy
2. Check worker startup logs for `outbox.worker.started` — if absent, the worker never started
3. Check if `NODE_ENV=test` was accidentally set in production — the worker does not start in test mode
4. Check if `EMAIL_PROVIDER=noop` is set — the worker runs but the adapter logs `email.noop.sent` and delivers nothing

**Resolution:**

- If `NODE_ENV=test`: correct the environment variable and restart
- If `EMAIL_PROVIDER=noop`: set `EMAIL_PROVIDER=smtp` and configure SMTP credentials, then restart
- If worker crashed: check for unhandled errors in logs around `outbox.tick.failed`

### Outbox messages are accumulating (worker running but messages not sending)

**Symptom:** `outbox.claimed` log lines exist but messages move to `dead` status. Users report not receiving emails.

**Investigation:**

1. Look for `outbox.dead_lettered` log lines — they include `lastError` which identifies the failure cause
2. Common causes:
   - `decrypt_failed:...` — the encryption key is missing or wrong for the message's version prefix
   - SMTP connection errors — check SMTP host, port, credentials, and firewall
   - `NonRetryableEmailError` — permanent SMTP rejection (5xx), check `lastError` for the provider message

**Resolution by error type:**

`decrypt_failed`:

- The message was encrypted with a key version that is no longer configured
- Check `OUTBOX_ENC_DEFAULT_VERSION` and `OUTBOX_ENC_KEY_V*` environment variables
- See ADR-002 in `docs/decision-log.md` for the key rotation procedure

SMTP `5xx` rejection:

- Check if the recipient address is valid
- Check if the sending domain is verified with the SMTP provider
- Check sender `SMTP_FROM` for format errors

SMTP connection errors:

- Verify `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE` settings
- Check if the SMTP provider requires specific IP allowlisting
- Test the connection manually: `curl -v smtp://SMTP_HOST:SMTP_PORT`

### Dead-lettered messages

Messages with `status = 'dead'` will not be retried automatically.

**To inspect dead-lettered messages:**

```sql
SELECT id, type, attempts, last_error, created_at
FROM outbox_messages
WHERE status = 'dead'
ORDER BY created_at DESC
LIMIT 20;
```

**To manually resend a dead-lettered message** (use with caution — idempotency key prevents duplicate delivery if the original was already sent):

```sql
UPDATE outbox_messages
SET status = 'pending', attempts = 0, available_at = now(), last_error = null
WHERE id = '<message-id>';
```

Only do this after confirming the original message was never delivered and the root cause has been fixed.

### Outbox backlog growing faster than it is draining

**Symptom:** Pending count in `outbox_messages` increases over time even with the worker running.

**Investigation:**

1. Check worker poll interval and batch size — default is 5-second poll, 10 messages per batch
2. Check if SMTP is throttling — the SMTP provider may be rate-limiting sends
3. Check if a high-volume event created many messages at once (e.g., bulk invite send)

**Resolution:**

- Temporarily increase `OUTBOX_BATCH_SIZE` and/or decrease `OUTBOX_POLL_INTERVAL_MS` to drain the backlog faster
- If SMTP is throttling, work with the provider to increase the send rate limit

---

## Session and Authentication Issues

### Users are being unexpectedly logged out

**Symptom:** Users report being logged out randomly without taking any action.

**Investigation:**

1. Check `SESSION_TTL_SECONDS` — default 86400 (24 hours). If set lower, sessions expire faster
2. Check Redis eviction: if Redis is under memory pressure and evicting keys, sessions will be lost
3. Check if a `destroyAllForUser` event was triggered — this happens on password reset
4. Check if session cookies are being cleared by the browser (check for `Max-Age=0` in Set-Cookie headers)

### Login returns 401 with valid credentials

**Symptom:** A user with correct credentials gets `Invalid email or password.`

**Investigation:**

1. Check if the user's membership is `SUSPENDED` — this returns a different error but check anyway
2. Check if the tenant is active: `SELECT is_active FROM tenants WHERE key = '<tenantKey>';`
3. Check rate limits: `SELECT * FROM redis WHERE key LIKE 'rl:login:email:%'` — check the Redis key for this email hash
4. Check if the user only has SSO identities (no password identity) — the login policy returns `invalidCredentials` for SSO-only users

### MFA setup is stuck or recovery codes are lost

**Symptom:** User cannot complete MFA setup or is locked out because recovery codes were lost.

**Investigation:**

1. Check `mfa_secrets` for the user: `SELECT id, is_verified, created_at FROM mfa_secrets WHERE user_id = '<userId>';`
2. If `is_verified = false`, the setup was started but not completed. The user can restart MFA setup.
3. If `is_verified = true`, the user needs admin assistance to reset their MFA secret

**Admin MFA reset (requires direct DB access — use only for verified support requests):**

```sql
BEGIN;
DELETE FROM mfa_recovery_codes WHERE user_id = '<userId>';
DELETE FROM mfa_secrets WHERE user_id = '<userId>';
COMMIT;
```

After this, the next login will return `nextAction: 'MFA_SETUP_REQUIRED'` and the user can set up MFA again.

---

## Invite Flow Issues

### Invite link says "already used" but user never accepted it

**Symptom:** User receives invite email, clicks the link, and gets `This invitation has already been accepted.`

**Investigation:**

1. Check the invite row: `SELECT status, used_at, expires_at FROM invites WHERE token_hash = sha256('<raw-token-from-link>');`
   (Note: token_hash is SHA-256 of the raw token. Use `sha256hex()` or hash it in application code.)
2. If `status = 'ACCEPTED'`: the invite was already consumed. Check if another user used the same link.
3. If `status = 'EXPIRED'`: the invite expired before the user clicked

**Resolution:**

- Create a new invite for the user via the admin invite management UI or API
- The old invite cannot be reactivated

### Invite resend is not delivering a new email

**Symptom:** Admin clicks "Resend" but the user reports receiving nothing new.

**Investigation:**

1. Check if the original invite was cancelled: `SELECT status FROM invites WHERE id = '<inviteId>';`
2. Check the outbox for a new message: `SELECT status, attempts, last_error FROM outbox_messages WHERE payload->>'inviteId' = '<inviteId>' ORDER BY created_at DESC LIMIT 3;`
3. If the outbox message exists and `status = 'dead'`: follow the outbox dead-letter runbook above

---

## Password Reset Issues

### Password reset email not arriving

**Symptom:** User requests password reset but receives no email.

**Investigation:**

1. Check if the user exists and has a password identity:
   ```sql
   SELECT u.id, u.email, ai.provider
   FROM users u
   LEFT JOIN auth_identities ai ON ai.user_id = u.id
   WHERE u.email = '<email>';
   ```
   If no `password` identity row exists, the user cannot reset their password (SSO-only users do not receive reset emails — by design).
2. Check if the rate limit was hit: the forgot-password flow silently skips sending if the rate limit is exceeded. Check audit events for `auth.password_reset.requested` with `outcome: 'rate_limited'`.
3. Check the outbox for the reset message: `SELECT status, attempts, last_error FROM outbox_messages WHERE type = 'password.reset' ORDER BY created_at DESC LIMIT 5;`

### Password reset token says "expired or invalid"

**Symptom:** User clicks the reset link and gets the expired token error.

**Investigation:**

1. Reset tokens expire after 1 hour
2. Only the most recent token for a user is valid — requesting a new reset cancels the old token
3. Check if the token was already used: `SELECT used_at FROM password_reset_tokens WHERE token_hash = <hash>;`

---

## Rate Limiting Issues

### Legitimate user is locked out by rate limiting

**Symptom:** A user cannot log in and receives the lockout message despite having correct credentials.

**Investigation:**

1. The login rate limit is 5 attempts per email per 15 minutes and 20 per IP per 15 minutes
2. Check the Redis key TTL to understand how long until the lock expires:
   `TTL rl:login:email:<sha256(email)>` — returns seconds until expiry

**Resolution:**

- Wait for the rate limit window to expire (maximum 15 minutes)
- If immediate access is needed, delete the Redis key: `DEL rl:login:email:<sha256(email)>`
- **Only do this for verified support requests** — deleting rate limit keys removes abuse protection

---

## Audit Event Issues

### Audit events not appearing in admin view

**Symptom:** Admin views the audit log but recent events are missing.

**Investigation:**

1. Check if the audit events were written: `SELECT COUNT(*) FROM audit_events WHERE created_at > NOW() - INTERVAL '1 hour';`
2. Check if the admin audit query has a tenant filter bug — audit events are tenant-scoped
3. Check if the admin user's session is properly authenticated with `role = 'ADMIN'` and `mfaVerified = true`

---

## [PENDING — DEPLOYMENT PHASE]

The following runbook sections will be added when the deployment infrastructure is finalized:

- Application startup and shutdown procedures
- Database migration rollback procedure
- Log access and log search guides
- Alert routing and escalation paths
- Redis backup and restore procedures

---

## How to Add a New Runbook Section

When a new module ships with non-obvious operational failure modes, add a section to this file in the same PR as the module. Follow this structure:

```markdown
## <Module Name> Issues

### <Symptom name>

**Symptom:** What the operator or user observes.

**Investigation:**

1. First check
2. Second check
3. ...

**Resolution:**

- Resolution step
```

Do not add sections for failure modes that are handled by generic sections already in this document (Postgres down, Redis down, health check failures). Only add sections for failure modes that are specific to the module's behavior.
