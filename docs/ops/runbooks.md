# Hubins Auth-Lab — Operations Runbooks

## Purpose

This file contains the operational runbooks for the current Auth-Lab foundation.

It is intentionally practical.

It answers:

- how to check whether the system is healthy
- how to identify the current environment mode
- how to reset/reseed local state
- how to troubleshoot local mail delivery
- how to perform and validate bootstrap/invite proof
- how to validate public signup, email verification, resend verification, and password recovery proof
- how to reason about common auth-related failure modes without violating the locked topology

This file does **not** redefine architecture.
It assumes the topology and auth/session ownership already locked in the current topology and foundation docs.

---

## System Dependencies & Health Checks

### Local core dependencies

The local auth environment depends on:

- PostgreSQL
- Redis
- backend app
- frontend app
- Mailpit for non-production email capture

Depending on the workflow you are running, you may also have the local reverse proxy stack up.

### Minimum local health checklist

Before testing any auth flow, confirm:

- Postgres is reachable
- Redis is reachable
- backend `/health` responds
- frontend app loads
- Mailpit UI loads
- the tenant host you plan to use resolves locally

### Suggested local checks

#### Infra state

```bash
docker compose -f infra/docker-compose-infra.yml ps
```

#### Full stack state

```bash
docker compose -f infra/docker-compose.yml ps
```

#### Backend health

```bash
curl -i http://127.0.0.1:4001/health
```

#### Frontend health

Open the tenant-aware frontend URL in the browser, for example:

```text
http://goodwill-ca.localhost:3000
```

#### Mailpit health

Mailpit UI should be reachable at:

```text
http://127.0.0.1:8025
```

Mailpit SMTP listener should be reachable at:

```text
127.0.0.1:1025
```

---

## Environment Mode Identification

Always identify the current mode before debugging email or bootstrap flows.

### Local developer mode

Expected characteristics:

- `NODE_ENV=development`
- local Postgres/Redis
- Mailpit SMTP sink
- tenant-aware frontend URLs on localhost/lvh.me style hosts
- convenience seed flow allowed

### Shared QA / staging mode

Expected characteristics:

- non-production deploy
- sandbox SMTP provider, not Mailpit UI on localhost
- no raw token logging contract
- tenant bootstrap performed through explicit operator path
- invite delivery validated through the real outbox + SMTP path

### Production-like operator mode

Expected characteristics:

- bootstrap is explicit
- no convenience raw token logging
- no dependency on local-only seed assumptions
- delivery occurs only through the real outbox + provider path

---

## Outbox & Email Delivery

### Local Mailpit expectations

In local development, the backend should deliver email through SMTP to Mailpit.

Expected local values:

- `EMAIL_PROVIDER=smtp`
- `SMTP_HOST=127.0.0.1`
- `SMTP_PORT=1025`
- local non-production sender/from settings

### What local proof should be able to deliver

At this stage, local proof must be able to deliver:

- invite email
- verify-email email
- password-reset email

If any of these are missing in local while SMTP is configured, treat it as a real break in the auth proof chain.

### Mailpit inspection flow

1. open Mailpit UI
2. clear old messages when starting a clean proof session
3. trigger the auth flow under test
4. confirm message arrival
5. inspect the rendered link and confirm:
   - it points at the expected tenant-aware frontend host
   - it uses the correct path for the flow
   - the token/query payload exists

### Local failure checklist for missing mail

If expected mail does not appear:

1. confirm Mailpit is running
2. confirm backend is using SMTP mode, not noop
3. confirm SMTP host/port values match Mailpit
4. confirm the backend actually queued the outbox message
5. confirm the outbox poller/worker is running in the current backend process model
6. inspect backend logs for SMTP connection or delivery errors

### Staging sandbox expectations

For shared QA/staging, the documented sandbox SMTP provider for this module is **Mailtrap Email Sandbox**.

Use sandbox credentials only.
Do not point shared QA/staging at a real production mail provider for Phase 2/3/4 proof work.

Expected staging proof at this point:

- invite email arrival confirmed
- verify-email arrival confirmed
- provider error classification behavior checked against real provider responses when practical

---

## Session & Authentication Issues

### Symptom: login succeeds but browser is not authenticated on the next page

Check the following in order:

1. backend returned success with the expected `nextAction`
2. session cookie was set by the backend
3. browser remained on the correct tenant host
4. frontend redirected according to backend truth rather than local guesswork
5. `/auth/me` or server bootstrap sees the same session

### Symptom: authenticated page unexpectedly becomes public

Check:

1. tenant host mismatch between initial request and follow-up request
2. session cookie scope and host usage
3. whether logout or password reset invalidated the previous session
4. whether the browser opened a link on the wrong host

### Important rule

Do **not** “fix” auth issues by bypassing the backend-owned session model.
Do **not** move token truth into the frontend.
Any repair must preserve:

- same-origin browser `/api/*`
- backend-owned auth/session truth
- host-derived tenant identity

---

## Invite Flow Issues

### Symptom: invite email arrives but onboarding cannot continue

Check:

1. invite link host matches the expected tenant
2. invite token exists in the URL
3. invite has not expired or been revoked
4. frontend accept-invite page loaded on the correct host
5. backend invite acceptance endpoint returns the expected state

### Symptom: invite link says invalid/expired unexpectedly

Check:

1. whether the invite was replayed after successful use
2. whether the invite expired naturally
3. whether an admin resent/replaced the invite and the older token is no longer valid
4. whether the wrong tenant host was used when opening the link

### Rule for shared QA/staging/production-style testing

Do **not** use raw token logging as the proof method.
Use the delivered email and the real browser link.

---

## Password Reset Issues

### Symptom: forgot-password appears to succeed but no reset mail arrives

Check:

1. whether the email belongs to a real password user in the target tenant
2. whether Mailpit/sandbox inbox received the message
3. whether outbox delivery happened
4. whether the link host/path is correct

### Symptom: reset link opens but reset submission fails

Check:

1. whether the token is missing from the URL
2. whether the token already expired
3. whether the token was already used once
4. whether the user triggered a newer reset email, invalidating the older token

### Symptom: old password still works after reset

Treat this as a real bug.
Password reset completion must replace the credential and invalidate the old one.

Verify:

1. reset request completed with success
2. subsequent login with old password fails
3. subsequent login with new password succeeds
4. existing sessions for that user were invalidated if that is the current contract

---

## MFA & Recovery Issues

### Current phase boundary reminder

This runbook file may mention MFA because the repo already contains MFA logic, but **real authenticator-app proof belongs to Phase 5**, not Phase 4.

Do not treat the absence of real authenticator proof in this phase as a Phase 4 failure.

### If MFA setup unexpectedly blocks another proof flow

Check:

1. whether the persona or tenant policy you are using is expected to require MFA
2. whether you intended to test an admin bootstrap flow versus a public member flow
3. whether the nextAction returned by the backend is correct for that persona

For Phase 3 bootstrap proof, continuation into MFA setup entry is acceptable and expected.

---

## Rate Limiting Issues

### Symptom: repeated login or auth actions suddenly return throttling behavior

Check:

1. whether Redis is healthy
2. whether the client IP derivation is correct in the current topology
3. whether you unintentionally reused the same client flow too many times during manual testing
4. whether the proxy/header path is collapsing IP identity

Do not disable rate limiting just to make proof work.
If rate limiting blocks proof unexpectedly, debug the topology/request identity instead.

---

## Audit Event Issues

### Symptom: auth behavior works but audit records seem missing or misleading

Check:

1. whether the flow reached the correct backend branch
2. whether the success/failure path used the expected audit action
3. whether a generic response intentionally hides user existence while the audit layer still records the correct internal outcome

For example, forgot-password for a nonexistent email should still preserve the non-enumerating public response while internal audit captures the true outcome.

---

## Local reset / reseed procedure

Use this when the local environment is too dirty to trust.

### 1. Stop local app processes

Stop frontend/backend processes if they are running in host mode.

### 2. Reset infra volumes when necessary

```bash
docker compose -f infra/docker-compose-infra.yml down -v
```

### 3. Start fresh infra

```bash
docker compose -f infra/docker-compose-infra.yml up -d
```

### 4. Recreate backend database schema / migrations if required

Use the current backend workflow documented in `docs/developer-guide.md`.

### 5. Run the canonical local dev seed

```bash
yarn seed:dev
```

### 6. Start backend/frontend again

### 7. Confirm baseline health

At minimum, confirm:

- backend `/health`
- frontend loads
- Mailpit loads
- seeded admin/member personas exist as expected

---

## Tenant bootstrap runbook

This runbook captures the current real operator/bootstrap flow for the first admin invite path.

### Goal

Create or ensure a tenant, issue the first admin invite through the real outbox + SMTP path, and validate the onboarding chain in a real browser.

### Local developer path

Local development may still use convenience-friendly seed behavior, including precreated data and Mailpit capture.

### Shared QA / staging / production-style path

Use the explicit bootstrap command.

Example shape:

```bash
yarn bootstrap:tenant --tenant goodwill-ca --email admin@example.com --name "First Admin"
```

Use the exact command contract implemented in the backend package.

### Validation sequence

1. run/reset the target environment
2. confirm backend and email sink/provider are healthy
3. execute tenant bootstrap command
4. confirm an outbox message is created
5. confirm the invite email arrives through the real delivery path
6. open the invite link in a real browser
7. confirm the accept-invite page loads correctly
8. continue through registration if required
9. confirm session creation after onboarding
10. if the admin is subject to MFA setup, confirm continuation reaches the MFA setup entry point

### Important contract

In shared QA/staging/production-style proof:

- do **not** rely on raw invite token logs
- do **not** bypass email delivery
- do **not** hand-edit database rows as the normal bootstrap mechanism

---

## Phase 4 public signup, verification, and password recovery proof

This section closes the current Phase 4 operational proof requirements.

### A. Local public signup + email verification proof

#### Goal

Prove the following end to end on a signup-enabled tenant:

- public signup succeeds
- verification email is delivered through Mailpit
- opening the verification link in a real browser works
- resend verification sends a fresh email
- the older token becomes invalid after resend
- verified login works normally afterward

#### Preconditions

- local environment is healthy
- Mailpit is running and empty or easy to inspect
- you know the signup-enabled tenant host, for example `http://goodwill-open.localhost:3000`

#### Local signup proof checklist

1. Start from a clean or trusted local state
2. Open Mailpit and clear old messages if needed
3. Open `http://goodwill-open.localhost:3000/auth/signup`
4. Sign up with a brand-new email address that has not been used before
5. Confirm the browser lands on `/verify-email`
6. Confirm the page offers resend behavior because the link token is not yet present in the URL
7. In Mailpit, open the first verification email and copy the verification link
8. Back in the browser, click **Resend verification email**
9. Confirm a second verification email arrives in Mailpit
10. Open the **older** verification link first and confirm the app shows the invalid/expired-link outcome
11. Open the **newest** verification link in the same browser session
12. Confirm the browser completes verification and continues into authenticated usage
13. Log out
14. Sign in again with the same email and password
15. Confirm login now succeeds normally

#### What counts as a pass

All of the following must be true:

- signup succeeded only on the signup-enabled tenant host
- verification mail was delivered through Mailpit via the real outbox + SMTP path
- resend produced a fresh verification email
- the older verification token no longer worked after resend
- the newest verification link worked in a real browser
- the verified session continued into normal authenticated usage
- later login with the verified credentials worked

### B. Local blocked-signup proof

#### Goal

Prove the frontend and backend both honor a tenant where public signup is disabled.

#### Checklist

1. Open the signup-disabled tenant host, for example `http://goodwill-ca.localhost:3000/auth/signup`
2. Confirm the page renders the blocked-signup state instead of a usable signup form
3. Confirm a direct `POST /auth/signup` against the same tenant still returns the backend-forbidden outcome if you probe it manually

#### What counts as a pass

- the signup-disabled tenant does not expose a working public signup path
- the browser and backend behavior agree on the blocked outcome

### C. Local forgot-password + reset-password proof

#### Goal

Prove password recovery works end to end in local development through:

- forgot-password request
- reset email delivery through Mailpit
- opening the reset link in a real browser
- setting a new password
- invalidating the old password
- confirming the new password works
- proving expired-token rejection
- proving reused-token rejection

#### Preconditions

- Mailpit is empty or easily inspectable
- you have a password-based account on a tenant host (for example `member@example.com` on `goodwill-open.localhost`)

#### Local password-recovery proof checklist

1. Open `http://goodwill-open.localhost:3000/auth/forgot-password`
2. Submit forgot-password for a real password user such as `member@example.com`
3. Confirm the page shows the generic success copy
4. In Mailpit, open the newest password reset email and copy the reset link
5. Open the reset link in a real browser tab
6. Set a new password and submit the form
7. Confirm the page shows password-update success
8. Return to `/auth/login`
9. Confirm the **old** password no longer works
10. Confirm the **new** password works
11. Log out again if needed
12. Request another password reset email
13. Open the newest reset link and complete another successful reset
14. Immediately reopen that same reset link and confirm the already-used-token outcome is rejected

#### Local expired-reset-token proof

Because reset-token expiry is time-based, the practical local proof may use a direct database update after the email is generated but before the browser uses the link.

Example `psql` pattern:

```sql
UPDATE password_reset_tokens prt
SET expires_at = now() - interval '1 minute'
FROM users u
WHERE prt.user_id = u.id
  AND u.email = 'member@example.com'
  AND prt.used_at IS NULL;
```

After expiring the active token row:

1. Reopen the matching reset link from Mailpit
2. Submit a new password
3. Confirm the browser shows the invalid/expired-token outcome

#### What counts as a pass

All of the following must be true:

- forgot-password produced a real Mailpit email for the password user
- the reset link opened correctly on the tenant-aware frontend host
- reset-password accepted a valid token exactly once
- the old password stopped working after reset
- the new password worked after reset
- an expired reset token failed
- a reused reset token failed

## Invite lifecycle behaviors during bootstrap

These are the expected operator-visible outcomes for terminal invite states.

### Invite replay / already accepted

**Symptom:** the same invite link is opened again after successful acceptance.

**Expected behavior:**

- `POST /auth/invites/accept` returns `409`
- backend message is `Invite already accepted`
- UI should guide the user toward continuing registration (same token) or signing in, depending on where they are in the onboarding chain

### Invite expiry

**Symptom:** the invite link is opened after its expiry window.

**Expected behavior:**

- `POST /auth/invites/accept` returns `409`
- backend message indicates the invite expired
- operator/admin must resend or recreate the invite

### Invite cancellation / revocation

**Symptom:** an admin cancelled the invite before it was used.

**Expected behavior:**

- `POST /auth/invites/accept` returns `409`
- backend message indicates the invite is no longer valid
- operator/admin must resend or recreate the invite

### Operator response rule

Do **not** attempt to mutate database rows manually to rescue a terminal invite.

For replay/expired/cancelled states, use the supported admin/operator path:

- resend invite when available
- otherwise create a fresh invite/tenant bootstrap action

---

## SMTP classification investigation guide

### Symptom: mail stays pending/retries forever

**Possible causes:**

- provider/network failure is being treated as retryable
- provider is timing out or intermittently unavailable
- a supposed permanent rejection is actually being surfaced as a transient/network error

**Steps:**

1. inspect backend logs for SMTP adapter error details
2. inspect provider response code/message if available
3. confirm whether the adapter classified it as retryable or permanent
4. compare with the intended provider behavior
5. if classification is wrong, open a targeted bug with the exact provider response and current classification outcome

### Symptom: mail goes directly to permanent failure

**Possible causes:**

- bad credentials
- sender/from rejection
- malformed recipient/address rejected by provider
- provider sandbox restriction violation

**Steps:**

1. confirm credentials and sender identity
2. inspect the exact provider response
3. verify the current backend classification is expected
4. correct configuration before replaying

---

## Data Reset / Recovery

### Symptom: local environment is too inconsistent to trust

Use a full local reset.

#### Infra-only reset

```bash
docker compose -f infra/docker-compose-infra.yml down -v
docker compose -f infra/docker-compose-infra.yml up -d
```

Then rerun backend/frontend and reseed.

#### Full-stack reset

```bash
docker compose -f infra/docker-compose.yml down -v
docker compose -f infra/docker-compose.yml up -d --build
```

After reset, verify:

- `/health`
- Mailpit UI
- seeded invite email

---

## Logging guidance during incidents

When investigating auth/email incidents, prioritize logs that answer these questions:

1. Did the request reach the backend through the expected topology path?
2. Which tenant/host was derived?
3. Was an outbox message created?
4. Did the poller attempt delivery?
5. What exact SMTP/provider response came back?
6. How was the failure classified?
7. Was the bootstrap action local-dev convenience mode or operator mode?

If logs do not make those questions answerable, capture that gap and improve observability after the incident.

---

## Escalation guidance

Escalate when:

- dependency health cannot be restored quickly
- tenant identity is being derived incorrectly and risks cross-tenant behavior
- SMTP classification appears wrong for a real provider response
- staging sandbox proof cannot be completed due to networking or secret-management blockers
- the system can only be made to work by violating the locked topology
- operator bootstrap requires raw token access to proceed

---

## Change discipline reminder

Operational pressure is not permission to rewrite architecture.

During incidents or proof work:

- do not bypass same-origin browser routing
- do not move tenant truth into the frontend
- do not replace host-derived tenant identity with manual toggles
- do not swap sandbox/local delivery for production delivery shortcuts
- do not treat raw invite token logging as the staging or production bootstrap contract

Repair within the locked system model.
