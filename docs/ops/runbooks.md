## System Dependencies & Health Checks

### Health check surface

Before any auth/provisioning proof or QA run, confirm the following are healthy:

- frontend app
- backend app
- Postgres
- Redis
- email provider path for the target environment

For local work this normally means:

- frontend reachable in browser
- backend health endpoint responding
- infra containers running
- Mailpit available for local email inspection

### Minimal local health sequence

1. Start infra
2. Start backend
3. Start frontend
4. Confirm backend health endpoint
5. Confirm frontend loads on the tenant host you intend to test
6. Confirm Mailpit UI loads if you are proving any email-driven flow

### If health fails

Do not start debugging auth behavior first.
Stabilize:

- database availability
- Redis availability
- backend env/config
- frontend env/config
- proxy/host routing

---

## Outbox & Email Delivery

### Local expectation

Local proof uses real SMTP wiring into a local capture sink.
The repo contract for local proof is Mailpit.

That means:

- auth emails are actually sent through SMTP
- delivery can be inspected without using real end-user inboxes
- token links can be copied from Mailpit into the browser for proof

### Typical local checks

If an expected email does not appear:

1. confirm Mailpit is running
2. confirm backend SMTP env values point to Mailpit
3. confirm the outbox worker path is running in the current backend mode
4. confirm the expected outbox row was created
5. confirm the backend logs did not classify the attempt as permanent or retryable failure

### Staging / sandbox expectation

Non-local proof should use the configured non-production sandbox SMTP provider.
For this repo, the current documented provider choice is Mailtrap Email Sandbox.

Do not treat raw token logs as the delivery contract outside local-dev convenience paths.

---

## Session & Authentication Issues

### Symptom: login succeeds but authenticated browser state is wrong

Check:

1. whether the request used the correct tenant host
2. whether the session cookie was set by the backend
3. whether the browser request path stayed same-origin under `/api/*`
4. whether SSR versus browser fetch path was used correctly
5. whether `nextAction` from backend implies continuation rather than normal app landing

### Symptom: user loops between auth pages and authenticated pages

Check:

1. backend `/auth/me` response for that exact browser session
2. whether the frontend resolved the correct route from backend `nextAction`
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

This runbook file may mention MFA because the repo already contains MFA logic.

Phase 4 intentionally stopped before real authenticator-app proof. Phase 5 adds the dedicated MFA proof procedure below.

### If MFA setup unexpectedly blocks another proof flow

Check:

1. whether the persona or tenant policy you are using is expected to require MFA
2. whether you intended to test an admin bootstrap flow versus a public member flow
3. whether the nextAction returned by the backend is correct for that persona

For Phase 3 bootstrap proof, continuation into MFA setup entry is acceptable and expected.

---

## Phase 5 real MFA setup / verify / recovery proof

This section is the canonical operational procedure for the Phase 5 MFA proof scope.

### Goal

Prove all of the following against the real backend:

- authenticator-app enrollment with a real scan flow
- issuer + label presentation correctness
- post-login MFA challenge continuation
- recovery-code success exactly once with single-use enforcement

### Preconditions

Before starting the proof, confirm all of the following:

1. the QR label correction from LOCK-2 is already present in the environment you are testing
2. any stale local/test data created before the QR label correction has been reset or reseeded
3. you have a real authenticator app available, for example Google Authenticator, Microsoft Authenticator, 1Password, or another TOTP app
4. you have a password-based user that is expected to require MFA in the target tenant
5. Mailpit or your staging sandbox inbox is available if you need to re-run an earlier invite/bootstrap flow first

### A. Real MFA setup proof

#### Goal

Prove a real authenticator app can scan the QR code rendered by the frontend, show the correct issuer/email presentation, and complete MFA setup with a live TOTP code.

#### Local proof checklist

1. Start from a clean or trusted environment
2. If there is any doubt about stale MFA rows, run the documented local reset / reseed procedure first
3. Sign in with a user that should continue to `/auth/mfa/setup`
4. Confirm the browser lands on the real MFA setup page
5. Confirm the page renders a visible QR code, the raw authenticator secret, and recovery codes
6. Scan the QR code with a real authenticator app
7. In the authenticator app, confirm the created entry shows `Hubins` as the issuer and the verified email address as the account label, or an equivalent issuer/email presentation depending on the app UI
8. Enter the current 6-digit authenticator code into the setup form
9. Submit **Finish MFA setup**
10. Confirm the backend accepts the real code and the browser continues into authenticated usage
11. Save one recovery code for the recovery proof and keep the remaining codes unused

#### What counts as a pass

- the QR code is actually scannable in a real authenticator app
- the app entry is not labeled with an opaque internal identifier such as `userId`
- setup succeeds only after submitting a real current TOTP code
- the user lands in authenticated state after setup completion

### B. MFA-required login verification proof

#### Goal

Prove that a user with MFA already configured is challenged after a fresh login and can complete the challenge with a real TOTP code.

#### Checklist

1. Log out fully after the setup proof
2. Start a brand-new login for the same MFA-configured user
3. Confirm the backend returns MFA continuation and the browser lands on `/auth/mfa/verify`
4. In the authenticator app, generate the current 6-digit code for that existing entry
5. Submit the code through the MFA verify form
6. Confirm the backend accepts it and the browser continues into the authenticated area
7. Confirm authenticated session state now reflects MFA verification

#### What counts as a pass

- a fresh login does not bypass MFA
- the challenge occurs before authenticated access is granted
- the real TOTP code completes the continuation successfully

### C. Recovery-code proof

#### Goal

Prove one saved recovery code can replace TOTP exactly once and that the same code cannot be reused later.

#### Checklist

1. Log out again after the TOTP login proof
2. Start another brand-new login for the same MFA-configured user
3. Confirm the browser lands on `/auth/mfa/verify`
4. Choose one unused recovery code that was saved during setup
5. Submit that recovery code through the recovery form instead of a TOTP code
6. Confirm recovery succeeds and the browser continues into authenticated usage
7. Log out again to force a fresh login session
8. Sign in once more with the same user so the MFA challenge appears again
9. Submit the **same** recovery code a second time
10. Confirm the backend rejects it and does not complete MFA
11. If needed for extra confidence, submit a different unused recovery code and confirm that a new unused code still works once

#### What counts as a pass

- one valid recovery code can replace TOTP exactly once
- the same code cannot be reused in a later fresh login session
- recovery completion still results in authenticated usage only after the backend accepts the code

### Evidence to capture

Capture at least the following during the proof:

- screenshot or screen recording of the QR setup page showing the visible QR code
- screenshot of the authenticator app entry showing issuer/email presentation
- screenshot or log output showing successful setup completion
- screenshot or log output showing successful MFA verification after fresh login
- screenshot or log output showing first successful recovery-code usage
- screenshot or log output showing the second reuse attempt being rejected

### Important boundary

This section is a manual operator/QA proof procedure.
It is intentionally different from the repo's existing mocked browser tests and backend E2E tests.
Do not claim Phase 5 is operationally proven until this real-device checklist has been executed in the target environment.

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
7. Confirm the browser reports reset success
8. Attempt login with the old password and confirm it fails
9. Attempt login with the new password and confirm it succeeds
10. Trigger another reset email if you need an extra token for negative-path proof
11. For expired-token proof, expire the token by waiting past validity or by using the available local test support if that is your current workflow
12. Confirm an expired reset token fails
13. For reuse proof, successfully use one reset token once and then try the same link again
14. Confirm the reused token fails

#### What counts as a pass

- forgot-password delivered a real email through the local SMTP capture path
- the reset link worked in a real browser
- the old password stopped working
- the new password worked
- expired-token failure was confirmed
- reused-token failure was confirmed

---

## [PENDING — DEPLOYMENT PHASE]

These procedures are intentionally deferred until the deployment/release phase is in scope:

- startup/shutdown runbooks for deployed environments
- rollback procedure
- production log access procedure
- production secret rotation procedure
- production mail-provider cutover procedure
