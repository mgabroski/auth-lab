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

## Phase 6 real Google SSO integration proof

This section is the canonical operational procedure for the Phase 6 Google live-provider proof scope.

### Goal

Prove all of the following against the real staging stack:

- Google OAuth browser round-trip works end to end
- session creation is correct after callback completion
- user, membership, and tenant data are correct after Google sign-in
- Google SSO respects LOCK-4 for expired invites
- Google SSO respects LOCK-5 and continues into app-level MFA when required
- audit evidence exists for the successful sign-in
- Google provider key discovery is reachable from the staging network

### Preconditions

Before starting the proof, confirm all of the following:

1. the shared staging backend is running with real `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`
2. the staging Google app registration includes the exact redirect URI for the tenant host you are about to prove
3. the target tenant allows Google SSO
4. you have one real Google account that matches an already-`ACTIVE` membership in the target tenant
5. you have one target email whose only tenant-entry basis is an expired invite, for LOCK-4 validation
6. you have one admin-path persona that should require MFA after SSO, for LOCK-5 validation
7. you have access to the staging audit log surface or direct DB/log inspection method used by the team
8. the staging network can reach Google's JWKS endpoint:

```bash
curl -fsS https://www.googleapis.com/oauth2/v3/certs > /dev/null
```

### A. Configuration proof

#### Goal

Prove the staging Google configuration is correct before spending time on browser debugging.

#### Checklist

1. open the staging backend secret/config source and confirm `GOOGLE_CLIENT_ID` is set
2. confirm `GOOGLE_CLIENT_SECRET` is set
3. confirm `SSO_STATE_ENCRYPTION_KEY` is set to the staging value
4. confirm the Google app registration type is **Web application**
5. confirm the exact authorized redirect URI is registered in Google Cloud Console:

```text
https://<tenant-host>/api/auth/sso/google/callback
```

6. confirm the tenant being tested has `google` in its allowed SSO providers
7. confirm the staging tenant host loads through the normal browser path and that browser requests still use same-origin `/api/*`

#### What counts as a pass

- backend secrets are present in staging
- the Google app registration exactly matches the callback URI used by the tenant host under proof
- provider-key reachability succeeds from the staging network

### B. Active member success proof

#### Goal

Prove an already-active member can sign in with a real Google account and that the resulting session and tenant context are correct.

#### Checklist

1. open the target tenant host in a fresh browser session
2. start Google SSO from the real login page
3. complete the Google account chooser / consent flow with the real test account
4. confirm the browser returns to the tenant host, not another tenant
5. confirm the browser lands on `/auth/sso/done` only transiently and then resolves into the correct post-auth route
6. call or inspect `/api/auth/me` for that same browser session
7. confirm the returned user email matches the Google account used in the round-trip
8. confirm the returned tenant key and membership role/status match the expected tenant membership
9. confirm the backend session cookie exists and the session is bound to the same tenant
10. confirm an `auth.sso.login.success` audit entry exists for that sign-in

#### What counts as a pass

- a real Google account completes the OAuth round-trip successfully
- authenticated session truth is owned by the backend after callback completion
- `/auth/me` reflects the correct user, tenant, and membership context
- success audit evidence exists

### C. LOCK-4 expired-invite rejection proof

#### Goal

Prove Google SSO does not revive an expired invite when that invite is the user's only tenant-entry basis.

#### Checklist

1. prepare or confirm an expired invite for the target tenant and email address
2. start Google SSO on that tenant host using the matching Google account
3. complete the Google provider flow
4. confirm the backend rejects the callback instead of activating membership
5. confirm no new user row or active membership was created as a side effect
6. confirm the recovery path remains admin resend or recreate invite

#### What counts as a pass

- expired invite flow is rejected
- Google SSO does not bypass invite expiration
- no orphan user or revived membership is created

### D. LOCK-5 MFA continuation proof

#### Goal

Prove Google SSO does not bypass app-level MFA requirements.

#### Checklist

1. use an admin-path persona that should require MFA in the target tenant
2. start Google SSO and complete the provider flow
3. confirm the callback resolves into the backend-owned continuation route instead of direct authenticated access
4. if MFA has not yet been configured for that user, confirm continuation goes to `/auth/mfa/setup`
5. if MFA is already configured for that user, confirm continuation goes to `/auth/mfa/verify`
6. complete the required MFA step and confirm only then does authenticated access continue

#### What counts as a pass

- Google SSO never lands directly in the authenticated area when app-level MFA is still required
- setup is required for MFA-unconfigured admin users
- verify is required for MFA-configured admin users

### Evidence to capture

Capture at least the following during the proof:

- screenshot of the Google Cloud Console redirect URI configuration
- screenshot or terminal output proving JWKS endpoint reachability from staging
- browser capture of successful Google sign-in for an already-active member
- `/api/auth/me` evidence showing correct user, tenant, and membership context after success
- audit evidence for `auth.sso.login.success`
- browser and/or backend evidence showing expired-invite rejection
- browser evidence showing MFA continuation after Google SSO for the admin-path persona

### Important boundary

This is a live-provider operator/QA proof procedure.
The repository's automated tests can prove policy and callback behavior, but they do not replace a real Google credential round-trip in staging.
Do not claim Phase 6 is operationally proven until this checklist has been executed with real Google credentials in the target staging environment.

## Phase 7 real Microsoft SSO integration proof

This section is the canonical operational procedure for the Phase 7 Microsoft live-provider proof scope.

### Goal

Prove all of the following against the real staging stack:

- Microsoft OAuth browser round-trip works end to end
- session creation is correct after callback completion
- user, membership, and tenant data are correct after Microsoft sign-in
- Microsoft SSO respects the repo's email-claim fallback contract
- Microsoft SSO respects LOCK-4 for expired invites
- Microsoft SSO respects LOCK-5 and continues into app-level MFA when required
- audit evidence exists for the successful sign-in
- Microsoft provider key discovery is reachable from the staging network

### Preconditions

Before starting the proof, confirm all of the following:

1. the shared staging backend is running with real `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET`
2. the staging Microsoft app registration includes the exact redirect URI for the tenant host you are about to prove
3. the target tenant allows Microsoft SSO
4. you have one real Microsoft account that matches an already-`ACTIVE` membership in the target tenant
5. you have one target email whose only tenant-entry basis is an expired invite, for LOCK-4 validation
6. you have one admin-path persona without MFA configured, for the `MFA_SETUP_REQUIRED` branch
7. you have one admin-path persona with verified app-level MFA already configured, for the `MFA_REQUIRED` branch
8. you have access to the staging audit log surface or direct DB/log inspection method used by the team
9. the staging network can reach Microsoft's JWKS endpoint:

```bash
curl -fsS https://login.microsoftonline.com/common/discovery/v2.0/keys > /dev/null
```

### A. Microsoft app registration creation guide

#### Goal

Create the exact Microsoft Entra app registration shape required by this repo, starting from the Azure portal, with no guessing.

#### Steps

1. Open `https://portal.azure.com/` in a real browser and sign in with the Azure account that owns the staging Microsoft Entra tenant
2. In the portal search bar, type **Microsoft Entra ID** and open it
3. In the left navigation, open **Applications** → **App registrations**
4. Click **New registration**
5. In **Name**, enter exactly: `Hubins Auth-Lab Staging SSO`
6. Under **Supported account types**, choose **Accounts in any organizational directory and personal Microsoft accounts**
7. Leave the initial **Redirect URI** field empty on the first screen and click **Register**
8. After the app opens on the **Overview** page, copy and store:
   - **Application (client) ID**
   - **Directory (tenant) ID**

9. In the left navigation for the app, open **Authentication**
10. Under **Platform configurations**, click **Add a platform**
11. Choose **Web**
12. In **Redirect URI**, enter the exact callback URL for the tenant host you are proving:

```text
https://<tenant-host>/api/auth/sso/microsoft/callback
```

13. Click **Configure**
14. Stay on the app and open **Certificates & secrets**
15. Under **Client secrets**, click **New client secret**
16. In **Description**, enter exactly: `Hubins Auth-Lab staging backend secret`
17. Choose an expiration that matches your team's staging secret-rotation policy
18. Click **Add**
19. Immediately copy the new **Value** for the client secret and store it securely
20. Do **not** use the secret's **Secret ID** in this repo

#### Exact repo mapping from Microsoft values

- **Application (client) ID** → `MICROSOFT_CLIENT_ID`
- client secret **Value** → `MICROSOFT_CLIENT_SECRET`
- **Directory (tenant) ID** → operator record only; this repo does **not** read a `MICROSOFT_TENANT_ID` env var

### B. Configuration proof

#### Goal

Prove the staging Microsoft configuration is correct before spending time on browser debugging.

#### Checklist

1. open the staging backend secret/config source and confirm `MICROSOFT_CLIENT_ID` is set
2. confirm `MICROSOFT_CLIENT_SECRET` is set
3. confirm the values match the Microsoft app registration you just created
4. confirm `SSO_STATE_ENCRYPTION_KEY` is set to the staging value
5. confirm the exact redirect URI configured in Microsoft matches the tenant host under test:

```text
https://<tenant-host>/api/auth/sso/microsoft/callback
```

6. confirm the tenant being tested has `microsoft` in its allowed SSO providers
7. confirm the frontend is still using the locked same-origin `/api/*` browser topology and is **not** trying to call Microsoft through `fetch()`

#### What counts as a pass

- backend secrets are present in staging
- the Microsoft app registration exactly matches the callback URI used by the tenant host under proof
- provider-key reachability succeeds from the staging network

### C. Claim / issuer proof

#### Goal

Prove the repo's Microsoft-specific claim and issuer assumptions line up with the real provider.

#### What must be true

1. the repo resolves user email in this order:
   - `email`
   - `preferred_username`
   - `upn`

2. the backend lowercases the resolved email before membership lookup and identity linking
3. the backend does **not** use a static Microsoft tenant ID env var
4. the backend reads `tid` from the unverified token payload only to build the expected issuer and then verifies the token against:

```text
https://login.microsoftonline.com/<tid>/v2.0
```

#### Manual confirmation steps

1. perform one successful Microsoft sign-in with the real active member account
2. inspect the resulting user row / session / audit evidence using the team's normal staging inspection path
3. confirm the resolved email matches the expected Microsoft account email identity for that user
4. if the sign-in used an enterprise account without a direct `email` claim, record whether the match came from `preferred_username` or `upn`
5. if the token or logs expose tenant metadata through approved inspection channels, confirm the tenant-specific issuer path corresponds to the token `tid`

#### What counts as a pass

- the successful sign-in resolved the expected email identity
- fallback behavior is understood and documented for the tested account
- issuer resolution matches the token tenant context instead of relying on a static tenant env var

### D. Active-member success proof

#### Goal

Prove an already-active member can complete the real Microsoft browser round-trip and land in an authenticated session.

#### Checklist

1. open the real tenant login page on the staging tenant host
2. start Microsoft SSO from the real login page
3. complete the Microsoft browser sign-in with the active-member account
4. confirm the browser is redirected back to the app through:

```text
/api/auth/sso/microsoft/callback
```

5. confirm the app lands on the expected post-SSO page, not an error screen
6. call or inspect `/api/auth/me` for that same browser session
7. confirm the returned user email matches the Microsoft account used in the round-trip
8. confirm the returned tenant key and membership role/status match the expected tenant membership
9. confirm the backend session cookie exists and the session is bound to the same tenant
10. confirm an `auth.sso.login.success` audit entry exists for that sign-in

#### What counts as a pass

- a real Microsoft account completes the OAuth round-trip successfully
- authenticated session truth is owned by the backend after callback completion
- `/api/auth/me` reflects the correct user, tenant, and membership context
- success audit evidence exists

### E. LOCK-4 expired-invite rejection proof

#### Goal

Prove Microsoft SSO does not revive an expired invite when that invite is the user's only tenant-entry basis.

#### Checklist

1. prepare or confirm an expired invite for the target tenant and email address
2. start Microsoft SSO on that tenant host using the matching Microsoft account
3. complete the Microsoft provider flow
4. confirm the backend rejects the callback instead of activating membership
5. confirm no new user row or active membership was created as a side effect
6. confirm the recovery path remains admin resend or recreate invite
7. confirm a failure audit entry exists if your normal inspection path exposes it

#### What counts as a pass

- expired invite flow is rejected
- Microsoft SSO does not bypass invite expiration
- no orphan user or revived membership is created

### F. LOCK-5 MFA continuation proof

#### Goal

Prove Microsoft SSO does not bypass app-level MFA requirements.

#### `MFA_SETUP_REQUIRED` branch

1. use the admin-path persona that does **not** yet have verified MFA configured
2. start Microsoft SSO and complete the provider flow
3. confirm the callback resolves into the backend-owned continuation route instead of direct authenticated access
4. confirm continuation goes to `/auth/mfa/setup`
5. complete setup and confirm only then does authenticated access continue

#### `MFA_REQUIRED` branch

1. use the admin-path persona that already has verified app-level MFA configured
2. start Microsoft SSO and complete the provider flow
3. confirm the callback resolves into the backend-owned continuation route instead of direct authenticated access
4. confirm continuation goes to `/auth/mfa/verify`
5. complete verification and confirm only then does authenticated access continue

#### What counts as a pass

- Microsoft SSO never lands directly in the authenticated area when app-level MFA is still required
- setup is required for MFA-unconfigured admin users
- verify is required for MFA-configured admin users

### G. Audit and session proof

#### Goal

Prove the successful Microsoft callback produced the expected internal application state.

#### Checklist

1. inspect the created or reused session after successful callback completion
2. confirm the session contains the expected user ID, membership ID, tenant ID/tenant key, role, and verified-auth state
3. inspect audit evidence for the same sign-in event
4. confirm a success audit entry exists for `auth.sso.login.success`
5. confirm the audit metadata records `provider: microsoft`
6. do **not** require raw token logging as proof

#### What counts as a pass

- session truth is correct after callback completion
- tenant and membership context are correct
- audit evidence exists and attributes the success to Microsoft SSO

### H. Minimal operator checklist

Use this short checklist when you only need the minimum operational path:

1. create the Microsoft app registration
2. add the **Web** redirect URI for `https://<tenant-host>/api/auth/sso/microsoft/callback`
3. create the client secret and copy the **Value**
4. update backend env from `backend/.env.example` or `infra/.env.stack.example`:
   - `MICROSOFT_CLIENT_ID`
   - `MICROSOFT_CLIENT_SECRET`

5. confirm frontend env from `frontend/.env.example` stays unchanged for Microsoft secrets
6. restart the app / stack so backend picks up the new credentials
7. run a real browser Microsoft sign-in
8. verify callback completion, authenticated session, and audit evidence
9. verify expired-invite rejection
10. verify MFA continuation for both setup-required and verify-required cases

### Evidence to capture

Capture at least the following during the proof:

- screenshot of the Microsoft Entra app registration redirect URI configuration
- screenshot or terminal output proving Microsoft JWKS endpoint reachability from staging
- browser capture of successful Microsoft sign-in for an already-active member
- `/api/auth/me` evidence showing correct user, tenant, and membership context after success
- audit evidence for `auth.sso.login.success` with `provider: microsoft`
- browser and/or backend evidence showing expired-invite rejection
- browser evidence showing MFA continuation after Microsoft SSO for both setup-required and verify-required admin personas
- notes or screenshot proving which claim supplied the resolved email if the account did not expose a direct `email` claim

### Important boundary

This is a live-provider operator/QA proof procedure.
The repository's automated tests can prove policy and callback behavior, but they do not replace a real Microsoft credential round-trip in staging.
Do not claim Phase 7 is operationally proven until this checklist has been executed with real Microsoft credentials in the target staging environment.

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

1. whether the current path writes audit only on success, or on both success and failure
2. whether the tenant/user context was available at the point the event was written
3. whether the event exists but you are looking in the wrong tenant scope
4. whether a failing transaction rolled back an earlier write you expected to survive

For auth/provisioning, the audit trail is not optional convenience data.
If a required audit event is missing, treat it as a real defect.

---

## Local reset / reseed procedure

Use this when local data is dirty and you need a predictable starting point.

### 1. Stop local app processes

Stop any running backend/frontend dev processes.

### 2. Reset infra volumes when necessary

If you need a full clean reset:

```bash
docker compose -f infra/docker-compose-infra.yml down -v
```

### 3. Start fresh infra

```bash
docker compose -f infra/docker-compose-infra.yml up -d
```

### 4. Recreate backend database schema / migrations if required

Run the repo-standard migration/reset commands used by the backend package.

### 5. Run the canonical local dev seed

```bash
yarn workspace @auth-lab/backend dev:seed
```

### 6. Start backend/frontend again

Use the normal host-run workflow from `docs/developer-guide.md`.

### 7. Confirm baseline health

Confirm:

- backend health endpoint works
- tenant host loads
- Mailpit loads
- the seeded bootstrap invite email is present

If those checks pass, you are back at the canonical local baseline.

---

## Tenant bootstrap runbook

This section is the operator-facing proof contract for bootstrap invite creation in shared QA/staging/production-style environments.

### Goal

Create or ensure a tenant and queue the first pending ADMIN invite through the real outbox + SMTP path, without logging raw invite tokens.

### Local developer path

Local dev may still use seed convenience behavior.
That is not the proof contract for shared environments.

### Shared QA / staging / production-style path

Run the explicit tenant bootstrap command with tenant/admin values appropriate for the environment.

Expected outcome:

- tenant exists or is created
- one pending ADMIN invite exists
- one outbox message is queued for invite delivery
- no raw invite token is printed as the operational delivery mechanism

### Validation sequence

1. run the tenant bootstrap command
2. confirm backend accepted the command without error
3. confirm invite email arrives through the configured email path
4. open the delivered email in the target inbox/sandbox
5. open the invite link in a real browser
6. confirm `/accept-invite` loads on the correct tenant host
7. continue through invite acceptance / registration
8. confirm authenticated session creation
9. if applicable, confirm continuation into MFA setup entry point

### Important contract

In shared QA/staging/production-style environments:

- delivery proof is the delivered email, not raw token logging
- browser proof is the real frontend path, not direct API-only completion
- bootstrap remains an operator action, not a public tenant self-serve flow

---

## Phase 4 public signup, verification, and password recovery proof

This section is the canonical operational procedure for the Phase 4 public auth proof scope.

### A. Local public signup + email verification proof

#### Goal

Prove the real local browser flow for:

- public signup on a signup-enabled tenant
- verification email delivery
- verification link completion
- verified session/auth state
- resend verification behavior

#### Local signup proof checklist

1. Start from a clean or trusted local state
2. Ensure the target tenant under test has public signup enabled
3. Open the tenant signup page in the real browser
4. Complete signup with a new email address
5. Confirm the browser shows the expected post-signup continuation state
6. Open Mailpit and confirm the verification email arrived
7. Open the verification link in the browser
8. Confirm verification succeeds and the authenticated state is correct
9. Log out if needed and confirm login now succeeds for that user

#### Resend verification proof checklist

1. Repeat signup or use a user that is still unverified
2. Trigger resend verification
3. Confirm a fresh verification email arrives
4. Open the newest verification link and confirm success
5. If validating old-token behavior, confirm the older token no longer works according to the current contract

#### What counts as a pass

- signup succeeds only on a signup-enabled tenant
- verification email is delivered through the real configured email path
- the verification link works in the real browser
- verified login/authenticated usage is possible afterward
- resend verification sends a fresh usable email

### B. Local blocked-signup proof

#### Goal

Prove signup is blocked where tenant policy disables it.

#### Checklist

1. Choose a tenant with public signup disabled
2. Open signup on that tenant host
3. Attempt the normal signup path
4. Confirm the UI/API response reflects the blocked policy
5. Confirm no active user/membership is created through that blocked path

#### What counts as a pass

- signup cannot be used to bypass tenant policy
- blocked tenant behavior is explicit and consistent

### C. Local forgot-password + reset-password proof

#### Goal

Prove the real local browser flow for:

- forgot-password mail delivery
- reset link completion
- old-password invalidation
- expired-token failure
- reused-token failure

#### Local password-recovery proof checklist

1. Use a real password user in the target tenant
2. Trigger forgot-password from the real UI
3. Confirm the reset email arrives in Mailpit
4. Open the reset link in the browser
5. Set a new password
6. Confirm reset completion succeeds
7. Confirm login with the old password fails
8. Confirm login with the new password succeeds

#### Expired-token proof checklist

1. Generate a reset token
2. Wait for expiry or manipulate test state according to the environment contract
3. Open the expired reset link
4. Confirm reset is rejected

#### Reused-token proof checklist

1. Generate a reset token
2. Complete one successful reset with it
3. Attempt to use the same token again
4. Confirm the second use is rejected

#### What counts as a pass

- forgot-password delivery works through the configured email path
- reset works once with a valid token
- the old password no longer works after successful reset
- expired tokens fail
- reused tokens fail

---

## Phase 8 real-stack browser E2E proof

This section is the operational procedure for running and verifying the Phase 8 real-stack Playwright smoke suite.

### Goal

Prove all of the following against the real Docker Compose topology:

- member login reaches `/app` and the session cookie is set correctly through the proxy
- logout clears the backend session in Redis; `/api/auth/me` returns 401; SSR on `/app` redirects to `/auth/login`
- admin login with no MFA configured continues to `/auth/mfa/setup` (real backend `MFA_SETUP_REQUIRED` nextAction)
- public signup triggers outbox email delivery via Mailpit; the verify-link from the email completes authentication
- signup is blocked on the invite-only tenant (`goodwill-ca`)
- host-derived tenant identity resolves correctly through the Caddy proxy for two different tenant hosts
- SSO start through the proxy sets the `sso-state` cookie (SameSite=Lax, HttpOnly) and returns a redirect to Google
- a session created on `goodwill-open` is rejected with 401 when used on `goodwill-ca`

### Prerequisites

1. Docker and Docker Compose installed
2. `jq` installed (`brew install jq` or equivalent) — required only for proxy conformance, not for Playwright
3. `yarn install` completed at repo root
4. Playwright Chromium installed: `yarn workspace frontend playwright install chromium --with-deps`
5. `infra/.env.stack` exists (copy from `infra/.env.stack.example` if needed)

### Running the real-stack suite locally

```bash
# 1. Start the full Docker Compose topology
./scripts/stack.sh up

# 2. Wait for the health check to pass (stack.sh polls internally)
#    Confirm manually if needed:
curl -sf http://goodwill-ca.lvh.me:3000/api/health && echo "✅ Backend healthy"

# 3. Seed the E2E admin persona (idempotent — safe to re-run)
./scripts/seed-e2e-fixtures.sh

# 4. Run real-stack Playwright smoke tests
yarn workspace frontend test:e2e:real-stack
```

### What counts as a pass

All 8 tests in `frontend/test/e2e/real-stack-smoke.spec.ts` must pass:

1. `member login reaches /app and session cookie is set correctly`
2. `logout clears session and /app is rejected afterward`
3. `admin login without MFA continues to /auth/mfa/setup`
4. `signup delivers verification email and verify-link completes auth`
5. `signup page shows blocked state on invite-only tenant`
6. `topology: host-derived tenant identity resolves correctly through Caddy`
7. `topology: SSO start through proxy sets sso-state cookie and redirects to provider`
8. `cross-tenant isolation: goodwill-open session rejected on goodwill-ca`

### Debugging failures

**Symptom: test 4 (signup/email) times out waiting for email**

Check in order:

1. Mailpit is running: `curl -sf http://localhost:8025/api/v1/messages | jq .messages_count`
2. Backend SMTP env points to Mailpit: `SMTP_HOST=mailpit` in `infra/.env.stack`
3. Outbox worker is running: backend logs show `outbox.worker` events
4. Outbox poll interval is low enough for CI: `OUTBOX_POLL_INTERVAL_MS=2000` recommended

**Symptom: test 1 fails — tenant name does not match heading**

Check that the stack seeded correctly:

```bash
docker compose --env-file infra/.env.stack -f infra/docker-compose.yml \
  exec postgres psql -U auth_lab -d auth_lab \
  -c "SELECT key, name FROM tenants;"
```

Expected rows: `goodwill-ca`, `goodwill-open`, and any other seed-created tenants.

**Symptom: test 3 fails — admin continues to /app instead of /auth/mfa/setup**

The E2E admin persona has MFA set up from a previous manual test run. Re-run the fixture seed to clear MFA rows:

```bash
./scripts/seed-e2e-fixtures.sh
```

**Symptom: SSO test (test 7) fails with non-302 or missing Location header**

Check that the tenant has Google in `allowed_sso`:

```bash
docker compose --env-file infra/.env.stack -f infra/docker-compose.yml \
  exec postgres psql -U auth_lab -d auth_lab \
  -c "SELECT key, allowed_sso FROM tenants WHERE key = 'goodwill-open';"
```

Expected: `allowed_sso` contains `google`.

Also confirm `GOOGLE_CLIENT_ID` is set in `infra/.env.stack` (a placeholder value is fine — the SSO start route only needs a non-empty client ID to build the redirect URL).

### Teardown

```bash
./scripts/stack.sh down
```

To fully reset volumes (needed when DB state is dirty):

```bash
docker compose --env-file infra/.env.stack -f infra/docker-compose.yml down -v
```

### CI execution

The CI job `.github/workflows/frontend-e2e-real-stack.yml` runs automatically on push/PR to any of:

- `frontend/**`
- `backend/**`
- `infra/**`
- `scripts/**`

The job performs all setup steps above automatically: writes a deterministic `infra/.env.stack`, builds the Docker stack, waits for health, seeds E2E fixtures, runs Playwright, uploads traces/screenshots on failure, and tears down.

`MAILPIT_API_URL=http://localhost:8025` is injected by the CI job so the Playwright helper can reach Mailpit from the runner.

---

## Phase 9 — Workspace setup banner and /admin/settings

This section documents the Phase 9 operational contract for workspace setup
state and the admin settings route (ADR 0003).

### Design principle

Workspace setup state belongs to the tenant, not to individual users.
If five admin invites are sent simultaneously and all five complete onboarding,
all five should have a consistent experience — not a race condition where only
one gets a special redirect and the others are silently skipped.

Phase 9 solves this with a **non-blocking banner** on the admin dashboard
(`/admin`) rather than an auth continuation redirect. Any admin can dismiss
it. Once dismissed, it disappears for all admins in the workspace.

### What changed in Phase 9

**`GET /auth/config`** now returns `setupCompleted: boolean` in
`ConfigResponse.tenant`. Derived from `tenants.setup_completed_at IS NOT NULL`.

**All admins always land on `/admin`** after full authentication. No auth
redirect to `/admin/settings` ever occurs. The `AuthNextAction` contract is
unchanged.

**`/admin` dashboard** renders a `WorkspaceSetupBanner` when
`config.tenant.setupCompleted === false`. The banner prompts any admin to
open `/admin/settings` to complete workspace configuration.

**`/admin/settings`** is a new SSR-gated admin-only route. When visited with
`setupCompleted === false`, it calls `POST /auth/workspace-setup-ack` on SSR
load, which sets `tenants.setup_completed_at = now()`. On the next page load
anywhere in the workspace, `GET /auth/config` returns `setupCompleted: true`
and the banner disappears for all admins.

**Role-aware `NONE` routing** was fixed as part of this phase:
`NONE + ADMIN` → `/admin`, `NONE + MEMBER` → `/app`.

### Final destination after bootstrap invite chain

```
operator runs bootstrap command
  → outbox queues invite email
  → admin receives email, opens invite link → /accept-invite
  → registers password → /auth/register
  → MFA setup required → /auth/mfa/setup
  → submits TOTP code → POST /auth/mfa/verify-setup
  → GET /auth/me returns nextAction: NONE, role: ADMIN
  → frontend routes to /admin
  → /admin renders WorkspaceSetupBanner (setupCompleted: false)
  → admin clicks "Open workspace settings →"
  → /admin/settings SSR loads, calls POST /auth/workspace-setup-ack
  → tenants.setup_completed_at = now()
  → admin sees workspace settings placeholder
  → next /admin load: setupCompleted: true → banner gone for all admins
```

### POST /auth/workspace-setup-ack endpoint contract

- **Method:** POST
- **Path:** `/auth/workspace-setup-ack`
- **Auth guard:** ADMIN role + email verified + MFA verified
- **Body:** none
- **Response:** `200 { status: 'ACKNOWLEDGED' }`
- **Scope:** tenant-level — affects all admins in the workspace
- **Idempotent:** yes — `UPDATE WHERE setup_completed_at IS NULL` is a no-op
  when already set. Repeated calls are safe.
- **Effect:** sets `tenants.setup_completed_at = now()`. On the next
  `GET /auth/config` call, `setupCompleted` is `true` and the banner is gone.

### /admin/settings route contract

- **URL:** `/admin/settings`
- **Type:** Next.js SSR Server Component
- **Access gate:** `AUTHENTICATED_ADMIN` only. Any other route state redirects.
- **On first visit** (`setupCompleted === false`): calls
  `POST /auth/workspace-setup-ack` during SSR. Ack failure is swallowed —
  non-fatal. Banner remains until the next successful visit.
- **Content:** placeholder at Phase 9. Settings configuration content belongs
  to later product phases.

### Symptom: setup banner keeps appearing for all admins

This means `setup_completed_at` is not being set. Check in order:

1. Confirm the admin visiting `/admin/settings` is fully authenticated (email
   verified + MFA verified). A session still in `MFA_SETUP_REQUIRED` or
   `MFA_REQUIRED` is redirected away before the ack fires.
2. Check backend logs for `POST /auth/workspace-setup-ack` — confirm it was
   called and returned 200.
3. Inspect the tenant row directly:

```sql
SELECT id, key, name, setup_completed_at
FROM tenants
WHERE key = '<tenant-key>';
```

4. If `setup_completed_at` is still NULL, check backend error logs for the ack
   request. The ack call is swallowed on the frontend — errors are silent.
5. If the ack call returns 403, the session is not fully MFA-verified.

### Symptom: admin lands on /app instead of /admin

As of Phase 9, `NONE + ADMIN` routes to `/admin` and `NONE + MEMBER` routes
to `/app`. If an admin lands on `/app`, check:

1. That the frontend build has the Phase 9 `redirects.ts` changes deployed.
2. That `GET /auth/me` returns `role: 'ADMIN'` for that session.
3. That the session cookie is present and the correct tenant host is being used.

### DB column reference

Migration `0013_tenants_setup_completed_at` adds:

```sql
ALTER TABLE tenants
ADD COLUMN setup_completed_at TIMESTAMPTZ NULL;
```

Existing tenants have `NULL` after migration. Every admin will see the banner
once. The first admin to visit `/admin/settings` clears it for the entire
workspace.

---

---

## Secret Management and Environment Promotion Rules

This section documents the key-separation requirements and staging promotion checklist
that must be satisfied before any shared environment (staging, production) receives a
deployment of this module.

---

### MFA_ENCRYPTION_KEY_BASE64 — key isolation (mandatory before staging)

The MFA encryption key (`MFA_ENCRYPTION_KEY_BASE64`) is an AES-256-GCM key that
encrypts TOTP secrets at rest in the `mfa_secrets` table. If this key is shared
between environments, a DB compromise in one environment can decrypt TOTP secrets
from another. The MFA HMAC key (`MFA_HMAC_KEY_BASE64`) has the same requirement.

**Rule: every environment must have a unique, independently generated key.**

| Environment | Source                             | May reuse another env's key? |
| ----------- | ---------------------------------- | ---------------------------- |
| Local dev   | `.env.example` default             | Yes — data is ephemeral      |
| CI          | CI workflow env var (test DB only) | Yes — isolated test database |
| Staging     | Secret manager (unique)            | **No. Generate fresh.**      |
| Production  | Secret manager (unique)            | **No. Generate fresh.**      |

**Generate a new key:**

```bash
openssl rand -base64 32
```

Store in your secret manager (AWS Secrets Manager, GCP Secret Manager, Doppler, etc.).
Never write a real staging or production key to any file in this repo.

---

### SSO_STATE_ENCRYPTION_KEY — strong key required in all shared environments

The SSO state encryption key (`SSO_STATE_ENCRYPTION_KEY`) protects the CSRF-binding
state cookie during OAuth redirect flows. The `backend/.env.example` default is all-zeros
(`AAAA...=`) which is intentional for local HTTP dev but trivially decryptable.

**Rule: replace with a real 32-byte random key before any shared environment.**

```bash
openssl rand -base64 32
```

The all-zeros key in `.env.example` must never reach staging or production.

---

### Outbox encryption key (`OUTBOX_ENC_KEY_V1`)

Same isolation requirement as MFA keys. The outbox encryption key protects email
payloads at rest. Generate a unique key per environment using `openssl rand -base64 32`.

---

### Staging promotion checklist

Complete this checklist before the first deployment to any shared or staging environment.
Each item is a hard gate — do not promote without all items confirmed.

- [ ] `MFA_ENCRYPTION_KEY_BASE64` is a freshly generated key, unique to this environment
- [ ] `MFA_HMAC_KEY_BASE64` is a freshly generated key, unique to this environment
- [ ] `SSO_STATE_ENCRYPTION_KEY` is a freshly generated 32-byte key (not all-zeros)
- [ ] `OUTBOX_ENC_KEY_V1` is a freshly generated key, unique to this environment
- [ ] `NODE_ENV=production` is set — required for the `Secure` cookie flag on `sid`
- [ ] `LOCAL_OIDC_ENABLED` is absent or `false` — the local OIDC server is CI-only
- [ ] Real Google OAuth credentials (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`) are loaded
      from the secret manager, not from any file
- [ ] Real Microsoft OAuth credentials (`MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`)
      are loaded from the secret manager, not from any file
- [ ] Google OAuth redirect URI is updated to the staging domain in Google Cloud Console
- [ ] Microsoft OAuth redirect URI is updated to the staging domain in Entra (Azure AD)
- [ ] `EMAIL_PROVIDER=smtp` with real SMTP credentials — `noop` is rejected at startup
      when `NODE_ENV=production` (enforced in `di.ts`)
- [ ] SENTRY_DSN is configured if error tracking is required for this environment

---

### Credential rotation procedure

If real OAuth credentials are accidentally exposed — for example, by being included
in a zip artifact that is shared externally — rotate immediately. Do not wait.

**For Google:**

1. Go to Google Cloud Console → APIs & Services → Credentials.
2. Find the OAuth 2.0 Client ID in use and regenerate the client secret.
   (Do not delete and recreate the client — redirect URIs are preserved on regeneration.)
3. Update the secret manager with the new `GOOGLE_CLIENT_SECRET` value.
4. Redeploy the backend (it reads credentials from env at startup).
5. Confirm the old secret is no longer accepted by attempting an SSO start/callback
   cycle with the old value.
6. Record the incident in the decision log if the exposure scope is non-trivial.

**For Microsoft:**

1. Go to Microsoft Entra admin center → App registrations → your app → Certificates & secrets.
2. Delete the exposed client secret and create a new one.
3. Update the secret manager with the new `MICROSOFT_CLIENT_SECRET` value.
4. Redeploy the backend.
5. Confirm the old secret is inactive in the Entra console.

**Note on `.env` files in build artifacts:**

The repo `.gitignore` correctly excludes `backend/.env`. The risk is accidental
inclusion when manually creating zip archives for sharing or review (e.g. zipping
the project directory without using `git archive`). CI workflows use placeholder
values only and never write real credentials to any file. Real credentials must
exist only in the secret manager and in the running process environment — never
in any artifact, log, or commit.

---

## Deferred Operational Items

The following operational items are explicitly deferred from the Auth + User Provisioning
module closure. Each entry names the trigger condition that must be true before the item
becomes required. These are not missing work — they are accepted defers with named
conditions.

---

### DEFER-OPS-1 — Production startup and shutdown procedures

**Status:** Deferred
**Named trigger:** `PRODUCTION_DEPLOY_TRIGGER` — required before the first production
deployment begins.
**Scope:** Ordered startup sequence (infra → backend → frontend → proxy), graceful
shutdown procedure, and health-gate checks required before marking a deployment as live.

---

### DEFER-OPS-2 — Production rollback procedure

**Status:** Deferred
**Named trigger:** `PRODUCTION_DEPLOY_TRIGGER` — required before the first production
deployment begins.
**Scope:** How to roll back a bad backend deploy without losing data. Applied migrations
are immutable — a rollback procedure must address this constraint explicitly. Options
are forward-only migration with a compensating migration, or a point-in-time database
restore depending on the severity of the incident.

---

### DEFER-OPS-3 — Production log access runbook

**Status:** Deferred
**Named trigger:** `PRODUCTION_DEPLOY_TRIGGER` — required before the first production
deployment begins.
**Scope:** How operators access structured JSON logs (CloudWatch or equivalent).
Log query patterns for auth events, session events, and error events. Log retention
policy and access control.

---

### DEFER-OPS-4 — Production secret rotation runbook

**Status:** Deferred
**Named trigger:** `PRODUCTION_SECRET_ROTATION_TRIGGER` — required before any of the
following keys approaches its rotation schedule or requires emergency rotation:
`MFA_ENCRYPTION_KEY_BASE64`, `MFA_HMAC_KEY_BASE64`, `SSO_STATE_ENCRYPTION_KEY`,
`OUTBOX_ENC_KEY_V*` (versioned), session signing secret if added.
**Scope:** Zero-downtime key rotation procedure for each secret type. The outbox
encryption key already supports versioned rotation (`v1`/`v2` key envelope). Other
keys require a migration + re-encrypt pass or a rolling restart with grace period
depending on their usage pattern.

---

### DEFER-OPS-5 — Production TLS certificate provisioning

**Status:** Deferred
**Named trigger:** `PRODUCTION_DOMAIN_REGISTERED_TRIGGER` — required once the production
domain and subdomain pattern are confirmed and DNS is configured.
**Scope:** Caddy (or nginx) TLS configuration for wildcard or per-tenant subdomains.
Certificate authority choice, auto-renewal configuration, and staging certificate
validation before production promotion.
**Current behavior:** `lvh.me` subdomains are used in local and CI environments without
TLS. This is correct for development only and must not be used in staging or production.

---

### DEFER-OPS-6 — Production email-provider failover guidance

**Status:** Deferred
**Named trigger:** `PRODUCTION_DEPLOY_TRIGGER`
**Scope:** What to do when the production SMTP provider becomes unavailable. Note that
outbox messages survive provider downtime — they remain in the DB until successfully
delivered or until `OUTBOX_MAX_ATTEMPTS` is exhausted. Guidance must cover: operator
procedure for switching providers, how to confirm no messages were permanently lost,
and how to replay failed outbox messages after provider recovery.

---

### DEFER-OPS-7 — Incident escalation matrix

**Status:** Deferred
**Named trigger:** `TEAM_GROWTH_TRIGGER` — required when the engineering team exceeds
3 people or when the product enters a paying-customer environment.
**Scope:** Who to contact for a P0 incident. Escalation path for auth/session failures,
data isolation concerns, SSO provider outages, and email delivery failures. On-call
rotation policy if applicable.
