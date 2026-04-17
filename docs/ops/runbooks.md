# Hubins Auth-Lab — Operations Runbooks (Auth + Control Plane)

## Purpose

This document is the operator-facing runbook for the currently implemented Auth + User Provisioning and Control Plane foundations.

It is intentionally practical.
It is not a design essay.
It exists to answer:

- how to check whether the stack is healthy
- how to bootstrap and validate the current auth flows
- how to validate and recover the current Control Plane publish/status flows
- how to triage the most likely auth and CP failures
- how to rotate security-sensitive keys safely in the current repo
- what adversarial review must happen before major releases

This file is only about the repository's current, real surface.
If a flow is not implemented, this runbook does not pretend it exists.

---

## 1. System dependencies and health checks

## 1.1 Local full-stack health check

Before testing or debugging any auth issue locally, confirm the stack is actually healthy.

### Expected services

- frontend
- backend
- Postgres
- Redis
- Mailpit
- local proxy
- Control Plane frontend

### Commands

```bash
yarn dev
```

In a separate terminal if needed:

```bash
yarn status
```

### Required health checks

#### Backend health endpoint

Open:

```text
http://goodwill-ca.lvh.me:3000/api/health
```

Expected result: JSON response with `ok: true` and healthy dependency checks. In non-production environments the body may also include `env`, `service`, `requestId`, `tenantKey`, and per-dependency `checks`.

#### Mailpit

Open:

```text
http://localhost:8025
```

Expected result:

Mailpit inbox UI loads.

#### Auth surface

Open:

```text
http://goodwill-open.lvh.me:3000/auth/login
```

Expected result:

Login page renders without server error.

#### Control Plane surface

Open:

```text
http://cp.lvh.me:3000/accounts
```

Expected result:

Accounts list page renders without server error and browser requests stay same-origin under the CP host.

#### Seeded member login smoke

Use:

- email: `member@example.com`
- password: `Password123!`

Expected result:

Redirect to `/app`.

### If health checks fail

1. stop assuming the auth flow is broken
2. inspect stack status first
3. reset local DB if state is dirty
4. restart the stack cleanly

Useful commands:

```bash
yarn reset-db
yarn stop
yarn dev
```

---

## 1.2 Control Plane publish and recovery checks

Use this section when CP publish, review, or status-toggle behavior looks wrong.

### Core CP validation path

1. open `http://cp.lvh.me:3000/accounts`
2. confirm the target account row exists and note `cpStatus`
3. open the review page for the target account
4. confirm Activation Ready checks and blocking reasons match the saved Step 2 truth
5. if publish was expected to provision a tenant, confirm the review DTO now shows provisioning state and published timestamp
6. if only a status toggle was performed, confirm the status changed without implying a new allowance revision

### What to check when publish fails

Work these checks in order:

1. confirm the account is still visible in the CP accounts list and uses the expected `accountKey`
2. confirm all required Step 2 groups were actually saved
3. if Personal is enabled, confirm the Personal sub-page was explicitly saved
4. confirm integrations are compatible with Access decisions (for example, Google/Microsoft login cannot stay enabled while the matching integration is disabled)
5. confirm the target status is valid for the current Activation Ready state
6. if the error mentions an existing tenant collision, treat it as a real provisioning conflict rather than a UI bug

### Provisioning truth consistency check

If a publish attempt looks partially applied, verify the following together:

- CP account detail still returns the expected `cpStatus`
- CP review/provisioning data shows whether the account is provisioned
- the tenant key expected from the account key is not duplicated by a tenant created outside Control Plane

The repo contract is that CP provisioning truth and tenant configuration truth stay separate. Do not “fix” a publish issue by inventing manual Settings state.

### Topology note

When validating CP recovery, prefer the proxy-routed host (`cp.lvh.me:3000`) instead of the direct dev server. That is the path that exercises the same-origin `/api/*` contract honestly.

## 2. Local bootstrap and invite proof

## 2.1 Purpose

This proves the current invite bootstrap path end to end using:

- the real backend
- the real outbox path
- Mailpit as the local SMTP sink
- real browser navigation

## 2.2 Reset to clean state

```bash
yarn reset-db
```

Then start the stack:

```bash
yarn dev
```

## 2.3 Generate or verify bootstrap invite state

Use the repo's canonical seed/bootstrap path already wired for the current environment.
Do not invent an alternate “quick local hack” flow when validating operator bootstrap behavior.

## 2.4 Proof sequence

1. open Mailpit
2. confirm the inbox is empty or note existing messages
3. trigger/bootstrap the first admin invite through the normal backend path
4. confirm invite email arrives in Mailpit
5. open the invite link in a real browser
6. confirm the invite is accepted only if valid and tenant is active
7. complete registration if the invitee is a new user
8. confirm authenticated session creation
9. if admin MFA is not yet configured, confirm continuation lands on MFA setup

## 2.5 Expected outcomes

- invite email arrives through the real outbox + SMTP path
- no raw invite token is logged as the operator contract
- invite replay fails
- expired invite fails
- canceled/replaced invite fails
- valid invite reaches authenticated continuation successfully

---

## 3. Public signup, verification, and password recovery proof

## 3.1 Public signup proof

Use the open tenant host:

```text
http://goodwill-open.lvh.me:3000/auth/signup
```

Expected high-level path:

1. sign up with a fresh email
2. land on verify-email waiting screen
3. verification email arrives in Mailpit
4. open the link in the browser
5. verification succeeds
6. login works afterward

## 3.2 Disabled signup proof

Use the invite-only tenant:

```text
http://goodwill-ca.lvh.me:3000/auth/signup
```

Expected result:

The tenant blocks self-service signup.
No live signup form should proceed as though the workspace were open.

## 3.3 Resend verification proof

Expected result:

- resend creates a fresh verification email
- the older token is no longer the one the user should rely on
- invalid or already-consumed verification links fail with a public-safe error

## 3.4 Forgot/reset password proof

Use:

```text
http://goodwill-open.lvh.me:3000/auth/forgot-password
```

Expected high-level path:

1. submit the email
2. observe the generic public-safe confirmation
3. reset email arrives in Mailpit for password users
4. open the reset link in browser
5. set a new password
6. old password no longer works
7. new password works
8. used or expired reset link fails cleanly

---

## 4. MFA proof and triage

## 4.1 MFA setup proof

Use a real authenticator app.
Do not treat mocked unit tests as a substitute for this proof.

Expected path:

1. admin logs in
2. if MFA is required and not configured, user lands on `/auth/mfa/setup`
3. QR is scannable
4. issuer shows `Hubins`
5. account label shows the verified email address
6. code from device is accepted
7. user lands on `/admin`

## 4.2 MFA verify proof

Expected path:

1. admin logs in again after MFA is configured
2. user lands on `/auth/mfa/verify`
3. valid current TOTP succeeds
4. invalid or expired code fails cleanly

## 4.3 Recovery-code proof

Expected path:

1. choose recovery option on MFA verify screen
2. submit a valid unused recovery code
3. login succeeds
4. same code fails if reused

## 4.4 MFA triage checklist

If MFA setup or verification fails:

1. confirm the user is actually on the expected tenant host
2. confirm system time on the test phone is correct
3. confirm the QR issuer/account label is what the repo expects
4. confirm the code was entered within the active 30-second TOTP window
5. confirm the MFA setup record exists for the user in the environment being tested
6. if rotating MFA keys or restoring DB snapshots, check whether stored MFA material is still decryptable under the current key

---

## 5. Google and Microsoft SSO proof

## 5.1 Current scope

Google and Microsoft SSO live-provider proof belongs to staging or another environment with real credentials.
Local dev may prove callback mechanics indirectly, but not full provider round-trips.

## 5.2 SSO start rule

SSO must be started by browser navigation, not `fetch()`.
The browser must perform a real redirect flow to the provider.

## 5.3 Callback expectations

On successful provider return:

- the callback receives both query `state` and matching `sso-state` cookie
- tenant identity still comes from host
- provider/tenant/state coherence checks pass
- session is created only after validation succeeds
- `sso-state` cookie is cleared
- routing continues through backend-authoritative session truth and `nextAction`

## 5.4 SSO failure triage

If SSO fails, check the following in order:

1. was the flow started by full page navigation?
2. is the callback coming back to the correct tenant host?
3. is the `sso-state` cookie present on callback?
4. does the query `state` exactly match the cookie value?
5. is `SSO_STATE_ENCRYPTION_KEY` valid and non-placeholder for this environment?
6. did the return path violate validation rules?
7. are provider credentials and redirect URIs correct?
8. did the provider auth code exchange fail upstream?

## 5.5 Current expected blocked outcomes

The following are expected to fail closed:

- callback with missing `sso-state` cookie
- callback with state mismatch
- callback using tenant-A state on tenant-B host
- expired invite trying to activate membership through SSO when invite validity is required

---

## 6. Session and tenant-isolation triage

## 6.1 Symptom: authenticated on one tenant, denied on another

This is usually correct behavior, not a bug.

The repo intentionally binds sessions to tenant identity.
A session for tenant A must not authenticate tenant B.

## 6.2 Symptom: login looks successful, but SSR renders as unauthenticated

Likely causes:

- SSR wrapper failed to forward `Host`
- SSR wrapper failed to forward `Cookie`
- proxy/forwarded header contract drift
- request hit the wrong host

## 6.3 Symptom: browser login works, but API calls lose session

Check:

1. browser is using same-origin `/api/*`
2. cookie is present for the correct host
3. proxy is not stripping or rewriting cookies
4. session store is reachable
5. session has not been invalidated by logout or rotation

---

## 7. Outbox and email-delivery triage

## 7.1 Symptom: email-triggering flow succeeded but no email arrived

Check in this order:

1. did the business flow actually enqueue an outbox message?
2. is Mailpit or staging SMTP reachable?
3. is the backend worker running?
4. did SMTP adapter classify the provider failure as retryable or permanent?
5. is the outbox payload decryptable under the active outbox key set?

## 7.2 Important storage rule

Auth email payloads are expected to store encrypted token and recipient email fields in outbox storage.
Plaintext token/email in outbox persistence is a security defect.

---

## 8. Key rotation procedures

This section is intentionally honest about what the current repo supports well and what remains more operationally disruptive.

## 8.1 Outbox encryption key rotation

### Current support level

Strongest current support.
The repo already supports versioned outbox encryption keys.
Old ciphertext may remain decryptable while new writes use a newer default version.

### Safe rotation sequence

1. generate a new 32-byte key
2. add it as a new versioned env var, for example `OUTBOX_ENC_KEY_V2`
3. update config so the default outbox encryption version points to the new version
4. deploy with both old and new keys present
5. verify:
   - new outbox writes use the new version prefix
   - existing old-version payloads still decrypt

6. keep the old version present until old queued payloads are fully drained or explicitly rewrapped
7. remove the old key only after confirming no durable payload still depends on it

### Expected impact

No user-facing auth outage if done correctly.

### Required proof

- unit tests for old-version decrypt + new-version write behavior
- operator confirmation that no old-version payloads remain before final old-key removal

## 8.2 SSO state encryption key rotation

### Current support level

Operationally simple, short-lived impact.
The state cookie is ephemeral and short-lived.

### Safe rotation sequence

1. generate a new valid 32-byte SSO state key
2. deploy the new key during a low-traffic window
3. expect any in-flight SSO starts to fail and require restart of the SSO flow
4. confirm new SSO starts succeed normally after deployment

### Expected impact

Short-lived disruption for users who began but did not complete SSO during the rotation window.
This is acceptable because callback state is intentionally short-lived.

## 8.3 MFA TOTP secret encryption key rotation

### Current support level

More disruptive.
The current repo uses a single active MFA encryption key for stored TOTP secrets.
It does **not** yet provide automated multi-version rewrap for those stored secrets.

### Safe rotation reality

Current safe options are:

- planned data re-encryption with explicit migration tooling, if such tooling exists and is validated before production use
- or forced MFA re-enrollment/reset for affected users

### Operator rule

Do **not** rotate `MFA_ENCRYPTION_KEY_BASE64` casually.
Treat it as a maintenance event that requires an explicit plan and user-impact decision.

## 8.4 MFA recovery-code HMAC key rotation

### Current support level

Also disruptive.
Stored recovery-code hashes depend on the active HMAC key.
Rotation invalidates the ability to verify previously issued recovery codes.

### Safe rotation reality

Current safe options are:

- coordinated regeneration of recovery codes after rotation
- or full MFA reset/re-enrollment path for affected users

### Operator rule

Do **not** rotate `MFA_HMAC_KEY_BASE64` casually.
Treat it as a user-impacting security maintenance event.

---

## 9. Startup-guard failures

The repo intentionally fails closed on several dangerous startup configurations.
If startup aborts, inspect configuration before trying to bypass the guard.

Examples of expected hard failures outside test:

- placeholder or invalid SSO state key
- unsafe email provider configuration for production-like mode
- illegal reuse of crypto key material across independent security purposes
- enabling local OIDC in production-like mode

Operational rule:

A startup guard failure is a safety mechanism, not a nuisance.
Fix the configuration.
Do not weaken the guard just to get the app running.

---

## 10. Pre-release adversarial security review

Before any major release that changes auth, session, MFA, SSO, invite, verification, reset, or proxy/SSR contract behavior, perform this explicit review.

## 10.1 Scope gate

Ask:

- did tenant resolution logic change?
- did cookie behavior change?
- did SSR forwarding change?
- did callback/state/redirect handling change?
- did token lifecycle or invalidation behavior change?
- did any security-sensitive env/config rules change?

If yes to any item, continue with this checklist.

## 10.2 Required review checklist

### Architecture / trust-boundary review

- confirm topology invariants still hold
- confirm tenant identity remains host-derived
- confirm backend remains session truth authority
- confirm cookie separation remains intact
- confirm fail-closed behavior is preserved on sensitive paths

### Abuse-regression review

- cross-tenant cookie misuse still rejected
- invite replay still rejected
- reset token reuse still rejected
- verification token reuse still rejected
- SSO state tampering still rejected
- return-path abuse still rejected

### Config / startup review

- startup guards still pass in intended environments
- no dev-only auth/provider flags are enabled in production-like configs
- no real secrets were added to repo files or examples

### CI review

- dependency scan green or explicitly triaged
- secret scan green or explicitly triaged
- container scan green or explicitly triaged
- auth/session tests green
- proxy conformance green

### Docs / operator truth review

- runbook updated if operational behavior changed
- threat model updated if new trust boundary or threat path appeared
- ADR updated/added if a security-significant design choice changed

## 10.3 Release stop rule

If a load-bearing security assumption changed and the related tests/docs/review are missing, the release is not security-complete.
Ship only after the missing proof is added or the risk is explicitly accepted by the owner role.

---

## 11. Incident notes and escalation rule

If the system exhibits any of the following, treat it as a high-severity security issue until proven otherwise:

- authenticated access appears to cross tenant boundaries
- session cookies suddenly authenticate the wrong host
- plaintext auth tokens or recipient emails appear in DB/logs/audit payloads
- SSO callback accepts mismatched or missing state material
- MFA verification starts succeeding with stale/reused material
- redirect/return-path handling sends users to unexpected locations after auth

Immediate actions:

1. stop rollout or isolate the environment
2. preserve logs and relevant evidence
3. confirm whether the issue is reproducible on current main
4. inspect the last changes to auth/session/proxy/SSR/security config
5. do not dismiss it as “just QA oddness” until tenant isolation and token/session integrity are ruled out

---

## 12. Practical truth

This repo already has serious auth/security behavior.
But serious behavior is not enough by itself.

These runbooks exist so the system stays operable when something goes wrong, when keys must change, and when release pressure is high.
That is the point of Stage 4: security as a maintained system, not just careful code.
