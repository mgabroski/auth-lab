# Hubins Auth-Lab — QA Execution Pack

**Module:** Auth + User Provisioning
**Status:** Ready for QA execution
**Last updated:** 2026-03
**Prepared by:** Engineering
**Validated by:** Engineering lead (see validation note in `docs/developer-guide.md`)

This is the canonical QA execution document for the Auth + User Provisioning module.
A QA engineer or operator can follow this document to execute all critical auth
journeys against the real stack without any additional context.

---

## 1. Environments

### 1.1 Local development (primary pre-staging validation)

Used for: developer self-validation, initial QA dry-runs.

| Component                      | Address                            |
| ------------------------------ | ---------------------------------- |
| Proxy entry (tenant 1)         | `http://goodwill-ca.lvh.me:3000`   |
| Proxy entry (tenant 2)         | `http://goodwill-open.lvh.me:3000` |
| Backend API (direct, internal) | `http://localhost:3001`            |
| Frontend (direct, internal)    | `http://localhost:3000`            |
| Mailpit (email capture)        | `http://localhost:8025`            |
| Postgres                       | `localhost:5432`                   |
| Redis                          | `localhost:6379`                   |

**Start sequence:**

```bash
# 1. Start infra
docker compose -f infra/docker-compose-infra.yml up -d

# 2. Start backend (in one terminal)
yarn workspace @auth-lab/backend dev

# 3. Start frontend (in another terminal)
yarn workspace frontend dev

# 4. Confirm health
curl -sf http://goodwill-ca.lvh.me:3000/api/health && echo "✅ healthy"

# 5. Confirm Mailpit
open http://localhost:8025
```

**Reset to clean state:**

```bash
docker compose -f infra/docker-compose-infra.yml down -v
docker compose -f infra/docker-compose-infra.yml up -d
yarn workspace @auth-lab/backend dev:seed
```

### 1.2 Staging (shared QA / pre-production validation)

Used for: real SSO validation (Google, Microsoft), real email delivery, cross-browser proof.

- Staging must use real SMTP (Mailtrap Email Sandbox or equivalent — not Mailpit).
- SSO credentials (`GOOGLE_CLIENT_ID`, `MICROSOFT_CLIENT_ID`, etc.) must be real staging values.
- Raw token logging must **not** be used as the delivery contract.
- All invite and reset flows must go through the real outbox → SMTP path.
- See `docs/ops/runbooks.md` for staging bootstrap procedure.

---

## 2. Personas

| Persona            | Email                                     | Tenant          | Role   | Notes                                                     |
| ------------------ | ----------------------------------------- | --------------- | ------ | --------------------------------------------------------- |
| Seed admin         | `system_admin@example.com`                | `goodwill-ca`   | ADMIN  | Created by dev seed via invite chain                      |
| E2E member         | `member@goodwill-ca.example.com`          | `goodwill-ca`   | MEMBER | ACTIVE, has password, no MFA                              |
| E2E admin (no MFA) | `e2e_admin_nomfa@goodwill-ca.example.com` | `goodwill-ca`   | ADMIN  | ACTIVE, no MFA configured — triggers `MFA_SETUP_REQUIRED` |
| Open-tenant member | `member@goodwill-open.example.com`        | `goodwill-open` | MEMBER | ACTIVE — used for cross-tenant isolation                  |
| Fresh public user  | Any new email                             | `goodwill-open` | —      | For public signup flows; create fresh per test run        |

**How personas are created:**

- Seed personas are created by `yarn workspace @auth-lab/backend dev:seed` (local) or `db:seed:e2e` (E2E CI).
- Fresh public users are created during test execution.
- SSO personas require a real Google or Microsoft account in staging.

---

## 3. Test Preconditions

Before beginning any QA execution, confirm all of the following:

1. **Stack is healthy.** Backend health endpoint responds. Frontend loads. Mailpit (local) or staging inbox is reachable.
2. **Data is clean.** Run the reset/reseed sequence if any test data is dirty or if this is the first run on a new environment.
3. **Correct host is used.** All browser interactions use the correct tenant host (`goodwill-ca.lvh.me:3000`, not plain `localhost`). Tenant identity is host-derived — using the wrong host is a real error, not a cosmetic one.
4. **Proxy is routing correctly.** Confirm with:
   ```bash
   curl -sf http://goodwill-ca.lvh.me:3000/api/auth/config | jq .
   ```
   This must return tenant config for `goodwill-ca`, not an error.
5. **For SSO flows (staging only):** SSO credentials are confirmed present in the backend env. Redirect URIs are registered in the Google / Microsoft app registration. JWKS endpoints are reachable from the staging network.
6. **For MFA flows:** A real authenticator app (Google Authenticator, 1Password, Microsoft Authenticator, or any TOTP app) is available on the device being used for proof.

---

## 4. Test Flows — Exact Steps and Expected Results

### TC-01 — Invite-based admin bootstrap

**Goal:** Prove invite-based onboarding works end to end for an admin, including MFA setup and workspace setup banner.
**Persona:** Fresh admin email (not previously seeded)
**Tenant:** `goodwill-ca` (invite-only)

| Step | Action                                                                                        | Expected result                                                                                             |
| ---- | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| 1    | Operator runs the tenant bootstrap command targeting `goodwill-ca` with the fresh admin email | Backend logs no error. Outbox row created in DB.                                                            |
| 2    | Open Mailpit (local) or staging inbox                                                         | Invite email delivered to the target address.                                                               |
| 3    | Click the invite link in the email                                                            | Browser opens `/accept-invite?token=…` on `goodwill-ca.lvh.me:3000`.                                        |
| 4    | Fill in name + password and submit                                                            | Backend accepts. Browser continues to `/auth/mfa/setup` (admin requires MFA).                               |
| 5    | Scan the QR code with a real authenticator app                                                | App entry shows issuer `Hubins` and label is the user's verified email address (LOCK-2).                    |
| 6    | Enter the 6-digit TOTP code and submit                                                        | Setup succeeds. Browser lands on `/admin`.                                                                  |
| 7    | Confirm workspace setup banner is visible on `/admin`                                         | `WorkspaceSetupBanner` rendered. `config.tenant.setupCompleted` is `false`.                                 |
| 8    | Click banner link → open `/admin/settings`                                                    | Page loads. Backend SSR calls `POST /auth/workspace-setup-ack`. Response: `200 { status: 'ACKNOWLEDGED' }`. |
| 9    | Return to `/admin` or reload                                                                  | Banner is gone. `GET /auth/config` returns `setupCompleted: true`.                                          |
| 10   | Try to use the original invite link again                                                     | Backend rejects: invite already used.                                                                       |

**Pass criteria:** All steps complete. Invite is single-use. MFA QR is scannable in a real app with correct issuer/label. Banner appears, then disappears after ack.

**Evidence to capture:** Email screenshot; authenticator app screenshot showing issuer + email label; `GET /api/auth/me` JSON after step 6; banner visible screenshot (step 7); `/admin` screenshot after ack (step 9); rejected-reuse response (step 10).

---

### TC-02 — Invite acceptance for an existing user joining a second tenant

**Goal:** Prove a user already active in one tenant can accept an invite into a second tenant without creating a duplicate account.
**Persona:** User who is already ACTIVE in `goodwill-open`, receiving an invite to `goodwill-ca`

| Step | Action                                                            | Expected result                                                                                   |
| ---- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| 1    | Admin sends invite to the existing user's email for `goodwill-ca` | Invite email delivered.                                                                           |
| 2    | User opens invite link on `goodwill-ca.lvh.me:3000`               | `/accept-invite` loads with the invite context.                                                   |
| 3    | User logs in with their existing password (does not re-register)  | Membership created and activated for `goodwill-ca`. Browser continues appropriately.              |
| 4    | `GET /api/auth/me` on `goodwill-ca` host                          | Returns correct `tenantKey: 'goodwill-ca'`, correct `role`, and new membership for `goodwill-ca`. |
| 5    | Confirm user count in DB                                          | Only one user row exists for that email. No duplicate created.                                    |

**Pass criteria:** Existing user gains new tenant membership. No duplicate user row. Session is correctly scoped to `goodwill-ca`.

---

### TC-03 — Public signup and email verification

**Goal:** Prove public signup and email verification work end to end, and that verify tokens are single-use.
**Tenant:** `goodwill-open` (public signup enabled)

| Step | Action                                              | Expected result                                                                                     |
| ---- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| 1    | Open `http://goodwill-open.lvh.me:3000/auth/signup` | Signup form renders.                                                                                |
| 2    | Enter a new email + password + name and submit      | Backend accepts. Browser shows post-signup continuation state (e.g., "check your email").           |
| 3    | Open Mailpit / staging inbox                        | Verification email delivered to the new email address.                                              |
| 4    | Click the verify link from the email                | Browser processes verification. Authenticated state entered (or redirect to appropriate next step). |
| 5    | `GET /api/auth/me`                                  | Returns `session.emailVerified: true`, `nextAction: 'NONE'`.                                        |
| 6    | Try the same verify link a second time              | Backend rejects. Error indicates link is invalid or already used.                                   |

**Pass criteria:** Signup works on a signup-enabled tenant. Verification token is single-use. Second use is explicitly rejected.

---

### TC-04 — Signup blocked on invite-only tenant

**Goal:** Prove public signup is rejected where tenant policy disables it, consistently between the UI and the API.
**Tenant:** `goodwill-ca` (invite-only, `signupAllowed: false`)

| Step | Action                                            | Expected result                                             |
| ---- | ------------------------------------------------- | ----------------------------------------------------------- |
| 1    | Open `http://goodwill-ca.lvh.me:3000/auth/signup` | UI shows signup is not available on this workspace.         |
| 2    | Attempt the signup flow via a direct API call     | 403 or equivalent rejection. No user or membership created. |

**Pass criteria:** Signup cannot bypass tenant policy. UI and API are consistent.

---

### TC-05 — Forgot-password and reset

**Goal:** Prove forgot-password delivery, reset completion, old-credential invalidation, and token single-use enforcement.
**Persona:** Active member with a password (`member@goodwill-ca.example.com`)

| Step | Action                                               | Expected result                                                                   |
| ---- | ---------------------------------------------------- | --------------------------------------------------------------------------------- |
| 1    | Open forgot-password page, submit the member's email | HTTP 200 response regardless of whether email exists (no account-existence leak). |
| 2    | Open Mailpit / staging inbox                         | Reset email delivered.                                                            |
| 3    | Click the reset link from the email                  | `/auth/reset-password?token=…` loads.                                             |
| 4    | Set a new password and submit                        | Reset succeeds. Redirect to login or success state.                               |
| 5    | Attempt login with the OLD password                  | 401 invalid credentials.                                                          |
| 6    | Login with the NEW password                          | Success. Session created.                                                         |
| 7    | Try to use the same reset link again                 | Backend rejects. Error indicates link is invalid or already used.                 |

**Pass criteria:** Old credential is invalidated. Reset token is single-use. The forgot-password endpoint always returns 200 (no email leak).

---

### TC-06 — MFA setup, verify, and recovery code single-use enforcement

**Goal:** Prove real authenticator-app enrollment, post-login MFA challenge, and recovery code single-use enforcement.
**Persona:** Admin with no MFA configured (`e2e_admin_nomfa@goodwill-ca.example.com`)
**Precondition:** LOCK-2 QR label correction is present in the environment under test. Any stale MFA data must be cleared via reset/reseed.

See `docs/ops/runbooks.md` Phase 5 section for the full procedural checklist with sub-steps.

**Summary pass criteria:**

| Check                                                                            | Must be true |
| -------------------------------------------------------------------------------- | ------------ |
| QR code is scannable in a real authenticator app                                 | ✅           |
| Authenticator app entry shows issuer `Hubins` and verified email as label        | ✅           |
| Setup requires a real current TOTP code — a static or empty code is rejected     | ✅           |
| A fresh login after setup triggers the MFA challenge before authenticated access | ✅           |
| A valid TOTP code completes the MFA challenge                                    | ✅           |
| One recovery code works exactly once                                             | ✅           |
| The same recovery code is rejected on second use                                 | ✅           |
| A different unused recovery code still works after one is consumed               | ✅           |

---

### TC-07 — Logout and backend session invalidation

**Goal:** Prove logout clears the backend session (not just the cookie) and that the cleared session is rejected on subsequent requests.
**Persona:** Active member with a live session

| Step | Action                                                               | Expected result                                   |
| ---- | -------------------------------------------------------------------- | ------------------------------------------------- |
| 1    | Sign in as member on `goodwill-ca.lvh.me:3000`                       | `GET /api/auth/me` returns 200 with session data. |
| 2    | `POST /api/auth/logout`                                              | 200 response.                                     |
| 3    | `GET /api/auth/me` in the same browser immediately after             | 401.                                              |
| 4    | Navigate to `http://goodwill-ca.lvh.me:3000/app` in the same browser | SSR redirects to `/auth/login`.                   |
| 5    | Confirm Redis key for that session is gone                           | `redis-cli GET <session-key>` returns nil.        |

**Pass criteria:** Session is invalidated at the backend. Cookie-clearing alone is not sufficient to claim pass — the Redis key must be gone.

---

### TC-08 — Cross-tenant session isolation

**Goal:** Prove a session created on one tenant is rejected when used on a different tenant.
**Personas:** Active member on `goodwill-ca`; active member on `goodwill-open`

| Step | Action                                                                                     | Expected result                                                      |
| ---- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| 1    | Sign in on `goodwill-ca.lvh.me:3000`                                                       | Session cookie set. `GET /api/auth/me` on `goodwill-ca` returns 200. |
| 2    | Send `GET` to `http://goodwill-open.lvh.me:3000/api/auth/me` using the same session cookie | 401. Session is not accepted on a different tenant host.             |
| 3    | Confirm `GET /api/auth/me` on `goodwill-ca.lvh.me:3000` still returns 200                  | Session is still valid on the originating tenant.                    |

**Pass criteria:** The session is bound to the tenant where it was created. Cross-tenant re-use is rejected, not silently accepted.

---

### TC-09 — Google SSO (staging only)

**Precondition:** Real `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` configured in the staging backend. Correct redirect URI registered in Google Cloud Console for the tenant host being tested.

Full procedural checklist is in `docs/ops/runbooks.md` Phase 6 section.

**Key assertions that must be verified:**

| Assertion                                                                    | Reference           |
| ---------------------------------------------------------------------------- | ------------------- |
| Real Google account completes the browser OAuth round-trip                   | Phase 6-B           |
| `/api/auth/me` returns correct user, tenant, and membership after callback   | Phase 6-B           |
| `auth.sso.login.success` audit entry exists                                  | Phase 6-B           |
| Expired invite is rejected — no activation, no orphan user created           | Phase 6-C (LOCK-4)  |
| Admin-path persona continues to `/auth/mfa/setup` if MFA not configured      | Phase 6-D (LOCK-5)  |
| Admin-path persona continues to `/auth/mfa/verify` if MFA already configured | Phase 6-D (LOCK-5)  |
| SSO start uses browser navigation, not `fetch()`                             | Topology constraint |

---

### TC-10 — Microsoft SSO (staging only)

**Precondition:** Real `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET` configured in the staging backend. Correct redirect URI registered in Microsoft Entra app registration.

Full procedural checklist (including Microsoft app registration creation guide) is in `docs/ops/runbooks.md` Phase 7 section.

**Key assertions that must be verified:**

| Assertion                                                                  | Reference |
| -------------------------------------------------------------------------- | --------- |
| Real Microsoft account completes the browser OAuth round-trip              | Phase 7-D |
| Email claim resolved correctly (`email` → `preferred_username` → `upn`)    | Phase 7-C |
| `/api/auth/me` returns correct user, tenant, and membership after callback | Phase 7-D |
| `auth.sso.login.success` audit entry with `provider: microsoft` exists     | Phase 7-G |
| Expired invite is rejected (LOCK-4)                                        | Phase 7-E |
| Both `MFA_SETUP_REQUIRED` and `MFA_REQUIRED` branches validated (LOCK-5)   | Phase 7-F |

---

### TC-11 — Rate limiting behavior

**Goal:** Confirm rate limiting fires before DB work and does not create inconsistent auth state.

| Step | Action                                                                                                  | Expected result                           |
| ---- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| 1    | Send more than the allowed login attempts for a single IP/user combination within the rate-limit window | 429 returned when the threshold is hit.   |
| 2    | Confirm no partial session or unexpected DB row was created for throttled attempts                      | DB clean — no orphan session or user row. |
| 3    | Wait for the rate-limit window to expire, then retry once                                               | Normal flow resumes.                      |

**Note:** In CI, Redis is flushed before Playwright tests to prevent 429 noise. Do not disable rate limiting to make proof pass — if rate limiting blocks unexpected flows, debug the request identity / topology path instead.

---

### TC-12 — Workspace setup banner lifecycle (Phase 9)

**Goal:** Prove the workspace setup banner appears for a fresh tenant and disappears after any admin acknowledges it.
**Persona:** Fully onboarded admin in a tenant where `setup_completed_at IS NULL`

| Step | Action                                                                    | Expected result                                                                                     |
| ---- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| 1    | Admin completes the full onboarding chain (invite → register → MFA setup) | Lands on `/admin`.                                                                                  |
| 2    | Confirm banner is visible on `/admin`                                     | `WorkspaceSetupBanner` rendered. `GET /auth/config` returns `setupCompleted: false`.                |
| 3    | Open `/admin/settings`                                                    | Page loads. SSR calls `POST /auth/workspace-setup-ack`. Response: `200 { status: 'ACKNOWLEDGED' }`. |
| 4    | Return to `/admin` or reload                                              | Banner is gone. `GET /auth/config` returns `setupCompleted: true`.                                  |
| 5    | Open `/admin` in a second admin session (if applicable)                   | Banner is also gone for all admins in the workspace — ack is tenant-level.                          |

**Pass criteria:** Banner is driven by `config.tenant.setupCompleted`. Ack is idempotent and tenant-scoped.

---

## 5. Evidence Expectations

For each test flow, the following evidence must exist before the flow can be marked as passed.

| Category                | Required evidence                                                                                             |
| ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| Email delivery          | Screenshot or exported message from Mailpit / staging inbox showing the email, recipient address, and subject |
| Authentication state    | `/api/auth/me` JSON response (screenshot or curl output) showing user, tenant, membership, and session fields |
| MFA proof               | Authenticator app screenshot showing the entry with issuer `Hubins` and the verified email as label           |
| Audit events            | DB query output or admin audit log surface showing the expected audit action and metadata                     |
| SSO round-trip          | Browser screenshot post-callback; `/api/auth/me` JSON confirming user + tenant context                        |
| Rejection / error cases | Browser screenshot or curl response showing the error, the HTTP status code, and the `error.code` field       |
| Session invalidation    | `GET /api/auth/me` returning 401 after logout; Redis key confirmed absent                                     |
| Cross-tenant rejection  | `GET /api/auth/me` returning 401 on the wrong tenant host                                                     |
| Workspace banner        | Screenshot of `/admin` with banner visible; screenshot after ack with banner absent                           |

Evidence must be captured at time of execution. Screenshots must include the tenant host visible in the browser address bar where applicable.

---

## 6. Out-of-Scope Items

The following are **explicitly not in scope** for this QA execution pack:

- SCIM / SAML / HRIS integrations
- Admin-facing outbox UI
- Richer session / device controls
- Expanded MFA methods (SMS codes, hardware keys)
- Relational redesign of allowed email domains
- Deeper email operations UX beyond current invite / reset / verify flows
- Production rollback and disaster recovery procedures (see `docs/ops/runbooks.md`)
- Any module outside auth + user provisioning
- Performance or load testing

---

## 7. Bug Reporting Expectations

### Severity classification

| Severity | Definition                                                                                                           | Action                                                          |
| -------- | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| **P0**   | Tenant isolation violated — session accepted on wrong tenant; data visible across tenant boundary                    | Block all QA progress immediately; escalate to engineering lead |
| **P0**   | Security credential exposed — raw password, raw token, or secret in a log or response body                           | Block; immediate escalation                                     |
| **P1**   | Auth flow completes but session state is wrong — wrong role, wrong tenant key, wrong `nextAction`                    | Block the affected test flow; report before re-running          |
| **P1**   | Audit event missing for a required auth action                                                                       | Document; treat as a real defect, not a cosmetic issue          |
| **P1**   | Rate limiting does not fire — auth actions succeed indefinitely without throttling                                   | Block; report immediately                                       |
| **P2**   | UI/UX inconsistency without security impact — wrong redirect after correct auth; display error with correct behavior | Report; non-blocking for other test flows                       |
| **P3**   | Minor copy or display issue; non-blocking UI oddity                                                                  | Document; non-blocking                                          |

### Report format

Each bug report must include:

1. **TC reference** — which test case exposed it (e.g., TC-03, TC-08)
2. **Environment** — local / staging; stack version or git commit SHA
3. **Persona** — which persona was active at time of failure
4. **Tenant host** — exact URL shown in the browser address bar at time of failure
5. **Steps to reproduce** — starting from a documented clean reset state
6. **Actual result** — HTTP status, response body, or behavior observed
7. **Expected result** — from the expected results column in this document
8. **Evidence** — screenshot, curl output, or log excerpt
9. **Severity** — using the classification above

### P0 and P1 escalation

P0 and P1 findings must be reported to the engineering lead immediately. They block the release of the auth/provisioning module. No flow in this pack may be marked as passed while a P0 or P1 finding in that flow remains open.

---

## 8. Module Lock Criteria

The Auth + User Provisioning module may be considered **locked** only when all of the following are true:

- [ ] TC-01 through TC-08 executed and passed in local environment with evidence captured
- [ ] TC-09 (Google SSO) executed and passed in staging with real credentials and evidence captured
- [ ] TC-10 (Microsoft SSO) executed and passed in staging with real credentials and evidence captured
- [ ] TC-11 (rate limiting) confirmed
- [ ] TC-12 (workspace setup banner) confirmed
- [ ] All automated CI jobs are green:
  - `backend-tests.yml` (backend unit + DAL + E2E tests + typecheck)
  - `proxy-conformance.yml` (PT-01 through PT-08)
  - `frontend.yml` — `unit` job (typecheck + frontend unit tests)
  - `frontend.yml` — `e2e` job (Playwright real-stack smoke suite)
- [ ] Evidence captured for every test case per Section 5
- [ ] No open P0 or P1 findings
- [ ] `docs/decision-log.md` contains LOCK-1 through LOCK-5 as named entries
- [ ] This document has been reviewed by at least one person who did not author it
- [ ] `docs/developer-guide.md` validation annotation is present
