# QA Execution Pack — Auth + User Provisioning + Control Plane

## Purpose

This is the single canonical QA execution document for the Auth + User Provisioning and Control Plane surfaces shipped in this repository.

Use it for:

- environments
- personas
- test preconditions
- execution order
- exact flow coverage
- expected evidence
- out-of-scope items
- bug reporting expectations
- signoff readiness

This file is the authoritative QA execution surface for this area.
Do not maintain a second competing QA execution script for the same module.

If a tester-friendly derivative manual exists, it must be generated from this document or kept strictly secondary.
It must not become a second source of truth.

---

## Read This After

Before using this file, read:

1. `docs/current-foundation-status.md`
2. `docs/developer-guide.md`
3. relevant API docs only if a QA question becomes contract-specific

Use this file for QA execution.
Use `docs/developer-guide.md` for environment setup and daily developer workflow.

---

## Scope

This pack covers QA execution for the current shipped Auth + User Provisioning slice, including:

- login and logout
- public signup
- email verification and resend verification
- forgot password and reset password
- invite issuance, acceptance, resend, cancellation, invalidation behavior
- MFA setup, verify, and recovery
- admin invite management
- role-aware landing
- Settings-native workspace setup banner and overview behavior in the current shipped slice
- rate limiting
- access-control denial cases
- Google SSO staging proof
- Microsoft SSO staging proof
- Control Plane create/setup/review/publish/re-entry/status-toggle proof

---

## Out Of Scope

Do not use this pack to claim QA signoff for work outside the current shipped auth/provisioning and Control Plane slices.

Out of scope here:

- SCIM
- SAML
- HRIS module UX
- device/session management UX beyond current shipped flows
- broader Settings write implementation beyond the currently shipped `/admin`, `/admin/settings`, `/admin/settings/access`, and `/admin/settings/account` slice
- CP authentication, operator RBAC, or audit UI work that is not shipped in this repo
- future modules not yet shipped in the repo
- performance/load testing unless explicitly added later

---

## Environments

## Local

Use for:

- baseline auth and provisioning flow validation
- seeded persona validation
- Mailpit-backed email checks
- role-aware route behavior
- workspace invite flows
- MFA local proof
- rate-limit checks
- access denial checks

Expected environment traits:

- tenant-aware `*.lvh.me` local URLs
- Mailpit for email capture
- local developer-controlled reset/reseed flow
- no real production cookie/security claims beyond local intent

## Staging

Use for:

- real Google SSO round-trip
- real Microsoft SSO round-trip
- non-production real SMTP/provider proof where applicable
- browser validation against more realistic environment settings
- browser and backend validation of the shipped Settings bootstrap/overview/account/access slice, including `/settings/bootstrap`, `/settings/overview`, `/settings/access`, `/settings/access/acknowledge`, and the real Account per-card routes

Expected environment traits:

- real provider credentials configured
- correct redirect URIs
- reachable provider endpoints
- environment-specific secrets already set

## Production

This QA pack is not the production operations runbook.
Production release behavior belongs to the relevant ops and release docs.

---

## Canonical Personas

These personas must stay aligned with the current seed/bootstrap truth.
If they change, update this file and `docs/developer-guide.md` in the same PR.

### Required persona classes

- one seeded member persona
- one seeded admin persona
- one invite-only tenant
- one public-signup tenant
- one fresh invitee email for invite tests
- one fresh signup email for signup tests
- one real Google staging account for Google SSO proof
- one real Microsoft staging account for Microsoft SSO proof
- one CP draft account key and one CP published account key for re-entry/status-toggle checks

### Typical local examples

- `member@example.com` -> seeded member on GoodWill Open
- `e2e-admin@example.com` -> seeded admin on GoodWill Open
- `system_admin@example.com` -> invite/bootstrap admin path when present in current seed/bootstrap flow

Treat these as examples tied to the current repo state, not eternal constants.

---

## Preconditions

Before any serious QA execution begins:

1. local or staging environment is up
2. environment-specific secrets/config are already in place
3. seeded personas or required fresh test emails are ready
4. tester knows whether the case is LOCAL only, STAGING only, or both
5. Green-Light Health Check has passed in the active environment

### Green-Light Health Check

At minimum confirm:

- backend health endpoint returns expected success
- invite-only tenant login page loads
- public-signup tenant login page loads
- Mailpit loads for local email testing
- seeded baseline member login works where expected
- CP host loads and CP accounts list page renders

Do not begin deeper QA against a broken baseline environment.

---

## Execution Order

Run cases in this order unless a focused bug task explicitly needs a smaller subset.

### Group 1 — Baseline login and logout

- member login
- admin login continuation
- wrong password
- unknown email
- pending invite blocked login
- logout and protected-route rejection

### Group 2 — Signup and email verification

- public signup success
- invite-only signup blocked
- verification success
- verification invalid/expired
- resend verification

### Group 3 — Password reset

- forgot-password success
- reset-password success
- reset invalid/expired/reused
- unknown email remains vague

### Group 4 — MFA

- setup path reached
- real authenticator proof
- correct TOTP accepted
- wrong TOTP rejected
- recovery code works once
- used recovery code fails

### Group 5 — Invite lifecycle

- new-user invite acceptance
- existing-user invite acceptance
- expired invite
- already-used invite
- admin create invite
- admin cancel invite
- admin resend invite

### Group 6 — Access control and setup guidance

- role-aware landing
- rate limiting
- workspace setup banner behavior, `/admin/settings` overview consumption, real `/admin/settings/access` acknowledge behavior, and real `/admin/settings/account` per-card save behavior
- suspended account denial
- no-membership denial
- cross-workspace isolation if included in current proof scope

### Group 7 — Staging-only SSO

- Google SSO
- Microsoft SSO
- role-aware post-SSO landing
- MFA continuation where applicable

### Group 8 — Control Plane

- create account draft
- save all four Step 2 setup groups
- save Personal sub-page when Personal remains enabled
- confirm review gating blocks until required groups are truly configured
- publish as Disabled
- publish as Active only when Activation Ready passes
- re-enter published account from accounts list
- status toggle Active ↔ Disabled after publish
- confirm `cpRevision` changes on allowance saves but not on publish-only or status-only changes

---

## Core Test Coverage Matrix

Keep this matrix aligned with current shipped behavior.

| Area             | Must be proven                                                                                                                                                                                                                                                                                                    | Environment |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| Login            | member success, admin continuation, wrong password, unknown email                                                                                                                                                                                                                                                 | Local       |
| Logout           | protected pages rejected after logout                                                                                                                                                                                                                                                                             | Local       |
| Signup           | open-tenant signup works, invite-only signup blocked                                                                                                                                                                                                                                                              | Local       |
| Verification     | verify, resend, invalid/expired handling                                                                                                                                                                                                                                                                          | Local       |
| Password Reset   | send, reset, old-password invalidation, invalid/reused token                                                                                                                                                                                                                                                      | Local       |
| MFA              | setup, verify, recovery, single-use recovery code                                                                                                                                                                                                                                                                 | Local       |
| Invite Lifecycle | create, accept, cancel, resend, expired, already-used                                                                                                                                                                                                                                                             | Local       |
| Access Control   | suspended, no-membership, role-aware landing                                                                                                                                                                                                                                                                      | Local       |
| Setup Guidance   | Settings-native workspace setup banner, `/admin/settings` overview, real `/admin/settings/access` acknowledge flow, real `/admin/settings/account` card saves, real `/admin/settings/modules` hub, real `/admin/settings/modules/personal` foundation page, Communications placeholder route, Permissions absence | Local       |
| Rate Limiting    | repeated bad login triggers lockout behavior                                                                                                                                                                                                                                                                      | Local       |
| Google SSO       | live provider round-trip                                                                                                                                                                                                                                                                                          | Staging     |
| Microsoft SSO    | live provider round-trip                                                                                                                                                                                                                                                                                          | Staging     |
| Control Plane    | create, group saves, Personal save, review gating, publish, re-entry, status toggle, honest `cpRevision` behavior                                                                                                                                                                                                 | Local       |
| Settings closure | `/settings/bootstrap`, `/settings/overview`, `/settings/access`, `/settings/access/acknowledge`, `/settings/account`, the three Account card save routes, `/settings/modules`, `/settings/modules/personal`, synchronous CP cascade, persisted aggregate/section state, and honest route treatment                | Local       |

---

## Control Plane execution notes

Use the proxy-routed CP host for the honest browser proof path:
