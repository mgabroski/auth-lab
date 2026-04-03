# QA Execution Pack — Auth + User Provisioning

## Purpose

This is the single canonical QA execution document for the Auth + User Provisioning module.

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
- workspace setup banner behavior where present in the current shipped slice
- rate limiting
- access-control denial cases
- Google SSO staging proof
- Microsoft SSO staging proof

---

## Out Of Scope

Do not use this pack to claim QA signoff for work outside the current shipped auth/provisioning slice.

Out of scope here:

- SCIM
- SAML
- HRIS module UX
- device/session management UX beyond current shipped flows
- broader Settings module implementation beyond the currently shipped auth dependency
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
- workspace setup banner behavior
- suspended account denial
- no-membership denial
- cross-workspace isolation if included in current proof scope

### Group 7 — Staging-only SSO

- Google SSO
- Microsoft SSO
- role-aware post-SSO landing
- MFA continuation where applicable

---

## Core Test Coverage Matrix

Keep this matrix aligned with current shipped behavior.

| Area             | Must be proven                                                    | Environment |
| ---------------- | ----------------------------------------------------------------- | ----------- |
| Login            | member success, admin continuation, wrong password, unknown email | Local       |
| Logout           | protected pages rejected after logout                             | Local       |
| Signup           | open-tenant signup works, invite-only signup blocked              | Local       |
| Verification     | verify, resend, invalid/expired handling                          | Local       |
| Password Reset   | send, reset, old-password invalidation, invalid/reused token      | Local       |
| MFA              | setup, verify, recovery, single-use recovery code                 | Local       |
| Invite Lifecycle | create, accept, cancel, resend, expired, already-used             | Local       |
| Access Control   | suspended, no-membership, role-aware landing                      | Local       |
| Setup Guidance   | workspace setup banner behavior where currently shipped           | Local       |
| Rate Limiting    | repeated bad login triggers lockout behavior                      | Local       |
| Google SSO       | live provider round-trip                                          | Staging     |
| Microsoft SSO    | live provider round-trip                                          | Staging     |

---

## Evidence Expectations

For each executed case, collect only the evidence that materially proves the result.

### Required evidence types

- screenshot with visible address bar for page/result-sensitive cases
- Mailpit evidence for email-driven local flows
- tester notes for exact user-visible message comparisons
- staging screenshots for Google and Microsoft SSO completion
- clear record of any developer-assisted precondition needed for DB-backed cases

### Message discipline

Record exact user-visible messages word-for-word when the message meaning matters.
Do not paraphrase security-sensitive or contract-sensitive messages.

### Environment discipline

Always record whether the case was run locally or on staging.
Do not mix local and staging proof into one ambiguous result.

---

## Developer-Support Cases

Some cases may require engineering help before QA can execute them reliably.
Examples include:

- forcing a membership to `SUSPENDED`
- confirming a user has no membership in a target workspace
- resetting rate-limit state after lockout tests
- forcing a token into an expired state when reuse/expiry cannot be reached naturally within test time
- preparing staging SSO credentials and redirect configuration

When a case requires developer support:

- mark it clearly before execution
- document the exact precondition that engineering applied
- do not let the tester guess hidden setup state

---

## Bug Reporting Expectations

Every QA bug report must include:

- test case or flow area
- environment
- workspace URL
- persona used
- exact reproduction steps
- expected result
- actual result
- exact visible message if relevant
- screenshots with address bar visible
- browser and OS when relevant

### Severity discipline

Use a clear severity model that distinguishes at minimum:

- P0 -> isolation/security breach or stop-everything failure
- P1 -> critical auth/session/role/flow truth failure
- P2 -> functional issue without catastrophic security impact
- P3 -> cosmetic or minor wording issue with no material behavior impact

If tenant isolation is violated, stop testing and escalate immediately.

---

## Signoff Criteria

Do not sign off Auth + User Provisioning unless all of the following are true:

- core local auth flows executed successfully or failed only with known accepted issues
- email-driven local flows executed successfully
- MFA proof executed with real authenticator behavior locally
- invite lifecycle proof executed successfully
- role-aware landing and access denial behavior verified
- rate-limiting behavior verified
- workspace setup banner behavior verified where in current shipped scope
- Google SSO staging proof completed
- Microsoft SSO staging proof completed
- screenshots and evidence package are complete
- no open P0 bugs
- no open P1 bugs
- remaining lower-severity issues are recorded clearly

This aligns with the auth readiness closure rule that QA must have one clear execution document and that auth should not be declared done on code alone. fileciteturn11file11turn11file12

---

## Documentation Coupling Rule

Update this file in the same PR when any of the following change:

- seeded personas
- local/staging execution paths
- visible auth/provisioning flows
- required evidence expectations
- signoff checklist meaning
- environment gating for SSO or email proof
- user-visible message expectations used by QA

If the change is developer-workflow-facing rather than tester-facing, update `docs/developer-guide.md` as well.

---

## Single-Source Rule

This document is the canonical QA execution source for Auth + User Provisioning.

Any separate tester manual, exported PDF, or handoff doc must be treated as:

- a derivative of this pack, or
- a secondary convenience artifact

It must not become an independent truth surface.

---

## Final Position

Use this file to run QA clearly, consistently, and repeatably.

Use `docs/developer-guide.md` to get the environment running.
Use this file to execute, record evidence, and judge QA readiness.
