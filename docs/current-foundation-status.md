# Current Foundation Status

## Purpose

This file is the current shipped-truth snapshot for the repository.

Use it to answer:

- what is actually implemented now
- what is validated enough to rely on
- what exists only as broader architecture direction
- what is intentionally deferred
- which off-repo specs are currently active for future module work

This file is not a roadmap.
It is not a changelog.
It is not a replacement for `ARCHITECTURE.md`, `docs/security-model.md`, backend/frontend engineering law, API docs, or module master specs.

If a broader architecture doc describes something beyond the current shipped slice, this file wins for present-state questions.

---

## Current Repo Position

The repository currently proves and protects a foundation-first Hubins slice:

1. multi-tenant reverse-proxy topology
2. browser and SSR request contracts
3. host-derived tenant identity
4. session and cookie behavior
5. Auth + User Provisioning as the first real module

This repo is not yet the full Hubins platform.
It contains broader design direction for future modules, but only a smaller subset is implemented and operationally meaningful today.

---

## Shipped And Load-Bearing Now

### 1. Topology and request model

The following are part of current repo truth:

- single public browser origin through the reverse proxy
- browser requests use relative `/api/*` paths
- SSR requests use the internal backend path with forwarded host, cookie, and forwarded-header context
- host-derived tenant resolution is load-bearing
- same-origin cookie behavior is load-bearing
- proxy conformance is part of the foundation, not a nice-to-have

For details, see:

- `ARCHITECTURE.md`
- `docs/security-model.md`
- relevant ops docs when topology proof or recovery is the task

### 2. Security and trust boundaries

The following are part of current repo truth:

- tenant isolation is fail-closed
- session and cookie behavior are backend-owned and security-sensitive
- browser and SSR auth flows are intentionally different where topology requires it
- SSO start and callback behavior are trust-boundary-sensitive
- auth/session/tenant logic is not a frontend-owned concern

### 3. Auth + User Provisioning

The first shipped module is Auth + User Provisioning.

This includes current repo-level support for:

- register
- login
- logout
- `/auth/me`
- `/auth/config`
- forgot password
- reset password
- public signup
- email verification
- resend verification
- MFA setup
- MFA verify
- MFA recovery codes
- Google SSO
- Microsoft SSO
- invite issuance
- invite acceptance
- invite resend / invalidation behavior
- admin invite management
- audit viewing
- outbox-backed email delivery support

The backend API contract for this shipped slice is documented under:

- `backend/docs/api/auth.md`
- `backend/docs/api/invites.md`
- `backend/docs/api/admin.md`

### 4. Frontend shipped surface

The frontend currently contains shipped support for:

- public auth pages
- signup and verification flows
- forgot/reset-password flows
- MFA setup and verify flows
- SSO completion flow
- member landing
- admin landing
- invite acceptance and registration continuation
- admin invite management
- browser API client behavior through `/api/*`
- SSR API client behavior for server-side bootstrap

### 5. Foundation discipline that is already real

The repo already treats these as active engineering truth:

- backend and frontend engineering law
- review discipline
- quality-bar and readiness discipline
- security and threat-boundary documentation
- runbook and release-engineering documentation
- proxy/topology-sensitive proof expectations

These are part of current working discipline, not future intent only.

---

## Partially Implemented Or Transitional Now

These exist in the repo or current workflow, but should be described carefully.
They are not absent, but they are not yet the same thing as a fully closed next module.

### 1. Workspace setup banner and `/admin/settings`

Current truth:

- the auth/provisioning slice depends on a workspace setup concept
- `/admin` and `/admin/settings` behavior matters for admin continuation and setup guidance
- the final Settings state model is not yet the active shipped module state model
- current scaffolding or placeholder behavior must not be mistaken for the final Settings implementation

Use the auth docs and current repo code for what exists now.
Do not describe the Settings module as implemented.

### 2. QA and readiness closure depth

The repo has strong QA, audit, ops, and readiness material.
But some readiness/proof surfaces still represent closure work for the Auth + User Provisioning module rather than completed future-module expansion.

### 3. Prompt and documentation cleanup state

The repo contains documentation and prompt infrastructure that is already useful, but the documentation system is still being tightened to reduce duplication, drift risk, and continuation-chat waste.

That means:

- active docs exist now
- some router and support docs may still be in cleanup motion
- do not assume every secondary doc is canonical just because it exists

---

## Explicitly Deferred Or Not Yet Shipped

Do not describe the following as current shipped product surfaces unless a higher-truth module spec explicitly says otherwise.

### Deferred from Auth + User Provisioning closure

These are not part of the current shipped auth closure target:

- admin-facing outbox UI
- SCIM
- SAML
- HRIS import as a fully implemented user-facing module surface
- groups / teams
- device/session management UX
- advanced MFA methods beyond TOTP + recovery codes
- self-serve tenant/account creation

### Broader Hubins modules not yet implemented as shipped modules here

These may exist as architecture direction, planning, or future module truth, but are not current shipped repo modules:

- Account Settings as a completed implemented module
- Documents
  n- Benefits
- Payments
- Marketplace
- Policies as a built tenant surface
- full Shared Templates & Communications surface
- broader workflow/runtime/product surfaces beyond the current foundation slice

If a future-module spec exists, treat it as future module truth, not as evidence that the module is already implemented.

---

## Active Off-Repo Module Truth

One important exception exists for future module work:

### Settings module

`Account-Settings-Master-Context-v6_8.docx` is currently the highest source of truth for the Settings module specifically.

Use it only when the task is about Settings.
Do not let it override unrelated repo truth.

Important:

- it is module-specific, not repo-global
- it contains locked decisions and active future-module design truth
- it explicitly bans certain historical raw docs from continuation use

That document means:

- Settings design truth is real
- Settings implementation is not yet complete
- Settings should not be described as a shipped implemented module today

---

## Canonical Present-State Reading Rules

Use this order for current repo truth questions:

1. this file
2. `ARCHITECTURE.md`
3. `docs/security-model.md`
4. area-specific engineering law and API docs
5. code and tests
6. task-gated support docs only when needed

If a question is specifically about a future complex module with its own higher-truth master spec, use that module spec only for that module.

---

## What This File Intentionally Does Not Do

This file does not:

- retell the full architecture
- restate security law in detail
- duplicate backend or frontend engineering rules
- duplicate API docs
- act as a decision log
- list every historical hardening step
- act as a future roadmap for all modules

If those details are needed, route to the correct authority doc.

---

## Final Snapshot

### True now

- topology-first multi-tenant foundation is real
- browser and SSR request models are real
- host-derived tenant behavior is real
- session/cookie/auth trust boundaries are real
- Auth + User Provisioning is the first real shipped module
- repo quality/review/security/release discipline is real

### Not true now

- the full future Hubins product is implemented here
- Settings is fully implemented
- every documented future module is already shipped
- every support doc is equally canonical

### Working rule

When in doubt, describe the repo as:

**a foundation-first multi-tenant Hubins repository with Auth + User Provisioning implemented and broader module architecture partially designed but not yet broadly shipped.**
