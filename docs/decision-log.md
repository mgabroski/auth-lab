# Decision Log

This file records non-obvious architectural decisions that should not silently drift.

Each entry explains:

- what was decided
- why it was decided
- what alternatives were rejected
- what consequences follow from that decision

Format:
`## ADR-NNN — Title`

---

## ADR-001 — Next.js App Router over Vite SPA

**Date:** 2026-03
**Status:** Accepted

### Context

We needed to choose a frontend framework for the auth UI foundation. The two candidates were:

- Next.js App Router
- Vite React SPA

### Decision

Use **Next.js App Router**.

### Why

- Sessions use `HttpOnly` cookies. There is no browser-managed auth token in `localStorage`.
- The first render often needs server-side knowledge of session state.
- Tenant identity is derived from host/subdomain, which SSR can read reliably before hydration.
- SSR can call `GET /auth/me` and `GET /auth/config` using the server-side request context.
- This supports a cleaner auth/bootstrap flow than forcing the browser to discover everything after hydration.

### Rejected alternative

**Vite SPA**

A SPA can work, but for this topology it would push too much session/bootstrap logic into client-side loading states and route flicker. That is the wrong tradeoff for an auth-heavy, tenant-aware frontend foundation.

---

## ADR-002 — Two dev modes: host-run for daily work, full stack for topology validation

**Date:** 2026-03
**Status:** Accepted

### Context

We needed to decide whether local development should standardize on:

- host-run development
- or full Docker stack only

### Decision

Use **both**, intentionally.

### Why

#### Host-run mode

Best for daily engineering work:

- faster feedback loop
- backend hot reload
- frontend hot reload
- easier debugging

#### Full stack mode

Required for validating topology behavior that host-run mode does not prove:

- reverse proxy behavior
- forwarded header behavior
- cookie handling through proxy
- same-origin routing
- subdomain tenant resolution through the public entrypoint

### Consequence

A change can be "good enough for host-run" and still be unsafe for topology.
That is why topology-affecting changes must be validated in the full stack too.

---

## ADR-003 — SSO redirect URI embedded in encrypted state

**Date:** 2026-03
**Status:** Accepted

### Context

A single global redirect base URL is too weak for tenant-aware SSO in a subdomain-driven system.

### Decision

Construct the tenant-aware redirect URI at SSO start and embed it in the encrypted SSO state.

### Why

- callback processing uses the exact URI chosen for that flow
- avoids brittle global re-derivation
- supports tenant-aware redirect behavior
- keeps the redirect target protected inside the encrypted state payload

### Rejected alternative

**Global `SSO_REDIRECT_BASE_URL` re-derivation at callback time**

That centralizes the callback origin too aggressively and becomes fragile in a multi-tenant topology.

---

## ADR-004 — SSO state cookie CSRF binding

**Date:** 2026-03
**Status:** Accepted

### Context

OAuth `state` protects against CSRF, but state alone is stronger when also bound to the browser with a short-lived cookie.

### Decision

Set a short-lived `sso-state` cookie and require it to match the callback `state` query parameter.

### Why

- adds browser-bound CSRF protection
- keeps the SSO flow harder to replay incorrectly
- cookie is short-lived and contains only encrypted state
- aligns with a defense-in-depth approach for SSO entrypoints

### Cookie posture

- `HttpOnly`
- `SameSite=Lax`
- short TTL
- cleared on callback completion

### Why not `SameSite=Strict`

The OAuth provider redirects back to our callback URL as a top-level cross-site navigation. `Strict` would block the cookie in that flow and make validation fail.

---

## ADR-005 — Caddy manages `X-Forwarded-For` chain by default

**Date:** 2026-03
**Status:** Accepted

### Context

A manual `header_up X-Forwarded-For {remote_host}` override looked harmless, but it actually collapses the forwarded chain.

### Decision

Do not manually override `X-Forwarded-For` in Caddy. Rely on Caddy's normal reverse proxy behavior.

### Why

- preserves the client IP chain correctly
- avoids flattening all requests into a single proxy-shaped identity
- keeps rate limiting and audit behavior meaningful behind the proxy

### Rejected alternative

**Manual header override**

It is too easy to accidentally destroy the chain that the backend expects when `trustProxy` is enabled.

---

## ADR-006 — Topology-first foundation before broader module expansion

**Date:** 2026-03
**Status:** Accepted

### Context

Hubins is a broader platform, but this repository phase needed a strong foundation before expanding into more modules or richer UI flows.

There was a risk of treating broader product docs as if they implied current implementation completeness.

### Decision

Treat this repo phase explicitly as:

**Topology + FE/BE wiring + Auth/User Provisioning foundation first**

### Why

Because the following are load-bearing and must be correct before broader expansion:

- same-origin FE/BE contract
- SSR backend access contract
- tenant routing and isolation
- session/cookie behavior
- proxy trust assumptions
- backend module/bootstrap discipline
- truthful repo/documentation authority

### Consequence

The repo is allowed to describe the broader Hubins platform direction, but it must always keep current shipped scope explicit through:

- `README.md`
- `docs/current-foundation-status.md`
- this decision log

### Rejected alternative

**Pretend the wider platform architecture equals current repo completeness**

That creates false confidence and causes drift in both implementation and planning.

---

## ADR-007 — Browser uses same-origin `/api/*`, SSR uses direct backend access

**Date:** 2026-03
**Status:** Accepted

### Context

We needed one clear FE/BE communication rule that works with:

- tenant subdomains
- proxy routing
- session cookies
- SSR bootstrap flows

### Decision

Split communication paths by execution environment:

#### Browser

Use relative same-origin `/api/*` through the proxy.

#### SSR / server-side frontend code

Call backend directly through `INTERNAL_API_URL` and explicitly forward:

- `Host`
- `Cookie`
- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`

### Why

This keeps browser behavior aligned with the public topology while allowing SSR to bootstrap session-aware state directly and efficiently.

### Rejected alternatives

#### Browser directly calling backend origin

Rejected because it weakens topology discipline and complicates cookie / origin handling.

#### SSR also calling through public `/api/*`

Rejected because SSR already has direct backend reachability and should preserve the original request context explicitly.

---

## ADR-008 — Tenant identity is derived from routing, not client-selected state

**Date:** 2026-03
**Status:** Accepted

### Context

Multi-tenant systems often drift into client-selected tenant IDs passed in payloads or app state. That weakens isolation and complicates trust assumptions.

### Decision

Derive tenant identity from the request host/subdomain.

### Why

- aligns tenant identity with routing
- avoids client-controlled tenant switching in payloads
- simplifies reasoning about request ownership
- pairs naturally with same-origin browser behavior and SSR host forwarding

### Consequence

Frontend code must not invent its own tenant source of truth.
Tenant-aware behavior must follow the current host.

### Rejected alternatives

- tenant ID in request body
- tenant selection in query string
- tenant stored as client-auth state independent of host

## ADR-009 — Documentation home is scope-split, not single-folder-only

**Date:** 2026-03
**Status:** Accepted

### Context

The repository now has three kinds of active documentation:

- repo-wide truth and architecture documents
- backend law / contract documents
- frontend scope documents that intentionally live close to the frontend surface

Without an explicit rule, future work can create drift by duplicating truth across new folders or by moving backend/frontend docs away from the code they describe.

### Decision

Use a **scope-split documentation home**:

- repo-wide truth lives at repo root and under `/docs`
- backend law/contracts live under `backend/docs/`
- frontend implementation guidance stays close to the frontend surface (`frontend/README.md` and `frontend/src/shared/engineering-rules.md`)

### Why

- keeps repo-wide truth easy to find
- keeps backend contracts and law close to backend code
- keeps frontend guidance close to the frontend implementation surface
- avoids inventing a second parallel home for the same truth

### Consequences

When updating docs:

- change repo-wide status/architecture/decision documents in root `/docs`
- change backend-specific law/contracts in `backend/docs/`
- change frontend-specific guidance where the frontend already keeps it

A new document should not be added until its scope is clear.
If the same fact would need to live in two homes, one of those homes is wrong.

---

## ADR-010 — MFA secrets are global per user, not per tenant

**Date:** 2026-03
**Status:** Accepted

### Context

The auth system is multi-tenant. Users can belong to multiple tenants simultaneously. MFA (TOTP) setup requires generating and storing an encrypted TOTP secret and a set of hashed recovery codes.

We needed to decide whether MFA secrets should be scoped per-user globally or per-membership (per user + per tenant).

### Decision

MFA secrets are **global per user** (`UNIQUE(user_id)` on `mfa_secrets`).

A user has one TOTP secret across the entire platform. If they set up MFA while logged into `acme.hubins.com`, that same verified secret is used when they log into `techstart.hubins.com`.

### Why

#### Identity model is global

A user is a global entity identified by email. Auth identities (password, Google, Microsoft) are already global — a user has one password, not one per tenant. TOTP identity follows the same model.

#### UX coherence

Requiring users to set up a new authenticator app entry for each tenant they join would be confusing and impractical for users who belong to multiple tenants.

#### Simplicity and correctness

Per-tenant MFA would require each tenant's login flow to check for a tenant-scoped secret, and recovery flows would need tenant-scoped recovery code sets. This adds complexity with no security benefit — the TOTP secret authenticates the user's identity, not their membership in a specific tenant.

### Multi-tenant consequences

#### MFA requirement is per-tenant, secret is global

`isMfaRequiredForLogin` checks `membership.role` and `tenant.memberMfaRequired` — both are per-tenant. The enforcement decision (must verify MFA?) is tenant-scoped. The credential (the TOTP secret) is global.

This means:

- A user who is ADMIN in tenant A and MEMBER in tenant B uses the same TOTP secret in both tenants.
- When logging into tenant A (admin, MFA required), they verify their TOTP code.
- When logging into tenant B (member, MFA not required), the same secret exists but is not required.
- The session `mfaVerified` flag is set per-login based on whether the specific login flow required and completed MFA verification.

#### Setup requirement is triggered per-login, not globally

If a user has not yet set up MFA (`hasVerifiedMfaSecret = false`) and logs into a tenant where MFA is required for their role, `nextAction` will be `MFA_SETUP_REQUIRED` for that login session. This works correctly regardless of whether they have completed MFA setup for other tenants, because the global secret is either present and verified or it is not.

### Rejected alternatives

#### Per-membership MFA secrets

Rejected because it requires duplicate authenticator entries, complicates the recovery flow, and provides no meaningful security improvement over global secrets. The TOTP secret authenticates the user's identity, not their role in a specific workspace.

#### Per-tenant MFA secret with tenant-selection at setup time

Also rejected. The UX overhead of choosing "which tenant is this authenticator entry for" is unjustifiable given that the user's physical identity (and therefore their authenticator app) is the same across tenants.

### Named re-evaluation trigger

Re-evaluate this decision when any of the following becomes true:

**`MFA_PER_TENANT_TRIGGER`**

- a regulatory or compliance requirement mandates tenant-isolated MFA credentials
- a tenant requires the ability to independently revoke a user's MFA secret without affecting their access to other tenants
- user research shows the global MFA model creates a meaningful UX problem for multi-tenant users

---

## ADR-011 — Workspace setup banner, not auth continuation redirect

**Date:** 2026-03
**Status:** Accepted (Phase 9 implementation — official replacement for the original LOCK-1 redirect expectation)

### Context

LOCK-1 (see Locked Decisions Register at the end of this file) originally described a one-time
`FIRST_TIME_SETUP` nextAction that would redirect the first fully onboarded admin in a tenant
to `/admin/settings`. Phase 9 evaluated this approach before implementation began and changed
the design. This ADR records what was built in Phase 9 and why the redirect approach was
superseded.

### Decision

Workspace setup guidance is delivered via a **non-blocking banner on `/admin`**, not an auth
continuation redirect.

- All admins always land on `/admin` after full authentication (`NONE + ADMIN`).
- No `FIRST_TIME_SETUP` nextAction is emitted. The `AuthNextAction` contract is unchanged.
- `GET /auth/config` returns `setupCompleted: boolean` derived from `tenants.setup_completed_at IS NOT NULL`.
- The `/admin` page renders a `WorkspaceSetupBanner` when `config.tenant.setupCompleted === false`.
- Any admin visiting `/admin/settings` triggers `POST /auth/workspace-setup-ack` on SSR load,
  which sets `tenants.setup_completed_at = now()`.
- On the next `GET /auth/config` call, `setupCompleted` is `true` and the banner disappears
  for **all admins** in the workspace.

### Why the redirect approach was superseded

#### Race condition

If multiple admin invites are sent simultaneously and all complete onboarding at the same time,
redirect-based first-admin detection creates a race: exactly one admin gets the special redirect
and the rest are silently skipped. The banner approach is consistent — every admin sees it
until any admin dismisses it.

#### Auth continuation is the wrong mechanism for setup guidance

Auth continuation redirects enforce required steps such as email verification and MFA.
Workspace setup is onboarding assistance, not a security gate. Using the auth continuation
contract for a non-mandatory UI hint conflates two distinct concerns and adds unnecessary
complexity to the continuation contract.

#### Tenant-level state, not user-level state

Setup completion belongs to the tenant as a whole, not to the specific user who first
completes the setup flow. The banner correctly models this as a tenant-level flag.

### Consequences

- `FIRST_TIME_SETUP` nextAction does **not** exist and must never be added.
- `frontend/src/shared/auth/redirects.ts` has no `FIRST_TIME_SETUP` case — this is intentional.
- The `AuthNextAction` union type has no `FIRST_TIME_SETUP` member — this is intentional.
- Future product phases that need onboarding flows must model them as page-level state,
  not as auth continuation nextActions.

### Named re-evaluation trigger

**`FIRST_ADMIN_REDIRECT_TRIGGER`**: Re-evaluate if future product requirements need a
hard-gated admin workspace-onboarding sequence that cannot be skipped or deferred by
navigating to other admin pages before setup is complete.

---

## ADR-012 — MFA QR code label uses verified email, not `userId`

**Date:** 2026-03
**Status:** Accepted

### Context

The TOTP QR label is part of the real authenticator-app enrollment surface. The previous behavior used `userId` as the label, which makes the authenticator entry opaque to the user and does not match the intended product behavior.

### Decision

Use:

- issuer: `Hubins`
- label: the user's **verified email address**

The previous `userId` label is treated as an oversight, not as intentional privacy behavior.

### Why

- users recognize their own verified email immediately in authenticator apps
- the label now matches the product-facing identity model
- this is the correct basis for real MFA proof testing

### Consequences

- real MFA proof testing must use the verified-email label behavior
- previously generated dev MFA seeds may still display the old label and should not be treated as proof of the corrected behavior
- environments with stale pre-correction MFA seeds may need reset / reseed before real authenticator-app validation

### Rejected alternative

#### Continue using `userId`

Rejected because it weakens usability and does not reflect the intended user-facing identity for authenticator enrollment.

---

## ADR-013 — Seed/bootstrap invite delivery is environment-specific

**Date:** 2026-03
**Status:** Accepted

### Context

The current stage still relies on operator/bootstrap tenant creation rather than a public self-serve production onboarding flow. The roadmap needed an explicit environment-specific contract for how invite/bootstrap delivery works so that local convenience does not silently become the staging or production rule.

### Decision

Use an environment-specific bootstrap delivery contract.

### Local dev

- raw invite token may be logged to stdout for developer convenience
- local email capture may also be used when SMTP is enabled
- raw token logging is acceptable **only** in local development

### Shared staging / QA

- seed/bootstrap must queue an outbox message
- invite delivery must go through the real outbox + SMTP path
- raw token logging is **not** the operational contract in shared staging / QA

### Production

- seed-style bootstrap is accepted as the operator mechanism for tenant creation at this stage
- this is not a public self-serve onboarding flow
- raw token logging must never occur in production
- the production bootstrap runbook must describe the exact operator sequence

### Consequences

- staging / QA proof phases must validate real outbox-backed invite delivery
- production bootstrap remains an operator flow until a later public onboarding model is introduced
- local developer convenience does not change the staging or production contract

---

## ADR-014 — Expired invites are invalid for SSO activation

**Date:** 2026-03
**Status:** Accepted

### Context

The roadmap identified an open human-decision flag around whether Google or Microsoft SSO could activate a membership whose only tenant-entry basis was an expired invite.

Leaving that ambiguous would create a bypass around invite expiration and produce inconsistent membership activation behavior across login methods.

### Decision

Expired invites are **invalid** for SSO activation.

If a user's only tenant-entry basis is an expired invite, neither Google SSO nor Microsoft SSO may activate that membership.

### Recovery path

Admin must resend or recreate the invite.

### What this does not change

This rule does **not** affect users who already have an `ACTIVE` membership. It only prevents SSO from reviving an expired invite-based entry path.

### Why

- invite expiration must mean the same thing across password and SSO entry paths
- SSO must not become a bypass around invite lifecycle policy
- membership activation remains consistent regardless of authentication method

### Consequences

- tenant-entry policy must reject expired-invite-only SSO activation
- tests and code comments must reflect this as a closed decision, not an unresolved question

### Rejected alternative

#### Allow SSO to activate expired invites

Rejected because it would silently weaken the invite lifecycle contract and create a loophole around admin-controlled onboarding.

---

## ADR-015 — SSO does not bypass app-level MFA

**Date:** 2026-03
**Status:** Accepted

### Context

SSO proves identity with the upstream provider, but the application still owns its own session state, membership rules, and MFA enforcement decisions.

Without an explicit rule, future flows could incorrectly treat SSO as a reason to skip app-level MFA continuation.

### Decision

SSO authentication does **not** bypass app-level MFA.

If the authenticated user is subject to MFA:

- and MFA is not configured yet, SSO login must continue into MFA setup
- and MFA is already configured, SSO login must continue into MFA verification when required

Recovery-code behavior remains valid after SSO login exactly as it does after password login.

### Why

- the app, not the upstream identity provider, owns app-level continuation requirements
- MFA policy must stay consistent across password and SSO entry paths
- recovery behavior should not differ by login mechanism

### Consequences

- Google and Microsoft callback flows must preserve the same MFA continuation semantics as password login
- future proof testing for SSO must validate MFA continuation explicitly
- recovery-code support remains part of the same app-level MFA contract after SSO

### Rejected alternative

#### Treat SSO as sufficient to skip app-level MFA

Rejected because it would create inconsistent enforcement and weaken the application's own continuation / step-up policy.

---

## Locked Decisions Register (LOCK-1 through LOCK-5)

This section is the canonical cross-reference for the five decisions locked by the Auth +
User Provisioning module roadmap. These decisions are referenced by their LOCK-N labels
throughout `docs/ops/runbooks.md`, `docs/qa/qa-execution-pack.md`, and CI test comments.

Each entry states the decision in summary form and references the ADR above that contains
the full rationale, rejected alternatives, and named re-evaluation triggers.

---

### LOCK-1 — Workspace setup banner and admin-settings acknowledgement

**ADR:** ADR-011
**Status:** Locked — Phase 9 implementation complete

Workspace setup is delivered as a **tenant-scoped non-blocking banner on `/admin`**,
not an auth continuation redirect. All admins always land on `/admin` after full authentication
(`NONE + ADMIN`). No `FIRST_TIME_SETUP` nextAction exists or will be added to the
`AuthNextAction` union. The banner disappears for all admins in the workspace once any admin
visits `/admin/settings` and the acknowledgement is recorded on the tenant row.

**Named re-evaluation trigger:** `FIRST_ADMIN_REDIRECT_TRIGGER` (see ADR-011).

---

### LOCK-2 — MFA QR code TOTP label

**ADR:** ADR-012
**Status:** Locked — correction applied before Phase 5 proof

TOTP QR code issuer is `Hubins`. Label is the user's verified email address.
Using `userId` as the label was an oversight and was corrected. Any environment with
pre-correction MFA seeds must be reset before real authenticator-app proof is accepted
as evidence.

---

### LOCK-3 — Seed bootstrap delivery mechanism

**ADR:** ADR-013
**Status:** Locked

Invite delivery is environment-specific:

- **Local dev:** raw token logging acceptable as developer convenience only.
- **Staging / QA:** must use the real outbox + SMTP path. Raw token logging is not the delivery contract.
- **Production:** operator bootstrap only. Raw token logging must never occur in production.

---

### LOCK-4 — Expired invite is invalid for SSO activation

**ADR:** ADR-014
**Status:** Locked

An expired invite cannot be activated by Google or Microsoft SSO. If a user's only
tenant-entry basis is an expired invite, the SSO callback must reject activation and
create no orphan user or revived membership. Recovery path: admin resends or recreates
the invite.

**Referenced in:** `docs/ops/runbooks.md` Phase 6-C (Google), Phase 7-E (Microsoft);
`docs/qa/qa-execution-pack.md` TC-09, TC-10.

---

### LOCK-5 — SSO does not bypass app-level MFA

**ADR:** ADR-015
**Status:** Locked

SSO authentication does not remove app-level MFA requirements. If MFA is required and not
yet configured, SSO login continues into `MFA_SETUP_REQUIRED`. If MFA is configured and
required for that login, SSO login continues into `MFA_REQUIRED`. Recovery codes remain
valid after SSO login on the same terms as after password login.

**Referenced in:** `docs/ops/runbooks.md` Phase 6-D (Google), Phase 7-F (Microsoft);
`docs/qa/qa-execution-pack.md` TC-09, TC-10.
