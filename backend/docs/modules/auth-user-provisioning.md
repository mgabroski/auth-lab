# Auth / User Provisioning — Backend Module Guide

This document explains the **current backend behavior** of the Auth + User Provisioning foundation in this repository.

It is written for:

- backend engineers
- frontend engineers integrating with auth/bootstrap behavior
- QA engineers verifying tenant-aware auth behavior
- PM/technical stakeholders who need a truthful view of what the backend currently supports

This is **not** a generic platform vision document.
It is a backend module guide for the module surface that exists now.

Read this after:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `backend/docs/api/auth.md`

---

## 1. What this module is responsible for

At the current repo phase, the Auth + User Provisioning backend foundation is responsible for:

- authenticating users by password
- establishing and destroying tenant-bound sessions
- exposing auth bootstrap endpoints (`/auth/me`, `/auth/config`)
- handling public signup where tenant policy allows it
- handling invite-based registration / provisioning
- handling email verification and resend flows
- handling password reset initiation and completion
- handling MFA setup / verify / recovery
- handling Google and Microsoft SSO start/callback flows
- coordinating tenant membership creation/activation during provisioning flows
- supporting admin invite lifecycle behavior

This module is foundational because it sits on top of:

- tenant resolution
- request context
- session infrastructure
- tenant membership behavior
- email/outbox delivery
- audit behavior

---

## 2. What this module does not claim to do yet

This guide must remain truthful about current scope.

It does **not** claim that the repo already has:

- full frontend auth screens
- full frontend route guards/bootstrap state
- full tenant-admin UX for every auth configuration branch
- every future Hubins identity/provisioning feature that broader platform docs may discuss

If a behavior is planned but not yet implemented, it must not be described here as current backend capability.

---

## 3. Core backend model

## 3.1 Tenant identity

Tenant identity is derived from the request host/subdomain.

The backend does **not** trust the client to choose tenant identity through:

- request body
- query params
- local storage
- arbitrary headers

This means every auth/provisioning behavior is tenant-aware by construction.

---

## 3.2 Sessions

Sessions are server-side and Redis-backed.

Important consequences:

- browser code does not manage auth tokens in local storage
- the backend can revoke or rotate session state centrally
- session state can represent intermediate continuation state such as MFA verification status
- session identity is tenant-bound

A session from tenant A must not authenticate on tenant B.
That is a foundational security rule of this module.

---

## 3.3 Continuation state

Authentication is not modeled as a single binary “logged in / not logged in” result.

The backend can require continued action after session establishment, such as:

- email verification
- MFA setup
- MFA verification

This is surfaced through backend truth, especially:

- `AuthResult.nextAction`
- `GET /auth/me`

The frontend is expected to follow backend continuation truth rather than re-derive it independently.

---

## 4. Current backend capability areas

## 4.1 Password login

The module supports tenant-aware email/password login.

Behavior summary:

- validates credentials against the current tenant context
- creates a session on success
- returns continuation-aware auth result
- may still require next-step action (`nextAction`) rather than immediate app access

---

## 4.2 Invite-based registration / provisioning

The module supports invite-based registration.

Behavior summary:

- registration is tied to an invite token
- provisioning happens in the context of the current tenant
- the resulting user is associated to the tenant membership created or activated by the flow
- successful completion establishes a session and returns auth result data

This is distinct from public self-signup.

---

## 4.3 Public signup

The module supports self-service signup **only** when the tenant policy allows it.

Behavior summary:

- signup is tenant-scoped by host/subdomain
- backend checks tenant availability / signup policy
- successful signup may still require email verification before the session is considered fully continued

This is why the frontend must use backend bootstrap/config endpoints instead of assuming signup is globally allowed.

---

## 4.4 Email verification

The module supports:

- verify email via token
- resend verification email

Behavior summary:

- verification is associated with the authenticated user/session flow
- verifying email upgrades server-side truth so the session reflects verified state
- resend flow intentionally uses a generic success message rather than leaking detailed state

This is part of the continuation flow, not a separate unrelated feature.

---

## 4.5 Password reset

The module supports:

- forgot password initiation
- reset password completion

Behavior summary:

- forgot-password always returns generic success
- this is deliberate anti-enumeration behavior
- reset-password consumes a reset token and updates the password
- reset-password does not automatically log the user in

---

## 4.6 MFA

The module supports:

- MFA setup
- MFA setup verification
- MFA verification for partially authenticated sessions
- MFA recovery via recovery code

Behavior summary:

- MFA endpoints require an authenticated, email-verified session
- setup returns secret / QR URI / recovery codes
- verify-setup and verify elevate the session into MFA-verified state
- session rotation occurs on privilege elevation
- recovery also results in MFA-verified session elevation

This is a security-critical part of the module, not optional decoration.

---

## 4.7 SSO

The module supports SSO start/callback for:

- Google
- Microsoft

Behavior summary:

- start endpoint validates provider and optional safe `returnTo`
- encrypted state carries redirect context
- short-lived `sso-state` cookie binds browser callback state for CSRF protection
- callback validates query `state` against the cookie
- successful callback provisions or signs in the user in the current tenant context
- successful callback establishes session and redirects back into the app

This is intentionally tenant-aware and topology-aware.
It is not a generic global callback hack.

---

## 4.8 Logout

The module supports authenticated logout.

Behavior summary:

- destroys session state
- clears session cookie
- works even if the current user has not yet completed email verification

That last point is deliberate: unverified users must still be able to log out.

---

## 4.9 Auth bootstrap surface

This is one of the most important responsibilities of the current backend foundation.

The backend exposes:

- `GET /auth/config`
- `GET /auth/me`

These are the main frontend bootstrap endpoints.

### `GET /auth/config`

Purpose:

- tell the unauthenticated/bootstrap UI what public-safe tenant auth configuration is visible

Current truth exposed:

- tenant display name
- tenant active/inactive availability
- whether public signup is enabled
- which SSO providers are allowed

Deliberately not exposed:

- internal tenant security settings not required by bootstrap UI
- sensitive tenant policy data that would overexpose internal configuration

### `GET /auth/me`

Purpose:

- tell the frontend who the current authenticated user is
- tell the frontend what tenant and membership are active
- tell the frontend whether email/MFA continuation is required

These two endpoints are central to the current frontend-readiness plan.

---

## 5. Tenant configuration behavior that currently matters

This section describes tenant-scoped backend behavior that is meaningful today.
It does **not** claim to document every possible future tenant setting.

## 5.1 Tenant active/inactive availability

Current effect:

- inactive or unavailable tenant state affects public-facing auth bootstrap behavior
- `GET /auth/config` deliberately returns the same unavailable shape for unknown and inactive tenants

Why:

- avoids unnecessary tenant state enumeration
- keeps public bootstrap behavior privacy-preserving

---

## 5.2 Public signup enabled/disabled

Current effect:

- controls whether self-service signup is available for the current tenant
- exposed as public-safe bootstrap information via `/auth/config`

This matters to both backend enforcement and frontend visibility.

---

## 5.3 Allowed SSO providers

Current effect:

- controls which SSO providers are allowed for the current tenant
- exposed through `/auth/config` as public-safe bootstrap truth
- current supported providers are Google and Microsoft

The frontend should show SSO entrypoints based on backend truth, not static UI assumptions.

---

## 6. Privacy and anti-enumeration posture

The current backend module intentionally avoids exposing too much account or tenant state through public responses.

Important behaviors:

### Unknown vs inactive tenant

`GET /auth/config` returns the same unavailable shape for both.

### Forgot password

`POST /auth/forgot-password` always returns generic success.

### Resend verification

`POST /auth/resend-verification` always returns generic success.

These are contract decisions, not implementation accidents.
They should not be “simplified” casually because they are part of the module’s privacy posture.

---

## 7. Current interaction with neighboring backend modules

The Auth + User Provisioning module does not exist in isolation.

It currently relies on neighboring bounded contexts such as:

- tenants
- users
- memberships
- invites
- audit

Typical responsibilities across boundaries:

### Tenants

- resolve tenant by key/host context
- provide tenant availability/config inputs

### Users

- user lookup and user creation/update behaviors needed by auth flows

### Memberships

- membership lookup, creation, activation, role information

### Invites

- invite lookup, validation, acceptance/provisioning coordination

### Audit

- structured audit recording for auth/admin-sensitive actions

This document describes the module behavior, not every internal boundary detail.
Those boundaries are governed by the repo’s backend engineering rules and actual code structure.

---

## 8. Current frontend integration truth

The frontend integration model expected by this backend foundation is:

### Before authentication

Use `GET /auth/config` to decide:

- whether the tenant is effectively available
- whether signup should be shown
- which SSO options should be shown

### After a session exists

Use `GET /auth/me` to decide:

- current user identity
- current membership role
- current tenant identity
- current continuation requirement through `nextAction`

### Do not re-derive continuation logic in frontend

The backend owns continuation truth.
The frontend should follow it.

### Do not hardcode browser-to-backend origins

Browser calls stay same-origin through `/api/*`.
SSR may call backend directly through `INTERNAL_API_URL` while forwarding request identity headers.

---

## 9. What is strong and stable enough to build on now

The following parts of this module should be treated as stable foundation behavior unless intentionally changed:

- tenant-scoped auth behavior
- session-tenant binding
- `/auth/config` as public-safe bootstrap endpoint
- `/auth/me` as authenticated bootstrap endpoint
- continuation semantics through `nextAction`
- generic success responses for selected privacy-sensitive endpoints
- tenant-aware SSO start/callback model
- MFA session elevation + rotation behavior

These are not temporary conveniences.
They are foundational behaviors for the next frontend and module work.

---

## 10. What is still intentionally next-step work

This backend module guide must remain explicit that some work is still ahead.

Not yet represented here as completed product surface:

- rich frontend auth screens and shells
- full frontend continuation routing behavior
- broader identity/admin settings UX beyond the current backend foundation
- future Hubins modules beyond this foundation slice

That future work should build on the behaviors described here, not replace them casually.

---

## 11. When to update this file

Update this file whenever:

- auth/provisioning backend behavior changes materially
- tenant-facing auth configuration behavior changes
- privacy/anti-enumeration behaviors change
- bootstrap endpoint responsibilities change
- new provisioning paths are added
- current documented capability becomes obsolete or removed

If the backend module changed and this file still describes the old behavior, this file is stale.

---

## 12. Final truth rule

This file should help future contributors answer one question clearly:

**What does the Auth + User Provisioning backend foundation actually do today?**

If the document becomes broader, vaguer, or more aspirational than the code, it has failed its job.
