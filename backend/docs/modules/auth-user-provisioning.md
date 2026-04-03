# Auth / User Provisioning — Module Complexity Guide

## Purpose

This is a **Tier 3 module-local reference** for Auth / User Provisioning.

Its job is narrow:

- explain the **non-obvious complexity** of the auth/provisioning module
- summarize the **flow shapes and state transitions** that are easy to misunderstand from API docs alone
- record **module-local design judgments** that should not be rediscovered during reviews or refactors
- point engineers toward the **most relevant proof surfaces**

This file is **not** the source of current shipped scope.
This file is **not** the API contract.
This file is **not** the repo router.

For canonical truth order, use:

1. `docs/current-foundation-status.md`
2. `ARCHITECTURE.md`
3. `docs/security-model.md`
4. `backend/docs/api/*.md`
5. this document

If this file conflicts with shipped-truth docs, security law, or API contracts, this file loses.

---

## When To Use This File

Read this file when you need to understand **why Auth behaves the way it does**, especially around:

- continuation state after login
- tenant-aware session rules
- invite vs signup vs existing-user branching
- MFA setup / verify / recovery transitions
- SSO start/callback behavior and state binding
- why some auth/privacy behaviors intentionally look stricter or more indirect than a typical CRUD module

Do **not** read this file first if you only need:

- current shipped capability status
- endpoint request/response shapes
- local setup commands
- QA execution steps

Those are owned elsewhere.

---

## Why This Module Qualifies For Tier 3

Auth / User Provisioning is not just a list of endpoints.
It qualifies for module-local documentation because it contains multiple interacting flows and state transitions that are easy to misuse during implementation or review:

- tenant resolution from host context
- tenant-bound session behavior
- partially authenticated continuation state
- email verification gating
- MFA setup vs MFA verify vs MFA recovery
- invite acceptance branching for new vs existing users
- SSO start and callback coordination through browser navigation plus short-lived state binding

A contributor can read the architecture and API docs and still miss how these pieces interact across a real login or provisioning journey. This guide exists to close that gap.

---

## Flow Overview

## 1. Password Login Flow

High-level shape:

1. request arrives under tenant host context
2. backend resolves tenant from host
3. backend validates credentials against the correct tenant membership context
4. backend establishes or updates session state
5. backend returns authenticated truth plus any required continuation state
6. frontend follows backend truth instead of inventing its own continuation logic

Important consequence:

A successful credential check does **not** always mean immediate app access.
The user may still need to complete a continuation step such as:

- email verification
- MFA setup
- MFA verification

That is a deliberate model choice.

---

## 2. Invite Provisioning Flow

Invite flows branch earlier than most people expect.
The important distinction is not just “invite valid or not.”
The flow also branches on whether the invited email already belongs to an existing user.

Typical shape:

1. invite token is validated
2. tenant and invite state are checked
3. backend determines whether the invited identity is already a known user
4. flow continues as either:
   - **new user invite acceptance** -> registration/setup path
   - **existing user invite acceptance** -> sign-in/continuation path

5. membership is activated only through the valid invite path
6. auth continuation rules still apply after acceptance

Important consequence:

Invite acceptance is not a separate universe from auth.
It is a provisioning entry into the same continuation model used elsewhere.

---

## 3. Public Signup Flow

Public signup is tenant-scoped and policy-controlled.
It is not a global platform capability.

Typical shape:

1. tenant is resolved from host
2. public-safe tenant auth config is read
3. signup availability is enforced for that tenant
4. user and membership are created in the tenant context
5. post-signup continuation truth is established
6. frontend continues based on backend truth

Important consequence:

Frontend must not assume signup is globally available.
It must read tenant-safe bootstrap truth instead.

---

## 4. Email Verification Flow

Email verification is part of auth continuation, not a disconnected profile action.

Typical shape:

1. user reaches a continuation point where verified email matters
2. backend issues or resends verification token through the mail flow
3. token consumption upgrades backend-authenticated truth
4. session-visible state changes after successful verification
5. user can continue through the next required step or into normal access

Important consequence:

This flow is intentionally privacy-preserving.
Resend behavior should not become an account-state leak.

---

## 5. Password Reset Flow

Password reset intentionally avoids becoming an enumeration surface.

Typical shape:

1. forgot-password accepts the identifier without revealing existence
2. backend decides internally whether a reset message should be sent
3. reset token is consumed by a dedicated reset flow
4. password is changed
5. user signs in again through the normal auth path

Important consequence:

Reset is not the same thing as login.
Completing password reset should not silently bypass the normal auth continuation model.

---

## 6. MFA Flow Family

MFA is not one screen; it is a small state family.

### MFA setup

Used when the user is authenticated enough to begin enrollment but is not yet MFA-configured.

### MFA verify

Used when the user is partially authenticated and must prove possession of the enrolled factor before becoming fully continued.

### MFA recovery

Used when the authenticator path is unavailable but recovery material exists.

Important consequence:

These are related flows, but they are not interchangeable.
A refactor that tries to collapse them into one generic “MFA endpoint” usually causes subtle behavior bugs.

---

## 7. SSO Flow Family

SSO has two critical stages:

### SSO start

- validates provider choice
- prepares redirect context
- creates short-lived state binding
- initiates browser navigation to provider

### SSO callback

- validates returned state against browser-bound state
- resolves/provisions user in tenant context
- establishes session and continuation truth
- redirects back into app flow

Important consequence:

This is a **browser navigation flow**, not a normal API fetch flow.
Treating SSO start like a standard XHR-style request is a design error.

---

## Non-Obvious Design Decisions

## 1. Tenant identity is host-derived

The module does not trust arbitrary client-supplied tenant identity.
This is why host handling, proxy behavior, SSR header forwarding, and tenant-bound session checks matter so much.

This is not implementation detail.
It is a security boundary.

---

## 2. Backend owns continuation truth

The frontend does not decide whether the user is “done.”
The backend owns the truth about whether the user must still:

- verify email
- set up MFA
- verify MFA

That is why `nextAction`-style continuation behavior exists and why frontend routing must follow backend-authenticated state.

---

## 3. Session success and full access are not the same thing

This module intentionally allows intermediate authenticated states.
A session may exist while access is still restricted by continuation requirements.

This is one of the biggest differences between this module and a simple login/logout module.

---

## 4. Privacy-preserving generic success is intentional

Some public-facing flows deliberately avoid revealing whether the requested identity exists or what exact state it is in.
That includes flows like forgot-password and resend-style behavior.

Do not “improve UX” by casually making these responses more specific.
That would weaken the privacy posture.

---

## 5. SSO state is browser-bound on purpose

The short-lived SSO state cookie is not decorative.
It exists to bind callback validation to the same browser journey that initiated the provider redirect.

If that state binding is weakened, callback integrity weakens with it.

---

## 6. SSO does not replace app-level continuation rules

A successful external provider identity check does not automatically mean the user bypasses app-level continuation requirements.
The app still owns its own tenant, membership, verification, and MFA rules.

---

## 7. MFA privilege elevation should be treated as security-sensitive state transition

Crossing from partially authenticated to MFA-verified state is not a cosmetic transition.
It changes trust level and must be treated carefully in both code and review.

---

## 8. Auth bootstrap is intentionally split between public-safe and authenticated truth

This module uses a two-surface model for bootstrap:

- one surface safe for pre-auth tenant-aware UI decisions
- one surface for authenticated user/membership/continuation truth

That split keeps bootstrap useful without overexposing internal state.

---

## Known Failure Modes And Review Traps

## 1. Wrong-host or rewritten-host behavior

If tenant identity is derived from the wrong host, the module can appear to “work” while actually resolving the wrong tenant context.

Typical symptom:

- user appears valid but membership/auth behavior is inconsistent across hosts

Review rule:

- always treat host and forwarded-host handling as load-bearing

---

## 2. Session cookie present but tenant context mismatched

A session that exists for one tenant must not silently authenticate against another tenant.

Typical symptom:

- cross-tenant `/auth/me` behavior looks unexpectedly authenticated

Review rule:

- tenant/session binding failures are security bugs, not convenience bugs

---

## 3. Frontend tries to re-derive continuation logic

When the frontend starts inventing its own “if admin then go here, if verified then skip there” behavior without using backend continuation truth, drift follows quickly.

Typical symptom:

- login succeeds but routing differs from `/auth/me` or server truth

Review rule:

- continuation logic belongs to backend-authenticated truth first

---

## 4. SSO start treated like normal fetch

SSO start must remain a navigation-first flow.
Using the wrong request primitive can break redirects, state, and browser behavior in ways that are easy to misdiagnose.

---

## 5. SSR requests lose request identity

When SSR/backend calls stop forwarding required request identity, auth bootstrap can fail in ways that look like random unauthenticated behavior.

Typical symptom:

- SSR pages render as if tenant or session is missing while browser requests look fine

Review rule:

- browser and SSR paths are related but not interchangeable

---

## 6. Invite acceptance simplified too aggressively

Invite acceptance has distinct branches for token validity, tenant validity, new-user vs existing-user path, and post-accept continuation.
Reducing it to “accept token then log in” usually breaks real behavior.

---

## 7. MFA flows collapsed together

Setup, verify, and recovery flows may share concepts but should not be casually merged into one generic path.
That often causes incorrect gating or incorrect privilege transition behavior.

---

## 8. Public-safe config becomes overexposed

Bootstrap-safe auth config should not become a dumping ground for internal tenant configuration.
If more fields are added there, they should be reviewed as exposure decisions, not convenience additions.

---

## What This File Must Not Re-Own

This file must stay narrow.
Do **not** expand it into any of the following:

- a current-shipped-capability tracker
- an API endpoint inventory
- a frontend integration contract
- a developer setup guide
- a QA execution manual
- a roadmap or closeout tracker
- a second architecture or security model document

If it drifts into those roles, it should be tightened again.

---

## Most Relevant Proof Surfaces

When validating changes to this module, the most useful proof surfaces are usually:

### API contracts

- `backend/docs/api/auth.md`
- `backend/docs/api/invites.md`
- `backend/docs/api/admin.md`

### Auth / policy / topology tests

Check current backend and frontend auth-related unit, integration, and E2E suites, especially around:

- login and continuation behavior
- MFA policy and next-action handling
- SSO callback behavior
- tenant/session isolation
- proxy and SSR conformance

### Current shipped-truth snapshot

- `docs/current-foundation-status.md`

### Security and topology law

- `docs/security-model.md`
- `ARCHITECTURE.md`

---

## Update Rule

Update this file only when the **non-obvious module-local auth complexity** changes materially.

Do **not** update it for every endpoint tweak, copy change, or ordinary behavior clarification that belongs in API docs, shipped-truth docs, QA docs, or code comments.

---

## Final Rule

This file should answer one narrow question well:

**What makes the Auth / User Provisioning module easy to misunderstand, even after reading the contracts?**

If it starts answering broader questions than that, it is too big.
