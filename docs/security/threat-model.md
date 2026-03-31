# Hubins Auth-Lab — Platform Threat Model

## Status

Stage 4 baseline threat model for the current repository.

This document is the security-system view of the repo as it exists today.
It is not a generic SaaS threat-model template.
It is intentionally anchored to the current Hubins Auth-Lab topology, auth/session design, and current module scope.

---

## 1. Purpose

This document exists to make the repository's most important security assumptions explicit, reviewable, and maintainable.

It answers five practical questions:

1. What are we protecting?
2. Where are the trust boundaries?
3. What realistic abuse paths matter most in this repo?
4. What controls already exist?
5. What proof exists today, and what remains deferred?

This file does **not** replace `docs/security-model.md`.

- `docs/security-model.md` is the invariant/reference view.
- `docs/security/threat-model.md` is the attacker-path and control view.

Both are required.

---

## 2. Scope

### In scope

This threat model covers the current implemented and load-bearing platform surfaces:

- single-origin browser → proxy → frontend/backend topology
- host-derived tenant resolution
- backend-owned session model
- SSR header-forwarding contract
- email-based auth flows:
  - invite acceptance
  - verify email
  - forgot/reset password

- MFA setup / verify / recovery flows
- Google and Microsoft SSO initiation/callback flows
- outbox payload protection for auth-delivered emails
- local/staging/production-like operator bootstrap assumptions
- current CI/runtime protections that materially affect security

### Out of scope

These are deliberately **not** modeled here as first-class threats because they are not implemented or not yet part of the current repo contract:

- SCIM
- SAML
- HRIS import engines
- marketplace/integration runtime sync flows
- device/session-management UI
- public self-serve tenant creation
- full tenant-configured secrets backend
- non-auth product modules beyond the current auth/provisioning slice

If those surfaces become real, this document must be expanded in the same PR or release train.

---

## 3. System summary

The system is a multi-tenant platform with host-derived tenant identity.
The browser interacts with a single public origin.
Browser API calls are same-origin under `/api/*`.
SSR code calls the backend directly via an internal URL, but must forward the original request headers that carry tenant and session truth.

Security-sensitive consequences of that design:

- tenant identity is not chosen by the client body or query string
- cross-tenant isolation depends on preserving `Host` and enforcing session/tenant equality
- browser session truth is represented by an HttpOnly cookie only
- SSO state uses a separate short-lived cookie with different SameSite behavior than the session cookie
- backend remains the only authority for authenticated session truth and continuation state

---

## 4. Protected assets

The following assets are considered load-bearing for this repo.

### A1. Tenant isolation boundary

A user or session from tenant A must not gain authenticated or implied access to tenant B through host confusion, cookie scope mistakes, SSR forwarding mistakes, or callback abuse.

### A2. Session integrity

A session must only represent the authenticated user, tenant, membership, role, and verified continuation state that the backend issued.

### A3. Auth transition tokens

Invite, verification, and password-reset tokens must remain single-use, non-guessable, and unusable after expiry or invalidation.

### A4. MFA material

TOTP secrets and recovery codes must not be recoverable from the database or logs in raw form.

### A5. SSO callback trust boundary

The SSO callback must not accept a forged or replayed cross-tenant state, tampered return path, or provider/tenant mismatch.

### A6. Outbox email-delivery material

Auth email payloads must not store raw tokens or recipient emails in plaintext in durable outbox storage.

### A7. Security configuration keys

The following keys are high-value assets:

- `MFA_ENCRYPTION_KEY_BASE64`
- `MFA_HMAC_KEY_BASE64`
- `SSO_STATE_ENCRYPTION_KEY`
- `OUTBOX_ENC_KEY_V*`
- SMTP credentials used for non-local delivery
- OAuth client credentials

### A8. Auditability of security-sensitive actions

Security-sensitive flows must remain reviewable after the fact without leaking secrets into audit payloads, logs, or metrics.

---

## 5. Trust boundaries

## TB1. Browser ↔ public origin

The browser is untrusted.
It may tamper with query params, initiate cross-site navigations, replay links, and send cookies only under browser rules.

## TB2. Public proxy ↔ backend

The proxy is trusted only if it preserves the topology contract:

- `Host` preserved
- `/api/*` prefix stripped correctly
- cookies passed through unchanged
- forwarded headers preserved correctly

Proxy drift is a security concern because it can silently weaken tenant isolation.

## TB3. Frontend SSR ↔ backend internal calls

SSR is privileged because it can call the backend directly inside the container network.
It must forward tenant/session-bearing headers explicitly.
A broken SSR wrapper can cause tenant confusion or false unauthenticated renders.

## TB4. Backend ↔ Redis session store

Redis holds active session truth.
Compromise or misuse here affects active sessions immediately.
The browser must never become the source of truth for session claims.

## TB5. Backend ↔ database

The database stores hashed/encrypted security material, invite and verification lifecycle state, and outbox payload ciphertext.
Database compromise must not directly reveal raw tokens, raw emails from outbox storage, TOTP secrets, or recovery codes.

## TB6. Backend ↔ external identity/email providers

OAuth providers and SMTP providers are external trust boundaries.
The system must validate callback state, provider identity, redirect expectations, and provider-dependent failures safely.

---

## 6. Threat actors

### T1. Unauthenticated internet attacker

Capabilities:

- can send arbitrary requests
- can tamper with query params and form bodies
- can replay expired or reused links
- can attempt brute-force and enumeration attacks
- can start but not complete legitimate flows

### T2. Authenticated tenant user acting outside their authorization

Capabilities:

- has a real session for one tenant
- may try cross-tenant cookie reuse
- may try direct route access beyond their role
- may try using old links or stale state after partial progress

### T3. Compromised email inbox recipient

Capabilities:

- can click received invite, verification, or reset links
- may attempt replay of already-consumed links
- may attempt delayed use after expiry

### T4. Misconfigured operator or engineer

Capabilities:

- may introduce weak env values
- may reuse keys across crypto purposes
- may enable dev-only features in production-like environments
- may accidentally leak secrets through config or scanning gaps

### T5. Attacker with read access to database/logs

Capabilities:

- can inspect durable storage
- benefits if raw tokens, raw emails, raw TOTP secrets, or recovery codes are stored insecurely

This threat model assumes **read access**, not full code-execution compromise.
If the attacker has runtime code execution on backend hosts, many protections fall away and incident-response mode applies.

---

## 7. Highest-risk threat scenarios

## TM-1. Cross-tenant session misuse

### Attack

Use a valid session cookie minted on tenant A against tenant B.

### Why it matters

This is the central multi-tenant isolation failure mode.

### Controls

- host-derived tenant resolution
- host-only cookie scope
- exact `session.tenantKey === req.requestContext.tenantKey` enforcement
- same-origin browser contract
- proxy conformance checks

### Current proof

- backend tenant-isolation tests
- proxy-conformance tests
- frontend/browser auth smoke behavior through tenant-specific hosts

### Residual risk

A future proxy/header regression or relaxed middleware check would be catastrophic.
This remains a P0 invariant.

---

## TM-2. SSR tenant confusion

### Attack

Cause SSR to bootstrap against the wrong tenant or without the real user cookies by breaking forwarded headers.

### Why it matters

SSR has an internal path to the backend.
If it stops forwarding the original request context correctly, the app can silently render the wrong auth or tenant state.

### Controls

- dedicated SSR fetch wrapper
- forwarded `Host`, `Cookie`, and `X-Forwarded-*` contract
- architecture tests for SSR forwarding

### Current proof

- SSR/client contract tests already present in the repo

### Residual risk

This remains a sharp edge because SSR paths are easy to accidentally bypass during refactors.

---

## TM-3. Invite replay / token reuse

### Attack

Reuse an already-consumed or replaced invite token to activate a membership again or bypass current invite state.

### Controls

- secure random token generation
- token hashing at rest
- one-time lifecycle enforcement
- resend invalidates older link behavior
- explicit acceptance-state checks

### Current proof

- invite acceptance E2E coverage
- bootstrap proof coverage

### Residual risk

Low if existing lifecycle checks remain intact.
Still requires regression coverage whenever invite flow changes.

---

## TM-4. Verification or reset token replay

### Attack

Reuse an old verification or password-reset link after successful use or after a fresher replacement token has been issued.

### Controls

- secure random tokens
- token hashing at rest
- single-use lifecycle enforcement
- invalidation on fresh issuance where applicable
- generic public-safe error responses

### Current proof

- verify-email E2E/unit coverage
- reset-password E2E/unit coverage

### Residual risk

Low, provided public-safe error handling and invalidation rules stay coupled to the flow.

---

## TM-5. SSO state tampering

### Attack

Tamper with `state`, remove the state cookie, mix tenant-A cookie with tenant-B callback host, or abuse return-path values.

### Why it matters

The SSO callback is one of the highest-risk trust boundaries in the entire repo.
It is the point where cross-site navigation returns with externally issued identity context.

### Controls

- separate short-lived `sso-state` cookie
- encrypted state payload
- exact cookie/query equality check
- host-derived tenant enforcement at callback time
- redirect/return-path validation
- cookie clear on callback completion
- backend-authoritative continuation routing after callback

### Current proof

- state validation unit coverage
- return-path/frontend validation coverage
- explicit abuse-regression tests added in Stage 4 baseline

### Residual risk

Medium.
The repo currently relies on encrypted short-lived state plus cookie clearing, not a server-side used-state ledger.
That is acceptable for the current baseline but remains a conscious design tradeoff to revisit if threat posture or provider behavior changes.

---

## TM-6. Return-path abuse after SSO or auth continuation

### Attack

Use a crafted return path to redirect users to an unintended location after callback or continuation.

### Controls

- validation of return-path at state creation
- validation again at callback/consumption boundary
- backend-authoritative `nextAction`
- frontend route resolution that treats query hints as hints, not truth

### Current proof

- unit coverage around SSO path validation and redirect resolution

### Residual risk

Low to medium.
This stays sensitive because redirect handling often regresses during UX refactors.

---

## TM-7. Session fixation after MFA completion

### Attack

Observe or set a pre-MFA session identifier, then retain that same session after the user completes MFA.

### Controls

- session rotation after MFA setup/verify/recovery
- backend-owned session truth

### Current proof

- auth contract and MFA-flow tests

### Residual risk

Low if session rotation remains mandatory on privilege elevation.

---

## TM-8. Database disclosure of raw auth material

### Attack

An attacker with read access to DB tables or logs directly recovers raw tokens, raw emails in outbox storage, TOTP secrets, or recovery codes.

### Controls

- token hashing for invites, verification, reset
- AES-GCM encryption for TOTP secrets
- HMAC hashing for recovery codes
- versioned AES-GCM encryption for outbox email/token payloads
- no raw token logging in operator flows

### Current proof

- unit tests for token hashing and outbox encryption
- ADR and Stage 4 rotation tests for outbox key versioning

### Residual risk

Medium for key-management operations, not for static storage design.
The storage model is sound, but operator mishandling of key rotation can still create outages or forced resets.

---

## TM-9. Secret/config leakage through repo or CI

### Attack

Commit real secrets, example secrets that look real enough to be reused, or vulnerable dependency/container changes that reach the main branch unnoticed.

### Controls

- repo scanning in CI for secrets
- dependency vulnerability scan in CI
- container image scan in CI
- startup guards for unsafe prod-like config

### Current proof

- Stage 4 security scan workflow
- startup-guard tests

### Residual risk

Medium.
Secret scanning is only durable if findings are handled instead of suppressed casually.

---

## 8. Security assumptions that must remain true

These assumptions are treated as load-bearing.
If any become false, security review is required before shipping.

1. Browser API traffic remains same-origin under `/api/*`.
2. Tenant identity remains host-derived.
3. Session truth remains backend-owned.
4. Session and SSO-state cookies remain separate and differently scoped.
5. Session cookies remain host-only and backend-set.
6. SSR direct backend calls continue to forward original tenant/session headers.
7. Tokens remain hashed at rest; raw tokens remain email-only transport data.
8. TOTP secrets remain encrypted at rest.
9. Recovery codes remain hashed and single-use.
10. Outbox payloads continue to store encrypted token/email values, not plaintext.
11. Security-sensitive startup guards continue to fail closed outside test.
12. Any tenant integration secret foundation must store secrets outside plain config JSON.

---

## 9. Deferred or intentionally limited areas

The following are known limitations or intentionally deferred areas, not hidden gaps.

### D1. No concrete tenant integration secrets backend yet

The foundation is documented at ADR level, but the repo does not yet ship a full tenant secret vault implementation.
This means secret-bearing tenant-configured integrations remain blocked from real implementation.

### D2. No server-side used-state ledger for SSO state

Current SSO protection uses encrypted short-lived state, cookie/query equality, host-derived tenant checks, and immediate cookie clearing.
That is the current accepted baseline, but not the only possible design.

### D3. No automated multi-version rewrap for MFA secret rotation

Outbox rotation is versioned.
MFA secret/recovery material currently requires a more disruptive operational procedure if keys rotate.
This is an honest limitation and must remain documented.

---

## 10. Evidence map

This threat model is only useful if its claims map to real proof.

### Documentation proof

- `docs/security-model.md`
- `backend/docs/adr/0002-outbox-payload-encryption-key-rotation.md`
- `backend/docs/adr/0004-sso-callback-trust-boundary.md`
- `backend/docs/adr/0005-tenant-integration-secrets-foundation.md`
- `docs/ops/runbooks.md`

### Runtime/config proof

- startup guards in backend DI/bootstrap
- cookie-setting helpers
- SSR API client / forwarding path
- session middleware tenant equality check

### Test proof

- tenant isolation tests
- proxy conformance tests
- invite/bootstrap abuse tests
- verify-email/reset token lifecycle tests
- SSO state validation tests
- SSO state abuse regressions
- outbox encryption rotation tests

---

## 11. Change triggers

This document must be reviewed and updated when any of the following happens:

- tenant resolution logic changes
- cookie model changes
- SSR forwarding model changes
- SSO providers or callback rules change
- new auth token types are added
- new tenant-configured integrations with secrets are added
- security scan policy changes materially
- a major release includes auth, session, MFA, or SSO changes

---

## 12. Practical review rule

A change is not security-complete in this repo just because the code looks careful.

For the current architecture, a security-significant change is only complete when all of the following are true:

- the trust-boundary decision is explicit
- the main abuse path is named
- fail-closed behavior is preserved where required
- tests prove the intended boundary
- docs/runbooks reflect the operational reality

That is the Stage 4 standard for this repository.
