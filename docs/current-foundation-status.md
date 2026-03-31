# Hubins Auth-Lab — Current Foundation Status

## Purpose

This document is the repo's practical truth snapshot.

It exists to keep four things aligned:

- what the repository actually implements now
- what the active documentation claims
- what future implementation sessions assume
- what is intentionally deferred to later hardening stages

If another active document overclaims shipped scope compared with this file, this file wins until the lower document is repaired.

---

## 1. High-level status

The repository is no longer only a topology or auth-foundation sandbox.
It now contains a real Auth + User Provisioning slice with real browser surfaces, real backend behavior, real test proof, and real operability foundations.

At the time of this snapshot, the repo status is:

- Before Stage 1 quality-bar work: completed
- Stage 1A minimum enforcement: completed
- Stage 1B deeper enforcement: still parallel / not fully closed
- Stage 2 architecture-invariant proof: completed
- Stage 3 operability baseline: completed
- Stage 4 security-system baseline: established, with some deeper implementation work still deferred

That means the repository now has:

- real topology invariants and topology proof
- real auth/provisioning flows
- real observability/operability baseline
- explicit threat-model and security ADR foundation
- runnable security scanning in CI
- explicit abuse-regression proof for the highest-risk callback boundary

It does **not** mean the broader Hubins product is finished.
It means the current repo has moved from “careful auth implementation” to “maintained auth platform baseline” for its current scope.

---

## 2. What is implemented now

## 2.1 Repository and infrastructure foundation

The following are real and load-bearing:

- monorepo/workspace structure
- backend application
- frontend application
- proxy/container topology for full-stack local testing
- Postgres and Redis infrastructure
- Mailpit local email capture for non-production email proof
- same-origin browser API model under `/api/*`
- SSR direct-backend model with forwarded headers

## 2.2 Locked topology and request model

The topology decisions remain unchanged and are now continuously provable:

- one public origin from the browser's perspective
- browser calls use same-origin `/api/*`
- SSR/server-side frontend calls use internal backend URL plus explicit forwarded headers
- tenant identity is derived from request host
- backend owns session/auth truth
- session cookies remain backend-owned and host-scoped
- SSO state handling remains separate from session-cookie handling

## 2.3 Backend auth/provisioning implementation

The backend currently implements:

- login
- logout
- current-user/session bootstrap
- invite creation and acceptance
- verify-email / resend verification
- forgot-password / reset-password
- MFA setup / verify / recovery
- Google SSO start/callback surfaces
- Microsoft SSO start/callback surfaces
- outbox-backed email sending for auth flows
- startup guards for dangerous production-like misconfiguration
- local dev seed and operator bootstrap support for auth onboarding proof

## 2.4 Frontend auth/provisioning implementation

The frontend currently contains the real user-facing surface for the implemented module scope, including:

- public auth routes
- invite acceptance and invite-driven registration
- verify-email flow
- reset-password flow
- MFA setup/verify/recovery surfaces
- role-aware authenticated landing behavior
- admin invite-management surface already shipped in earlier phases
- workspace setup banner and `/admin/settings` acknowledgement surface

## 2.5 Current local developer contract

The repository supports a repeatable local proof contract:

- Mailpit receives auth emails locally
- canonical local hosts represent different tenant policies
- canonical seed/bootstrap flows support invite onboarding proof
- local browser proof can validate signup, verification, reset-password, MFA, and invite lifecycle behavior

---

## 3. What is already locked and operating as law

The following remain repo law for the current foundation:

- host-derived tenant identity
- same-origin browser contract
- backend-authoritative session truth
- SSR forwarded-header contract
- separate session cookie vs SSO-state cookie contract
- token hashing at rest for invite/verification/reset tokens
- encrypted TOTP secrets at rest
- hashed MFA recovery codes
- encrypted outbox payload fields for auth-delivered email material
- startup guards that fail closed for unsafe production-like config

These are not optional implementation preferences.
They are architecture/security invariants.

---

## 4. What Stage 2 established

Stage 2 made the architecture invariants continuously provable.

That includes proof for:

- same-origin browser contract
- SSR header forwarding
- host-derived tenant resolution
- tenant/session mismatch fail-closed behavior
- cookie/session contract behavior
- no browser path to a private backend origin
- route-state and redirect truth behavior
- proxy/topology conformance

Operational meaning:
The repo now has executable proof for the assumptions that matter most for tenant isolation and auth correctness.

---

## 5. What Stage 3 established

Stage 3 added the current operability baseline.

That includes:

- structured logging
- request correlation
- metrics export
- operability smoke checks
- observability docs and incident-triage material

Operational meaning:
The repo can now answer the first serious operational questions under pressure instead of relying on developer intuition alone.

---

## 6. What Stage 4 established

Stage 4 did **not** redesign auth flows.
It established the security-system baseline around the current implementation.

### Stage 4 baseline additions

The repository now has, or expects as part of the active baseline:

- an explicit platform threat model
- security ADR coverage for the highest-risk SSO callback trust boundary
- an explicit secrets-management foundation ADR for future tenant-configured integrations
- explicit abuse-regression tests for SSO state tampering paths
- stronger outbox key-rotation test proof
- CI security scanning for:
  - secret leakage
  - dependency vulnerabilities
  - container-image vulnerabilities

- runbook coverage for:
  - key rotation realities
  - startup-guard failures
  - adversarial pre-release security review

### What Stage 4 means here

Security in this repo is no longer only “careful code plus good intentions.”
The main trust boundaries are now named, documented, and attached to proof and process.

---

## 7. What remains intentionally deferred after the Stage 4 baseline

The Stage 4 baseline does **not** mean every deeper security capability is already built.
The following remain intentionally deferred or limited:

## 7.1 Tenant integration secrets runtime implementation

The foundation decision is now explicit, but the repo does **not** yet ship a full runtime secret-store implementation for tenant-configured secret-bearing integrations.

Consequence:

Secret-bearing tenant integrations remain blocked/deferred until that implementation exists.

## 7.2 Server-side used-state ledger for SSO callbacks

The current accepted SSO baseline uses:

- encrypted short-lived state
- exact cookie/query equality
- host/provider coherence checks
- return-path validation
- immediate cookie clearing

The repo does **not** currently add a server-side consumed-state ledger for SSO callback state.
That is a conscious Stage 4 boundary decision, not an accidental omission.

## 7.3 Non-disruptive multi-version rotation for all auth crypto materials

Outbox encryption now has the clearest multi-version rotation support.
Other auth crypto materials are still more operationally disruptive to rotate.

Consequence:

- rotating SSO state key is operationally acceptable but invalidates in-flight starts
- rotating MFA encryption/HMAC keys requires more deliberate maintenance handling and may require re-enrollment/reset strategies

## 7.4 Stage 1B broader enforcement still remains parallel work

The repo has the minimum executable governance baseline, but not every deeper enforcement coupling is fully closed yet.

---

## 8. Practical evidence map

This snapshot is supported by three classes of proof.

## 8.1 Code/runtime proof

- topology/proxy config
- SSR API client and forwarding contract
- session middleware tenant binding
- auth module flows
- startup guards
- cookie/state handling

## 8.2 Test proof

- backend unit/integration/E2E auth coverage
- frontend unit/E2E auth coverage
- proxy conformance checks
- tenant-isolation regressions
- token lifecycle and replay/reuse regressions
- SSO state validation and abuse regressions
- outbox encryption rotation tests

## 8.3 Documentation/process proof

- current architecture docs
- security model
- threat model
- ADRs
- runbooks
- quality-bar/governance docs
- observability docs

---

## 9. What this repo is ready for next

Given the current status, the repo is ready to continue with later roadmap work **without pretending earlier foundations are still missing**.

Practical meaning:

- new major modules must still obey Cross-Cutting Track A
- Stage 1B can continue in parallel where deeper enforcement is still needed
- later stages may build on a now-explicit security-system baseline instead of inheriting undocumented assumptions

What should **not** happen next:

- re-litigating topology
- re-litigating backend-authoritative auth/session truth
- weakening tenant isolation for convenience
- pretending secret-bearing tenant integrations are ready before the secrets foundation runtime exists
- treating Stage 4 docs/tests as optional polish

---

## 10. Change triggers for this file

This file must be updated whenever any of the following materially changes:

- stage-completion truth for active roadmap stages
- shipped auth/provisioning feature scope
- security baseline truth
- topology or tenant-isolation guarantees
- startup guard behavior
- CI security scanning behavior
- tenant integration secrets readiness status

---

## 11. Bottom-line truth

The current repository is now stronger than a typical “auth feature implementation” repo.
It has:

- architecture proof
- operability proof
- security boundary documentation
- security scanning
- concrete abuse regressions
- operator-facing security/process runbooks

That is a serious foundation.

It is also honest about what is **not** done yet.

That honesty is part of the quality bar.
