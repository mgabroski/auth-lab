# Hubins Auth-Lab — Current Foundation Status

**Status:** Active repo truth snapshot
**Scope:** Current implemented foundation only
**Audience:** Engineers, reviewers, future implementation sessions
**Last Updated:** 2026-04-01

---

## Purpose

This document is the repo's practical truth snapshot.

It exists to keep these things aligned:

- what the repository actually implements now
- what the active documentation claims
- what future implementation sessions assume
- what is intentionally deferred to later hardening stages
- what is baseline-only versus what is fully closed
- what is enforceable in-repo versus what still depends on external GitHub settings or human review behavior

This file is not a roadmap and not a wish list.
It is the current-state truth for the repository as it exists now.

---

## 1. High-level status

The repository is no longer only a topology or auth-foundation sandbox.
It now contains a real Auth + User Provisioning slice with real browser surfaces, real backend behavior, real test proof, and meaningful hardening work.

At the time of this snapshot, the repo status is:

- **Before Stage 1 quality-bar work:** completed
- **Stage 1A minimum enforcement:** completed
- **Stage 1B deeper enforcement:** completed in-repo
- **Stage 2 architecture-invariant proof:** completed and strong
- **Stage 3 operability baseline:** completed as a baseline, not yet a fully mature ops system
- **Stage 4 security-system baseline:** completed as a baseline, not yet a fully mature security program
- **Cross-Cutting Track A:** completed to the strongest honest repo-native enforcement depth
- **Stage 5 release-engineering baseline:** established in-repo, but not yet fully closed in practice until external branch-protection settings and ongoing usage match the documented contract

That means the repository now has:

- real topology invariants and topology proof
- real auth/provisioning flows
- real observability/operability baseline
- explicit threat-model and security ADR foundation
- runnable security scanning in CI
- explicit abuse-regression proof for the highest-risk callback boundary
- a real governance layer for PRs and repo law
- a stronger Stage 1B enforcement layer for drift, exceptions, ADR linkage, and high-risk review surfaces
- a real Track A enforcement surface for major-module quality expectations, signoff evidence, and visible deferred-quality handling
- a real release-engineering baseline for lanes, migration safety, rollback expectations, post-change verification, hotfix handling, and changelog discipline

It does **not** mean:

- Stage 3 has full dashboard/alert/SLO maturity
- Stage 4 has fully closed every deeper security concern
- Stage 5 is fully operationalized beyond repo-visible process and enforcement surfaces
- GitHub required-review merge blocking can be fully enforced from repository files alone

This distinction is intentional.
The repo is strong because the current state is real, and because the remaining limits are named instead of hidden.

---

## 2. What is implemented now

### 2.1 Repository and infrastructure foundation

The following are real and load-bearing:

- monorepo/workspace structure
- backend application
- frontend application
- proxy/container topology for full-stack local testing
- Postgres and Redis infrastructure
- Mailpit local email capture for non-production email proof
- same-origin browser API model under `/api/*`
- SSR direct-to-backend model with forwarded headers
- CI workflows covering repo guard, backend tests, frontend tests, proxy conformance, and security scans

### 2.2 Locked topology and request model

The topology decisions remain unchanged and are now continuously provable:

- one public origin from the browser's perspective
- browser calls use same-origin `/api/*`
- SSR/server-side frontend calls use internal backend URL plus explicit forwarded headers
- tenant identity is derived from request host
- backend owns session/auth truth
- session cookies remain backend-owned and host-scoped
- SSO state handling remains separate from session-cookie handling

### 2.3 Backend auth/provisioning implementation

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

### 2.4 Frontend auth/provisioning implementation

The frontend currently contains the real user-facing surface for the implemented module scope, including:

- public auth routes
- invite acceptance and invite-driven registration
- verify-email flow
- reset-password flow
- MFA setup / verify / recovery surfaces
- role-aware authenticated landing behavior
- admin invite-management surface
- workspace setup banner and `/admin/settings` acknowledgement surface

### 2.5 Current local proof contract

The repository supports a repeatable local proof contract:

- Mailpit receives auth emails locally
- canonical local hosts represent different tenant policies
- canonical seed/bootstrap flows support invite onboarding proof
- local browser proof can validate signup, verification, reset-password, MFA, invite lifecycle behavior, and proxy/topology behavior

This is stronger than a code-only module.
It is still local-first proof, not full delivery-platform maturity.

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
- repo-visible quality-bar authority
- repo-visible quality-exception authority
- explicit ADR / architecture-law linkage expectations for sensitive boundary changes

These are not optional implementation preferences.
They are architecture, governance, and security invariants.

---

## 4. What Before Stage 1 established

Before Stage 1 work is real in this repository.
The repo has a visible quality bar and an explicit owner role for the governance surface.

That foundation includes:

- a repo-visible quality bar
- stage and module completion definitions
- mandatory gates versus deferrable quality targets
- deprecation and removal expectations
- pressure-policy expectations
- named ownership for protected governance surfaces
- a single authoritative repo-visible location for deferred quality targets, refused signoff records, and explicit time-bounded quality exceptions

Operational meaning:
The repo no longer depends only on memory or verbal standards to define what “done” means.

Limit:
This does **not** mean every downstream enforcement mechanism can be expressed purely through prose.
That is why Stage 1A and Stage 1B exist.

---

## 5. What Stage 1A established

Stage 1A created the minimum executable governance baseline.

That includes:

- repo guard workflow
- PR template with Module Quality Gate structure
- prompt-catalog coupling checks
- route-to-API-doc coupling checks for protected surfaces
- import-boundary checks
- protected-law file checks
- same-origin discipline checks for the frontend proxy surface

Operational meaning:
Common drift paths are now blocked automatically instead of being left to reviewer memory.

Limit:
Stage 1A is the minimum viable enforcement layer.
It is real and load-bearing, but it is not the same thing as Stage 1B depth.

---

## 6. What Stage 1B now establishes

Stage 1B is now treated as completed **in-repo**.

The repository now has a deeper enforcement layer for:

- stronger doc/code truth-coupling on critical route and contract surfaces
- stronger ADR / architecture-law linkage expectations for sensitive changes
- stronger review-surface protection for high-risk files and directories
- selective error-message audit coupling for user-visible auth/invite message surfaces
- CI-visible drift, exception, and waiver reporting
- stronger major-module applicability enforcement through repo guard
- stronger PR evidence expectations for signoff, documentation, release notes, and exception handling

Operational meaning:
Repo law is now broadly executable.
Important drift is harder to hide, exceptions are harder to keep informal, and sensitive changes require more explicit reviewer-visible context.

Important limit:
This file does **not** claim that Stage 1B can force every external hosting-platform behavior from inside the repo.

In particular, the repository can define:

- ownership metadata
- PR structure
- repo guard failure conditions
- required update surfaces
- exception visibility
- stronger evidence rules

But it cannot, by repository files alone, guarantee:

- GitHub branch-protection configuration
- GitHub required-review merge blocking
- actual reviewer diligence

Correct reading:
**Stage 1B is completed in-repo.**
External review-enforcement depth still depends on platform settings and review practice outside the repository itself.

---

## 7. What Stage 2 established

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

Current strength:
Stage 2 is one of the strongest parts of the repository.
This is not baseline-only wording.
This stage is currently treated as completed and strong.

---

## 8. What Stage 3 established

Stage 3 added the current operability baseline.

That includes:

- structured logging
- request correlation
- metrics export
- operability smoke checks
- observability documentation
- runbook and incident-triage material

Operational meaning:
The repo can now answer the first serious operational questions under pressure instead of relying on developer intuition alone.

Important limit:
This file does **not** claim that the repo already has a fully mature operations system.
The repository currently has an **operability baseline**, not full operational maturity.

That means the repo does **not** yet claim, from this file alone:

- fully wired dashboard infrastructure
- fully wired alert routing or paging
- a mature SLO operating loop inside the repo itself

Correct reading:
**Stage 3 is completed as a baseline.**
It should not be described as a fully matured ops program.

---

## 9. What Stage 4 established

Stage 4 did **not** redesign auth flows.
It established the security-system baseline around the current implementation.

### 9.1 Stage 4 baseline additions

The repository now has real baseline work for:

- an explicit platform threat model
- security ADR coverage for the highest-risk SSO callback trust boundary
- an explicit secrets-foundation ADR for future tenant-configured integrations
- abuse-regression tests for SSO state tampering and related callback-boundary risks
- stronger outbox key-rotation test proof
- CI security scanning for:
  - secret leakage
  - dependency vulnerabilities
  - container-image vulnerabilities

- runbook/process coverage for:
  - key rotation realities
  - startup-guard failures
  - adversarial pre-release security review expectations

### 9.2 What Stage 4 means here

Security in this repo is no longer only “careful code plus good intentions.”
The main trust boundaries are now named, documented, and attached to proof and process.

### 9.3 Important Stage 4 limit

This file does **not** claim that the repo already operates as a fully mature security program.
Stage 4 is currently closed as a **security-system baseline**, not as a complete security maturity endpoint.

That means the repository does **not** yet claim, from this file alone:

- full tenant secret-runtime implementation for secret-bearing integrations
- non-disruptive multi-version rotation maturity for every auth crypto material
- fully release-blocking vulnerability enforcement across all scan surfaces
- complete security-program closure for all later product areas

Correct reading:
**Stage 4 is completed as a baseline.**
It should not be described as the finished state of security engineering for the platform.

---

## 10. What remains intentionally deferred or limited after the Stage 4 baseline

The Stage 4 baseline does **not** mean every deeper security capability is already built.
The following remain intentionally deferred or limited:

### 10.1 Tenant integration secrets runtime implementation

The foundation decision is explicit, but the repo does **not** yet ship a full runtime secret-store implementation for tenant-configured secret-bearing integrations.

Consequence:
Secret-bearing tenant integrations remain blocked or deferred until that implementation exists.

### 10.2 Server-side used-state ledger for SSO callbacks

The current accepted SSO baseline uses:

- encrypted short-lived state
- exact cookie/query equality
- host/provider coherence checks
- return-path validation
- immediate cookie clearing

The repo does **not** currently add a server-side consumed-state ledger for SSO callback state.
That is a conscious baseline boundary decision, not an accidental omission.

### 10.3 Non-disruptive multi-version rotation for all auth crypto materials

Outbox encryption currently has the clearest multi-version rotation support.
Other auth crypto materials are still more operationally disruptive to rotate.

Consequence:

- rotating the SSO state key is operationally acceptable but invalidates in-flight starts
- rotating MFA encryption or HMAC material requires more deliberate maintenance handling and may require re-enrollment or reset strategies

### 10.4 Security scan enforcement depth

Security scanning is real and valuable.
However, this file does **not** overclaim every scan surface as fully release-blocking policy.
Any stronger blocking posture must be stated explicitly in release/process docs when adopted.

---

## 11. What Track A means in the repo right now

Cross-Cutting Track A is now treated as completed to the **strongest honest repo-native enforcement depth**.

### 11.1 What is real now

The repo currently has:

- Track A defined in the quality bar
- a Module Quality Gate section in the PR template
- stronger repo-guard checks that require:
  - applicability classification
  - stronger evidence sections
  - signoff-evidence visibility
  - deferred-quality visibility
  - refusal/escalation visibility
  - stronger release/change-management structure
- stronger major-module / major-surface detection heuristics
- a named owner role for the protected governance surface
- a repo-visible quality-exception register for:
  - deferred quality targets
  - refused Track A signoff records
  - explicit time-bounded process exceptions
  - closures

### 11.2 What this means

New major-module work is no longer merely asked to “follow the standard.”
It is now required to present reviewer-visible evidence for the standard inside the normal repo workflow.

That means the repo now has meaningful enforcement for:

- architecture fit
- contract/doc updates
- minimum test expectation visibility
- security/failure-mode review visibility
- observability/runbook review visibility
- migration-safety visibility
- owner signoff evidence
- explicit deferred-quality tracking
- explicit refusal/escalation recording

### 11.3 Important Track A limit

This file does **not** claim that the repository can fully replace external review controls.

The repo can strongly enforce:

- PR structure
- exception visibility
- evidence expectations
- ownership metadata
- stronger major-module applicability pressure

The repo cannot, by itself, fully guarantee:

- actual human signoff quality
- GitHub required-review blocking behavior
- branch-protection correctness outside repo files

Correct reading:
**Track A is completed to the strongest honest repo-native depth.**
Final merge authority still depends in part on review behavior and GitHub settings outside the repository.

---

## 12. What Stage 5 established

Stage 5 is no longer only a future item in this repository.
A real release-engineering baseline now exists in-repo.

### 12.1 What is real now

The repo now contains:

- a release-engineering baseline document
- explicit release lanes
- explicit migration classes and migration-safety expectations
- explicit rollback-expectation and post-change verification expectations in the PR contract
- changelog discipline
- expanded ownership metadata intent across major repo areas
- repo-guard enforcement for the release/change-management PR structure

### 12.2 What this means

Release discipline is no longer only implied through review culture.
The repository now has written and partially enforced expectations for:

- how changes are classified
- what must be written for migration-bearing work
- how rollback should be described honestly
- what post-change verification should exist
- how hotfixes should stay disciplined

### 12.3 Important Stage 5 limit

This file does **not** claim that Stage 5 is fully closed in practice yet.
Practical closure still depends on:

- correct GitHub branch-protection / required-check settings outside the repo
- consistent use of the stronger PR contract by contributors
- ownership metadata remaining correct and actually used in review flow

Correct reading:
**Stage 5 baseline is established in-repo.**
It is stronger than “not started,” but still not the same as a fully institutionalized delivery organization.

---

## 13. Practical evidence map

This snapshot is supported by four classes of proof.

### 13.1 Code and runtime proof

- topology and proxy config
- SSR API client and forwarding contract
- session middleware tenant binding
- auth module flows
- startup guards
- cookie/state handling
- logging and metrics surfaces

### 13.2 Test proof

- backend unit, integration, and E2E auth coverage
- frontend unit and E2E auth coverage
- proxy conformance checks
- tenant-isolation regressions
- token lifecycle and replay/reuse regressions
- SSO state validation and abuse regressions
- outbox encryption rotation tests

### 13.3 Documentation and process proof

- architecture docs
- security model
- threat model
- ADRs and decision log
- runbooks
- quality-bar and governance docs
- quality-exception register
- observability docs
- release-engineering docs
- PR/repo-guard governance surfaces

### 13.4 Review and drift-control proof

- CODEOWNERS coverage for high-risk surfaces
- protected-law file review context requirements
- route-to-doc coupling checks
- architecture-law linkage expectations
- selective auth/invite message-audit coupling
- CI-visible summary output for drift, exceptions, and enforcement warnings

---

## 14. Known truth limits and documentation discipline

This file intentionally distinguishes between:

- fully completed stages
- stages completed as baselines
- in-repo-closed governance layers
- repo-native enforcement depth versus externally enforced review controls
- work that remains deferred

That distinction matters.
The repository is stronger when status language is exact.

This file should be read together with a simple rule:

- do not describe baseline-complete work as fully mature if the repo does not prove that maturity yet
- do not downgrade real completed work just because later hardening stages still exist
- do not describe Stage 1B or Track A as “still open” once the in-repo enforcement layer is actually in place
- do not describe Stage 5 as absent now that the baseline has been established in-repo
- do not describe CODEOWNERS as equivalent to external branch protection when that platform enforcement is outside the repository

Practical implication:
If another document says or implies that Stage 3, Stage 4, Track A, Stage 1B, or Stage 5 are stronger than stated here, that lower document must be corrected.
If another document says Stage 1B or Track A are still merely partial after the stronger in-repo enforcement layer lands, that lower document must also be corrected.

---

## 15. What this repo is ready for next

Given the current status, the repo is ready to continue with later roadmap work **without pretending earlier foundations are still missing**.

Practical meaning:

- new major modules must obey Cross-Cutting Track A
- Stage 1B should now be maintained, not reopened casually
- Stage 5 baseline should continue to harden through real usage and external required-check alignment
- later stages may build on an explicit security-system baseline and release baseline instead of inheriting undocumented assumptions
- future governance changes should extend the current system, not create a parallel one

What should **not** happen next:

- re-litigating topology
- re-litigating backend-authoritative auth/session truth
- weakening tenant isolation for convenience
- pretending secret-bearing tenant integrations are ready before the secrets foundation runtime exists
- treating Stage 3 and Stage 4 baseline docs/tests as optional polish
- pretending CODEOWNERS alone equals GitHub-required review enforcement
- pretending Stage 5 is already fully institutionalized beyond the repo-visible baseline
- overclaiming operational or security maturity that the repo does not yet prove
