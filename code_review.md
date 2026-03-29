# Code Review Guide

**Status:** Draft for lock
**Version:** 1.0
**Scope:** Repo-wide review contract for AI-assisted and human code review
**Audience:** Engineers, reviewers, technical leads, architecture owners, and release owners
**Owner:** Review / architecture owner
**Last Updated:** 2026-03-29

---

## 1. What This Document Is

This document defines **how code review should be performed in this repository**.

It is the repo-wide review contract for:

- changed-files / PR review
- pre-merge review
- whole-codebase audits
- design challenge reviews
- migration and rollback-risk reviews
- security / tenant-isolation reviews
- observability / operability reviews
- performance / scalability reviews
- failure-mode / misuse reviews

It applies to both:

- human review
- AI-assisted review

The purpose of this file is not to replace engineering judgment. Its purpose is to make review behavior:

- consistent
- grounded
- evidence-based
- harder to misuse

---

## 2. What This Document Is Not

This document is **not**:

- the architecture source of truth
- the backend engineering rules file
- the frontend engineering rules file
- a product requirements document
- a test plan
- a substitute for CI, QA, or runtime proof

This file defines **how to review**, not what the product should be.

---

## 3. Review Goals

Every meaningful review in this repo should try to answer these questions:

### 3.1 Correctness

Is the change likely to behave correctly?

### 3.2 Boundary Safety

Is the change in the right place, with acceptable coupling and ownership?

### 3.3 Security / Trust Safety

Does the change preserve auth, tenant isolation, session, topology, and trust boundaries?

### 3.4 Operational Safety

Will this be diagnosable, supportable, and recoverable if it fails?

### 3.5 Change Safety

Could this break under retry, rollback, partial deploy, stale data, or migration conditions?

### 3.6 Documentation Alignment

Do the docs that govern this area still match reality?

### 3.7 Proof Quality

Has the right level of validation actually been run?

---

## 4. Review Grounding Requirements

Before making strong review claims, the reviewer must be clear about what was actually inspected.

A good review should identify:

- what files were reviewed
- what docs were reviewed
- what tests or checks were reviewed
- whether the review is static-only or backed by executed validation
- any missing context that limits confidence

### Required Behavior

- Do not review from memory when the repo can answer the question.
- Do not imply proof that was not actually run.
- Do not let polished wording substitute for repo evidence.

---

## 5. Truth Ladder For Review

When sources disagree, use this order:

1. active locked product/module source-of-truth documents
2. current foundation / shipped-scope truth docs
3. architecture and decision records
4. security model and topology law
5. contract and API docs
6. implementation code
7. tests and CI workflows
8. runbooks, QA docs, and developer guides
9. temporary notes, chat summaries, and scratch prompts

### Required Behavior

- If a lower-truth source conflicts with a higher-truth source, call it out explicitly.
- Do not silently smooth over contradictions.
- Do not let passing tests alone erase architecture, security, or contract drift.

---

## 6. Severity Model

Use these severity levels consistently.

### P0 — Blocker / Unsafe

Use when the change creates or likely creates:

- serious auth or tenant-isolation risk
- serious data integrity risk
- serious rollback or deployment risk
- severe security weakness
- critical behavior that is unproven and too risky to merge or release blindly

### P1 — Serious Issue

Use when the change has a meaningful correctness, operational, or review-readiness problem that should normally be fixed before merge.

### P2 — Important but Not Usually Merge-Blocking

Use when the issue is real and worth fixing, but does not normally require blocking merge on its own.

### P3 — Cleanup / Clarity / Improvement

Use for maintainability, naming, readability, consistency, and other lower-risk improvements.

### Required Behavior

- Do not hide P0/P1 issues inside general commentary.
- Do not inflate every nit into a blocker.
- Say clearly whether a finding is blocking or advisory.

---

## 7. Review Modes

This repo uses different review modes depending on the kind of work.

### 7.1 Changed-Files / PR Review

Used when reviewing a concrete diff or PR.

### 7.2 Design Challenge Review

Used before implementation when pressure-testing a proposed design.

### 7.3 Module / Feature Audit

Used during implementation or refactor when a bounded area needs structural review.

### 7.4 Security / Authz / Tenant-Isolation Review

Used when auth, session, topology, tenant, membership, or trust boundaries are involved.

### 7.5 Migration / Change-Risk Review

Used when schema, data shape, rollout, rollback, or partial-deploy risk exists.

### 7.6 Observability / Operability Review

Used when diagnosability, runbooks, and support readiness matter.

### 7.7 Performance / Scalability Review

Used when hot paths, repeated IO, scale assumptions, or query behavior are at risk.

### 7.8 Failure-Mode / Misuse Review

Used when replay, retry, state gaps, admin misuse, or dangerous flow behavior must be assessed.

### 7.9 Whole-Codebase Weak-Spot Audit

Used for broad release readiness or architectural health checks.

---

## 8. Required Review Lenses

When relevant, meaningful reviews in this repo should examine these lenses.

### 8.1 Product / Domain Lens

- Is the behavior aligned with the current product truth?
- Are business rules being expressed in the right place?
- Is the change accidentally redefining product behavior?

### 8.2 Architecture / Boundary Lens

- Is the code in the right place?
- Is ownership clear?
- Is coupling acceptable?
- Is the design still resilient to future change?

### 8.3 Security / Trust Lens

- Are auth, session, topology, or tenant boundaries weakened?
- Are permissions or trust assumptions drifting?
- Are unsafe defaults being introduced?

### 8.4 Failure / Risk Lens

- Could this break on retry, replay, partial deploy, rollback, or stale data?
- Are state transitions, side effects, and edge cases still safe?

### 8.5 Operability Lens

- Will this be diagnosable when it breaks?
- Are logs, messages, alerts, and runbooks still adequate?
- Is operator supportability improving or getting worse?

### 8.6 Performance / Scale Lens

- Are queries, repeated work, or hot paths getting worse?
- Is the change hiding cost that will matter later?

### 8.7 Engineering Quality Lens

- Is the code understandable?
- Is it testable?
- Are side effects explicit enough?
- Is complexity justified?

---

## 9. Documentation Coupling Checks

A review must check whether the change should have updated or reviewed matching docs.

Look for doc coupling when the change affects:

- architecture or cross-cutting system behavior
- security/session/tenant rules
- API contracts
- operational procedures
- QA-visible flows
- AI/review operating behavior

### Required Behavior

If a change affects one of these areas but no doc update or doc review happened, call that out.

---

## 10. Validation Expectations

A good review should care not only about the code, but also about whether the right validation was run.

### 10.1 Smallest Meaningful Proof

Expect the smallest validation that actually proves the affected area.

### 10.2 Stronger Proof For High-Risk Changes

If the change affects auth, topology, sessions, tenant boundaries, migrations, or operationally sensitive flows, expect stronger proof than a local typecheck alone.

### 10.3 Report What Was Actually Run

A review should distinguish between:

- reasoned confidence
- static validation
- runtime proof

### Required Behavior

Do not say “looks good” in a way that implies runtime proof if runtime proof was never run.

---

## 11. Review Output Format

For meaningful review work, use a structure that makes the conclusion clear.

Recommended structure:

1. **Review grounding**
   What was reviewed, what docs were consulted, and what validation context exists.

2. **What appears correct**
   What is solid, aligned, or well-handled.

3. **Findings by severity**
   P0 / P1 / P2 / P3 findings, clearly separated.

4. **Boundary / architecture verdict**
   Whether the change is in the right place and respects repo structure.

5. **Security / trust verdict**
   Whether auth/session/tenant/topology boundaries remain safe.

6. **Documentation / proof gaps**
   Missing doc updates, missing tests, missing validation, or unclear rollout details.

7. **Final verdict**
   Clear summary: safe / safe with fixes / not ready.

### Required Behavior

- Keep blocker findings prominent.
- Keep advisory cleanup separate from risky issues.
- Do not bury the verdict.

---

## 12. Review Behavior By Risk Level

### Low-Risk Changes

Examples:

- isolated docs-only edits
- copy-only UI tweaks
- tiny internal cleanup with no flow or contract impact

Expected review depth:

- focused diff review
- doc consistency check
- smallest relevant validation

### Medium-Risk Changes

Examples:

- route behavior changes
- API response shape changes
- moderate refactors
- workflow adjustments without major auth/tenant impact

Expected review depth:

- changed-files review
- contract/docs check
- relevant area validation
- failure-mode thinking where needed

### High-Risk Changes

Examples:

- auth/session/tenant/topology changes
- migrations
- setup/bootstrap logic
- invite/reset/MFA/SSO behavior
- cross-cutting architecture shifts

Expected review depth:

- changed-files review plus specialized review mode(s)
- doc coupling check
- stronger validation expectations
- explicit risk statements
- explicit merge/release readiness position

---

## 13. What Good Review Looks Like

A good review in this repo is:

- grounded in files and docs
- specific to the actual change
- clear about what is proven vs assumed
- willing to block risky changes when needed
- unwilling to create fake confidence
- respectful of repo architecture and source-of-truth layering

A good review does **not** need to be long. It needs to be correct, scoped, and useful.

---

## 14. What Bad Review Looks Like

Bad review patterns include:

- generic praise without evidence
- blocker issues buried in soft language
- treating tests as architecture truth
- ignoring docs that should move with code
- reviewing from memory instead of the repo
- assuming runtime safety from static reading alone
- calling a risky change “fine” because the code looks clean
- confusing implementation preference with real risk

---

## 15. When To Escalate Review

Escalate review depth when the change affects:

- auth or permissions
- session or cookie behavior
- tenant or workspace isolation
- topology or proxy assumptions
- migrations or data integrity
- outbox/email/audit side effects
- setup/bootstrap behavior
- release-critical operational behavior
- hot paths or scale-sensitive areas

If one of these is in play, generic review is not enough.

---

## 16. AI-Assisted Review Rules

When AI is used during review:

- attach the real diff or files
- attach governing docs when relevant
- distinguish fact from inference
- say what validation was actually run
- treat AI output as assistance, not authority

AI-assisted review is acceptable in this repo only when it remains:

- repo-aware
- evidence-based
- transparent about limits
- coupled to human judgment and real validation

---

## 17. When To Update This Document

Update this file when:

- review expectations change materially
- the repo adopts a new stable review mode
- severity handling changes materially
- the expected review output structure changes materially
- AI-assisted review rules change materially

Do not update this file for:

- ordinary feature delivery
- temporary prompt experiments
- one-off review comments
- ordinary implementation changes that do not change review behavior

---

## 18. Final Position

This document is the repo-wide review contract.

Its job is to keep review in this repository:

- grounded
- severity-aware
- boundary-aware
- documentation-aware
- validation-aware
- resistant to fake confidence

That is the standard both humans and AI-assisted review should follow.
