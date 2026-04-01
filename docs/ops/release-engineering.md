# Hubins Auth-Lab — Release Engineering Baseline

**Status:** Stage 5 baseline
**Scope:** Current repo reality only
**Audience:** Engineers, reviewers, release owner, incident owner
**Last Updated:** 2026-04-01

---

## Purpose

This document defines the current release-engineering contract for this repository.

It exists to make shipping more predictable **without pretending the repo has automation or environments it does not yet have**.

This file covers:

- required green gates before merge
- release lanes
- current promotion rules
- migration safety rules
- rollback expectations grounded in current tooling
- post-change verification
- release notes and changelog discipline
- incident severity classification for release-impacting failures
- hotfix expectations
- ownership metadata expectations

This file does **not** redefine:

- topology law
- auth/session architecture
- Stage 1–4 architecture/security truth
- operator troubleshooting runbooks

Those remain authoritative in:

- `ARCHITECTURE.md`
- `docs/quality-bar.md`
- `docs/current-foundation-status.md`
- `docs/ops/runbooks.md`
- `docs/security/threat-model.md`

---

## 1. Current release reality

The repo already has meaningful delivery proof, but not a full deployment platform.

### 1.1 Repo-visible release surfaces that are real today

The current repo provides:

- local host-run development mode
- local full Docker topology mode
- GitHub Actions CI for repo guard, backend tests, frontend tests, proxy conformance, and security scans
- explicit migrations with `up()` and `down()` implementations
- operability smoke and proxy conformance scripts
- real auth/provisioning browser proof via Playwright against the running stack
- real local email proof via Mailpit

### 1.2 Things this repo does **not** currently provide

Be explicit:

- no in-repo preview deployment environment
- no in-repo automated staging deployment workflow
- no in-repo production deployment workflow
- no generic one-command rollback runner for DB migrations
- no release-branch automation
- no fully automated changelog generation
- no built-in pager/alert-routing system in the repo itself

Stage 5 must improve release safety within those constraints.
It must not invent fake infrastructure.

---

## 2. Release lanes

Every change should be treated as one of these lanes.

## 2.1 Lane A — standard code/doc change

Examples:

- UI change with no schema change
- backend logic change with no migration
- doc correction
- test-only change

## 2.2 Lane B — topology / auth / security-sensitive change

Examples:

- proxy config
- SSR header forwarding
- session/cookie behavior
- SSO start/callback behavior
- tenant resolution or request context
- MFA or invite token behavior
- startup guards or crypto handling

## 2.3 Lane C — migration-bearing change

Examples:

- new migration file
- schema change affecting app behavior
- data-shape transition requiring compatibility thinking
- release-sensitive data backfill

## 2.4 Lane D — hotfix

A hotfix is a narrowly scoped urgency-driven fix for a live issue.
A hotfix is **not** permission to skip discipline.

---

## 3. Required green gates before merge

The current repo-visible merge gates are the following.

## 3.1 Hard required CI gates

For any runtime-affecting change, these must be green:

- `Repo Guard`
- `Backend Tests`
- `Frontend`
- `Proxy Conformance`

### What those gates protect

- `Repo Guard` protects repo law, protected-file discipline, module-quality gate presence, route/doc coupling, and same-origin discipline
- `Backend Tests` protect backend behavior and regression coverage
- `Frontend` protects frontend unit coverage and Playwright auth smoke against the real running stack
- `Proxy Conformance` protects topology truth, proxy assumptions, and operability smoke

## 3.2 Security scan rule

`Security Scans` must run.

Current truthful status:

- the workflow is real and useful
- it is currently an **advisory scan surface**, not a strict fail-on-vulnerability gate for all findings
- workflow/tool failure is a blocker
- relevant findings must be reviewed in the PR when the change is Lane B, C, or D

Do **not** describe the current security-scans workflow as a stronger blocking policy than it actually is.

## 3.3 Required human checks outside CI

For changes in Lane B, Lane C, or Lane D, CI green is not enough.
The PR must also contain:

- risk notes
- deployment / release notes
- migration safety notes when applicable
- rollback expectation
- post-change verification steps

---

## 4. Current promotion model

This section defines the current honest promotion path.

## 4.1 Dev → merge candidate

### Lane A

Minimum expectation:

- required CI green
- targeted local proof or reasoning grounded in the changed files
- documentation updated if repo truth changed

### Lane B

Minimum expectation:

- required CI green
- `yarn stack:test` when proxy/topology/forwarded-header/cookie/session behavior changed
- targeted local or real-stack proof for the changed auth/security behavior
- explicit PR notes about trust-boundary impact

### Lane C

Minimum expectation:

- required CI green
- migration safety section completed
- local migration proof on a clean DB or freshly reset local state
- explicit rollback path documented
- explicit post-migration verification steps documented

### Lane D

Minimum expectation:

- smallest safe diff
- required CI green for the affected surface
- explicit hotfix reason
- explicit rollback path
- immediate post-change verification plan

## 4.2 Merge candidate → staging / QA proof

Current truthful rule:

- this repo does **not** automatically deploy preview or staging environments
- staging / QA remains manual or externally managed for the flows that cannot be proven locally

Staging / QA proof is still required when a change affects things local-only proof cannot fully close, such as:

- Google SSO live-provider proof
- Microsoft SSO live-provider proof
- real non-local SMTP provider proof
- environment-specific provider/network behavior not reproducible locally

Do not call those flows release-ready from local proof alone.

## 4.3 Staging / QA → production-like approval

Because deployment automation is not in this repo yet, the current approval rule is:

- all applicable CI gates green
- all required manual proof complete for the lane
- migration safety signed off when applicable
- release notes recorded
- rollback expectation recorded
- post-change verification steps prepared before rollout starts

---

## 5. Migration safety standard

Migration-bearing changes require extra discipline.

## 5.1 Migration classes

### Class 1 — additive / backward-compatible

Examples:

- add table
- add index
- add nullable column
- add non-breaking defaulted field

This is the preferred default.

### Class 2 — expand / contract

Examples:

- introduce a new shape while keeping old and new paths compatible temporarily
- shift reads/writes safely over multiple changes
- remove the old path later, not immediately

Use this when the target change cannot honestly be made backward-compatible in one step.

### Class 3 — destructive or operationally risky

Examples:

- drop column/table still relied on by old code
- rewrite data shape in place with meaningful risk
- tighten uniqueness/constraint behavior with runtime impact
- heavy backfill that may materially slow or lock important flows

These are release-sensitive by default.
They require explicit justification.

## 5.2 Required migration statements in the PR

Every migration-bearing PR must state:

1. migration class: 1, 2, or 3
2. whether old code can still run safely after the migration
3. whether new code can still run safely before the migration
4. rollback path
5. post-migration verification steps

## 5.3 Rollback truth

Current repo reality:

- migrations contain `up()` and `down()` implementations
- the repo exposes `db:migrate`
- the repo does **not** expose a general-purpose safe reviewed `db:rollback` command

Therefore:

- do **not** assume rollback is one command away
- every migration-bearing PR must describe its rollback path explicitly
- acceptable rollback may be one of:
  - redeploy previous app code because the migration is backward-compatible
  - apply an explicit revert/follow-up migration
  - run a rehearsed manual DB step documented in the PR and runbook notes

If none of those is realistically true, the migration is not release-ready.

## 5.4 Minimum local migration proof

For migration-bearing PRs, the author must prove at least:

1. migration succeeds on clean local state
2. backend health is green after migration
3. the primary affected flow still works

For this repo, that usually means:

- run/reset local DB state
- apply migrations
- confirm `/health`
- confirm one representative auth/provisioning path still works

## 5.5 Post-migration verification checklist

After a migration is applied in the target environment, verify at minimum:

- health endpoint is green
- one representative tenant can load `/api/auth/config`
- one representative login/bootstrap path still works for the changed area
- no obvious migration/app failures appear in logs

If the change affected invite, verify-email, reset-password, MFA, SSO, outbox, or proxy behavior, the verification checklist must include one flow from that area.

---

## 6. Release checklist

Use this before calling a change ready to ship.

## 6.1 Standard release checklist

- release lane identified
- required CI gates green
- relevant docs updated
- PR risk notes filled
- deployment / release notes filled
- migration safety filled if applicable
- rollback expectation written
- post-change verification steps written

## 6.2 Additional checklist for Lane B changes

- proxy/topology proof completed if affected
- SSR/header-forwarding behavior checked if affected
- tenant isolation not weakened
- relevant security-scan findings reviewed
- security/adversarial reasoning documented when the trust boundary changed materially

## 6.3 Additional checklist for hotfixes

- issue/incident explicitly named
- smallest safe diff chosen
- unrelated cleanup excluded
- rollback path written before merge
- immediate post-change verification owner named

---

## 7. Release notes and changelog discipline

The Stage 5 baseline is intentionally simple.

## 7.1 PR-level release notes are mandatory

Every runtime-affecting PR must fill the PR template's deployment / release notes section.
That section should state, as applicable:

- deploy coordination need
- migration impact
- rollback expectation
- operator action required
- environment-specific proof still required

## 7.2 Changelog rule

This repo should maintain a human-written changelog for released changes.
Until release automation exists, the changelog discipline is:

- one clear entry per merged release-relevant change or release batch
- focus on user-visible, operator-visible, migration-visible, or security-visible impact
- do not fill it with trivial internal refactors unless they change release risk or operator action

## 7.3 No fake release notes

Do not write release notes that imply:

- automated preview deployments that do not exist
- one-click rollback that does not exist
- staging automation that does not exist
- stronger security guarantees than the current gates actually provide

---

## 8. Incident severity policy

This section exists for release-impacting issues.

## 8.1 SEV-1

Use SEV-1 when any of the following is true:

- tenant isolation may be broken
- authenticated access crosses tenant boundaries
- login or auth bootstrap is broadly unavailable for most tenants
- session/cookie behavior authenticates the wrong host
- SSO callback trust boundary appears broken
- a migration has materially broken the app's core auth path across the environment

Expected response:

- stop rollout or halt promotion immediately
- preserve logs and evidence
- assign a single incident owner
- contain first, then clean up

## 8.2 SEV-2

Use SEV-2 when:

- a major auth or provisioning flow is broken for a subset of tenants/users
- invite, verification, or password-reset delivery is failing broadly
- admin onboarding or MFA is degraded but not cross-tenant unsafe
- a migration caused partial but significant functionality loss

Expected response:

- stop further promotion until understood
- assess rollback vs forward-fix quickly
- keep the incident timeline explicit in PR/hotfix notes

## 8.3 SEV-3

Use SEV-3 when:

- the issue is real but limited in blast radius
- there is no evidence of tenant isolation failure
- a workaround exists and core login/auth still functions

Expected response:

- fix in normal priority order or via a scoped hotfix if the impact justifies it

---

## 9. Hotfix workflow

Hotfixes are allowed, but not exempt from discipline.

## 9.1 Entry rule

A change is a hotfix only when it is tied to a live issue that should not wait for the next normal change batch.

## 9.2 Required hotfix PR content

The PR must contain:

- a one-line incident summary
- blast-radius statement
- exact fix scope
- explicit rollback path
- explicit post-deploy verification steps

## 9.3 Minimum validation for a hotfix

At minimum:

- `Repo Guard` green
- all directly affected test surfaces green
- `Proxy Conformance` green if the hotfix touches topology/proxy/SSR/cookies/session/tenant routing
- migration safety filled if any migration is involved

## 9.4 Hotfix follow-through

After the hotfix lands:

- verify the fix in the affected environment immediately
- update runbook/release notes if the operator contract changed
- record deferred cleanup as explicit follow-up work

Do not smuggle unrelated cleanup into a hotfix unless it is required for safety.

---

## 10. Ownership metadata rule

Ownership metadata for major repo areas must live in `.github/CODEOWNERS`.

At minimum, ownership metadata should cover:

- backend
- frontend
- infra
- workflows / repo guard
- security docs / models
- ops / runbooks / release docs

The same person may currently own many of these surfaces.
That is acceptable for this stage.
What is **not** acceptable is having major areas with no named owner surface at all.

---

## 11. Stop rules

Do **not** ship if any of the following is true:

- a required CI gate is red
- migration safety is required but not written
- rollback path is hand-waved
- post-change verification is “we’ll see after deploy”
- auth/topology/security trust boundaries changed without matching proof
- PR notes or docs overclaim automation the repo does not actually have

---

## 12. Practical position

The goal of this Stage 5 baseline is not enterprise theater.

It is to make sure that when this repo ships:

- gates are named
- migration risk is explicit
- rollback expectations are honest
- hotfixes stay disciplined
- release notes stop being an afterthought
- ownership stops being implied only in people’s heads

That is the minimum bar for predictable shipping in the repository as it exists today.
