# Prompt Usage Guide

**Status:** Locked
**Version:** 1.2
**Scope:** Repo-level operating guide for when and how to use approved prompt artifacts
**Audience:** Engineers, reviewers, technical leads, and architecture owners
**Owner Role:** Lead Architect or Designated Quality Owner
**Last Updated:** 2026-03-29

---

## 1. What This Document Is

This document explains **when to use the repo’s approved prompt artifacts and how to use them well**.

It exists so prompt usage becomes part of repo workflow instead of relying on memory, habit, or improvised chat behavior.

This file explains:

- when to use each approved prompt
- when not to use it
- what minimum context to attach
- what kind of output to expect
- whether the result is advisory or merge/release-relevant
- what validation should normally follow

This file is the **usage guide**.
It is not the prompt catalog.
It is not the review contract.
It is not a product roadmap.

---

## 2. Read These Together

Use this document together with:

- `docs/quality-bar.md`
- `AGENTS.md`
- `code_review.md`
- `docs/prompts/catalog.md`
- `backend/AGENTS.md` when backend work is involved
- `frontend/AGENTS.md` when frontend work is involved

These files work together as one system:

- `docs/quality-bar.md` defines what quality means
- `AGENTS.md` routes repo-aware work
- `code_review.md` defines how review is performed
- `docs/prompts/catalog.md` defines which prompt artifacts are approved
- this file explains how to apply those artifacts at the right time

---

## 3. Core Usage Rules

### 3.1 Repo truth comes first

A prompt should help apply repo truth, not replace it.

### 3.2 Prompt output is not proof

A strong answer does not replace tests, CI, runtime checks, topology proof, QA, or signoff.

### 3.3 Use the smallest prompt that fits the job

Do not stack many prompts when one well-chosen prompt is enough.

### 3.4 High-risk changes need higher-risk prompts

Auth, tenant isolation, sessions, topology, migrations, rollout, and rollback-sensitive work should use specialized prompts rather than only generic review prompts.

### 3.5 Attach real context

If the review is about a real change, attach the real diff, files, and governing docs.

### 3.6 Prompts do not waive the quality bar

For major-module work, prompt usage does not replace the mandatory gates, evidence, or signoff path defined in `docs/quality-bar.md`.

### 3.7 Prefer stage-appropriate usage

Use design prompts before coding, audit prompts during coding, and review prompts when the change is concrete enough to inspect.

---

## 4. Workflow Map

Use prompts according to the stage of work.

### Before coding

Use:

- `docs/prompts/design-challenge.md`
- `docs/prompts/better-architecture.md`

### During coding / while shaping a module

Use:

- `docs/prompts/module-audit.md`

### Before push

Use:

- `docs/prompts/pre-push-self-review.md`

### Before or during PR review

Use:

- `docs/prompts/pr-review.md`

### For security / topology / tenant-boundary-sensitive work

Use:

- `docs/prompts/security-tenant-review.md`

### For schema / rollout / rollback / migration-sensitive work

Use:

- `docs/prompts/migration-change-risk.md`

### For structured generation work

Use:

- `docs/prompts/module-generation-fullstack.md`

---

## 5. Prompt-by-Prompt Guidance

## 5.1 `docs/prompts/design-challenge.md`

### Use it when

- a design exists but should be pressure-tested before coding
- the cost of choosing the wrong approach is meaningful
- you want to expose missing assumptions, weak boundaries, or hidden complexity early

### Do not use it when

- the work is already implemented and you need changed-files review
- you mainly need a security/topology review
- you mainly need migration or rollback-risk review

### Minimum context to attach

- the proposed design or plan
- relevant source-of-truth docs
- architecture/topology docs if boundaries matter
- known constraints and non-goals

### Expected output

- pressure-tested design feedback
- hidden risks
- boundary concerns
- likely drift paths
- concrete questions or required corrections

### Output type

Advisory, but often high-value before implementation.

### Validation that should follow

- design decision update
- doc alignment
- later concrete code review once implementation exists

---

## 5.2 `docs/prompts/better-architecture.md`

### Use it when

- the current design may work but you want to compare it with safer or cleaner alternatives
- you suspect boundary placement, coupling, or structure is not ideal
- you want a serious alternatives analysis before committing further

### Do not use it when

- you already need concrete changed-files review
- the decision is purely local and low-risk
- the question is mainly about migration or security policy rather than architecture shape

### Minimum context to attach

- the current design or current implementation slice
- relevant architecture docs
- constraints, non-goals, and tradeoffs already known

### Expected output

- alternative structures
- tradeoff analysis
- safer default recommendation
- explicit risk of staying with current design

### Output type

Advisory.
Use it to improve design quality before or during implementation.

### Validation that should follow

- architecture decision update if the direction changes materially
- code review after implementation exists

---

## 5.3 `docs/prompts/module-audit.md`

### Use it when

- implementation is in progress and you want structural review before it sprawls
- a module boundary feels messy or unclear
- a feature is growing and you want an audit before it becomes harder to change

### Do not use it when

- the change is tiny and local
- you only need final changed-files review
- you are mainly reviewing migration/rollback risk or security/topology risk

### Minimum context to attach

- relevant module files
- current governing docs
- known goals and non-goals
- any open risks already suspected

### Expected output

- boundary audit
- ownership/coupling findings
- structural weaknesses
- missing proof or missing doc coupling

### Output type

Advisory, but often strong enough to affect merge readiness for in-progress module work.

### Validation that should follow

- targeted refactor or design correction
- pre-push or PR review once the diff stabilizes

---

## 5.4 `docs/prompts/pre-push-self-review.md`

### Use it when

- you are about to push a real change
- you want a last pass for missing docs, missing tests, coupling issues, or obvious drift

### Do not use it when

- the work is only at idea stage
- you need a formal PR-level verdict with severity handling across a stable diff

### Minimum context to attach

- the changed files or diff
- relevant docs for the affected area
- what validation you already ran

### Expected output

- likely missing doc updates
- likely missing tests or validation
- obvious boundary mistakes
- obvious risk items to fix before push

### Output type

Advisory, but very practical.

### Validation that should follow

- run the smallest meaningful checks for the area
- correct obvious drift before pushing

---

## 5.5 `docs/prompts/pr-review.md`

### Use it when

- a diff or PR is stable enough for real review
- you want severity-aware changed-files review
- you want a merge-readiness signal grounded in the repo

### Do not use it when

- the design is still too early and fluid
- the main concern is a specialized security or migration review that deserves its own prompt first

### Minimum context to attach

- the diff or changed files
- relevant source-of-truth docs
- what validation was actually run
- any known risk areas or constraints

### Expected output

- what appears correct
- findings by severity
- boundary verdict
- trust/security verdict when relevant
- doc/proof gaps
- final merge-readiness position

### Output type

Merge-relevant when grounded in the real diff and accompanied by real validation context.

### Validation that should follow

- fix blocking items
- run missing checks
- escalate to specialized review prompts for high-risk areas if needed

---

## 5.6 `docs/prompts/migration-change-risk.md`

### Use it when

- a change affects schema or data shape
- rollout/rollback safety matters
- partial deploy or state skew could break behavior
- backward compatibility or migration sequencing matters

### Do not use it when

- there is no real migration or rollout risk
- the main issue is general code quality rather than change safety

### Minimum context to attach

- migration files or schema changes
- rollout assumptions
- backward-compat expectations
- relevant code paths and docs

### Expected output

- rollout and rollback risks
- ordering concerns
- partial deploy hazards
- stale-data and backward-compat findings
- safer sequencing recommendations

### Output type

Merge/release-relevant for migration-sensitive work.

### Validation that should follow

- explicit migration test or dry-run where applicable
- release/runbook updates where needed
- concrete rollout/rollback plan

---

## 5.7 `docs/prompts/security-tenant-review.md`

### Use it when

- auth, session, cookies, permissions, topology, SSR/browser boundaries, tenant resolution, or trust boundaries are touched
- a change could weaken isolation, identity, or security posture

### Do not use it when

- the change is clearly unrelated to trust boundaries
- you only need generic changed-files review on low-risk code

### Minimum context to attach

- changed files or design under review
- security/topology docs
- relevant route or flow docs
- what was actually validated

### Expected output

- trust-boundary findings
- tenant/session/auth concerns
- topology or SSR/browser drift risks
- unsafe assumptions
- explicit severity judgment

### Output type

Merge-relevant for security- or isolation-sensitive work.

### Validation that should follow

- stronger runtime or end-to-end proof where relevant
- contract or topology validation
- doc updates if trust-boundary rules changed or were clarified

---

## 5.8 `docs/prompts/module-generation-fullstack.md`

### Use it when

- you are generating a new repo-aligned module scaffold or structured feature slice
- you need implementation help that should follow repo architecture and standard patterns

### Do not use it when

- you need a review verdict rather than generation help
- the task is mainly design challenge, migration risk, or security review

### Minimum context to attach

- governing architecture docs
- current module skeleton / engineering rules
- relevant product truth docs
- any route/API/persistence expectations already locked

### Expected output

- generated implementation guidance or scaffolding aligned to repo law
- repo-consistent structure
- doc/test reminders tied to the change

### Output type

Build-support and implementation-support.
It is not a substitute for review.

### Validation that should follow

- normal code review
- doc coupling updates
- tests and checks appropriate to the generated work

---

## 6. How To Combine Prompts Safely

Use one primary prompt by default.

Only add a second prompt when the risk profile truly justifies it.

Good combinations:

- design challenge + better architecture
- module audit + security/tenant review
- PR review + migration/change-risk
- PR review + security/tenant review

Avoid stacking many prompts for normal work.
Too many prompts increase noise, repetition, and false confidence.

---

## 7. Major-Module Rule

If the change introduces or substantially expands a major module, prompt usage must respect the repo quality bar.

That means prompt usage does **not** replace:

- architecture fit and boundary review
- required API or contract documentation
- minimum test coverage at the right levels
- failure-mode and security review proportional to risk
- observability touchpoints appropriate to the module
- runbook and ops impact review
- migration safety review when schema or data-shape changes are involved
- explicit Track A signoff

### Practical rule

For major-module work:

- use prompts to improve the work
- use prompts to surface missing gates
- do not present prompt output as module closure by itself

---

## 8. What To Attach To A Prompt Request

For the prompt system to be useful, the requester should attach the smallest real context that makes a grounded answer possible.

Usually that means some combination of:

- changed files or PR diff
- architecture docs
- product or module source-of-truth docs
- API docs
- migration files
- test results
- what validation was actually run
- known constraints or non-goals

### Required behavior

- Do not ask for strong review on an abstract summary if the real diff exists.
- Do not omit governing docs for high-risk work.
- Do not imply validation that was not actually performed.

---

## 9. How To Read Prompt Output

Prompt output should be treated as one of these:

### 9.1 Advisory

Useful guidance that improves design or implementation quality, but does not directly decide merge or release readiness.

### 9.2 Merge-relevant

A grounded review result that should influence whether a change is ready to merge.

### 9.3 Release-relevant

A grounded review result for migration, security, topology, rollout, or operationally sensitive changes that should influence release readiness.

### Required behavior

Always separate:

- what the prompt found
- what was actually validated
- what still remains unproven

---

## 10. Anti-Patterns

Avoid these prompt-usage failures:

- using review prompts without the real diff when the real diff exists
- treating prompt output as proof of runtime correctness
- using design prompts as if they were final PR review
- using generic review where a security or migration prompt is clearly needed
- stacking too many prompts for one low-risk change
- letting prompts drift away from repo docs
- using prompts to bypass the major-module quality bar or Track A signoff
- using unofficial prompt files that are not in the catalog

---

## 11. When To Update This File

Update this file when:

- a new approved prompt artifact is added and needs usage guidance
- the recommended timing for an approved prompt changes materially
- the expected input or output model for a prompt changes materially
- the major-module or quality-bar relationship to prompt usage changes materially
- the prompt workflow itself changes materially

Do not update this file for:

- ordinary product feature work
- one-off chat experiments
- normal code changes that do not change how the prompt pack should be used

---

## 12. Final Position

This file exists so approved prompt artifacts are used at the right time, with the right inputs, and with the right expectations.

Its job is to make prompt usage:

- repo-aware
- stage-aware
- risk-aware
- smaller and cleaner
- harder to misuse
- clearly subordinate to real proof and the repo quality bar
