# Prompt Usage Guide

**Status:** Draft for lock
**Version:** 1.2
**Scope:** Repo-level guidance for when and how to use AI review and decision-support prompts
**Audience:** Engineers, reviewers, technical leads, and architecture owners
**Owner:** Review / architecture owner
**Last Updated:** 2026-03-29

---

## 1. What This Document Is

This document defines **when to use each AI prompt or review mode** in this repository.

It exists to turn prompt usage into an operational workflow instead of informal chat habit.

This document answers:

- which prompt to use
- when to use it
- who should use it
- what context must be attached
- what kind of output to expect
- whether the result is advisory or merge/release-relevant
- what smallest validation should follow it

---

## 2. What This Document Is Not

This document is **not**:

- the root repo law for AI routing
- the full review contract
- the architecture source of truth
- the place to store full prompt bodies
- a substitute for tests, CI, QA, or runtime proof

Those concerns belong in other repo files.

This file is only the **usage guide** for prompt timing and prompt selection.

---

## 3. How To Use This Guide

Use this guide in four steps:

1. Identify the current stage of work.
2. Choose the prompt that matches the main risk.
3. Attach the minimum required context.
4. Run the smallest validation that actually proves the changed area.

If more than one prompt seems applicable:

- choose **one primary prompt** tied to the highest-risk decision
- add **one specialized prompt** only if the change is materially high-risk
- do not stack many prompts for normal work

---

## 4. General Rules

### 4.1 Repo Truth First

A prompt is only as good as the repo context attached to it.

### 4.2 Review Output Is Not Proof

A strong answer does not replace tests, CI, topology validation, QA, or production-readiness proof.

### 4.3 Smallest Effective Prompt

Do not use a whole-codebase audit when a pre-push review is enough.

### 4.4 Escalate For Risk

If a change affects auth, topology, sessions, tenant boundaries, migrations, or release behavior, use the more specialized review prompt.

### 4.5 Prompt Use Should Be Visible

For meaningful review work, the author or reviewer should be able to say which prompt/review mode was used and what inputs were attached.

---

## 5. Required Context By Area

When choosing a prompt, attach the area-specific repo context that governs the work.

### Backend work

Attach the relevant backend files and, when they exist:

- `backend/AGENTS.md`
- backend API docs
- backend engineering rules
- backend tests for the affected area

### Frontend work

Attach the relevant frontend files and, when they exist:

- `frontend/AGENTS.md`
- relevant backend contract/API docs
- auth/bootstrap/topology-related docs when the change touches those areas
- frontend tests for the affected area

### Review / audit / risk work

Attach, when they exist:

- `AGENTS.md`
- `code_review.md`
- the relevant backend/frontend AGENTS file
- the relevant source-of-truth docs for the affected area

### High-risk changes

Also attach, when relevant:

- tests already run
- rollout plan
- screenshots
- logs
- migration notes
- topology-sensitive behavior notes

---

## 6. Prompt Usage Checklist

Use the prompt that matches the **current stage of work**.

---

### 6.1 Before Coding

#### Design challenge

**Use when:** you want to pressure-test a proposed design before implementation starts.
**Primary file:** `docs/prompts/design-challenge.md`

**Best for:** engineer, tech lead, architect.

**Attach:**

- proposed approach
- affected docs
- affected files or areas
- constraints

**Expect:**

- tradeoff critique
- boundary risks
- recommendation on whether the approach is sound

**Do not use when:**

- the change is routine and low-risk
- you already know the design is fixed and only need implementation review

---

#### Better architecture

**Use when:** you want to know whether there is a cleaner, safer, or more durable architectural direction.
**Primary file:** `docs/prompts/better-architecture.md`

**Best for:** engineer, tech lead, architect.

**Attach:**

- current approach
- goal
- constraints
- affected areas

**Optional:**

- alternative idea you are considering
- migration concerns

**Expect:**

- keep / adapt / replace recommendation
- explanation of tradeoffs

**Do not use when:**

- the task is purely mechanical
- there is no real design choice to make

---

### 6.2 During Coding

#### Module audit

**Use when:** implementation is in progress and you want a quality check before the work is finished.
**Primary file:** `docs/prompts/module-audit.md`

**Best for:** engineer, reviewer.

**Attach:**

- working files
- current docs
- known uncertainties

**Optional:**

- tests already written
- intended next changes

**Expect:**

- ownership review
- missing proof
- missing docs
- coupling concerns

**Do not use when:**

- you need a whole-repo review
- you need final PR-level judgment on a finished diff

---

#### Failure-mode / admin misuse review

**Use when:** the feature has meaningful workflow, retry, replay, state, or admin-misuse risk.
**Primary mode:** guided by this usage guide and `code_review.md`

**Best for:** engineer, reviewer, lead.

**Attach:**

- flow summary
- affected files
- tests
- state transitions

**Optional:**

- screenshots
- sequence notes
- known edge cases

**Expect:**

- state-gap analysis
- misuse paths
- retry/idempotency concerns

**Do not use when:**

- there is no meaningful workflow or state risk
- the change is simple and non-behavioral

---

### 6.3 Before Push

#### Pre-push self-review

**Use when:** you want to catch obvious issues before the branch leaves your machine.
**Primary file:** `docs/prompts/pre-push-self-review.md`

**Best for:** author.

**Attach:**

- changed files
- summary of intent
- commands already run

**Optional:**

- screenshots
- logs
- known unresolved items

**Expect:**

- exact gaps to close before push
- missing docs/tests
- obvious boundary mistakes

**Do not use when:**

- you are trying to replace PR review
- you have not gathered the changed files yet

**Validation after use:**

- run the smallest checks that prove the changed area

---

### 6.4 Before Opening A PR

#### Changed-files / PR review

**Use when:** the diff is stable enough to be reviewed as a real merge candidate.
**Primary file:** `docs/prompts/pr-review.md`

**Best for:** reviewer, author, lead.

**Attach:**

- diff or changed file list
- change summary
- relevant docs

**Optional:**

- test results
- screenshots
- rollout notes

**Expect:**

- severity-ranked findings
- merge recommendation
- doc drift callouts

**Do not use when:**

- the diff is incomplete or unstable
- you cannot provide the actual changed files

**Validation after use:**

- run the smallest checks that prove the reviewed area

---

### 6.5 Before Merge

#### Security / authz / tenant-isolation review

**Use when:** the change affects auth, sessions, topology, permissions, or tenant boundaries.
**Primary file:** `docs/prompts/security-tenant-review.md`

**Best for:** reviewer, security-minded engineer, lead.

**Attach:**

- final diff
- security-sensitive files
- tests already run

**Optional:**

- threat assumptions
- incident history

**Expect:**

- blocker-level security findings
- isolation risks
- unsafe defaults or escalation paths

**Do not use when:**

- the change is purely cosmetic
- there is no meaningful security or boundary impact

**Validation after use:**

- run security-sensitive area checks
- run topology proof when relevant

---

#### Migration / change-risk review

**Use when:** the change affects schema, data shape, rollout, rollback, or partial deployment behavior.
**Primary file:** `docs/prompts/migration-change-risk.md`

**Best for:** reviewer, backend owner, lead.

**Attach:**

- migration files
- schema/data changes
- rollout plan
- tests already run

**Optional:**

- rollback notes
- sample data assumptions

**Expect:**

- failure modes
- rollback risk
- data integrity concerns

**Do not use when:**

- there is no data, schema, or rollout risk

**Validation after use:**

- run migration-related tests
- run affected backend checks

---

#### Performance / scalability review

**Use when:** the change touches hot paths, repeated queries, scaling assumptions, or performance-sensitive behavior.
**Primary mode:** guided by this usage guide and `code_review.md`

**Best for:** engineer, reviewer, lead.

**Attach:**

- affected hot-path code
- data access patterns
- scale assumptions

**Optional:**

- metrics
- profiler notes
- prior incidents

**Expect:**

- likely bottlenecks
- acceptable-now vs risky-later guidance
- recommended next hardening steps

**Do not use when:**

- the change is trivial
- the change is docs-only or UI-copy-only

**Validation after use:**

- run affected area checks
- run any targeted performance validation available

---

### 6.6 Before Release

#### Whole-codebase weak-spot audit

**Use when:** you want a broad review of repo weaknesses before release or during periodic health checks.
**Primary mode:** guided by this usage guide and `code_review.md`

**Best for:** lead, architect, senior reviewer.

**Attach:**

- repo truth docs
- relevant codebase areas
- current risk focus

**Optional:**

- CI state
- recent incident history

**Expect:**

- strengths
- top risks
- drift
- recommended next actions

**Do not use when:**

- you only need single-file or PR review

---

#### Observability / operability review

**Use when:** you want to judge diagnosability, runbook readiness, and operational supportability.
**Primary mode:** guided by this usage guide and `code_review.md`

**Best for:** lead, platform owner, reviewer.

**Attach:**

- docs/runbooks
- relevant flows
- logging/diagnostic surfaces
- release scope

**Optional:**

- incident examples
- monitoring gaps

**Expect:**

- operational blind spots
- missing runbooks
- supportability gaps

**Do not use when:**

- the change has no operational impact

**Validation after use:**

- run area checks
- run stack/proxy/topology proof where relevant

---

### 6.7 During Refactors

#### Module audit

**Use when:** refactoring a module and you want to catch hidden coupling, ownership drift, or missing doc/test updates.
**Primary file:** `docs/prompts/module-audit.md`

**Best for:** engineer, reviewer.

**Attach:**

- old/new boundary shape
- affected files
- current docs
- known risk areas

**Optional:**

- tests already written
- design notes

**Expect:**

- hidden coupling findings
- ownership drift callouts
- missing doc/test follow-up

**Do not use when:**

- the change is still too early to explain clearly
- you need final merge judgment on the complete diff

---

#### Performance / scalability review

**Use when:** a refactor could affect hot paths, repeated work, query behavior, or scaling assumptions.
**Primary mode:** guided by this usage guide and `code_review.md`

**Best for:** engineer, reviewer, lead.

**Attach:**

- affected performance-sensitive areas
- old/new approach summary
- scale assumptions

**Optional:**

- metrics
- profiler notes
- prior incidents

**Expect:**

- performance regression risk
- hidden cost callouts
- recommended follow-up validation

**Do not use when:**

- the refactor is trivial and has no meaningful performance implications

---

### 6.8 Quick Selection Guide

Use this shortcut when you are unsure:

- **I am choosing a design** → `design-challenge.md`
- **I think there may be a cleaner architecture** → `better-architecture.md`
- **I am halfway through implementation** → `module-audit.md`
- **I am about to push** → `pre-push-self-review.md`
- **I am about to open or review a PR** → `pr-review.md`
- **The change touches security or tenant boundaries** → `security-tenant-review.md`
- **The change touches DB, schema, rollout, or rollback** → `migration-change-risk.md`
- **The change may create replay/retry/state issues** → failure-mode / misuse review mode
- **The change may affect performance or scale** → performance / scalability review mode
- **I want a broad release-level review** → whole-codebase weak-spot audit mode
- **I want to check supportability and diagnosis readiness** → observability / operability review mode

---

## 7. Validation Principle

After a prompt is used, run the **smallest validation that actually proves the affected area**.

Examples:

- backend-only change → backend typecheck/tests
- frontend-only change → frontend typecheck/unit tests
- topology-sensitive change → stack/proxy/topology proof where relevant
- migration-risk change → migration-related tests and affected backend checks

Do not hide behind prompt output when validation should be run.

---

## 8. Bad Usage Patterns

Do not use prompts as a substitute for:

- reading the actual diff
- reading the governing docs
- running required validation
- performing human judgment on product tradeoffs
- confirming runtime behavior

Bad prompt usage usually looks like:

- vague request
- no diff
- no files
- no docs
- expecting a precise answer anyway

Also do not escalate into heavyweight prompts when the change is tiny and low-risk.

---

## 9. How To Interpret Outputs

### 9.1 Advisory Output

Advisory output helps the author think better, but does not directly block merge.

### 9.2 Merge-Relevant Output

Merge-relevant output should be taken seriously during review and may require fixes or proof.

### 9.3 Release-Relevant Output

Release-relevant output affects readiness, supportability, or rollback confidence.

### 9.4 Blocker-Level Output

Security, tenant-isolation, migration, or operational findings may be blocker-level when the risk is serious and unproven.

---

## 10. How This Document Should Evolve

Update this file when:

- a new stable review mode is added
- prompt timing guidance changes materially
- the repo’s review workflow changes materially
- the meaning of advisory vs merge/release relevance changes materially

Do not update this file for:

- temporary prompt experiments
- one-off chat usage
- ordinary feature delivery
- ordinary module implementation changes

---

## 11. Final Position

This document exists to make prompt usage:

- visible
- consistent
- operational
- reviewable

It is not meant to make the repo prompt-heavy.

It is meant to make prompt usage disciplined enough to support real engineering work.
