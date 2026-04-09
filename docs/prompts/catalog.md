# Prompt Catalog

This file is the single routing surface for prompt artifacts kept in `docs/prompts/`.

Its job is simple:

- make the approved prompt set explicit
- tell humans and AI which prompt to use for which kind of work
- keep prompt governance aligned with `scripts/repo-guard.mjs`

If a prompt file exists in `docs/prompts/`, it must be represented here.
If a prompt should not be part of the approved prompt system, it should not remain in `docs/prompts/`.

---

## How to Use This Catalog

Choose the prompt based on the type of work you are doing.

Do not pick prompts by title alone.
Pick them by intent:

- implementation
- review
- refactor
- module planning
- design challenge
- architecture challenge
- migration/change risk
- PR review
- pre-push self-review
- tenant/security review
- module audit

This file is a router, not a substitute for the prompts themselves.

---

## Core Prompt Set

These are the primary day-to-day prompts.

### 1. Implement

**File:** `docs/prompts/implement.md`

Use when:

- writing or extending code in an already-understood area
- applying a locked design into implementation
- making scoped feature or bug-fix changes

Do not use when:

- the design is still unresolved
- the main task is critique, challenge, or audit

### 2. Review

**File:** `docs/prompts/review.md`

Use when:

- reviewing existing implementation quality
- checking correctness against repo rules
- pressure-testing a completed or mostly completed change

Do not use when:

- the main task is to write the implementation from scratch

### 3. Refactor

**File:** `docs/prompts/refactor.md`

Use when:

- changing structure without changing intended behavior
- simplifying a stable implementation
- improving maintainability, boundaries, naming, or flow

Do not use when:

- the task is primarily product expansion or new feature design

### 4. Module Generation (Full-Stack)

**File:** `docs/prompts/module-generation-fullstack.md`

Use when:

- preparing a full-stack module plan across backend, frontend, docs, and proof
- converting a locked design into an execution-ready module plan
- generating a structured blueprint for a new bounded context

Do not use when:

- the module design itself is still not locked

---

## Specialized Prompt Set

These prompts are intentionally narrower.
Use them when the work needs a more opinionated challenge or audit lens than the core prompt set.

### 5. Better Architecture

**File:** `docs/prompts/better-architecture.md`

Use when:

- you already have a candidate approach and want a stronger architectural alternative
- you want to challenge whether the current design is the cleanest durable option
- you want a sharper system-design critique before committing to an implementation path

Best fit:

- shared patterns
- cross-cutting architectural choices
- monorepo structure decisions
- runtime boundary design

### 6. Design Challenge

**File:** `docs/prompts/design-challenge.md`

Use when:

- the design exists but needs structured adversarial challenge before implementation
- you want to uncover ambiguity, drift risk, missing constraints, or hidden coupling
- you want to stress-test a proposed product or engineering direction

Best fit:

- pre-implementation design pressure tests
- roadmap challenge sessions
- architecture and UX decision challenge work

### 7. Migration / Change Risk

**File:** `docs/prompts/migration-change-risk.md`

Use when:

- a change may affect schema, rollout safety, backward compatibility, or data integrity
- a change touches migration order, production risk, or change-management concerns
- you need explicit risk framing before merging or deploying

Best fit:

- database changes
- environment/runtime shifts
- contract changes
- rollout/rollback planning

### 8. Module Audit

**File:** `docs/prompts/module-audit.md`

Use when:

- auditing one module or bounded area for drift, gaps, or structural weakness
- checking whether a module still matches repo law, docs, and intended boundaries
- evaluating completeness after several rounds of implementation

Best fit:

- focused bounded-context audits
- architecture-vs-implementation alignment checks
- “is this module actually clean and complete?” reviews

### 9. PR Review

**File:** `docs/prompts/pr-review.md`

Use when:

- reviewing a concrete diff, branch, or pull request
- checking code, docs, tests, and risk in one review pass
- producing review feedback that maps directly to a merge candidate

Best fit:

- pull request review
- final pre-merge review
- diff-based correctness and standards review

### 10. Pre-Push Self-Review

**File:** `docs/prompts/pre-push-self-review.md`

Use when:

- the author wants to inspect their own change before pushing
- you want a disciplined self-check on docs, tests, drift, and obvious regressions
- you want to catch preventable issues before CI or PR review

Best fit:

- local author-side review
- pre-push validation
- small but important cleanup passes before publish

### 11. Security / Tenant Review

**File:** `docs/prompts/security-tenant-review.md`

Use when:

- a change affects tenant boundaries, sessions, cookies, SSR forwarding, auth, or access isolation
- the work touches same-origin discipline, topology, identity, or security-sensitive behavior
- you need a review lens specifically tuned for multi-tenant risk

Best fit:

- auth routes
- frontend proxy/SSR contract changes
- session/cookie logic
- tenant-isolation checks
- topology-sensitive changes

---

## Fast Decision Table

| Situation                                               | Use This Prompt                               |
| ------------------------------------------------------- | --------------------------------------------- |
| Implement a scoped change in a known area               | `docs/prompts/implement.md`                   |
| Review completed or mostly completed work               | `docs/prompts/review.md`                      |
| Restructure code without intended behavior change       | `docs/prompts/refactor.md`                    |
| Prepare a full-stack plan for a locked module           | `docs/prompts/module-generation-fullstack.md` |
| Challenge whether the architecture itself can be better | `docs/prompts/better-architecture.md`         |
| Stress-test a proposed design before implementation     | `docs/prompts/design-challenge.md`            |
| Evaluate schema / rollout / migration risk              | `docs/prompts/migration-change-risk.md`       |
| Audit one module for drift and completeness             | `docs/prompts/module-audit.md`                |
| Review a concrete PR or merge candidate                 | `docs/prompts/pr-review.md`                   |
| Do an author-side check before push                     | `docs/prompts/pre-push-self-review.md`        |
| Review tenant/security/topology-sensitive work          | `docs/prompts/security-tenant-review.md`      |

---

## Current Approved Prompt Inventory

The approved prompt files currently tracked by this catalog are:

- `docs/prompts/better-architecture.md`
- `docs/prompts/design-challenge.md`
- `docs/prompts/implement.md`
- `docs/prompts/migration-change-risk.md`
- `docs/prompts/module-audit.md`
- `docs/prompts/module-generation-fullstack.md`
- `docs/prompts/pre-push-self-review.md`
- `docs/prompts/pr-review.md`
- `docs/prompts/refactor.md`
- `docs/prompts/review.md`
- `docs/prompts/security-tenant-review.md`

If any of these files are removed, this catalog must be updated in the same change.
If any new prompt file is added under `docs/prompts/`, this catalog must be updated in the same change.

---

## Governance Rule

Prompt files are governed repo artifacts.
They are not scratch notes, not wiki pages, and not untracked personal helpers.

That means:

- prompt files must be intentional
- prompt files must be cataloged here
- prompt files should be reviewed with the same seriousness as code and stable docs
- stale prompt files should be removed, not silently ignored

This file exists so repo governance stays explicit and machine-checkable.
