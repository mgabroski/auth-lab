# Prompt Catalog

This file is the single routing surface for the approved prompt artifacts kept in `docs/prompts/`.

Its job is simple:

- make the approved prompt set explicit
- tell humans and AI which prompt to use for which kind of work
- keep prompt governance aligned with `scripts/repo-guard.mjs`

If an approved prompt file exists in `docs/prompts/`, it must be represented here.
If a file is support material rather than a prompt, call that out explicitly instead of pretending it is a prompt.

---

## How to use this catalog

Choose the prompt by intent, not by title alone.

Common intents in the current repo:

- architecture challenge
- design challenge
- migration or rollout risk
- module audit
- full-stack module planning
- pre-push self-review
- pull-request review
- tenant / security / topology review

For general repo review expectations, also read `code_review.md`.
For deeper guidance on how the prompt system is meant to be used, read `docs/prompts/usage-guide.md`.

---

## Approved prompt set

### 1. Better Architecture

**File:** `docs/prompts/better-architecture.md`

Use when:

- you already have a candidate approach and want a stronger architectural alternative
- you want to challenge whether the current design is the cleanest durable option
- the task cuts across shared boundaries, topology, or monorepo structure

### 2. Design Challenge

**File:** `docs/prompts/design-challenge.md`

Use when:

- the design exists but needs adversarial challenge before implementation
- you want to expose ambiguity, hidden coupling, or drift risk
- the main task is pressure-testing a proposal rather than coding it

### 3. Migration / Change Risk

**File:** `docs/prompts/migration-change-risk.md`

Use when:

- a change affects schema, rollout order, backward compatibility, or data integrity
- the task needs explicit rollback and deployment-risk framing
- you want a change-management review before merge or release

### 4. Module Audit

**File:** `docs/prompts/module-audit.md`

Use when:

- auditing one bounded area for drift, gaps, or structural weakness
- checking whether a module still matches repo law and intended boundaries
- evaluating completeness after several implementation rounds

### 5. Module Generation (Full-Stack)

**File:** `docs/prompts/module-generation-fullstack.md`

Use when:

- preparing a full-stack module plan across backend, frontend, docs, and proof
- converting a locked design into an execution-ready module plan
- generating a structured blueprint for a new bounded context

### 6. Pre-Push Self-Review

**File:** `docs/prompts/pre-push-self-review.md`

Use when:

- the author wants to inspect their own change before pushing
- you want a disciplined self-check on docs, tests, drift, and obvious regressions
- the task is a local author-side validation pass

### 7. PR Review

**File:** `docs/prompts/pr-review.md`

Use when:

- reviewing a concrete diff, branch, or pull request
- checking code, docs, tests, and risk in one pass
- producing feedback that maps directly to a merge candidate

### 8. Security / Tenant Review

**File:** `docs/prompts/security-tenant-review.md`

Use when:

- a change affects tenant boundaries, sessions, cookies, SSR forwarding, auth, or access isolation
- the work touches same-origin discipline, topology, identity, or security-sensitive behavior
- you need a review lens tuned for multi-tenant risk

---

## Fast decision table

| Situation                                               | Use this prompt                               |
| ------------------------------------------------------- | --------------------------------------------- |
| Challenge whether the architecture itself can be better | `docs/prompts/better-architecture.md`         |
| Stress-test a proposed design before implementation     | `docs/prompts/design-challenge.md`            |
| Evaluate schema / rollout / migration risk              | `docs/prompts/migration-change-risk.md`       |
| Audit one module for drift and completeness             | `docs/prompts/module-audit.md`                |
| Prepare a full-stack plan for a locked module           | `docs/prompts/module-generation-fullstack.md` |
| Do an author-side check before push                     | `docs/prompts/pre-push-self-review.md`        |
| Review a concrete PR or merge candidate                 | `docs/prompts/pr-review.md`                   |
| Review tenant/security/topology-sensitive work          | `docs/prompts/security-tenant-review.md`      |

---

## Support docs in this folder

These files live beside the prompts but are not themselves prompts:

- `docs/prompts/catalog.md` — this routing file
- `docs/prompts/usage-guide.md` — deeper prompt-system usage guidance

---

## Current approved prompt inventory

The approved prompt files currently tracked by this catalog are:

- `docs/prompts/better-architecture.md`
- `docs/prompts/design-challenge.md`
- `docs/prompts/migration-change-risk.md`
- `docs/prompts/module-audit.md`
- `docs/prompts/module-generation-fullstack.md`
- `docs/prompts/pre-push-self-review.md`
- `docs/prompts/pr-review.md`
- `docs/prompts/security-tenant-review.md`

If any of these files are removed, this catalog must be updated in the same change.
If any new prompt file is added under `docs/prompts/`, this catalog must be updated in the same change.
