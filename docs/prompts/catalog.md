# Prompt Catalog

**Status:** Locked
**Version:** 1.2
**Scope:** Repo-level catalog of approved reusable AI prompt artifacts
**Audience:** Engineers, reviewers, technical leads, and architecture owners
**Owner Role:** Lead Architect or Designated Quality Owner
**Last Updated:** 2026-03-29

---

## 1. What This Document Is

This document is the **authoritative catalog for the repo’s approved reusable prompt artifacts**.

It tells you:

- which prompt files are part of the approved prompt pack
- what each prompt is for
- when to use each prompt at a high level
- which files are core review/decision prompts versus adjacent build/generation prompts
- where to go for detailed timing and usage rules

This file is the **catalog and index**.
It is not the full usage guide.
It is not the review contract.
It is not a product roadmap.

---

## 2. Why This File Exists

Without a catalog, prompt systems usually decay into:

- duplicate prompts with overlapping jobs
- unofficial prompt files that silently look authoritative
- chat-history dependence instead of repo assets
- prompt sprawl that is hard to review or maintain
- review prompts that drift away from repo truth

This file exists to make the approved prompt set:

- visible
- stable
- reviewable
- enforceable
- hard to silently expand

---

## 3. Read These Together

Use this file together with:

- `docs/quality-bar.md`
- `AGENTS.md`
- `code_review.md`
- `docs/prompts/usage-guide.md`
- `backend/AGENTS.md` when backend work is involved
- `frontend/AGENTS.md` when frontend work is involved

These files work together as one operating system:

- `docs/quality-bar.md` defines what quality means
- `AGENTS.md` routes repo-aware work
- `code_review.md` defines how review is performed
- `docs/prompts/usage-guide.md` explains how to use the prompt pack well
- this file defines which prompt artifacts are officially in the pack

---

## 4. Approved Prompt Artifacts

These are the currently approved reusable prompt artifacts in this repo.

### Core review / decision prompts

#### `docs/prompts/design-challenge.md`

Use before coding to pressure-test a proposed design.

#### `docs/prompts/better-architecture.md`

Use before coding when you want to compare the current approach with potentially cleaner, safer, or more durable alternatives.

#### `docs/prompts/pre-push-self-review.md`

Use before push to catch missing docs, missing tests, coupling issues, and obvious risk.

#### `docs/prompts/pr-review.md`

Use when a diff or PR is stable enough for real review.

#### `docs/prompts/module-audit.md`

Use during implementation or refactor to inspect a module or feature boundary in progress.

#### `docs/prompts/migration-change-risk.md`

Use when a change affects schema, data shape, rollout, rollback, partial deploy behavior, or migration safety.

#### `docs/prompts/security-tenant-review.md`

Use when a change affects auth, session, topology, permissions, trust boundaries, or tenant isolation.

### Adjacent approved prompt artifacts

#### `docs/prompts/module-generation-fullstack.md`

This is an approved prompt artifact, but it is **not** one of the core review/decision prompts.

It exists for structured build/generation work and should be treated as a separate prompt type from the core review modes above.

---

## 5. Catalog Rules

### 5.1 Authoritative catalog rule

If a prompt artifact is intended to be an approved reusable repo prompt, it must appear in this catalog.

If it is not listed here, it is not part of the approved prompt pack.

### 5.2 No silent authoritative prompts

No new authoritative prompt artifact may appear in `docs/prompts/` without a matching catalog update.

### 5.3 Prompt files are repo assets

Approved prompt files are not disposable chat text.
They are repo assets and should be reviewed with the same seriousness as other governance artifacts.

### 5.4 Keep the pack small

Do not add new prompt files when an existing prompt can be improved or reused.

### 5.5 Do not use the catalog as a backlog

This file lists approved prompt artifacts that exist now.
It is not a place to brainstorm future prompts.

---

## 6. How To Choose The Right Prompt

Use `docs/prompts/usage-guide.md` for the full timing and selection rules.

Short version:

- before coding → design or architecture prompts
- during coding → module audit
- before push → pre-push self-review
- before or during PR → PR review
- before merge on high-risk changes → security or migration prompt
- for structured generation work → module generation prompt

If more than one prompt seems applicable:

- choose one primary prompt tied to the highest-risk concern
- add one specialized prompt only if the change is materially high-risk
- do not stack many prompts for normal work

---

## 7. Prompt Quality Rules

Every prompt in this catalog assumes:

- repo truth comes first
- the quality bar still applies
- AI output is not proof
- the real diff or files must be attached when review is concrete
- the reviewer should say what was actually validated
- governing docs should be included when relevant
- prompts do not override architecture, product, or security truth

---

## 8. When This File Must Change

Update this file when:

- a new approved prompt artifact is added
- an approved prompt artifact is removed
- an approved prompt artifact is renamed
- a prompt changes category materially, such as moving from adjacent build/generation into core review/decision use

Do not update this file for:

- ordinary product work
- one-off chat prompts that are not being adopted into the repo
- normal implementation changes that do not change the approved prompt set

---

## 9. Relationship To Enforcement

The repo’s minimum guard layer may verify catalog completeness for approved prompt artifacts.

That means:

- prompt files in the approved prompt area should not silently appear without being added here
- this file is part of the prompt-law enforcement surface
- changing the approved prompt set should be a visible repo change, not an accidental byproduct

This enforcement is meant to block drift, not to replace judgment.

---

## 10. Final Position

This catalog exists so the repo has a durable, reusable, reviewable prompt system instead of relying on scattered chat history or unofficial prompt sprawl.

It is the authoritative index of the approved prompt pack.
It is not the usage guide and not the review contract.
