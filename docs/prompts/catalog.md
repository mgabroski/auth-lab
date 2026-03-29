# Prompt Catalog

**Status:** Draft for lock
**Version:** 1.0
**Scope:** Repo-level catalog of reusable AI review and decision-support prompts
**Audience:** Engineers, reviewers, technical leads, architecture owners
**Owner:** Review / architecture owner
**Last Updated:** 2026-03-29

---

## 1. What This Document Is

This document is the entry point for the repo’s reusable AI prompts.

It tells you:

- which prompt files exist
- what each one is for
- when to use each one
- where to look for timing and usage rules

This file is the **index**, not the full usage guide and not the review contract.

---

## 2. Read These Together

Use this file together with:

- `AGENTS.md`
- `code_review.md`
- `docs/prompts/usage-guide.md`
- `backend/AGENTS.md` when backend work is involved
- `frontend/AGENTS.md` when frontend work is involved

---

## 3. Available Prompt Files

### `docs/prompts/design-challenge.md`

Use before coding to pressure-test a proposed design.

### `docs/prompts/better-architecture.md`

Use before coding when you want to compare the current approach with potentially cleaner or safer alternatives.

### `docs/prompts/pre-push-self-review.md`

Use before push to catch missing docs, missing tests, and obvious risks.

### `docs/prompts/pr-review.md`

Use when a diff or PR is stable enough for real review.

### `docs/prompts/module-audit.md`

Use during implementation or refactor to inspect a module/feature boundary in progress.

### `docs/prompts/migration-change-risk.md`

Use when a change affects schema, data shape, rollout, rollback, or partial deploy behavior.

### `docs/prompts/security-tenant-review.md`

Use when a change affects auth, session, topology, permissions, or tenant boundaries.

---

## 4. How To Choose The Right Prompt

Use `docs/prompts/usage-guide.md` for timing and selection rules.

Short version:

- before coding → design / architecture prompts
- during coding → module audit
- before push → pre-push self-review
- before or during PR → PR review
- before merge on high-risk changes → security or migration prompt

If more than one prompt seems applicable:

- choose one primary prompt tied to the highest-risk concern
- add one specialized prompt only if the change is materially high-risk
- do not stack many prompts for normal work

---

## 5. General Prompt Quality Rules

Every prompt in this catalog assumes:

- repo truth comes first
- AI output is not proof
- the real diff/files must be attached when review is concrete
- the reviewer must say what was actually validated
- docs that govern the area must be included when relevant

---

## 6. Final Position

This catalog exists so the repo has a durable set of reusable prompt artifacts instead of relying on scattered chat history.
