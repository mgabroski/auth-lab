# Prompt Catalog

**Status:** Draft for lock
**Version:** 1.1
**Scope:** Repo-level catalog of reusable AI review and decision-support prompts
**Audience:** Engineers, reviewers, technical leads, and architecture owners
**Owner:** Review / architecture owner
**Last Updated:** 2026-03-29

---

## 1. What This Document Is

This document is the **entry point for the repo’s reusable prompt pack**.

It tells you:

- which prompt files exist
- what each one is for
- when to use each one at a high level
- where to look for detailed timing and usage rules

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

## 3. Prompt Files In This Pack

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

## 4. Related Prompt Files Outside This Review Pack

### `docs/prompts/module-generation-fullstack.md`

This file is a separate build/generation prompt, not one of the core review/decision prompts in this pack.

It belongs in the broader prompts area, but it is intentionally not treated as one of the main review-mode prompts listed above.

---

## 5. How To Choose The Right Prompt

Use `docs/prompts/usage-guide.md` for the detailed timing and selection rules.

Short version:

- before coding → design/architecture prompts
- during coding → module audit
- before push → pre-push self-review
- before or during PR → PR review
- before merge on high-risk changes → security or migration prompt
- before release or health checks → whole-repo / operability guidance from the usage guide

If more than one prompt seems applicable:

- choose one primary prompt tied to the highest-risk concern
- add one specialized prompt only if the change is materially high-risk
- do not stack many prompts for normal work

---

## 6. Prompt Quality Rules

Every prompt in this catalog assumes:

- repo truth comes first
- AI output is not proof
- the real diff/files must be attached when review is concrete
- the reviewer should say what was actually validated
- governing docs should be included when relevant

---

## 7. Final Position

This catalog exists so the repo has a durable, reusable prompt system instead of relying on scattered chat history.

It is the index for the prompt pack, not the usage guide and not the review contract.
