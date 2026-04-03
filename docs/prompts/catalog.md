# Prompt Catalog

**Status:** Active  
**Scope:** Repo-level approved prompt index

This is the only prompt index/routing file for the repo.

Its job is simple:

- list the approved reusable prompt assets in `docs/prompts/`
- state what each one is for
- keep the approved prompt pack visible and small
- make prompt drift obvious

It is not:

- a usage essay
- a review contract
- a roadmap
- a backlog for future prompts

---

## Read First

Before using any prompt in this folder, read:

1. `AGENTS.md`
2. `docs/quality-bar.md`
3. `code_review.md`

Use this catalog after that, only to choose the right reusable prompt asset.

If you need detailed usage notes, use `docs/prompts/usage-guide.md` as secondary reference only.

---

## Catalog Rule

If a reusable repo prompt in `docs/prompts/` is meant to be approved and durable, it must appear in this file.

If it is not listed here, it is not part of the approved prompt pack.

No other file should act as a competing prompt index.

---

## Approved Prompt Pack

### Design and architecture prompts

#### `docs/prompts/design-challenge.md`

Use before implementation to pressure-test a proposed design.

#### `docs/prompts/better-architecture.md`

Use before implementation when you want to compare the current approach with cleaner or more durable alternatives.

---

### Review prompts

#### `docs/prompts/pre-push-self-review.md`

Use before push to catch obvious drift, missing docs, missing proof, and coupling mistakes.

#### `docs/prompts/pr-review.md`

Use when a diff or PR is ready for real review.

#### `docs/prompts/module-audit.md`

Use to inspect a module or feature boundary during implementation, refactor, or targeted review.

---

### Risk-focused prompts

#### `docs/prompts/migration-change-risk.md`

Use when a change affects schema, data shape, rollout, rollback, migration safety, or partial deploy risk.

#### `docs/prompts/security-tenant-review.md`

Use when a change affects auth, session, permissions, trust boundaries, topology, or tenant isolation.

---

### Structured generation prompt

#### `docs/prompts/module-generation-fullstack.md`

Use for structured full-stack generation work when the repo already has enough law and constraints to generate safely.

This is an approved prompt asset, but it is not a substitute for design review or PR review.

---

## What To Use When

### Before coding

Prefer one of:

- `design-challenge.md`
- `better-architecture.md`

### During implementation or refactor

Prefer:

- `module-audit.md`

### Before push

Prefer:

- `pre-push-self-review.md`

### During PR review

Prefer:

- `pr-review.md`

### For high-risk changes

Add one specialized prompt when needed:

- `migration-change-risk.md`
- `security-tenant-review.md`

### For structured generation work

Prefer:

- `module-generation-fullstack.md`

Do not stack many prompts for normal work.

Pick one primary prompt tied to the highest-risk concern.
Add one specialized prompt only when the change genuinely needs it.

---

## Prompt Pack Boundaries

This catalog governs the approved reusable prompt pack under `docs/prompts/`.

It does **not** automatically treat other prompt-like files elsewhere in the repo as part of the approved repo-level pack.

That means this file is stronger than:

- ad hoc prompt text in chats
- one-off prompt notes
- prompt-like docs outside `docs/prompts/` that are not listed here

If another prompt asset should become part of the approved repo-level pack, add it here explicitly.

---

## Maintenance Rules

Update this file when:

- an approved prompt file is added
- an approved prompt file is removed
- an approved prompt file is renamed
- an approved prompt changes role materially

Do not update this file for:

- one-off chat prompts
- ordinary implementation work
- non-approved draft prompts
- product changes that do not affect the approved prompt pack

---

## What This File Should Be

Keep this file:

- small
- explicit
- authoritative
- limited to indexing approved prompt assets

Do not let it become:

- a second usage guide
- a second review guide
- a prompt design manifesto
- a dumping ground for future prompt ideas

---

## Final Position

This file is the repo’s only prompt index/routing file.

Use it to choose from the approved prompt pack in `docs/prompts/`.
Use `docs/prompts/usage-guide.md` only as secondary reference when needed.
