# Prompt Catalog

## Purpose

This file is the single index for the active prompt system in the repository.

Use it to choose the right prompt asset for a task.
Do not treat it as architecture law, implementation law, API truth, or QA truth.

Prompts are execution infrastructure.
They must follow repo law.
They must not compete with canonical docs.

---

## Active Prompt System

The active prompt pack for this repository lives under:

- `docs/prompts/`

This is the only active prompt pack that should be treated as canonical prompt infrastructure.

If another prompt file exists elsewhere in the repo, it is secondary, transitional, or deprecated unless repo law explicitly says otherwise.

---

## Read Before Using Any Prompt

Before using a prompt for real work, load the relevant authority docs first.

### Minimum baseline

1. `AGENTS.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/security-model.md`

Then add the area-specific law needed for the task.

Prompts do not replace the repo’s truth order.
They operate inside it.

---

## Prompt Selection Rules

Choose prompts by work type, not by habit.

### Implementation work

Use the implementation-oriented prompt only after loading:

- the correct routers
- the relevant engineering rules
- the relevant backend API docs
- any module-specific highest-truth spec if the task is for that module

### Review or audit work

Use the review-oriented prompt only after loading:

- the relevant authority docs for the changed area
- `code_review.md`
- `docs/quality-bar.md` when readiness or signoff is the question

### Refactor work

Use the refactor-oriented prompt only when the task is explicitly about safe restructuring rather than new feature behavior.

### Module-generation work

Use the module-generation prompt only when the repo law and module shape are already clear enough to generate within the established architecture.

If the task reveals a missing repo-level architectural decision, stop and update repo law first.
Do not use prompts to paper over missing architecture.

---

## Canonical Prompt Assets

The exact active files under `docs/prompts/` may evolve, but this folder is where the canonical prompt system lives.

Typical prompt roles include:

- implementation
- review
- refactor
- module generation
- task-specific review aids where they still obey repo law

Every prompt in this folder must remain aligned with:

- `AGENTS.md`
- `ARCHITECTURE.md`
- `docs/security-model.md`
- backend and frontend engineering rules
- the current documentation-coupling rules of the repo

---

## Deprecation Rule For Other Prompt Docs

Prompt docs outside `docs/prompts/` must not remain parallel active prompt systems.

### Backend prompt docs

If prompt files still exist under locations such as:

- `backend/docs/prompts/`

then treat them as deprecated unless and until any unique permanent rules have been migrated into canonical law docs such as:

- `backend/AGENTS.md`
- `backend/docs/engineering-rules.md`
- root-level canonical prompt files under `docs/prompts/`

After migration, those backend-local prompt docs should be removed or archived from the active documentation surface.

### Important rule

Do not let multiple prompt packs drift independently.
One canonical prompt system is the goal.

---

## Prompt Maintenance Rules

### 1. Prompts must follow repo law

If repo law changes, the relevant prompts must be updated in the same change.
A prompt that encodes stale repo behavior is a bug.

### 2. Prompts are not truth sources

Prompts help execute work.
They do not outrank architecture docs, security docs, API contracts, or shipped-truth docs.

### 3. Prompts should stay small and operational

A prompt should tell the model how to work, not re-explain the whole product.
If a prompt starts duplicating architecture or module truth, move that material back to canonical docs.

### 4. Do not create per-module prompt packs casually

Complex modules may need stronger specs, build packets, or bug-triage maps.
They do not automatically need their own prompt ecosystems.

### 5. Prompt updates are reviewed like code

A prompt change that weakens repo discipline, truth order, review rigor, or architecture alignment is a real defect.

---

## When Not To Use Prompt Docs

Do not reach for prompts first when the real problem is one of these:

- missing architecture decision
- missing API contract
- missing module spec
- missing QA execution truth
- missing runbook or recovery guidance
- missing router or truth-order clarity

Fix the repo truth first.
Then use prompts to execute inside that truth.

---

## Documentation Coupling Rule

Update this catalog when:

- a prompt is added to or removed from the canonical prompt pack
- a prompt role changes materially
- a non-canonical prompt surface is deprecated or retired
- prompt routing rules change

If a prompt change also changes how implementation or review should behave, update the relevant router or engineering law docs in the same PR.

---

## Final Position

Use this file as the single prompt index.

- root docs define truth
- engineering rules define execution law
- API docs define contract
- QA and ops docs define proof and support surfaces
- prompts help apply those rules consistently

There should be one active prompt system, not several competing ones.
