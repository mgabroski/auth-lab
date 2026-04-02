# Implementation Session Charter

This document defines how to run a focused implementation or review session against this repository.

It exists to keep sessions disciplined, repo-aware, and low-noise.

It is intentionally **not**:

- the main onboarding document
- a second architecture overview
- a replacement for `AGENTS.md`
- a replacement for `CONTRIBUTING.md`
- a substitute for the repo’s authoritative law docs

If you are new to the repository, read `docs/onboarding.md` first.

---

## Purpose

A good implementation session should begin with the right authority, stay inside scope, update coupled truth, and end with honest proof.

This charter exists to prevent five common failure modes:

- working from partial context
- drifting outside scope
- changing code without moving the governing docs
- treating prompts or summaries as stronger than repo law
- claiming completion without appropriate proof

Use this file when starting a new implementation, review, or refactor session with a human contributor or an LLM.

---

## What this document governs

This document governs the **session process**, not the architecture itself.

It tells you how to prepare a session, what context must be loaded, what the session should output, and when the session must stop and escalate.

Architecture law still lives elsewhere.

---

## Session truth hierarchy

Every implementation session must follow this order of authority.

### Highest authority

1. the actual repository code and current file contents
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `docs/security-model.md`

### Area-specific authority

Then load the governing docs for the area being changed.

Examples:

- backend work → `backend/docs/README.md`, `backend/docs/engineering-rules.md`, `backend/docs/module-skeleton.md`, relevant `backend/docs/api/*.md`
- frontend work → `frontend/README.md`, `frontend/src/shared/engineering-rules.md`, `frontend/docs/module-skeleton.md`
- release/ops work → relevant docs under `docs/ops/`
- governance/doc-system work → `docs/onboarding.md`, `README.md`, `CONTRIBUTING.md`, and any relevant repo-law docs

### Support material only

These can help guide execution, but they do not outrank the sources above:

- `AGENTS.md`
- `code_review.md`
- `docs/prompts/*.md`
- this file

If support material conflicts with a higher-authority source, the support material loses.

---

## Minimum preparation before any session starts

Before implementation begins, the session must identify:

- the exact task being solved
- the scope boundary
- the governing docs for the affected area
- the likely truth-coupled docs that may need updates
- the expected proof level

If those are unclear, the session should not pretend to be implementation-ready yet.

---

## Required session opening checklist

At the beginning of a substantial implementation or review session, explicitly establish:

- [ ] the concrete task
- [ ] what is in scope
- [ ] what is out of scope
- [ ] which docs are authoritative for this work
- [ ] which files are likely to change
- [ ] which truth-coupled docs may need updates
- [ ] what proof is expected before calling the work done

The goal is not ceremony.
The goal is to stop silent assumption drift before code starts moving.

---

## What a good session should produce before coding

Before editing code, a serious session should usually be able to state:

### 1. The problem in one paragraph

What is broken, missing, or being changed?
Why does it matter?

### 2. The governing law

Which docs and architectural rules control this work?

### 3. The intended change boundary

What will change?
What will deliberately not change?

### 4. The likely coupling impact

What contracts, docs, runbooks, or decision records may need to move with the change?

### 5. The proof plan

What tests, checks, or stack-level validation are needed?

If a session cannot state these, it is usually still in discovery, not implementation.

---

## Session behavior rules

### 1. Work from the repo, not from memory

Do not rely on prior conversation memory when the repo or docs can answer the question directly.

### 2. Preserve repo law unless the task explicitly changes it

Do not quietly redesign architecture, trust boundaries, or contributor law during routine implementation.

### 3. Keep scope tight

A small task should remain a small task.
Do not smuggle redesign, doc sprawl, or cleanup campaigns into a focused change.

### 4. Move code and truth together

If code changes affect an authoritative doc, update that doc in the same unit of work.

### 5. Stay honest about uncertainty

If proof is incomplete, say so.
If the repo state is unclear, say so.
If a limit is external to the repo, say so.

---

## Required doc/code coupling during a session

Every session should actively check whether the implementation affects one or more of these:

| Change type                                 | Likely required companion update                                            |
| ------------------------------------------- | --------------------------------------------------------------------------- |
| backend contract change                     | relevant `backend/docs/api/*.md`                                            |
| auth/session/security/trust-boundary change | `docs/security-model.md`, `docs/decision-log.md`, and possibly backend ADRs |
| shipped-scope change                        | `docs/current-foundation-status.md`                                         |
| onboarding or contributor-path change       | `docs/onboarding.md`, `README.md`, `CONTRIBUTING.md`                        |
| runbook-worthy operational change           | relevant `docs/ops/*.md`                                                    |
| repo-law or governance change               | the governing repo-law docs plus any linked contributor docs                |

The session must not finish by updating only code while leaving the truth chain stale.

---

## Output expectations for an implementation session

A good implementation session should usually end with these outputs:

### 1. Change summary

What changed, in concrete repo terms?

### 2. File list

Which files were added or modified?

### 3. Coupled-doc summary

Which authoritative docs moved with the change, and why?

### 4. Proof summary

What was actually run, checked, or reviewed?

### 5. Remaining gaps

What was intentionally not covered or could not be verified yet?

These outputs make the session auditable and reduce handoff confusion.

---

## Special rule for architecture-sensitive sessions

For work touching any of the following:

- topology
- proxy behavior
- SSR bootstrap
- request context
- tenant resolution
- sessions or cookies
- SSO, MFA, or auth continuation
- trust boundaries
- security-sensitive flows

the session must use stronger discipline.

That means:

- explicitly reloading the governing security and architecture docs
- checking decision-log / ADR impact early
- avoiding casual “small refactor” framing
- using stronger proof expectations than unit tests alone when appropriate

These surfaces are load-bearing.
Treat them that way.

---

## Special rule for LLM-assisted sessions

When an LLM is used, the session must remain repo-law-first.

That means:

- prompts do not replace source-of-truth docs
- generated plans must stay inside the requested scope
- generated content must still be validated against repo files
- generated confidence does not count as proof
- the contributor remains responsible for correctness and coupling

If an LLM proposes something that conflicts with the repo law docs, follow the repo law docs.

---

## When a session must stop and escalate

Stop normal implementation flow and escalate when:

- the task appears to require breaking an existing architecture law
- two authoritative docs conflict materially
- the real repo state differs from the task assumptions in a load-bearing way
- the change crosses from routine implementation into architectural decision-making
- the change needs a decision-log entry or ADR before safe implementation can continue
- the proof required for safe completion is not currently available

Do not hide these situations inside a “best effort” implementation.

---

## What this charter must not become

Do not let this file become:

- a duplicate onboarding guide
- a duplicate contribution guide
- a second architecture overview
- a prompt catalog
- a bloated generic process document

Its job is narrow:

**make individual implementation sessions cleaner, safer, and more truthful.**

---

## Maintenance rule

Update this charter when the repository changes how implementation sessions are supposed to work, including:

- the authority chain used during sessions
- required session opening expectations
- expected session outputs
- escalation rules
- doc/code coupling expectations at session level

Do not update this file for routine feature growth.
Update it only when the **session operating model** changes.

---

## Final rule

A strong session is not the one that changes the most.
A strong session is the one that loads the right truth, stays within scope, updates the right files, and reports honestly what was verified.
