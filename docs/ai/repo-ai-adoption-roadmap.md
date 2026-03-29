# Repo AI Adoption Roadmap

**Status:** Draft for lock
**Version:** 1.0
**Scope:** Repo-level AI operating model, review system, prompt usage, and rollout plan
**Audience:** Engineering, architecture, review owners, and technical leads
**Owner:** Repo / platform owner
**Last Updated:** 2026-03-29

---

## 1. What This Document Is

This document is the **global repo-level roadmap and operating guide for AI adoption** in this repository.

It defines:

- why AI-related repo files are being introduced
- what those files are
- what each file owns
- rollout order
- what is in scope now
- what is intentionally deferred
- when the AI operating model itself must be updated

This document is **not**:

- a product roadmap
- a module implementation roadmap
- a feature delivery tracker
- the source of truth for Auth, Settings, CP, Personal, Email Templates, or any other product/domain surface

Those truths belong in their own product, architecture, QA, readiness, and module documents.

This file exists only to govern **how AI is used and structured at the repo level**.

---

## 2. Why This Document Exists

This repo already has strong engineering discipline:

- architecture and topology are explicitly documented
- proof and readiness matter
- product/design work is being locked before implementation drift
- documentation structure is being treated deliberately rather than casually

What is still missing is a fully formalized **repo-native AI operating model**.

Without that, AI usage usually drifts into weak patterns:

- generic prompts disconnected from repo truth
- inconsistent review quality across backend, frontend, and infra-sensitive work
- duplicated guidance across chats and docs
- AI suggestions that ignore architecture law
- false confidence from polished but ungrounded reviews
- weak coupling between code changes and documentation changes

This document exists to stop that drift before it becomes normal.

---

## 3. What This Document Is Used For

This document is used as the **control document** for adopting AI into the engineering workflow.

Its practical uses are:

### 3.1 Rollout Control

It defines the order in which AI-related repo files are introduced.

### 3.2 Scope Control

It clarifies what belongs in the AI operating model and what does not.

### 3.3 Ownership Control

It defines which repo file is responsible for which part of the AI/review system.

### 3.4 Change Control

It defines when the AI operating model must be updated and when it should be left alone.

### 3.5 Anti-Drift Control

It prevents repo-level AI guidance from turning into duplicate product truth, duplicate architecture truth, or random prompt sprawl.

---

## 4. What This Document Does Not Track

This document does **not** track:

- which product module is currently under implementation
- which delivery phase the product team is in
- what is already implemented in each module
- what feature ships next
- which product decisions are locked/open inside Auth, Settings, CP, or Email Templates

Those belong in their own source-of-truth documents.

This document may refer to those areas only when needed to explain **boundaries** or **why the AI operating model must stay global**.

---

## 5. Core Positioning

The repo should adopt AI the same way it adopts architecture, review discipline, and release readiness:

- deliberately
- explicitly
- with clear truth routing
- with clear ownership
- with small enforceable first steps

The goal is not to make the repo “AI-heavy.”
The goal is to make AI:

- grounded
- predictable
- reviewable
- useful
- hard to misuse

---

## 6. Adoption Principles

### 6.1 AI Must Follow Repo Truth

AI is a reader, reviewer, and assistant for the repo. It is not a competing authority.

### 6.2 Documentation Beats Memory

If repo documentation and conversational memory disagree, repo documentation wins.

### 6.3 Review Must Be Grounded

A strong-sounding answer without repo evidence is not a valid review.

### 6.4 Prompts Are Infrastructure

Stable prompts are repo assets, not disposable chat text.

### 6.5 Keep the First System Small

The first AI operating model should be small, understandable, and enforceable.

### 6.6 Separate Global Rules from Area Rules

The root repo needs global AI/review law. Backend and frontend need their own focused rules.

### 6.7 Proof Still Matters

AI may improve thinking and review quality, but tests, CI, topology proof, QA, and release evidence remain mandatory.

---

## 7. Truth Ladder For AI Work

When AI is used for planning, review, challenge, or audit work, it must follow this truth order:

1. active locked product/module source-of-truth documents
2. current foundation / shipped-scope truth docs
3. architecture and decision records
4. security model and topology law
5. contract and API docs
6. implementation code
7. tests and CI workflows
8. runbooks, QA docs, and developer guides
9. temporary prompts, chat summaries, and scratch notes

### 7.1 Required Behavior

If a lower-truth source conflicts with a higher-truth source, the conflict must be called out explicitly.

### 7.2 Required Behavior

If a code change affects a higher-truth artifact, the artifact must be updated in the same change or the missing update must be called out.

---

## 8. Current Starting Position

This roadmap starts from the following reality:

- the repo already has strong architecture/topology discipline
- the repo already values proof, QA readiness, and explicit closure
- product/design master-context documents are already being treated as real truth sources
- AI usage is still partly implicit and needs to become repo-governed
- the best first move is documentation and operating-model alignment, not advanced automation

That means the first adoption wave should focus on a **small set of durable repo files**, not on advanced AI tooling.

---

## 9. Target End State

When this roadmap is complete, the repo should have all of the following properties:

### 9.1 Repo-Aware AI Behavior

AI work is routed through repo-native files that define:

- what is truth
- which docs must be read first
- how changes are reviewed
- what validation is required
- what is still unproven

### 9.2 Durable Review System

The repo supports consistent AI-assisted review for:

- changed-files / PR review
- pre-push / pre-PR self-review
- whole-codebase audits
- design challenge reviews
- migration / rollback-risk reviews
- security / authz / tenant-isolation reviews
- observability / operability reviews
- performance / scale reviews
- failure-mode / misuse reviews

### 9.3 Clear Prompt Usage

Prompt usage is documented and operational, not tribal knowledge.

### 9.4 Lightweight Enforcement

The repo has a small but real enforcement layer so the AI operating model is not purely aspirational.

### 9.5 Deferred Complexity

Advanced AI integrations remain intentionally deferred until the core system is stable.

---

## 10. Rollout Phases

### Phase 1 — Foundation Documents

**Goal:** Establish the repo-native AI operating model in documentation before adding enforcement.

**Deliverables:**

1. `docs/ai/repo-ai-adoption-roadmap.md`
2. `AGENTS.md`
3. `backend/AGENTS.md`
4. `frontend/AGENTS.md`
5. `code_review.md`
6. `docs/prompts/usage-guide.md`

**Exit Criteria:**

- all six files exist or are updated
- each file has a clear, non-overlapping role
- root truth routing is explicit
- prompt usage is documented in repo form

### Phase 2 — Lightweight Enforcement

**Goal:** Add a minimal but real enforcement layer.

**Deliverables:**

1. `.github/workflows/repo-guard.yml`
2. doc-coupling rules confirmed in repo instructions
3. review flow aligned to the new repo files

**Exit Criteria:**

- repo guard runs in CI
- AI/review guidance is connected to actual checks
- the repo has at least one lightweight enforcement mechanism for the AI/review operating model

### Phase 3 — Working Usage Model

**Goal:** Make the system usable in daily engineering flow.

**Deliverables:**

1. prompt usage guidance finalized
2. review timing clarified
3. team usage expectations documented

**Exit Criteria:**

- engineers know which prompt/review mode to use when
- prompt usage is not ambiguous
- review outputs are standardized enough to be useful across the repo

### Phase 4 — Advanced Capability Evaluation

**Goal:** Evaluate higher-complexity AI infrastructure only after the core system is stable.

**Candidate Areas:**

- MCP
- Skills
- subagents
- PR templates
- CODEOWNERS expansion
- security automation additions
- deeper GitHub integration

**Exit Criteria:**

- deferred items are revisited intentionally
- no advanced feature is adopted without clear ROI
- each advanced addition has clear ownership and maintenance expectations

---

## 11. Files To Add Or Update

| Path                                  | Action | Purpose                                     | Phase |
| ------------------------------------- | ------ | ------------------------------------------- | ----- |
| `docs/ai/repo-ai-adoption-roadmap.md` | Add    | Master rollout/control document             | 1     |
| `AGENTS.md`                           | Update | Root repo AI/router law                     | 1     |
| `backend/AGENTS.md`                   | Add    | Backend-specific review and truth routing   | 1     |
| `frontend/AGENTS.md`                  | Add    | Frontend-specific review and topology rules | 1     |
| `code_review.md`                      | Add    | Repo-wide review contract                   | 1     |
| `docs/prompts/usage-guide.md`         | Add    | Prompt timing, usage, and context checklist | 1     |
| `.github/workflows/repo-guard.yml`    | Add    | Repo-wide lightweight enforcement           | 2     |

---

## 12. File Responsibilities

### 12.1 `docs/ai/repo-ai-adoption-roadmap.md`

Owns:

- rollout order
- scope boundaries for AI adoption
- what is in scope now vs deferred
- ownership model for AI/review repo artifacts
- when the AI operating model must be updated

Does not own:

- product truth
- module truth
- architecture truth
- implementation details for normal feature work

### 12.2 `AGENTS.md`

Owns:

- root truth ladder
- repo-wide routing rules
- repo-wide hard laws
- doc-coupling expectations
- validation routing
- topology-sensitive change escalation

Does not own:

- detailed backend law
- detailed frontend law
- full review output format

### 12.3 `backend/AGENTS.md`

Owns:

- backend boundary reminders
- transaction and flow placement reminders
- tenant/request-context reminders
- backend doc coupling reminders
- backend validation routing

Does not own:

- repo-wide truth ladder
- frontend rules
- full review contract

### 12.4 `frontend/AGENTS.md`

Owns:

- browser vs SSR boundary reminders
- same-origin and proxy rules
- frontend auth/bootstrap reminders
- frontend validation routing

Does not own:

- repo-wide truth ladder
- backend rules
- full review contract

### 12.5 `code_review.md`

Owns:

- review modes
- severity model
- evidence rules
- required review output
- doc-drift checking rules

Does not own:

- architecture source of truth
- implementation rules themselves
- CI configuration

### 12.6 `docs/prompts/usage-guide.md`

Owns:

- when to use each prompt/review mode
- who should use it
- required inputs
- expected outputs
- advisory vs merge/release relevance

Does not own:

- architecture rules
- detailed review law
- CI configuration

---

## 13. Prompt Usage Guide Scope

The earlier “When To Use Each Prompt” guidance must become a repo artifact rather than remaining chat-only guidance.

The dedicated file will be:

**`docs/prompts/usage-guide.md`**

That file must answer, for each prompt/review mode:

- when to use it
- when not to use it
- who should use it
- what minimum context must be attached
- what a good output looks like
- whether it is advisory or merge/release relevant
- what smallest validation commands should follow it

The usage guide must remain short, operational, and deterministic.

---

## 14. Ownership Model

### 14.1 Repo / Architecture Owner

Owns:

- root AI operating model
- truth ladder alignment
- final approval of repo-level AI files
- approval or deferral of advanced AI capabilities

### 14.2 Backend Owner(s)

Own:

- backend instructions accuracy
- backend validation routing
- backend review alignment

### 14.3 Frontend Owner(s)

Own:

- frontend instructions accuracy
- SSR/browser/topology rule alignment
- frontend review alignment

### 14.4 Review Owner(s)

Own:

- `code_review.md`
- prompt usage guide quality
- keeping review expectations specific and non-generic

### 14.5 CI / Platform Owner

Owns:

- repo guard workflow
- workflow maintainability
- ensuring checks remain realistic and useful

---

## 15. Section 15 Usage Checklist Direction

The old Section 15 content was guidance about **when to use each prompt**.

That content should not remain only in chat form. It must become a real repo artifact in a later step.

The preferred target file is:

**`docs/prompts/usage-guide.md`**

That checklist should include these columns:

- Prompt name
- Purpose
- Use before / during / after
- Who uses it
- Required inputs
- Optional inputs
- Expected output
- Merge blocker or advisory only
- Smallest validation commands to run after it
- When not to use it

This keeps prompt usage operational instead of informal.

---

## 16. Resolved Adoption Decision Matrix

This section closes the initial open questions for the first AI adoption wave.

It defines:

- what is decided now
- what is intentionally deferred
- what remains outside normal repo-document scope and needs organization-level confirmation

This section is a decision register, not a brainstorming appendix.

### 16.1 Resolve Now

The following decisions are locked for the first adoption wave:

1. Root `AGENTS.md` will exist and be the authoritative repo-level AI routing document.
2. Only two directory-level AGENTS files will be added in the first rollout:
   - `backend/AGENTS.md`
   - `frontend/AGENTS.md`

3. `code_review.md` will be added as the repo-wide review contract.
4. `.github/workflows/repo-guard.yml` will be added as the first lightweight repo-wide enforcement workflow.
5. `.codex/config.toml` will remain minimal for now.
6. Prompts must remain repo-grounded and documentation-coupled.
7. Local-first review workflow is the starting point for adoption.
8. The first rollout must stay small, explicit, and enforceable.

### 16.2 Defer Intentionally

The following items are intentionally deferred until the first adoption wave is stable:

- MCP
- Skills
- subagents
- CODEOWNERS
- PR template
- security automation extras
- branch-protection refinements if not yet ready

These items are not rejected. They are deferred by design so the repo can stabilize the core AI operating model before introducing additional complexity.

### 16.3 External / Organization-Level Decisions

The following items are outside the normal scope of this repo document and may require organization-level confirmation:

- exact required GitHub status checks
- branch protection policy
- reviewer assignment policy
- who owns final release signoff

These do not block the first adoption wave, but they should be clarified before later-stage governance or automation expansion.

### 16.4 Update Rule For This Section

Update this section only when:

- a deferred item is moved into active scope
- a resolved-now item is reversed or materially changed
- a new organization-level dependency becomes important enough to track here

Do not update this section for normal feature delivery, module work, or ordinary implementation changes.

---

## 17. When To Update This Document

Update `docs/ai/repo-ai-adoption-roadmap.md` only when the **AI operating model itself** changes.

### Update this document when:

- a new repo-level AI file is added
- rollout order changes
- ownership of AI/review artifacts changes
- a deferred AI capability moves into active scope
- the AI/review workflow changes materially
- the enforcement model changes materially

### Do not update this document when:

- a normal feature is implemented
- a module roadmap changes
- a product phase advances
- Auth, Settings, CP, Personal, or Email Templates get normal feature work
- a normal endpoint/page/refactor is added without changing the AI operating model

### Practical Rule

If the change affects **how AI is governed, routed, reviewed, or enforced in the repo**, update this file.

If the change affects only **product/domain/module implementation**, do not update this file.

---

## 18. Risks and Failure Modes

The most likely failure modes for this rollout are:

### 18.1 Over-Engineering Too Early

Adding too many advanced AI features before the foundation files are stable.

### 18.2 Duplicate Guidance

Allowing root instructions, area instructions, review contract, and usage guide to repeat each other.

### 18.3 Fake Closure

Declaring the repo AI-ready before the rules are actually used and tied to enforcement.

### 18.4 Drift Between Repo Law and Prompt Usage

Allowing prompt habits to evolve separately from repo files.

### 18.5 Generic Review Regression

Writing polished but non-specific AI/review files that stop reflecting the actual repo.

### 18.6 Wrong-Layer Contamination

Letting this roadmap become a product roadmap or module truth document.

The prevention strategy is:

- keep file roles strict
- keep the first rollout small
- tie guidance to validation
- treat prompt and review docs as real repo assets
- update this file only when the AI operating model changes

---

## 19. Done Criteria

This roadmap is considered complete only when all of the following are true:

- root and area-specific AI instruction files exist and are clear
- review contract exists and is usable
- prompt usage guide exists and removes timing ambiguity
- repo-wide lightweight enforcement exists in CI
- deferred complexity remains explicitly deferred unless intentionally approved
- the AI operating model is small, understandable, and enforceable
- no file duplicates another file’s role
- the system is grounded in repo truth rather than chat habit

---

## 20. Final Position

This document is the **global control document for repo-level AI adoption**.

It is intentionally separate from:

- product roadmaps
- module source-of-truth documents
- implementation plans
- business lock documents

Its role is narrower and more durable:

It defines how the repository adopts and governs AI-assisted engineering and review.

That is the only job this document should do.
