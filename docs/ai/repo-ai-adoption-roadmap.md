# Repo AI Adoption Roadmap

**Status:** Locked
**Version:** 1.2
**Scope:** Repo-level AI operating model, review system, prompt usage, and enforcement direction
**Audience:** Engineering, architecture, review owners, and technical leads
**Owner Role:** Lead Architect or Designated Quality Owner
**Last Updated:** 2026-03-29

---

## 1. What This Document Is

This document is the **global repo-level roadmap and operating guide for AI adoption** in this repository.

It defines:

- why AI-related repo files exist
- what those files are
- what each file owns
- how the AI/review system is structured
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
- the repo now has an explicit quality bar for what counts as done

What still needs to stay explicit is the **repo-native AI operating model**.

Without that, AI usage usually drifts into weak patterns:

- generic prompts disconnected from repo truth
- inconsistent review quality across backend, frontend, and infra-sensitive work
- duplicated guidance across chats and docs
- AI suggestions that ignore architecture law
- false confidence from polished but ungrounded reviews
- weak coupling between code changes and documentation changes
- prompt sprawl without clear entrypoints or ownership

This document exists to stop that drift before it becomes normal.

---

## 3. What This Document Is Used For

This document is the **control document** for adopting AI into the engineering workflow.

Its practical uses are:

### 3.1 Rollout Control

It defines the shape of the AI/review operating model and the order in which the core repo files are introduced or stabilized.

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

This document may refer to those areas only when needed to explain **boundaries**, **ownership**, or **why the AI operating model must stay global**.

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

### 6.5 Keep The First System Small

The first AI operating model should be small, understandable, and enforceable.

### 6.6 Separate Global Rules From Area Rules

The root repo needs global AI/review law. Backend and frontend need their own focused rules.

### 6.7 Proof Still Matters

AI may improve thinking and review quality, but tests, CI, topology proof, QA, and release evidence remain mandatory.

### 6.8 Quality Bar Comes Before Convenience

AI assistance must not weaken the repo quality bar or create fake closure around major-module work.

---

## 7. Truth Ladder For AI Work

When AI is used for planning, review, challenge, or audit work, it must follow this truth order:

1. active locked product/module source-of-truth documents
2. repo quality bar and current foundation / shipped-scope truth docs
3. architecture and decision records
4. security model and topology law
5. contract and API docs
6. implementation code
7. tests and CI workflows
8. runbooks, QA docs, and developer guides
9. temporary prompts, chat summaries, and scratch notes

### Required Behavior

- If a lower-truth source conflicts with a higher-truth source, the conflict must be called out explicitly.
- If a code change affects a higher-truth artifact, that artifact should be reviewed or updated in the same change.
- Passing tests alone do not override higher-truth documentation drift.

---

## 8. Current Starting Position

This operating model starts from the following reality:

- the repo already has strong architecture/topology discipline
- the repo already values proof, QA readiness, and explicit closure
- product/design master-context documents are already being treated as real truth sources
- the repo now has an explicit quality bar
- AI usage needs to be repo-governed instead of remaining partly implicit
- the best first move is durable documentation plus lean enforcement, not advanced tooling sprawl

That means the first adoption wave should focus on a **small set of durable repo files and minimum viable enforcement**, not on advanced AI integrations.

---

## 9. Target End State

When this operating model is healthy, the repo should have all of the following properties:

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

The repo has a real but minimal enforcement layer where it adds value, without duplicating protections already covered elsewhere.

### 9.5 Deferred Complexity

Advanced AI integrations remain intentionally deferred until the core system is stable and worth expanding.

---

## 10. Operating Rollout

### 10.1 Foundation Documents

These are the core repo-native AI/review files:

- `docs/quality-bar.md`
- `AGENTS.md`
- `backend/AGENTS.md`
- `frontend/AGENTS.md`
- `code_review.md`
- `docs/ai/repo-ai-adoption-roadmap.md`
- `docs/prompts/usage-guide.md`
- `docs/prompts/catalog.md`
- reusable prompt files under `docs/prompts/`

### 10.2 Minimum Enforcement Layer

The first enforcement layer should stay lean and repo-useful.

Its job is to reduce obvious drift in areas where AI/review behavior and repo law can silently decay.

The minimum layer includes:

- prompt catalog completeness checks for approved prompt artifacts
- linked update context for changes to protected law/governance files
- module-quality gate path presence for new major-module work
- lean coupling between changed route surfaces and required API-doc updates where practical

This is not meant to replace human review or branch protection.
It exists to block the most common silent-failure paths.

### 10.3 Usage Model

Prompt usage should be visible, reusable, and tied to actual workflow stages instead of scattered chat habits.

### 10.4 Advanced Expansion

Advanced GitHub-level automation, MCP, Skills, subagents, and similar additions remain later decisions, not day-one requirements.

---

## 11. Files In Scope

### Root / repo-wide files

- `docs/quality-bar.md`
- `AGENTS.md`
- `code_review.md`

### Area-specific files

- `backend/AGENTS.md`
- `frontend/AGENTS.md`

### AI operating documents

- `docs/ai/repo-ai-adoption-roadmap.md`
- `docs/prompts/usage-guide.md`
- `docs/prompts/catalog.md`

### Reusable prompt files

- `docs/prompts/design-challenge.md`
- `docs/prompts/pre-push-self-review.md`
- `docs/prompts/pr-review.md`
- `docs/prompts/module-audit.md`
- `docs/prompts/migration-change-risk.md`
- `docs/prompts/security-tenant-review.md`
- `docs/prompts/better-architecture.md`

### Minimum enforcement surfaces

- `.github/pull_request_template.md`
- `.github/CODEOWNERS`
- repo-guard workflow and supporting scripts where present

---

## 12. File Responsibilities

### 12.1 `docs/quality-bar.md`

Owns:

- the repo-wide definition of major-module done
- mandatory gates vs quality targets
- stage completion rules
- debt acceptance rules
- Track A signoff expectations

Does not own:

- architecture truth
- product truth
- module implementation details

### 12.2 `docs/ai/repo-ai-adoption-roadmap.md`

Owns:

- scope boundaries for AI adoption
- what is in scope now vs deferred
- ownership model for AI/review repo artifacts
- when the AI operating model must be updated
- how lightweight enforcement fits into the operating model

Does not own:

- product truth
- module truth
- architecture truth
- ordinary feature implementation planning

### 12.3 `AGENTS.md`

Owns:

- root truth ladder
- repo-wide routing rules
- repo-wide hard laws
- doc-coupling expectations
- validation routing
- topology-sensitive change escalation

### 12.4 `backend/AGENTS.md`

Owns:

- backend boundary reminders
- transaction and flow placement reminders
- tenant/request-context reminders
- backend doc coupling reminders
- backend validation routing

### 12.5 `frontend/AGENTS.md`

Owns:

- browser vs SSR boundary reminders
- same-origin and proxy rules
- frontend auth/bootstrap reminders
- frontend validation routing

### 12.6 `code_review.md`

Owns:

- review modes
- severity model
- evidence rules
- required review output
- doc-drift checking rules
- major-module review expectations against the quality bar

### 12.7 `docs/prompts/usage-guide.md`

Owns:

- when to use each prompt/review mode
- who should use it
- required inputs
- expected outputs
- advisory vs merge/release relevance

### 12.8 `docs/prompts/catalog.md`

Owns:

- the index of reusable prompt files
- entrypoint guidance into the prompt pack
- the authoritative catalog list for approved prompt artifacts

---

## 13. Prompt Usage Direction

The prompt system should remain:

- stage-based
- operational
- repo-aware
- easy to scan
- hard to misuse

The usage guide should answer:

- when to use each prompt
- when not to use it
- who should use it
- what minimum context must be attached
- what a good output looks like
- whether it is advisory or merge/release relevant
- what smallest validation should follow it

The catalog should point to actual prompt artifacts, not abstract prompt names.

Approved prompt artifacts should not silently appear outside the catalog.

---

## 14. Resolved And Deferred Decisions

### 14.1 Resolved now

The following decisions are locked for the current operating model:

1. Root `AGENTS.md` exists and is the authoritative repo-level AI routing document.
2. Only two area-specific AGENTS files are used: backend and frontend.
3. `code_review.md` exists as the repo-wide review contract.
4. `docs/quality-bar.md` exists and governs major-module completion expectations.
5. Prompts remain repo-grounded and documentation-coupled.
6. Local-first review workflow is the primary operating mode during the active development/rebuild phase.
7. The first system remains small, explicit, and enforceable.
8. A minimum repo guard layer is valid where it blocks real drift without heavy process overhead.

### 14.2 Deferred intentionally

The following remain deferred until there is a strong reason to add them:

- MCP
- Skills
- subagents
- advanced AI-specific GitHub automation
- extra security automation layers beyond the current minimum repo guard layer
- GitHub-level automatic PR reviewer setup
- broad AI evaluation systems beyond the current prompt/review operating model

### 14.3 External / organization-level decisions

The following are outside the normal scope of this repo document and may require later org-level confirmation:

- exact required GitHub status checks
- branch protection policy
- reviewer assignment policy
- who owns final release signoff
- the exact GitHub team or username bindings used in CODEOWNERS

---

## 15. Ownership Model

### 15.1 Lead Architect / Designated Quality Owner

Owns:

- root AI operating model
- truth ladder alignment
- approval of repo-level AI files
- quality-bar alignment for major-module review behavior
- approval or deferral of advanced AI capabilities

### 15.2 Backend Owner(s)

Own:

- backend instruction accuracy
- backend validation routing
- backend review alignment

### 15.3 Frontend Owner(s)

Own:

- frontend instruction accuracy
- SSR/browser/topology rule alignment
- frontend review alignment

### 15.4 Review Owner(s)

Own:

- `code_review.md`
- prompt usage guide quality
- prompt catalog coherence
- keeping review expectations specific and non-generic

### 15.5 CI / Platform Owner

Owns:

- repo guard workflow alignment where relevant
- keeping enforcement useful, realistic, and low-noise
- ensuring automation does not pretend to replace review judgment

---

## 16. When To Update This Document

Update `docs/ai/repo-ai-adoption-roadmap.md` only when the **AI operating model itself** changes.

### Update this document when:

- a new repo-level AI file is added
- ownership of AI/review artifacts changes
- a deferred AI capability moves into active scope
- the AI/review workflow changes materially
- the enforcement model changes materially
- the quality-bar relationship to AI/review operation changes materially

### Do not update this document when:

- a normal feature is implemented
- a module roadmap changes
- a product phase advances
- Auth, Settings, CP, Personal, or Email Templates get normal feature work
- a normal endpoint/page/refactor is added without changing the AI operating model

### Practical rule

If the change affects **how AI is governed, routed, reviewed, cataloged, or lightly enforced in the repo**, update this file.

If the change affects only **product/domain/module implementation**, do not update this file.

---

## 17. Risks And Failure Modes

The most likely failure modes for this operating model are:

- over-engineering too early
- duplicate guidance across root, area, review, and prompt docs
- fake closure without real adoption or validation
- drift between prompt habits and repo files
- generic review language replacing repo-specific review
- wrong-layer contamination, where governance docs start becoming product docs
- enforcement that is noisy enough to be ignored
- checklist theater replacing actual proof

The prevention strategy is:

- keep file roles strict
- keep the system small
- tie guidance to validation
- treat prompt and review docs as real repo assets
- keep enforcement lean and targeted
- update this file only when the operating model changes

---

## 18. Done Criteria

The AI/review operating model is in good shape when all of the following are true:

- root and area-specific instruction files exist and are clear
- review contract exists and is usable
- quality bar exists and is referenced by the AI/review system
- prompt usage guide exists and is operational
- prompt catalog exists and points to real prompt files
- reusable prompt files exist for the core review/decision modes
- minimum enforcement blocks common drift without creating heavyweight process noise
- deferred complexity remains explicitly deferred unless intentionally approved
- the system is grounded in repo truth rather than chat habit
- no file duplicates another file’s role without a reason

---

## 19. Final Position

This document is the **global control document for repo-level AI adoption**.

It is intentionally separate from:

- product roadmaps
- module source-of-truth documents
- implementation plans
- business lock documents

Its role is narrower and more durable:

It defines how the repository adopts and governs AI-assisted engineering and review.
