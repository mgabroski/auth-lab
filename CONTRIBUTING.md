# Contributing to Hubins Auth Lab

This file defines how to contribute safely to this repository.

It is not the human entrypoint.
Start with `README.md`, then use this file when you are preparing, implementing, validating, and submitting changes.

---

## Read Before Changing Code

Read these first:

1. `docs/current-foundation-status.md`
2. `ARCHITECTURE.md`
3. `docs/quality-bar.md`
4. `docs/decision-log.md`
5. `docs/security-model.md`

Then load the area law for the code you are changing.

Examples:

- backend work → `backend/AGENTS.md`, `backend/docs/engineering-rules.md`, `backend/docs/module-skeleton.md`
- frontend work → `frontend/AGENTS.md`, `frontend/src/shared/engineering-rules.md`, `frontend/docs/module-skeleton.md`
- review work → `code_review.md`
- local execution details → `docs/developer-guide.md`

Do not contribute from memory, partial context, or stale chat summaries.

---

## Contribution Standard

Every meaningful change must satisfy all of the following:

1. it respects repo law
2. it keeps code and docs coupled
3. it uses proof appropriate to the risk
4. it keeps scope honest
5. it reports validation truthfully

That means:

- no silent architecture drift
- no undocumented contract drift
- no auth/session/topology changes with weak proof
- no duplicate docs when a canonical doc already owns the truth
- no claiming runtime proof when only static review was done

---

## Hard Rules

### 1. Do not fight the architecture

Non-negotiable direction includes:

- browser requests stay same-origin through `/api/*`
- SSR and browser request paths stay distinct
- tenant identity stays host-derived
- backend session and membership truth stay authoritative
- tenant/session mismatch must fail closed
- proxy, cookie, SSO, MFA, auth bootstrap, and trust-boundary behavior are not casual refactor surfaces

If the change appears to require breaking one of these, stop and route it through the decision path instead of forcing code through.

### 2. Keep code and docs coupled

If you change behavior already described by a canonical doc, update that doc in the same change.

Common examples:

- endpoint or API behavior change → relevant `backend/docs/api/*.md`
- architecture or cross-cutting behavior change → `docs/decision-log.md` and relevant ADRs
- security or trust-boundary behavior change → `docs/security-model.md`
- shipped capability or repo-truth change → `docs/current-foundation-status.md`
- release, migration, or operational behavior change → relevant `docs/ops/*.md`
- contributor or review workflow change → `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, or `code_review.md`

### 3. Do not add parallel docs casually

Before creating a new doc, ask:

- does an existing canonical doc already own this truth?
- can the current doc be tightened instead?
- is the new file durable enough to justify existing at all?

Prefer fewer stronger docs.

### 4. Do not expand scope invisibly

A focused PR should stay focused.

Do not mix unrelated cleanup, architecture redesign, or document sprawl into a narrow task unless the task explicitly requires it.

### 5. Do not fake proof

State what you ran.
State what you did not run.
Do not blur together review, unit tests, integration proof, and real-stack proof.

---

## Risk-Based Expectations

### Low risk

Examples:

- wording-only doc fixes
- narrow text changes
- clearly behavior-neutral cleanup

Expected:

- relevant formatting/lint/type checks if needed
- no truth drift
- no exaggerated proof claims

### Medium risk

Examples:

- ordinary backend or frontend behavior changes
- non-sensitive API additions or adjustments
- module logic changes inside established boundaries

Expected:

- targeted tests for changed behavior
- doc updates where coupling exists
- honest summary of proof performed

### High risk

Examples:

- auth, session, cookies, SSO, MFA
- request context or tenant resolution
- proxy or topology behavior
- SSR bootstrap behavior
- trust boundaries and security-sensitive flows
- migrations or rollback-sensitive changes

Expected:

- stronger proof than unit tests alone
- integration, E2E, or topology proof when appropriate
- explicit doc updates
- decision-log or ADR review when the change is architectural or cross-cutting

---

## Required Doc Coupling

| If you change...                        | update in the same change...                                  |
| --------------------------------------- | ------------------------------------------------------------- |
| backend HTTP contract                   | relevant `backend/docs/api/*.md`                              |
| architecture or cross-cutting design    | `docs/decision-log.md` and relevant ADRs                      |
| security or trust-boundary behavior     | `docs/security-model.md` and relevant ADRs/docs               |
| shipped capability or foundation status | `docs/current-foundation-status.md`                           |
| operational or support behavior         | relevant files under `docs/ops/`                              |
| contributor or review workflow          | `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, `code_review.md` |
| QA-visible behavior or message truth    | relevant files under `docs/qa/`                               |

If unsure, assume coupling exists until proven otherwise.

---

## Safe Change Process

### 1. Classify the work

Decide whether the task is mainly:

- backend
- frontend
- topology / infra
- security / trust boundary
- release / ops
- docs / governance

Then load only the governing docs for that area.

### 2. Identify impacted truth before editing

Before implementation, identify:

- which contracts may change
- which docs may need updates
- which proof paths are required
- whether the change is routine or architectural

### 3. Make the smallest truthful change

Keep the change narrow.
Prefer explicitness over cleverness.
Preserve existing repo law unless the task explicitly routes through a decision change.

### 4. Validate at the right level

Use the lightest proof that is still honest for the risk.
Do not stop at unit tests for topology-sensitive or auth-sensitive work.

### 5. Make review easy

A good change makes it obvious:

- what changed
- why it changed
- which docs moved with it
- what proof was run
- what remains intentionally unverified

---

## Validation Workflow

### Normal local iteration

```bash
yarn dev
```

### Standard repo verification

```bash
yarn verify
```

### Full topology-sensitive verification

```bash
yarn stack
yarn stack:test
```

### Useful supporting commands

```bash
yarn test
yarn build:frontend
yarn status
yarn reset-db
yarn stop
```

Use the smallest command set that still proves the changed behavior honestly.

---

## Pull Request Expectations

A PR should make these things easy to verify:

- scope
- repo-law alignment
- doc coupling
- validation actually run
- residual risk or intentional follow-up

Do not hide important behavioral changes inside vague titles or vague summaries.

If a change introduces or materially expands a major module surface, include the required quality-gate handling defined by the repo quality bar.

---

## What Not To Do

- do not start from low-authority docs when higher-truth docs already answer the question
- do not invent behavior because the repo is inconvenient to read
- do not leave canonical docs stale after changing behavior
- do not add “helpful” duplicate docs that compete with existing authority
- do not present unrun validation as completed proof
- do not use a focused task as cover for unrelated redesign

---

## Final Position

Use `README.md` to enter the repo.
Use this file to contribute safely.
Use `AGENTS.md` if the contributor is an AI/review agent.
