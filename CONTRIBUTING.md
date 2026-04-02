# Contributing to Hubins Auth-Lab

This file explains how to contribute safely to this repository.

It is intentionally **not** the main onboarding document.
If you are new to the repo, read `docs/onboarding.md` first.

Use this file after onboarding when you are actively preparing, implementing, validating, and submitting changes.

---

## Before you start

Do not begin from assumptions.

Read in this order:

1. `docs/onboarding.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. the area-specific law docs for the code you are changing

Examples:

- backend work → `backend/docs/README.md`, `backend/docs/engineering-rules.md`, `backend/docs/module-skeleton.md`
- frontend work → `frontend/README.md`, `frontend/src/shared/engineering-rules.md`, `frontend/docs/module-skeleton.md`
- topology/auth/session/trust-boundary work → also read `docs/security-model.md`, `docs/decision-log.md`, and relevant ops docs

This repository expects contributors to work from the governing docs first, not from memory and not from partial local context.

---

## What this repo expects from every change

Every meaningful change must satisfy five things:

1. it respects repo law
2. it updates truth-coupled docs in the same change
3. it includes proof appropriate to its risk
4. it does not silently expand scope
5. it is honest about what was actually verified

That means:

- no undocumented architecture drift
- no API behavior change without contract updates
- no auth/session/topology changes without higher scrutiny
- no claiming runtime proof when only static review was done
- no duplicate documentation when an existing authoritative doc already owns the truth

---

## Core contribution rules

### 1. Do not fight the architecture

This repo has locked architectural laws.
Do not work around them locally.

Examples of non-negotiable direction:

- browser traffic stays same-origin through `/api/*`
- SSR and browser fetch paths are different and must stay different
- tenant identity is host-derived
- backend session and membership truth are authoritative
- tenant/session mismatch must fail closed
- topology, auth bootstrap, and trust-boundary behavior are not casual refactor surfaces

If your change appears to require breaking one of these, stop and route the work through the decision path instead of forcing the code.

### 2. Do not create silent documentation drift

If you change behavior that is already documented in an authoritative file, update that file in the same PR.

Common coupling examples:

- new or changed endpoint → relevant `backend/docs/api/*.md`
- auth/bootstrap/trust-boundary/security behavior change → `docs/security-model.md`, `docs/decision-log.md`, and possibly backend ADRs
- new or changed shipped capability → `docs/current-foundation-status.md`
- release/migration/incident expectations change → `docs/ops/release-engineering.md` or other relevant ops docs
- onboarding or reading-order change → `docs/onboarding.md`, `README.md`, or this file if applicable

### 3. Do not add duplicate docs

Before creating a document, ask:

- does an existing authoritative doc already own this truth?
- can the current doc be tightened instead of adding a new file?
- is this stable repo law, growing contract/runbook content, or optional local explanation?

Prefer strengthening the canonical doc over adding a parallel one.

### 4. Do not expand scope invisibly

A small fix must stay a small fix.
A focused PR should not quietly reorganize unrelated systems, docs, or architecture.

If a larger change is genuinely needed, state that explicitly and prove why.

### 5. Do not fake proof

Say what you ran.
Say what you did not run.
Do not collapse “reviewed,” “unit-tested,” and “real-stack verified” into one claim.

---

## Risk-based contribution expectations

Not every change needs the same level of proof.
But every change needs an honest level of proof.

### Low-risk changes

Examples:

- wording-only docs fixes
- narrow UI text corrections
- internal cleanup with no behavior change

Expected:

- relevant lint/format/type checks as needed
- doc truth maintained
- no false claims about runtime proof

### Medium-risk changes

Examples:

- normal backend or frontend behavior changes
- non-sensitive API additions or updates
- module logic changes within already-established boundaries

Expected:

- targeted tests for changed behavior
- contract/doc updates where applicable
- honest summary of what paths were verified

### High-risk changes

Examples:

- auth, session, cookies, SSO, MFA
- request context or tenant resolution
- proxy/topology behavior
- SSR bootstrap behavior
- trust boundaries, secrets, security-sensitive flows
- migrations or rollback-sensitive data-shape changes

Expected:

- stronger proof than unit tests alone
- relevant integration/E2E/topology proof where appropriate
- explicit doc coupling updates
- decision-log / ADR review when the change is architectural or cross-cutting

---

## Required doc/code coupling

Use this as the default rule.

| If you change...                               | update in the same PR...                                |
| ---------------------------------------------- | ------------------------------------------------------- |
| backend HTTP contract                          | relevant `backend/docs/api/*.md`                        |
| architecture or cross-cutting design direction | `docs/decision-log.md` and/or backend ADRs              |
| security or trust-boundary behavior            | `docs/security-model.md` and related ADRs/docs          |
| shipped capability or foundation status        | `docs/current-foundation-status.md`                     |
| onboarding path or contributor reading order   | `docs/onboarding.md`, `README.md`, or `CONTRIBUTING.md` |
| runbook-worthy operational behavior            | relevant file under `docs/ops/`                         |
| major module delivery expectations             | PR Module Quality Gate and any linked repo-law docs     |

If you are unsure whether a doc update is needed, assume coupling exists until proven otherwise.

---

## How to approach a change safely

### 1. Classify the work

Decide whether the work is:

- backend
- frontend
- topology / infra
- security / trust-boundary
- release / ops
- documentation / governance

Then load only the governing docs for that area.

### 2. Identify impacted truth before editing code

Before implementation, identify:

- which contracts may change
- which docs may need updates
- which tests or proof paths are required
- whether the change is architectural or routine

### 3. Make the smallest truthful change

Keep the change narrow.
Prefer explicitness over cleverness.
Preserve existing laws unless the change is intentionally routed as an architectural decision.

### 4. Validate at the right level

Use the lightest proof that is still honest for the risk involved.
Do not stop at unit tests for topology- or auth-sensitive work.

### 5. Write the PR so reviewers can reason about it quickly

A good PR makes it obvious:

- what changed
- why it changed
- which docs moved with it
- what proof was run
- what remains intentionally unverified

---

## Local validation workflow

Use the repo commands intentionally.

### Normal iteration

```bash
yarn dev
```

### Standard verification

```bash
yarn verify
```

### Topology-sensitive verification

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

Important:

- `yarn verify` does **not** currently prove a frontend production build
- `yarn dev` does **not** automatically seed all test data paths
- topology-sensitive work should not rely only on host-run assumptions

Use `docs/developer-guide.md` for setup, reset, and command details.

---

## Pull request expectations

Every PR should make review easier, not harder.

### Your PR description should clearly state:

- the exact problem being addressed
- the intended scope boundary
- the affected architectural area
- which authoritative docs were updated
- what proof was run
- any follow-up explicitly left out of this change

### For major modules or substantial expansion

Use the Module Quality Gate in the PR template.
That checklist is not optional ceremony.
It is the executable surface of the repo quality bar.

### For architectural or cross-cutting changes

Expect stronger review.
If the change alters long-lived behavior or repo law, route it through the decision path instead of hiding it in implementation detail.

---

## Decision path

Use `docs/decision-log.md` when the decision is:

- architectural
- cross-cutting
- non-obvious
- likely to matter again later

Use backend ADRs when the decision is backend-architectural and does not belong in the repo-wide decision log.

Do **not** add decision-log entries for:

- routine bug fixes
- small refactors
- local naming changes
- behavior already fully governed by existing law

If the architecture changes, the code, docs, and decision trail must move together.

---

## Documentation discipline

This repo already has a substantial documentation system.
That is a strength only if it stays disciplined.

When writing or updating docs:

- prefer one canonical explanation over repeated summaries
- keep support docs below source-of-truth docs
- do not turn prompts or chat-oriented material into primary architecture law
- do not create “overview” documents that compete with existing onboarding or architecture docs
- remove or simplify overlap when possible instead of layering on more prose

If a support document conflicts with a higher-authority doc, the support document must be corrected.

---

## AI-assisted contribution rule

AI assistance is allowed in this repo, but it must follow repo law.

That means:

- prompts do not outrank architecture docs
- generated code must still satisfy module skeleton and engineering rules
- generated reviews must still be evidence-based
- LLM output does not count as proof by itself
- contributors remain responsible for correctness, scope control, and doc/code coupling

Start AI-assisted work from:

- `AGENTS.md`
- `docs/prompts/usage-guide.md`
- `docs/prompts/catalog.md`

But only after reading the actual repo law docs.

---

## What reviewers should be able to trust

A good contribution leaves reviewers able to trust that:

- the change stayed within scope
- the docs reflect the code truth
- the proof level matches the risk
- no hidden architecture drift was introduced
- the PR description is honest

That is the standard.

---

## When this file must be updated

Update `CONTRIBUTING.md` when contribution behavior changes materially, including:

- PR expectations
- required proof expectations
- doc/code coupling rules
- decision-routing expectations
- repo-level contribution workflow

Do **not** update this file for ordinary feature growth unless contribution expectations themselves changed.

If contributor behavior changes and this file is left stale, that is a real repo-governance defect.
