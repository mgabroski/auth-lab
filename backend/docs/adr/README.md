# Backend ADR Guide

This folder contains backend Architecture Decision Records (ADRs).

ADRs exist to capture **important backend decisions that future contributors should not have to rediscover from scratch**.

An ADR is not a generic note.
It is not a meeting summary.
It is not a backlog item.
It is a durable explanation of:

- what decision was made
- why it was made
- what alternatives were rejected
- what consequences follow from it

---

## 1. How ADRs fit into repo authority

ADRs are important, but they are **not** the top authority in the repo.

Read authority in this order:

1. `README.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/decision-log.md`
5. `backend/docs/engineering-rules.md`
6. `backend/docs/module-skeleton.md`
7. backend module/API docs
8. `backend/docs/adr/*.md`

What that means:

- an ADR explains a decision inside repo law
- an ADR must not silently contradict higher-level repo law
- if a higher-level rule changes, the ADR may need updating or superseding

---

## 2. When to create an ADR

Create an ADR when a backend decision is important enough that future engineers should not rely on memory, Slack history, or code archaeology to understand it.

Typical triggers:

### Create an ADR when you change or introduce:

- a meaningful backend architectural boundary
- a cross-module integration pattern
- a shared infrastructure primitive other modules will depend on
- a topology-sensitive backend assumption
- a transaction/audit/session rule with lasting design consequences
- a stable exception to an existing backend law
- a backend contract decision that affects future module design

### Do **not** create an ADR for:

- routine refactors
- small endpoint additions with no architectural consequence
- naming tweaks
- one-off bug fixes
- temporary implementation notes
- tasks that are still undecided

Rule of thumb:
If the answer to “why did we choose this?” will matter again in six months, an ADR is probably justified.

---

## 3. When to update an existing ADR

Update an ADR when:

- the decision still stands but the wording/details are stale
- the decision’s consequences changed materially
- repo law above it changed and the ADR must be reconciled

Do **not** silently edit an ADR in a way that changes historical meaning without saying so.
If the old decision is no longer the right one, prefer a new ADR that supersedes the previous one.

---

## 4. When to supersede instead of editing

Create a new ADR that supersedes an older one when:

- the original decision has been intentionally reversed
- the architecture has evolved enough that the original decision is no longer the right default
- the original ADR would become misleading if simply edited in place

In that case:

- keep the old ADR for history
- mark its status appropriately if needed
- link the new ADR to the old one clearly

ADRs are part of architectural memory, not just living documentation.

---

## 5. ADR naming rules

### File name format

```text
ADR-XXX-short-kebab-title.md
```

Examples:

- `ADR-001-session-tenant-binding.md`
- `ADR-002-sso-state-cookie-csrf-binding.md`
- `ADR-003-topology-first-foundation.md`

### Numbering rules

- use zero-padded numbering
- increment sequentially
- do not renumber old ADRs
- do not reuse a number once assigned

### Title rules

- short
- concrete
- decision-focused
- no vague names like `architecture-change.md`

---

## 6. ADR status values

Use one of these statuses:

- **Accepted** — current decision in force
- **Superseded** — replaced by a newer ADR
- **Deprecated** — no longer the active rule, kept for history
- **Proposed** — drafted but not yet accepted

Prefer `Accepted` for decisions already implemented or locked.
Do not mark something `Accepted` if it is still speculative.

---

## 7. ADR template

Use this exact structure unless there is a strong reason not to.

```md
# ADR-XXX — Title

**Date:** YYYY-MM  
**Status:** Accepted

## Context

What problem or decision pressure existed?
What repo/module/topology/business reality made the decision necessary?

## Decision

What was chosen?
State the decision plainly.

## Why

Why was this decision chosen?
List the key reasons.

## Rejected alternatives

What other options were considered and why were they rejected?

## Consequences

What follows from this decision?
What must future contributors now preserve, expect, or work around?

## Related files / docs

- ...
```

Keep it concise.
An ADR should be long enough to preserve reasoning, but short enough to stay readable.

---

## 8. Writing rules

### Good ADRs are:

- concrete
- specific to this repo
- explicit about tradeoffs
- explicit about consequences
- grounded in actual code/topology/module reality

### Bad ADRs are:

- vague
- aspirational
- generic architecture essays
- disguised meeting notes
- detached from the real repo
- written as if they describe features that are not actually decided

If an ADR sounds impressive but does not help a future engineer understand a real decision, it is a bad ADR.

---

## 9. Examples of good ADR topics in this repo

Examples that fit this repo well:

- why browser traffic uses same-origin `/api/*` while SSR uses direct backend access
- why tenant identity is host/subdomain-derived instead of payload-derived
- why session-tenant mismatch fails closed
- why SSO state is bound with a cookie
- why a cross-module contract was exposed publicly instead of copied or hidden
- why a shared primitive belongs in `shared/` instead of a bounded context

Examples that usually do **not** need ADRs:

- adding one new auth endpoint that follows existing patterns
- renaming a helper file
- splitting one large test into two files
- changing validation wording

---

## 10. Review checklist for ADRs

Before adding an ADR, ask:

1. Is there a real decision here, not just an observation?
2. Will future contributors likely need this reasoning?
3. Is this decision important enough to affect future module design, boundaries, topology, or backend law?
4. Is the ADR grounded in current repo reality?
5. Would a new engineer be more effective after reading it?

If the answer is mostly “no,” you probably do not need an ADR.

---

## 11. Relationship to `docs/decision-log.md`

`docs/decision-log.md` is the root-level repo decision file.

Use it for:

- major repo-level decisions
- cross-layer decisions
- foundation-level architecture choices

Use backend ADRs for:

- backend-specific decisions
- bounded-context/backend-law implications
- backend design choices that are important but do not need to live in the root repo decision log

If a decision is truly repo-wide or topology-wide, prefer the root `docs/decision-log.md`.

---

## 12. Final rule

An ADR should make the future cheaper.

If a decision is important enough that forgetting the reasoning would cause rework, confusion, or bad reimplementation, write the ADR.
If not, do not create documentation noise.
