# Decision Log Usage Guide

This guide explains how to use `docs/decision-log.md` correctly.

It exists so contributors do not misuse the decision log, ignore it, or turn it into a changelog.

This file is intentionally procedural.
It does not replace the decision log itself.
It explains:

- when a decision belongs in the repo decision log
- when it belongs somewhere else
- how to write a useful entry
- how decision-log updates must stay coupled to real changes

---

## Purpose

The decision log preserves the architectural memory of the repository.

Use it to record decisions that are:

- architectural
- cross-cutting
- non-obvious
- important enough that future contributors are likely to rediscover or accidentally reverse them

The goal is simple:

**future contributors should not have to reverse-engineer load-bearing intent from code alone.**

---

## What the repo decision log is for

`docs/decision-log.md` is the repo-level record for decisions that shape how the system works.

Typical examples:

- topology decisions
- auth/bootstrap contract decisions
- session/cookie policy decisions
- tenant resolution rules
- trust-boundary decisions
- documentation-system decisions
- repo-law or governance decisions
- cross-cutting security or operability decisions
- explicit architecture constraints that future work must preserve

If reversing the decision later would change how multiple areas of the repo work, it probably belongs in the repo decision log.

---

## What the repo decision log is not for

Do **not** use `docs/decision-log.md` for:

- ordinary bug fixes
- local refactors
- naming cleanups
- routine endpoint additions
- minor UI changes
- small implementation choices already governed by existing repo law
- temporary debugging notes
- status updates
- release notes
- task tracking

The decision log is not a diary and not a changelog.

If an entry would basically say “we implemented the thing,” it probably does not belong here.

---

## When to add a new decision-log entry

Add a new entry when the answer to one or more of these is yes:

### 1. Did we make or lock a non-obvious architectural decision?

Examples:

- choosing internal SSR backend calls instead of proxy-loop SSR calls
- locking host-derived tenant resolution
- locking a fail-closed tenant/session rule
- locking a two-cookie policy for session vs SSO state

### 2. Did we change a cross-cutting rule multiple contributors will rely on?

Examples:

- changing how repo law is enforced
- changing contributor truth hierarchy
- changing documentation-system structure
- changing release-governance expectations

### 3. Would a future contributor reasonably re-open this without a durable record?

If yes, write it down.

### 4. Does the decision constrain future module work?

If a module team needs to know this decision before building safely, it likely belongs here.

---

## When not to add a new entry

Do **not** add a new entry when the change is already fully explained by:

- `ARCHITECTURE.md`
- engineering-rules docs
- module skeleton docs
- API contract docs
- runbooks
- existing decision-log entries

Also do not create a new entry when the work is only an implementation of an already-locked decision.

Example:

- existing decision: browser stays same-origin under `/api/*`
- current PR: fixes one frontend request to obey that rule

That PR should update code and possibly contracts, but it does not need a fresh repo decision-log entry unless the rule itself changed.

---

## Repo decision log vs backend ADRs

Use the right level.

### Use `docs/decision-log.md` when the decision is repo-level

Examples:

- topology
- browser vs SSR contract
- tenant isolation
- session policy
- documentation-system structure
- governance and truth hierarchy
- cross-cutting security model

### Use backend ADRs when the decision is backend-architectural but not repo-wide

Examples:

- backend internal implementation structure
- a backend-specific trust-boundary detail
- an internal backend pattern that does not need to be elevated to repo law

If the decision matters mainly to backend internals, prefer the ADR path.
If it shapes repo-wide behavior or contributor understanding across areas, prefer `docs/decision-log.md`.

---

## Add vs update vs supersede

Not every change needs a brand-new entry.

### Add a new entry when

- a new decision is being made
- a new constraint is being locked
- a new cross-cutting rule is being introduced

### Update an existing entry when

- the entry has a factual mistake
- clarification is needed but the underlying decision is unchanged
- links, references, or wording need correction without changing the decision itself

### Supersede an existing entry when

- the old decision is no longer the active rule
- a later deliberate decision replaced it
- contributors would be misled if the old entry stood alone

When superseding, do not silently rewrite history.
Mark the relationship clearly so readers can follow the evolution.

---

## Required timing

Decision-log updates should happen in the same PR where the decision is made or locked.

Do not rely on “we will document it later.”
That is how architectural memory gets lost.

If the code change depends on the decision, the decision record should land with it.

---

## Minimum structure of a good entry

A good decision-log entry should make four things easy to understand.

### 1. Context

What problem or ambiguity existed?
What forced the decision?

### 2. Decision

What was chosen?
State it directly.

### 3. Why

Why was this chosen instead of the nearby alternatives?
Include the reasoning that future contributors would otherwise have to guess.

### 4. Consequences

What must contributors now preserve?
What does this rule out?
What docs, code paths, or future work does it affect?

If those four things are present, the entry is usually useful.
If they are missing, the entry is usually just noise.

---

## What good entries look like

Good entries are:

- specific
- constrained
- durable
- written in repo language
- explicit about what is now locked

Good entries avoid:

- vague motivational prose
- implementation trivia
- changelog-style narration
- pretending a temporary convenience is a final principle
- hiding the actual tradeoff

A useful entry should help a future reviewer say:

**I understand the rule, why it exists, and what would break if I ignored it.**

---

## Common mistakes

### Mistake 1 — using the log as a release history

Wrong:

- “implemented MFA setup page”
- “added invite tests”
- “finished stage work”

Those are not architectural decisions.

### Mistake 2 — writing an entry after memory is already fuzzy

If the entry is delayed too long, it usually becomes vague and unhelpful.
Write it when the decision is active and concrete.

### Mistake 3 — recording implementation detail as if it were architecture

Not every technical detail is a decision-log-worthy decision.
Focus on the load-bearing rule, not every internal mechanism.

### Mistake 4 — failing to say what future contributors must preserve

A decision log without consequences is incomplete.
Contributors need to know what this decision protects and what it forbids.

### Mistake 5 — duplicating the same explanation across many docs

Put the durable decision in the decision log.
Let other docs reference it instead of re-explaining it in parallel.

---

## Decision-log entry checklist

Before adding or updating an entry, check:

- [ ] Is this actually a decision, not just an implementation update?
- [ ] Is it architectural, cross-cutting, or durable enough to matter later?
- [ ] Does it belong in the repo decision log rather than a backend ADR?
- [ ] Does it state the decision clearly?
- [ ] Does it explain why the decision was taken?
- [ ] Does it explain what future contributors must preserve?
- [ ] Does it land in the same PR as the dependent change?
- [ ] Did we avoid duplicating the same explanation in other docs unnecessarily?

If several answers are no, stop and reassess.

---

## Coupling rules

A decision-log update is usually not standalone.

If you change a load-bearing decision, also check whether one or more of these must move in the same PR:

- `ARCHITECTURE.md`
- `docs/security-model.md`
- `docs/current-foundation-status.md`
- `README.md`
- `docs/onboarding.md`
- `CONTRIBUTING.md`
- backend ADRs
- relevant ops docs
- relevant API docs
- prompt usage/docs if the contributor workflow changed materially

The decision log records the decision.
It does not excuse leaving the rest of the truth chain stale.

---

## How to reference decisions from other docs

Do not duplicate long explanations everywhere.

Preferred pattern:

- keep the decision itself in `docs/decision-log.md`
- summarize briefly in higher-level docs only if needed
- point readers back to the decision log for durable rationale

This keeps the decision durable without creating competing sources of truth.

---

## Review expectations

When reviewing a PR, ask:

- did this change introduce or lock a real decision?
- if yes, was the decision recorded at the right level?
- if no, is the PR correctly avoiding unnecessary decision-log noise?
- if an entry was added, is it specific and durable enough to be useful later?
- are the related authoritative docs also updated?

A missing required entry is a real review problem.
An unnecessary entry is also a quality problem because it dilutes the log.

---

## Maintenance rule

Update this guide when the repository changes how it uses the decision log, including:

- repo-level decision-routing rules
- the boundary between repo decision log and backend ADRs
- required timing or coupling expectations
- the expected structure of decision entries

Do not update this guide for ordinary new decisions.
Update it only when the **usage model** changes.

---

## Final rule

Use the decision log sparingly, but use it seriously.

If every change creates a decision entry, the log becomes noise.
If real decisions are omitted, the repo loses architectural memory.

The correct standard is:

**record durable decisions that future contributors truly need, and keep everything else out.**
