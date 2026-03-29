# Repo Quality Bar

**Status:** Locked
**Version:** 1.0
**Scope:** Repo-level delivery and signoff standard for major-module work and stage completion
**Audience:** Engineers, reviewers, technical leads, architecture owners, and release owners
**Owner Role:** Lead Architect or Designated Quality Owner
**Last Updated:** 2026-03-29

---

## 1. What This Document Is

This document defines the repo-wide quality bar for:

- what counts as a major module
- what “done” means for a module
- what “done” means for a stage
- what is mandatory vs deferrable
- how debt is accepted
- what happens when signoff is blocked
- how authoritative governance artifacts are changed and retired

This document is repo law for delivery quality.
It is not a product roadmap.
It is not a module spec.
It does not replace architecture, API, security, or QA documents.

Those documents still own their own truth.
This file defines the minimum bar they must satisfy before a module or stage can be treated as complete.

---

## 2. Comparison Class

This repo is not measuring itself against hobby projects or generic side repos.

The comparison class is:

- professional SaaS product teams
- multi-tenant platforms
- customer-facing production systems
- startup to growth-stage engineering teams where speed matters, but reliability cannot be fake

“Good enough for a side project” is not an acceptable quality bar here.

---

## 3. Major Module Definition

A **major module** is any new bounded context or major surface that introduces one or more of:

- its own route or API surface
- database schema or migration impact
- distinct business rules or policy logic
- cross-cutting operational, security, or observability concerns
- a user-facing product area that can ship independently

If a change is ambiguous, it is treated as a major module until explicitly classified otherwise.

---

## 4. Module Completion Bar

A module is not done because code exists.

### 4.1 Mandatory gates — no ship without these

Every major module must satisfy all of the following:

- architecture fit and boundary review
- required API or contract documentation for exposed surfaces
- minimum test coverage at the right levels
- failure-mode and security review proportional to module risk
- observability touchpoints appropriate to the module
- runbook and ops impact review
- migration safety review when schema or data-shape changes are involved
- explicit Track A signoff

These are mandatory gates, not quality aspirations.

### 4.2 Concrete minimum test coverage expectation

Minimum test coverage means, at minimum:

- one primary happy-path E2E or real-stack integration path for the module’s main user or business flow
- unit tests for business rules, policy decisions, and branch-heavy logic
- contract or integration tests for risky boundaries such as auth/session, API contracts, persistence, or third-party behavior
- negative-path coverage for the module’s most important failure or permission conditions

This is the minimum, not the ideal.

### 4.3 Quality targets — expected within one iteration if not present at first ship

These may be deferred once with explicit debt tracking:

- expanded QA pack
- broader real-stack proof
- richer observability depth
- documentation polish
- non-critical optimization or secondary tooling

### 4.4 Evidence rule

A module gate is not considered satisfied by assertion alone.

Expected evidence is one or more of:

- updated authoritative docs
- linked tests
- linked CI runs
- linked runbook or QA updates
- linked migration notes
- explicit signoff record

“Reviewed mentally” is not sufficient evidence for a mandatory gate.

---

## 5. Stage Completion Bar

A stage is complete only when its required outputs are:

- written
- implemented
- testable or enforceable where relevant
- actually in use by the repo

A drafted document, unused checklist, or unhooked workflow does not count as stage completion.

---

## 6. Debt Acceptance Rules

Mandatory gates are non-negotiable.

Quality targets may be deferred only with an explicit debt record that includes:

- the specific deferred item
- the reason for deferral
- the named owner
- the target resolution date
- the impact of the defer
- the condition that will remove the debt

“We were under pressure” is not a valid reason to skip a mandatory gate.

A quality target may be deferred once.
Repeated defer without escalation is not allowed.

---

## 7. Track A Signoff Rules

Every PR that introduces or substantially expands a major module must go through the **Module Quality Gate** path.

The Module Quality Gate is the executable checklist surface for this document.
It is not a separate standard.

### 7.1 Required signoff role

Track A signoff must come from:

- the Lead Architect, or
- the Designated Quality Owner

That owner role must be bound to a real owner in repo ownership rules and CODEOWNERS.

### 7.2 If Track A signoff is refused

Refusal cannot be informal.

It must produce:

- the specific unmet gate
- the reason it is unmet
- the required remediation
- the target resolution timeline
- the named owner

Override is allowed only through an explicit documented decision by the owner role above.

No silent bypass is allowed.

---

## 8. Deprecation / Removal Standard

Parallel authoritative documents are not allowed.

If a document is superseded:

- the older artifact must be marked deprecated immediately
- the newer artifact must be identified as authoritative
- downstream references must be updated
- the deprecated artifact must be removed within a defined window unless deliberately preserved as historical reference with clear status and owner

No stale prompt, law, governance, or review artifact may silently remain authoritative.

---

## 9. Pressure Policy

This rule exists before deadline pressure appears.

- Mandatory gates are non-negotiable.
- Quality targets may be deferred only through the debt process in this document.
- Deadline pressure does not authorize silent bypass of required review, testing, or documentation coupling.

---

## 10. Change Control

This document may change only through:

- a linked PR
- explicit reviewer signoff from the owner role
- a stated reason for the change
- any required downstream updates to checklists, guardrails, or docs

If this document changes, any executable enforcement surface that depends on it must be reviewed in the same PR.
That includes PR templates, repo guards, and linked governance docs where relevant.

---

## 11. Review Cadence

This document must be reviewed:

- whenever mandatory gates change
- whenever a new major module type is introduced
- during recurring architecture and quality review cycles

If the repo’s quality bar changes but this file does not, the repo is in governance drift.

---

## 12. Definition of Done

### For a module

A major module is done only when:

- all mandatory gates are satisfied
- any deferred quality targets are explicitly recorded as debt
- the required evidence exists
- Track A signoff is explicit

### For a stage

A stage is done only when:

- its required outputs are written
- they are implemented
- they are testable or enforceable where relevant
- they are actually active in repo workflow

---

## 13. Final Position

This document is the repo’s quality bar.

It exists so “done” cannot be redefined under pressure, and so new major modules do not grow outside the same standard the repo claims to hold.
