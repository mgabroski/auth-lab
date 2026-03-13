# Hubins Auth-Lab — Implementation Session Charter

## Purpose

This document codifies how implementation and review sessions should operate against the current Hubins/Auth-Lab repository.

It exists so future sessions do not:

- redesign already-locked foundations by accident
- implement against stale or external-only documents
- overclaim repo completeness
- skip documentation coupling when changing behavior

---

## 1. Session baseline

Every meaningful implementation or review session starts from the same posture:

- inspect the current repo directly
- inspect the highest-authority uploaded sources directly
- assume nothing that has not been verified in the repo or in the active authority chain
- flag missing sources instead of inventing around them

---

## 2. Working authority chain

Use this order unless a higher-priority session brief explicitly narrows scope further:

1. locked business/source documents supplied for the session
2. locked topology documents supplied for the session
3. repo-root truth documents (`README.md`, `ARCHITECTURE.md`, `docs/current-foundation-status.md`, `docs/decision-log.md`)
4. repo engineering-law documents actually present in the repository
5. scope-specific contract docs such as `backend/docs/api/*.md`
6. scope-local implementation guides such as `frontend/README.md`
7. derived prompts and historical review material

If a lower source conflicts with a higher source, the lower source is wrong until repaired.

---

## 3. Scope control rules

### 3.1 Do not redesign locked foundations casually

If topology, tenant identity, session truth, or backend-truth-driven continuation are already locked, sessions must extend them rather than silently replacing them.

### 3.2 Change only the requested phase unless a contradiction forces a doc repair

A session should not spill into later phases just because adjacent work exists.
If a contradiction in an active truth-chain doc blocks safe progress, repair the contradiction and explicitly flag why.

### 3.3 Missing-source rule

If a required source is missing or unreadable, say:

```text
BLOCKED BY MISSING SOURCE
```

Do not pretend the missing source was inspected.

### 3.4 Human-decision rule

If two authoritative sources conflict and the conflict cannot be resolved by the active authority chain, say:

```text
FLAG — REQUIRES HUMAN DECISION
```

Do not silently choose a side without saying so.

---

## 4. Output discipline

Implementation sessions should produce:

- exact scope confirmation
- added / modified / removed file list
- a short reason for each file change
- explicit flags and blocked items
- full file content for every added or modified file
- one clean commit message
- an explicit deferred-to-next-phase list when scope is phased

Partial snippets are not enough for correctness-critical repo work.

---

## 5. Documentation coupling rules

When code or contracts change, the matching docs must be updated in the same session output.

Examples:

- API contract changes → update `backend/docs/api/*.md`
- repo truth changes → update `docs/current-foundation-status.md`
- repo framing changes → update `README.md` and/or `ARCHITECTURE.md`
- backend law/structure changes → update `backend/docs/engineering-rules.md` and related prompt artifacts
- frontend shipped-scope truth changes → update `frontend/README.md` or retire stale derived prompts

---

## 6. Documentation-home decision for current repo shape

The current repository uses a **scope-split documentation home**:

- repo-wide truth and decisions live at repo root and in `/docs`
- backend law/contracts live in `backend/docs/`
- frontend scope guidance stays close to the frontend surface

Do not create a new parallel documentation home for the same truth.
Pick the home that matches the scope of the document.

---

## 7. Historical sources

Historical uploaded files that are not inside the repo may still be useful context, but they are not current repo truth until explicitly adopted.

If they are stale, say so plainly.
Do not let a historical artifact override the repository.

---

## 8. One-sentence operating rule

> Inspect first, obey the authority chain, change only scoped truth, and leave no correctness-affecting doc drift behind.
