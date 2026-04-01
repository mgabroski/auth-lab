# Quality Exceptions Register

**Status:** Active
**Purpose:** Authoritative repo-visible register for deferred quality targets, refused Track A signoff records, explicit time-bounded process exceptions, and closures
**Authority Source:** `docs/quality-bar.md`
**Owner Role:** Lead Architect or Designated Quality Owner
**Last Updated:** 2026-04-01

---

## 1. What This File Is

This file is the single authoritative repo-visible register for quality-bar exceptions that must not live only in PR comments, chat, memory, or external notes.

This file records only the following categories:

- deferred quality targets allowed by `docs/quality-bar.md`
- refused Track A signoff records
- explicit time-bounded process exceptions that do **not** weaken mandatory gate truth
- closures of previously recorded items

This file is **not**:

- a general backlog
- a bug tracker
- a substitute for module docs
- a place to waive mandatory gates
- a place to hide unresolved architecture, tenant-isolation, auth/session, or security-law violations

If a change weakens mandatory gate truth, architecture law, tenant isolation, auth/session trust boundaries, or security foundations, it must not be normalized here as a casual exception.

---

## 2. Rules

### 2.1 Mandatory gates are not waivable

This file must never be used to silently waive or erase mandatory gates defined in `docs/quality-bar.md`.

Allowed records are limited to:

- deferred quality targets explicitly permitted by the quality bar
- refused signoff records awaiting remediation
- narrowly scoped, time-bounded process exceptions that do not weaken the quality bar itself
- closures of existing records

### 2.2 Repo-visible update requirement

If a PR introduces, updates, refuses, escalates, or closes a quality exception record, that PR must update this file in the same change.

A reviewer comment alone is not the authoritative record.

### 2.3 Owner requirement

Every open record in this file must name:

- an owner
- a target resolution date

Open-ended exceptions are not allowed.

### 2.4 Closure requirement

Every closed record must document:

- what changed
- when it was closed
- which PR closed it

### 2.5 No parallel registers

Parallel authoritative exception registers are not allowed.

This file is the canonical repo-visible location for these records.

---

## 3. Record Types

Use exactly one of the following record types:

- `Deferred Quality Target`
- `Refused Track A Signoff`
- `Explicit Process Exception`
- `Closure`

---

## 4. Record Template

Copy this template for every new record.

```md
## QE-XXXX — <short title>

- **Status:** Open | Closed
- **Type:** Deferred Quality Target | Refused Track A Signoff | Explicit Process Exception | Closure
- **Opened:** YYYY-MM-DD
- **Opened By PR:** #PR-NUMBER or `pending`
- **Owner:** <name or role>
- **Target Resolution Date:** YYYY-MM-DD
- **Area:** <module / repo area / workflow>
- **Related PR:** #PR-NUMBER or list
- **Authority Reference:** `docs/quality-bar.md`
- **Linked Docs / ADRs:** <paths or `None`>

### Summary

State the exact issue or exception in one short paragraph.

### Why This Is Allowed

State why this record is allowed under the quality bar.

If this is a refused signoff record, state why merge is blocked or what remediation is required before closure.

### Mandatory Gate Impact

State explicitly whether any mandatory gate is unmet.

Allowed values:

- `No mandatory gate weakened.`
- `Mandatory gate unmet — merge must not proceed without remediation or explicit owner decision path already documented.`

### User / System / Delivery Impact

State the concrete reviewer-visible impact.

### Required Remediation

List the exact remediation required to close the record.

### Notes

Add any reviewer- or operator-relevant notes.

### Closure

Use this section only when closing the record.

- **Closed:** YYYY-MM-DD
- **Closed By PR:** #PR-NUMBER
- **Resolution Summary:** <one short paragraph>
```
