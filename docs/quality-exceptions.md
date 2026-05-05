# Quality Exceptions Register

**Status:** Active
**Purpose:** Authoritative repo-visible register for deferred quality targets, refused Track A signoff records, explicit time-bounded process exceptions, and closures
**Authority Source:** `docs/quality-bar.md`
**Owner Role:** Lead Architect or Designated Quality Owner
**Last Updated:** 2026-05-05

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

## QE-0001 — Settings SSO Runtime Readiness Refresher Deferred

- **Status:** Open
- **Type:** Deferred Quality Target
- **Opened:** 2026-05-05
- **Opened By PR:** pending
- **Owner:** Auth / Runtime Readiness Owner
- **Target Resolution Date:** 2026-06-15
- **Area:** Settings Integrations / Auth runtime readiness
- **Related PR:** pending
- **Authority Reference:** `docs/quality-bar.md`
- **Linked Docs / ADRs:** `docs/ops/runbooks.md`, `backend/src/modules/settings/gateways/sso-provider-readiness.gateway.ts`

### Summary

The shipped Settings Integrations page is intentionally cache-only and never calls Google or Microsoft providers from Settings GET routes. The gateway exposes a runtime snapshot injection point, but this repo does not yet ship the production auth/runtime refresher that periodically populates external-provider SSO readiness snapshots.

### Why This Is Allowed

This is allowed as a deferred quality target because Settings v1 is informational-only for Integrations, exposes no tenant credential entry, and fails closed when a snapshot is missing or stale. The missing refresher does not widen access, fake a connected state, or allow tenant configuration drift. It only means external-provider SSO readiness may display degraded truth until the auth/runtime refresher is implemented.

### Mandatory Gate Impact

No mandatory gate weakened.

### User / System / Delivery Impact

For non-local runtimes without a populated SSO readiness snapshot, Google/Microsoft SSO cards can show `BLOCKED` degraded readiness even when credentials may exist elsewhere. Operators must treat that as an auth/runtime readiness-snapshot gap, not as a tenant Settings write issue.

### Required Remediation

Implement an auth/runtime readiness refresher that owns provider checks, writes fresh Google/Microsoft SSO readiness snapshots into the Settings gateway/cache boundary, and proves freshness/staleness behavior with tests. Settings GET routes must remain network-call-free.

### Notes

This exception must be closed before claiming production-grade live-provider readiness from the Settings Integrations page. It does not block v1 Settings lock because v1 Integrations is informational-only and fail-closed.

### Closure

- **Closed:** N/A
- **Closed By PR:** N/A
- **Resolution Summary:** N/A
