# Settings Lock Certification Checklist

**Status:** Support checklist for final Settings signoff  
**Scope:** Shipped tenant-facing Settings v1 only  
**Authority:** This file does not replace `docs/current-foundation-status.md`, `backend/docs/api/settings.md`, `docs/ops/runbooks.md`, or `docs/qa/qa-execution-pack.md`. It exists to collect final signoff evidence without creating a second source of truth.

---

## 1. Purpose

Use this checklist before treating the shipped Settings v1 surface as locked.

The checklist is intentionally evidence-based. A reviewer may not mark Settings locked from code inspection, green CI, or chat summary alone. Each gate below must be backed by command output, screenshots, trace artifacts, or linked review notes.

---

## 2. Source bundle for certification

Load these files before review:

1. `AGENTS.md`
2. `docs/current-foundation-status.md`
3. `ARCHITECTURE.md`
4. `docs/security-model.md`
5. `backend/docs/api/settings.md`
6. `docs/ops/runbooks.md`
7. `docs/qa/qa-execution-pack.md`
8. relevant Settings backend, frontend, and test files

Do not use older roadmap notes, prompt outputs, or external chat summaries as shipped truth when they conflict with the current repo.

---

## 3. Mandatory lock gates

| Gate                           | Required evidence                      | Pass criteria                                                                                                                                                          |
| ------------------------------ | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Backend-owned setup truth      | Backend Settings proof output          | `/admin` and `/admin/settings` consume `/settings/*` truth; auth scaffold route is retired and cannot mutate setup state.                                              |
| Required section behavior      | Backend + browser proof                | Access and Personal are required/gating when Personal is enabled; Account and Integrations never fake-complete required setup.                                         |
| Personal full-replacement save | Backend + browser proof                | Generated defaults can be explicitly saved; required-floor/system-managed fields cannot be removed; invalid section assignments fail closed.                           |
| Conflict safety                | `settings-concurrency.spec.ts` output  | Concurrent Account and Personal saves produce exactly one success and one conflict with no last-write-wins overwrite.                                                  |
| CP cascade truth               | `settings-cp-cascade.spec.ts` output   | Required CP changes create Needs Review; optional Personal removals do not; replay is idempotent.                                                                      |
| Placeholder/absent discipline  | Backend + browser proof                | Communications is placeholder-only, Workspace Experience has no route, and Permissions has no card/route/API.                                                          |
| Integrations honesty           | Backend proof + UI screenshot          | Google/Microsoft SSO readiness is cache-based and degraded when unavailable/stale; HRIS/Stripe remain deferred; no fake Connected state or credential entry exists.    |
| Audit correctness              | Backend proof or reviewed audit output | Success audits are transactional, failure audits survive rollback, and Settings audit metadata includes source, target, before/after, version, and cpRevision context. |
| Topology and tenant boundary   | Playwright + proxy proof               | Same-tenant Settings access succeeds; cross-tenant access fails; browser uses same-origin `/api/*`; proxy conformance remains green.                                   |
| Documentation truth            | Reviewer check                         | README, AGENTS, API docs, QA pack, runbooks, and current status describe the same shipped surface and route treatment.                                                 |

A single failed mandatory gate blocks lock.

---

## 4. Required commands

Run these from the repo root.

```bash
yarn workspace @auth-lab/backend test -- settings-proof-closure.spec.ts settings-foundation.spec.ts settings-access.spec.ts settings-account.spec.ts settings-concurrency.spec.ts settings-cp-cascade.spec.ts settings-modules-personal.spec.ts settings-integrations.spec.ts settings-read-surfaces.spec.ts settings-readiness-gate.spec.ts
```

```bash
yarn workspace frontend test:unit -- admin-settings
```

```bash
yarn workspace frontend test:e2e test/e2e/settings.spec.ts
```

When full-stack proxy proof is in scope:

```bash
yarn workspace frontend test:e2e:cp
./scripts/proxy-conformance.sh
```

Before final repository signoff, run the full repo gate:

```bash
yarn verify
```

---

## 5. Manual evidence required

Attach or link the following evidence to the final review or PR:

- `/admin` banner screenshot before Settings completion
- `/admin/settings` overview screenshot showing required Access and Modules/Personal work
- Access acknowledgement success screenshot
- Personal save screenshot with generated defaults accepted unchanged
- `/admin` screenshot after required setup is complete and the banner is gone
- Communications placeholder screenshot
- Workspace Experience route absence proof
- Permissions route absence proof
- Integrations screenshot showing informational/deferred states and no credential entry
- backend proof command output
- browser proof output or Playwright trace path
- proxy conformance output when run

---

## 6. Lock decision template

Copy this into the final review comment.

```md
## Settings v1 Lock Decision

- Decision: LOCKED | NOT LOCKED
- Reviewer / owner:
- Date:
- Repo commit:
- Backend Settings proof: PASS | FAIL | NOT RUN
- Frontend unit proof: PASS | FAIL | NOT RUN
- Browser Settings proof: PASS | FAIL | NOT RUN
- Proxy / topology proof: PASS | FAIL | NOT RUN | NOT IN SCOPE
- Documentation truth check: PASS | FAIL
- Open quality exceptions: NONE | LIST

### Residual risks

List only risks that do not weaken mandatory lock gates.

### Required remediation if NOT LOCKED

List concrete blockers only.
```

Do not mark Settings locked if any mandatory gate is failed, unrun without an explicit owner-approved reason, or contradicted by current repo evidence.
