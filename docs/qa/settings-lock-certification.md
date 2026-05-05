# Settings Lock Certification Checklist

## Status

**Status:** Evidence gate — must be filled during the final lock review.

This document is the repo-local checklist for certifying the shipped Settings module. It does not replace CI, QA execution, API docs, or runbooks. It defines the minimum evidence that must be attached to the final review before Settings can be called locked.

A reviewer may not mark Settings locked from code inspection, green CI, or chat summary alone.

---

## 1. Scope Under Certification

This checklist covers only the shipped Settings v1 slice:

- `/admin` bootstrap banner consumption
- `/admin/settings` overview
- `/admin/settings/access`
- `/admin/settings/account`
- `/admin/settings/modules`
- `/admin/settings/modules/personal`
- `/admin/settings/integrations`
- `/admin/settings/communications`
- Workspace Experience overview-card-only treatment
- Permissions absent treatment
- CP -> Settings cascade
- Settings mutation conflicts and audit behavior
- tenant isolation and same-origin/proxy boundaries relevant to Settings

It does not certify future live Communications, Workspace Experience, Permissions, HRIS, Stripe, Documents, Benefits, Payments, Marketplace, or CP authentication surfaces.

---

## 2. Required Command Evidence

Paste or attach command output for each required proof item.

| Gate                         | Command                                                                                                                                                                                                                                                                                                                                        | Evidence location | Result |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ------ |
| Backend Settings proof       | `yarn workspace @auth-lab/backend test -- settings-proof-closure.spec.ts settings-foundation.spec.ts settings-access.spec.ts settings-account.spec.ts settings-concurrency.spec.ts settings-cp-cascade.spec.ts settings-modules-personal.spec.ts settings-integrations.spec.ts settings-read-surfaces.spec.ts settings-readiness-gate.spec.ts` | TODO              | TODO   |
| Frontend Settings unit proof | `yarn workspace frontend test:unit -- admin-settings`                                                                                                                                                                                                                                                                                          | TODO              | TODO   |
| Browser Settings proof       | `yarn workspace frontend test:e2e test/e2e/settings.spec.ts`                                                                                                                                                                                                                                                                                   | TODO              | TODO   |
| CP full-stack smoke          | `yarn workspace frontend test:e2e:cp`                                                                                                                                                                                                                                                                                                          | TODO              | TODO   |
| Proxy conformance            | `./scripts/proxy-conformance.sh`                                                                                                                                                                                                                                                                                                               | TODO              | TODO   |
| Full repo verification       | `./scripts/verify.sh` or current CI equivalent                                                                                                                                                                                                                                                                                                 | TODO              | TODO   |

---

## 3. Required Browser / Manual Evidence

Attach screenshots or trace artifacts for:

| Evidence                                                  | Required artifact                            | Location | Result |
| --------------------------------------------------------- | -------------------------------------------- | -------- | ------ |
| `/admin` banner reads Settings bootstrap truth            | screenshot with URL bar                      | TODO     | TODO   |
| Settings overview required/optional grouping              | screenshot with URL bar                      | TODO     | TODO   |
| Access acknowledge flow                                   | screenshot before and after acknowledge      | TODO     | TODO   |
| Personal default-save flow                                | screenshot before save and completion result | TODO     | TODO   |
| Account non-gating save                                   | screenshot or API trace                      | TODO     | TODO   |
| Integrations degraded readiness / no fake connected state | screenshot with URL bar                      | TODO     | TODO   |
| Communications placeholder route                          | screenshot with URL bar                      | TODO     | TODO   |
| Workspace Experience no route / overview-only card        | screenshot or Playwright trace               | TODO     | TODO   |
| Permissions absence / 404                                 | screenshot or Playwright trace               | TODO     | TODO   |
| Cross-tenant Settings isolation                           | Playwright trace or backend output           | TODO     | TODO   |

---

## 4. Lock Criteria

Settings may be marked locked only when all of these are true:

- backend Settings proof suite passes
- frontend Settings unit proof passes
- browser Settings proof passes
- CP/proxy proof passes where topology is in scope
- mutation conflict behavior is proven for Account and Personal
- failure audits are proven for Settings write failures
- CP required/optional cascade behavior is proven
- placeholder/absent route treatment is proven
- tenant isolation is proven
- docs and runbooks match the shipped route/API surface
- all quality exceptions are either closed or explicitly acceptable for v1 lock

---

## 5. Open Quality Exceptions Reviewed

| ID      | Summary                                                                                                     | Accepted for v1 lock? | Reviewer |
| ------- | ----------------------------------------------------------------------------------------------------------- | --------------------- | -------- |
| QE-0001 | Settings SSO runtime readiness refresher deferred; Integrations fails closed and remains informational-only | TODO                  | TODO     |

---

## 6. Final Signoff

- **Reviewer:** TODO
- **Date:** TODO
- **Final decision:** TODO
- **Residual accepted risks:** TODO
- **Linked PR / CI run:** TODO
