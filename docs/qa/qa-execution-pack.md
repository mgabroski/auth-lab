# QA Execution Pack — Auth + User Provisioning + Control Plane + Settings

## Purpose

This is the single canonical QA execution document for the Auth, User Provisioning, Control Plane, and shipped Settings v1 surfaces in this repository.

`docs/qa/settings-lock-certification.md` is only a lightweight final signoff record. It must not duplicate this QA pack, raw command logs, screenshots, or Playwright traces.

Use it for:

- environment matrix
- personas
- deterministic fixture requirements
- test preconditions
- execution order
- exact Settings proof cases
- expected evidence
- out-of-scope items
- bug reporting expectations
- signoff readiness

Do not maintain a second competing QA execution script for these shipped surfaces. A tester-friendly derivative manual may exist, but this file remains the canonical execution pack.

---

## Read This After

Before using this file, read:

1. `docs/current-foundation-status.md`
2. `docs/developer-guide.md`
3. `docs/ops/runbooks.md`
4. relevant API docs only if a QA question becomes contract-specific

Use this file for QA execution. Use `docs/developer-guide.md` for environment setup and daily developer workflow.

---

## Scope

This pack covers QA execution for the current shipped repo slice:

- login and logout
- public signup
- email verification and resend verification
- forgot password and reset password
- invite issuance, acceptance, resend, cancellation, invalidation behavior
- MFA setup, verify, and recovery
- admin invite management
- role-aware landing
- Control Plane account create/setup/review/publish/re-entry/status-toggle
- Settings-native workspace setup banner and overview behavior
- `/admin/settings/access` read-only review and explicit acknowledgement
- `/admin/settings/account` non-gating per-card save behavior
- `/admin/settings/modules` navigation hub behavior
- `/admin/settings/modules/personal` family review, field configuration, section builder, and full-replacement save behavior
- `/admin/settings/people-teams` reusable group and membership management behavior
- `/admin/settings/integrations` informational SSO and deferred integration behavior
- `/admin/settings/communications` placeholder-only route behavior
- absent Permissions treatment
- version conflict and CP revision conflict proof
- CP required-vs-optional Settings cascade proof
- migration/backfill proof for legacy scaffold to native Settings rows
- retired auth scaffold removal proof so auth cannot mutate Settings setup truth
- tenant-safe SSR/proxy/cookie behavior where current local topology supports it

---

## Out Of Scope

Do not use this pack to claim QA signoff for work outside the current shipped repo.

Out of scope:

- SCIM
- SAML
- HRIS runtime module UX
- tenant secret entry for integrations
- Communications live configuration
- Workspace Experience live configuration
- Permissions / Permission & Policy Management tenant surface
- Operational Access grants, Person Exceptions, Managed People, Agent invite requirements, runtime role migration, and Effective Access Resolver behavior
- documents, benefits, payments, marketplace tenant modules
- CP authentication
- CP operator RBAC
- CP audit viewer UI
- production load/performance testing
- Operational Access runtime QA, Agent Groups as grant subjects, Person Exceptions, Managed People scope, branch/regional-manager scope, sensitive-field conflict runtime proof, and Effective Access explanation proof

When a future surface is intentionally absent or placeholder-only, missing configuration UI is not a bug.

---

## Future Operational Access QA Planning — Not Executable Yet

This section is planning guidance only. These scenarios are **future / not executable** in the current repo.

Current shipped truth remains:

- runtime roles are `ADMIN | MEMBER`
- `Agent` and distinct runtime `User` are future target concepts
- People & Teams foundation groups and group memberships are implemented
- group levels `ADMIN / AGENT / USER` are classification only and do not change runtime roles
- Agent Groups as Operational Access grant subjects are not implemented
- Person Exceptions are not implemented
- a reusable Effective Access Resolver is not implemented
- current `/admin/settings/access` is Access & Security, not Operational Access
- Permissions / Operational Access tenant UI remains absent

Do not add the scenarios below to the current executable checklist until implementation exists and the API/UI/test fixtures are real.

| Future ID | Scenario                                  | Future proof intent                                                                                                        | Current status |
| --------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | -------------- |
| OA-FUT-01 | Admin full tenant access by level         | Admin sees allowed operational records without needing Agent Groups or Person Exceptions.                                  | Not executable |
| OA-FUT-02 | User own/self-service access              | User sees only own/self-service data and cannot access cross-person operational records.                                   | Not executable |
| OA-FUT-03 | Agent access through Agent Group          | Agent sees only actions and target records granted through active Agent Group access.                                      | Not executable |
| OA-FUT-04 | Agent with no operational access          | Agent with no active Agent Groups and no Person Exceptions lands in a safe no-access state.                                | Not executable |
| OA-FUT-05 | Agent Groups archive/fail-closed behavior | Archiving the group that granted access immediately removes effective access and keeps remediation/audit truth.            | Not executable |
| OA-FUT-06 | Managed People exact-person scope         | Agent can operate only for explicitly managed people, not a whole employer, location, or group.                            | Not executable |
| OA-FUT-07 | Person Exception extra access             | Rare person-specific access requires reason, review/expiry discipline, audit, and explanation visibility.                  | Not executable |
| OA-FUT-08 | Branch manager scope                      | Branch Manager group with `Own Employer + Own Location` sees only matching target records.                                 | Not executable |
| OA-FUT-09 | Regional manager scope                    | Regional Manager group with selected employer/location pairs sees only those explicit pairs.                               | Not executable |
| OA-FUT-10 | Sensitive-field conflict                  | Sensitive fields stay masked/hidden when grants conflict unless explicit sensitive visibility applies.                     | Not executable |
| OA-FUT-11 | Direct API denial                         | Backend denies access directly even if a future UI button or link is hidden.                                               | Not executable |
| OA-FUT-12 | Effective Access explanation              | Support/admin explanation view accurately states why a card, field, action, or record is shown, masked, hidden, or denied. | Not executable |
| OA-FUT-13 | Group + scope audience targeting          | Agent-created audiences are limited by the Agent’s own effective access scope.                                             | Not executable |
| OA-FUT-14 | Personal Cards consumption                | Module renders backend-resolved Personal Cards and does not raw-read fields outside active cards.                          | Not executable |
| OA-FUT-15 | Orphaned target behavior                  | Removed action/card/field/scope target grants nothing, fails closed, and remains auditable/remediable.                     | Not executable |

Execution rule:

> Operational Access QA moves from this future-planning section into executable QA only after Agent Groups as grant subjects, Person Exceptions, backend Effective Access resolution, and at least one consuming module are implemented and documented as shipped truth. The current People & Teams executable QA covers group and membership management only.

---

## Environment Matrix

| Environment            | Use                                  | Required services                               | Email mode                             | SSO mode                                  | Settings proof level                                                         |
| ---------------------- | ------------------------------------ | ----------------------------------------------- | -------------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------------- |
| Local host-run         | Daily QA and developer proof         | Postgres, Redis, backend, frontend, CP, Mailpit | Mailpit                                | Local helper / disabled unless configured | Full backend/API proof plus browser Settings proof on `*.lvh.me:3000`        |
| Local full-stack proxy | Topology and CP smoke                | Compose stack with Caddy                        | Mailpit                                | Local helper / disabled unless configured | Host preservation, same-origin `/api/*`, CP host, tenant-host boundary proof |
| Staging                | Provider and release candidate proof | deployed stack                                  | sandbox SMTP or real non-prod provider | real Google/Microsoft                     | Repeat critical Settings browser paths and provider-dependent SSO flows      |
| Production             | Release verification only            | production stack                                | production provider                    | production providers                      | Smoke only, according to release runbook                                     |

Local host-run starts with `yarn dev`. Local full-stack proxy starts with `yarn dev:stack`.

---

## Canonical Personas and Fixtures

### Seeded local personas

| Persona                                         | Tenant          | Role   | Use                                              |
| ----------------------------------------------- | --------------- | ------ | ------------------------------------------------ |
| `member@example.com / Password123!`             | `goodwill-open` | Member | member login, logout, member routing             |
| `e2e-admin@example.com / Password123!`          | `goodwill-open` | Admin  | admin landing, MFA setup, Settings browser proof |
| `e2e-recovery-admin@example.com / Password123!` | `goodwill-open` | Admin  | MFA recovery proof                               |
| `e2e-reset-member@example.com / Password123!`   | `goodwill-open` | Member | password reset proof                             |

### Tenant fixtures

| Fixture              | URL                                | Purpose                                                 |
| -------------------- | ---------------------------------- | ------------------------------------------------------- |
| GoodWill Open        | `http://goodwill-open.lvh.me:3000` | public signup enabled, seeded member/admin personas     |
| GoodWill CA          | `http://goodwill-ca.lvh.me:3000`   | invite-only tenant, cross-tenant boundary checks        |
| CP-created QA tenant | generated account key              | CP publish, Settings cascade, and fixture-builder proof |

### Deterministic Settings fixture builder

Backend proof tests use `backend/test/helpers/settings-fixtures.ts`. It creates reviewer-usable Settings states through the shipped CP and Settings APIs:

- create CP account through `POST /cp/accounts`
- save CP integrations, Access, Account Settings, Module Settings, and Personal catalog through real CP endpoints
- publish the account through `POST /cp/accounts/:accountKey/publish`
- create an admin session with real auth/MFA session state
- drive Settings setup through `GET /settings/*`, `POST /settings/access/acknowledge`, and `PUT /settings/modules/personal`

This fixture is intentionally not hidden DB magic. It uses direct DB reads only to resolve tenant IDs and create test admin membership/session data.

---

## Green-Light Health Check

Run before every QA session.

| ID   | Action                                             | Expected result        | Evidence                      |
| ---- | -------------------------------------------------- | ---------------------- | ----------------------------- |
| HC-1 | Open `http://goodwill-ca.lvh.me:3000/api/health`   | healthy response       | screenshot or copied response |
| HC-2 | Open `http://goodwill-open.lvh.me:3000/auth/login` | login page loads       | screenshot                    |
| HC-3 | Open `http://localhost:3002/accounts`              | CP Accounts page loads | screenshot                    |
| HC-4 | Open `http://localhost:8025`                       | Mailpit loads          | screenshot                    |
| HC-5 | Log in as `member@example.com` on GoodWill Open    | reaches `/app`         | screenshot                    |

Stop immediately if any health check fails.

---

## Execution Order

Run cases in this order unless a focused bug task explicitly needs a smaller subset.

1. Baseline login and logout
2. Signup and email verification
3. Password reset
4. MFA
5. Invite lifecycle
6. Control Plane create/setup/review/publish/re-entry/status-toggle
7. Settings banner, overview, required setup, People & Teams management, Personal completion, placeholders, absent route
8. Settings conflict and CP cascade proof
9. Boundary and tenant isolation proof
10. Staging-only SSO proof
11. Signoff review

---

## Settings QA Cases

### SET-01 — Admin lands on `/admin` and sees setup banner

| Field         | Value                                                             |
| ------------- | ----------------------------------------------------------------- |
| Environment   | Local host-run                                                    |
| Persona       | `e2e-admin@example.com` admin                                     |
| Fixture       | clean seeded GoodWill Open state                                  |
| Preconditions | run `yarn reset-db`, start `yarn dev`, complete MFA when prompted |

Steps:

1. Open `http://goodwill-open.lvh.me:3000/auth/login`.
2. Sign in as `e2e-admin@example.com / Password123!`.
3. Complete MFA setup if the account is prompted.
4. Confirm the browser lands on `/admin`.
5. Confirm the admin dashboard shows the non-blocking Workspace setup banner.
6. Click `Open workspace settings →`.

Expected results:

- Admin lands on `/admin`, not `/app`.
- Banner text says workspace setup requires attention.
- Banner links to `/admin/settings`.
- No detailed completion logic is shown on `/admin`.

Evidence:

- screenshot of `/admin` with URL bar and banner visible
- screenshot after clicking into `/admin/settings`

---

### SET-02 — Settings overview shows correct cards and no Permissions card

| Field         | Value               |
| ------------- | ------------------- |
| Environment   | Local host-run      |
| Persona       | authenticated admin |
| Fixture       | same as SET-01      |
| Preconditions | SET-01 completed    |

Steps:

1. Open `/admin/settings`.
2. Confirm `Required sections` is visible.
3. Confirm `Optional sections` is visible.
4. Confirm cards for Access & Security, Modules, Account Settings, Integrations, People & Teams, Communications, and Workspace Experience.
5. Look for `Permissions`.

Expected results:

- Access and Modules/Personal are required setup paths.
- People & Teams is visible as a live, non-gating management surface.
- Communications is placeholder-only.
- Workspace Experience is overview-only placeholder.
- Permissions is absent: no card, no CTA, no placeholder.

Evidence:

- screenshot of overview required sections
- screenshot of overview optional sections

### SET-02B — People & Teams group and membership management

| Field         | Value               |
| ------------- | ------------------- |
| Environment   | Local host-run      |
| Persona       | authenticated admin |
| Fixture       | same as SET-01      |
| Preconditions | SET-01 completed    |

Steps:

1. Open `/admin/settings/people-teams`.
2. Confirm the page title is `People & Teams`.
3. Confirm the helper copy says group level is classification only and does not grant module access.
4. Create a group with a unique name and level `AGENT`.
5. Edit the group name or description.
6. Add an active tenant member to the selected group.
7. Remove that member from the group.
8. Archive the group.
9. Confirm no Operational Access grants, Person Exceptions, Managed People, `Can see`, `Can do`, or `Where` UI appears.

Expected results:

- Admin can create, edit, archive, add member, and remove member.
- Member management uses active tenant memberships only.
- The page remains a non-gating Settings management surface.
- Group membership does not change runtime role and does not grant module access.
- No Operational Access UI appears.

Evidence:

- screenshot of People & Teams page after create
- screenshot after member add/remove
- screenshot or note confirming no Operational Access controls are visible

---

### SET-03 — Access acknowledge updates only Access boundary

| Field         | Value                                    |
| ------------- | ---------------------------------------- |
| Environment   | Local host-run and backend tests         |
| Persona       | authenticated admin                      |
| Fixture       | seeded or deterministic Settings fixture |
| Preconditions | Access section not yet complete          |

Steps:

1. Open `/admin/settings/access`.
2. Confirm read-only Login Methods, MFA Policy, and Signup/Invite rows are visible.
3. Confirm the explicit acknowledgement panel is visible.
4. Click the acknowledgement button.
5. Return to `/admin/settings`.

Expected results:

- Access saves through explicit acknowledge only.
- Page visit alone does not complete Access.
- Access completion does not fake-complete Personal.
- Banner remains while Personal is still incomplete.

Evidence:

- screenshot before acknowledgement
- screenshot of `Review saved`
- screenshot of overview showing Personal/Modules still needing work when applicable

---

### SET-04 — Account save never fake-completes required setup

| Field         | Value                                                              |
| ------------- | ------------------------------------------------------------------ |
| Environment   | Backend API proof plus optional browser visit                      |
| Persona       | authenticated admin                                                |
| Fixture       | deterministic Settings fixture with Access and Personal incomplete |
| Preconditions | Account card DTO loaded                                            |

Steps:

1. Read `/settings/account`.
2. Save Branding using the card version and cpRevision returned by the backend.
3. Read `/settings/bootstrap`.
4. Confirm next action still points to the first incomplete required section.

Expected results:

- Account local status may become In Progress or Complete for its card.
- Overall setup does not become Complete.
- Banner remains.
- Access/Personal required truth is unchanged.

Evidence:

- API test output or screenshot of Account page
- bootstrap response or overview screenshot proving banner remains

---

### SET-05 — Personal save drives required setup completion

| Field         | Value                                               |
| ------------- | --------------------------------------------------- |
| Environment   | Local host-run and backend tests                    |
| Persona       | authenticated admin                                 |
| Fixture       | Access already acknowledged, Personal not yet saved |
| Preconditions | `/admin/settings/modules/personal` loads            |

Steps:

1. Open `/admin/settings/modules/personal`.
2. Confirm Family Review, Field Configuration, and Section Builder are present.
3. Make a real draft change if the button is disabled, for example rename the first section.
4. Click `Save Personal Configuration`.
5. Return to `/admin`.

Expected results:

- Save uses the single Personal full-replacement contract.
- Personal becomes Complete when current required-floor and section assignment rules are satisfied.
- If Access is already complete, overall setup becomes Complete.
- `/admin` banner disappears.

Evidence:

- screenshot of Personal page before save
- screenshot of success message
- screenshot of `/admin` without setup banner

---

### SET-06 — Communications placeholder loads, Workspace Experience has no route, Permissions remains absent

| Field         | Value                         |
| ------------- | ----------------------------- |
| Environment   | Local host-run                |
| Persona       | authenticated admin           |
| Fixture       | any authenticated admin state |
| Preconditions | admin session established     |

Steps:

1. Open `/admin/settings/communications`.
2. Confirm page says live configuration is not available and mutation endpoints are not available.
3. Open `/admin/settings/workspace-experience`.
4. Open `/admin/settings/permissions`.

Expected results:

- Communications route loads as placeholder-only.
- Workspace Experience route returns 404.
- Permissions route returns 404.
- No fake save, configure, connect, or request-access action appears.

Evidence:

- screenshot of Communications placeholder page
- screenshot or browser/network proof of both 404 routes

---

### SET-07 — Version conflict is surfaced

| Field         | Value                                                         |
| ------------- | ------------------------------------------------------------- |
| Environment   | Backend API test; frontend conflict rendering where practical |
| Persona       | authenticated admin                                           |
| Fixture       | deterministic Settings fixture                                |
| Preconditions | read an old DTO version, then submit a stale mutation         |

Steps:

1. Read a mutable Settings DTO.
2. Save the same section once to increment version.
3. Submit another save with the original `expectedVersion`.

Expected results:

- Backend returns a conflict response.
- Frontend must not silently retry, discard draft, or swallow the conflict.
- User sees reload/review guidance when a conflict is surfaced through the UI.

Evidence:

- API response showing conflict code
- screenshot of frontend conflict guidance when manually reproduced

---

### SET-08 — CP revision conflict is surfaced

| Field         | Value                                                      |
| ------------- | ---------------------------------------------------------- |
| Environment   | Backend API test                                           |
| Persona       | authenticated admin                                        |
| Fixture       | deterministic Settings fixture                             |
| Preconditions | read Personal DTO, then change CP Personal allowance truth |

Steps:

1. Read `/settings/modules/personal` and keep the returned `cpRevision`.
2. Change CP allowance truth for the same tenant.
3. Submit the stale Personal payload.

Expected results:

- Backend rejects invalid stale payloads with a CP revision conflict.
- Backend accepts stale cpRevision only when the payload still remains valid under current CP truth.
- No frontend-derived truth is used to hide the conflict.

Evidence:

- API response showing CP revision conflict or valid stale-acceptance path

---

### SET-09 — CP required change triggers Needs Review; optional removal does not

| Field         | Value                                                        |
| ------------- | ------------------------------------------------------------ |
| Environment   | Backend API proof                                            |
| Persona       | authenticated admin                                          |
| Fixture       | deterministic Settings fixture completed to overall Complete |
| Preconditions | Access and Personal are complete                             |

Steps:

1. Remove an optional Personal field from CP allowance truth.
2. Read Settings bootstrap and Personal DTO.
3. Change a required Access setting from CP, such as Member MFA policy.
4. Read Settings bootstrap again.
5. Acknowledge Access under the new CP truth.

Expected results:

- Optional Personal removal prunes/hides the removed field and keeps overall status Complete.
- Required Access change sets Access and aggregate to Needs Review.
- Banner returns.
- Explicit Access acknowledgement clears Needs Review when no blockers remain.

Evidence:

- backend test output or captured API responses for each transition

---

### SET-10 — Migration/backfill and retired auth scaffold behave correctly

| Field         | Value                                                                           |
| ------------- | ------------------------------------------------------------------------------- |
| Environment   | Backend migration/backfill and readiness-gate proof                             |
| Persona       | developer/test runner                                                           |
| Fixture       | legacy scaffold tenant with `setup_completed_at`, plus a native Settings tenant |
| Preconditions | migration/backfill path and Settings readiness tests run                        |

Steps:

1. Create or load a tenant with legacy acknowledgement data and no native Settings state rows.
2. Run the migration/backfill path.
3. Inspect native Settings state rows.
4. Against a tenant that already has native Settings rows, call the retired auth acknowledgement route.
5. Re-read the native aggregate and Access section rows.

Expected results:

- Native aggregate row exists.
- Access can be backfilled to Complete only if legacy acknowledgement semantics still satisfy the current Access acknowledgement rule.
- Overall setup is not backfilled to Complete from legacy acknowledgement alone.
- Other live sections remain Not Started unless real persisted config supports a stronger state.
- The retired auth acknowledgement route returns normal route-miss behavior.
- The retired route does not mutate `tenants.setup_completed_at`, `tenant_setup_state`, or `tenant_setup_section_state`.
- Current `/admin` and `/admin/settings` behavior remains driven by `/settings/*` DTOs only.

Evidence:

- automated test output from `settings-foundation.spec.ts` and `settings-readiness-gate.spec.ts`

---

### SET-11 — Cross-tenant isolation and topology-safe Settings access

| Field         | Value                                                 |
| ------------- | ----------------------------------------------------- |
| Environment   | Local host-run plus full-stack proxy where available  |
| Persona       | authenticated admin                                   |
| Fixture       | admin session for one tenant and a second tenant host |
| Preconditions | admin is logged into tenant A                         |

Steps:

1. Request `/api/settings/bootstrap` on the same tenant host.
2. Request `/api/settings/bootstrap` on a different tenant host using the same browser context.
3. In full-stack mode, run proxy conformance checks.

Expected results:

- Same-tenant request succeeds.
- Cross-tenant request returns 401.
- Browser uses same-origin `/api/*` paths.
- SSR forwards Host/Cookie/X-Forwarded headers according to the topology contract.
- Direct backend origin is not a valid authenticated browser Settings path.

Evidence:

- Playwright output for Settings isolation proof
- proxy conformance output when run in full-stack mode

---

## Automated Proof Commands

Run these from the repo root unless noted.

| Proof                                           | Command                                                                                                                                                                                                                                                                                                                                        | What it proves                                                                                                                                                                               |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Backend Settings proof suite                    | `yarn workspace @auth-lab/backend test -- settings-proof-closure.spec.ts settings-foundation.spec.ts settings-access.spec.ts settings-account.spec.ts settings-concurrency.spec.ts settings-cp-cascade.spec.ts settings-modules-personal.spec.ts settings-integrations.spec.ts settings-read-surfaces.spec.ts settings-readiness-gate.spec.ts` | migration/backfill and retired-scaffold removal, required/optional CP cascade, account/personal concurrency, conflicts, placeholder/absent behavior, account non-gating, personal completion |
| Backend People & Teams proof suite              | `yarn workspace @auth-lab/backend test -- people-teams-read.spec.ts people-teams-groups.spec.ts people-teams-members.spec.ts`                                                                                                                                                                                                                  | tenant-scoped group reads/writes, membership management, admin-only protection, archived-group behavior, and audit coverage                                                                  |
| Frontend Settings and People & Teams unit proof | `yarn workspace frontend test:unit -- admin-settings people-teams`                                                                                                                                                                                                                                                                             | SSR page loaders and component rendering contract for Settings pages                                                                                                                         |
| Browser Settings proof                          | `yarn workspace frontend test:e2e test/e2e/settings.spec.ts`                                                                                                                                                                                                                                                                                   | real browser admin journey through `/admin`, Settings overview, People & Teams create/edit/archive/member management, Access acknowledge, Personal save, placeholders, and tenant isolation  |
| CP full-stack proof                             | `yarn workspace frontend test:e2e:cp`                                                                                                                                                                                                                                                                                                          | CP host create/publish/re-entry/status and tenant-host boundary in full-stack mode                                                                                                           |
| Proxy conformance                               | `./scripts/proxy-conformance.sh`                                                                                                                                                                                                                                                                                                               | Host preservation, `/api` stripping, cookie continuity, X-Forwarded headers, tenant isolation                                                                                                |

The browser Settings proof should start from a clean seeded local state. Run `yarn reset-db` and restart `yarn dev` before it when the admin MFA state is dirty.

---

## Evidence Expectations

For manual QA, collect:

- screenshot with URL bar visible for every pass/fail checkpoint
- exact error text for every failed expectation
- environment name and startup mode (`yarn dev`, `yarn dev:stack`, staging)
- persona used
- account key / tenant key used
- Mailpit screenshot for email-dependent flows
- browser console/network screenshot when a route fails unexpectedly
- automated command output for backend/frontend/Playwright proof

A QA pass without evidence is incomplete.

---

## Bug Reporting Expectations

Every bug report must include:

- title with area prefix (`AUTH`, `CP`, `SETTINGS`, `PROXY`, `DOCS`)
- environment and startup mode
- tenant host
- persona/email used
- fixture state or CP account key
- exact steps to reproduce
- expected result from this pack
- actual result
- screenshots or trace artifacts
- severity

### Severity guide

| Severity | Meaning                                     | Examples                                                                                 |
| -------- | ------------------------------------------- | ---------------------------------------------------------------------------------------- |
| P0       | security boundary or data isolation failure | cross-tenant Settings access succeeds, session accepted on wrong tenant                  |
| P1       | critical shipped flow broken                | admin cannot complete MFA, `/admin/settings` crashes, CP cannot publish a valid tenant   |
| P2       | shipped flow works only with workaround     | Personal save fails after normal edit, conflict message missing but API returns conflict |
| P3       | copy/layout/non-blocking issue              | minor typo, helper text mismatch, visual spacing issue                                   |

Do not mark future deferred scope as a bug unless this pack says the shipped repo should expose it.

---

## Signoff Checklist

QA signoff for the shipped Settings proof slice requires all of the following:

- local health check passed
- baseline auth flows passed
- CP smoke path passed or explicitly deferred to full-stack proof window
- Settings browser proof passed
- backend Settings proof suite passed
- migration/backfill proof passed
- CP required/optional cascade proof passed
- version conflict and CP revision conflict proof passed
- Communications placeholder and Permissions absent behavior passed
- cross-tenant isolation proof passed
- docs/runbooks checked against actual commands
- `docs/qa/settings-lock-certification.md` updated only as a lightweight final signoff record, referencing the final passing repo gate / CI checks instead of duplicating raw logs or screenshots
- all open bugs triaged with severity

CI green alone is not a substitute for truthful QA docs and runbooks. Keep this execution pack current, but do not duplicate CI logs or screenshot evidence inside certification docs.
