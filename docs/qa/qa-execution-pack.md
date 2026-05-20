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
- `/admin/settings/operational-access` configuration shell behavior when the CP-owned capability is enabled
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
- Permissions tenant surface
- Operational Access runtime behavior beyond the selected backend people / Personal Card resolver proof surface, including Assigned Areas and broad module-consumer enforcement
- documents, benefits, payments, marketplace tenant modules
- CP authentication
- CP operator RBAC
- CP audit viewer UI
- production load/performance testing
- Operational Access runtime QA beyond the selected backend people / Personal Card proof surface, including Assigned Areas, search/export/notification leak proof, Benefits high-sensitivity proof, PDFs/generated outputs, and broad module integration proof

When a future surface is intentionally absent or placeholder-only, missing configuration UI is not a bug.

---

## Operational Access QA Status

Active planning source:

```text
hubins-operational-access-9_5-source-of-truth-guide-final.md
```

Current shipped truth:

- backend runtime roles are `ADMIN | AGENT | USER`
- `MEMBER` is a legacy alias for `USER`
- People & Teams foundation groups and group memberships are implemented
- group levels `ADMIN / AGENT / USER` do not grant Operational Access by themselves
- Agent Groups can receive Operational Access configuration only when the tenant capability is enabled
- Primary Where and Which Records configuration exists for product-defined choices
- Responsible For exact-person configuration exists using active tenant membership IDs
- Oversight, Temporary Coverage, and Special Access are implemented only for the selected backend people / Personal Card resolver proof surface
- Effective Access Resolver v1 is implemented for `personal_cards.view` only
- Assigned Areas are not implemented because stable employer/location pair IDs do not exist yet
- current `/admin/settings/access` is Access & Security, not Operational Access
- `/admin/settings/operational-access` is executable only when the CP-owned `operational_access_enabled` capability is enabled

Executable backend proof now covers the selected people / Personal Card surface:

| ID        | Scenario                          | Proof intent                                                                                                                                                            | Current status                                  |
| --------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| OA-RUN-01 | Admin full tenant access by level | Admin sees all active tenant people through the backend set resolver without needing Agent Groups, coverage keys, or Special Access. Explanation source is Admin level. | Executable backend proof                        |
| OA-RUN-02 | User own/self-service access      | User sees only their own people record and direct access to another person's record is denied.                                                                          | Executable backend proof                        |
| OA-RUN-03 | Agent with no operational access  | Agent with no active operational grants receives a safe empty people set.                                                                                               | Executable backend proof                        |
| OA-RUN-04 | Grant without coverage            | Agent with a grant but no matching coverage receives no people.                                                                                                         | Executable backend proof                        |
| OA-RUN-05 | Grant + Responsible For coverage  | Agent sees only explicitly responsible people for `personal_cards.view`.                                                                                                | Executable backend proof                        |
| OA-RUN-06 | Direct API denial                 | Backend denies unauthorized direct person detail access even if a URL is typed manually.                                                                                | Executable backend proof                        |
| OA-RUN-07 | Set-based list filtering          | Runtime people list is filtered by backend-resolved ID set, not frontend filtering.                                                                                     | Executable backend proof                        |
| OA-RUN-08 | Masking / leak check              | Agent runtime people output masks email and explanations do not contain hidden email values.                                                                            | Executable backend proof                        |
| OA-RUN-09 | Oversight non-reciprocal          | If A oversees B, B does not see A unless explicitly granted.                                                                                                            | Executable backend proof                        |
| OA-RUN-10 | Oversight include-team = No       | A sees B as the oversight target but not B's responsible people/work.                                                                                                   | Executable backend proof                        |
| OA-RUN-11 | Oversight include-team = Yes      | A sees B and B's direct Responsible For people/work.                                                                                                                    | Executable backend proof                        |
| OA-RUN-12 | Oversight single-hop              | If A oversees B and B oversees C, A does not automatically see C's team in MVP.                                                                                         | Executable backend proof                        |
| OA-RUN-13 | Temporary Coverage                | Active Temporary Coverage grants the intended covered person's keys and expired coverage grants nothing.                                                                | Executable backend proof                        |
| OA-RUN-14 | Special Access                    | Rare one-person extra access requires reason, review date, expiry, and appears in the source path.                                                                      | Executable backend proof                        |
| OA-RUN-15 | Cross-tenant target denial        | Operational Access configuration and runtime reads cannot cross tenant boundaries.                                                                                      | Covered by validation/fail-closed backend proof |

Still planning-only until future implementation exists:

| Future ID | Scenario                         | Future proof intent                                                                                                         | Current status |
| --------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | -------------- |
| OA-FUT-01 | Assigned Areas                   | Agent can operate only inside explicit employer/location pairs or module-equivalent area keys.                              | Not executable |
| OA-FUT-02 | Search leak prevention           | Hidden records and sensitive fields do not leak through counts, suggestions, autocomplete, or snippets.                     | Not executable |
| OA-FUT-03 | Notification leak prevention     | In-app/email/push notifications do not include sensitive hidden content.                                                    | Not executable |
| OA-FUT-04 | Export/generated output masking  | CSV, PDF, email attachments, and reports obey backend-resolved visibility and masking.                                      | Not executable |
| OA-FUT-05 | Benefits high-sensitivity access | Enrollment/benefit-sensitive records require explicit high-sensitivity access; broad Manage does not imply unmasked access. | Not executable |
| OA-FUT-06 | Full Personal Cards UI           | Tenant-facing Personal Card runtime UI consumes the backend resolver and resolved masking.                                  | Not executable |

Current executable Operational Access QA covers the capability-gated shell, configuration foundation, advanced coverage writes, Special Access writes, and the selected backend runtime people resolver proof. Broad module integrations remain future work.

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

| Persona                                         | Tenant          | Role  | Use                                              |
| ----------------------------------------------- | --------------- | ----- | ------------------------------------------------ |
| `member@example.com / Password123!`             | `goodwill-open` | User  | user login, logout, workspace routing            |
| `e2e-admin@example.com / Password123!`          | `goodwill-open` | Admin | admin landing, MFA setup, Settings browser proof |
| `e2e-recovery-admin@example.com / Password123!` | `goodwill-open` | Admin | MFA recovery proof                               |
| `e2e-reset-member@example.com / Password123!`   | `goodwill-open` | User  | password reset proof                             |

### Tenant fixtures

| Fixture              | URL                                | Purpose                                                 |
| -------------------- | ---------------------------------- | ------------------------------------------------------- |
| GoodWill Open        | `http://goodwill-open.lvh.me:3000` | public signup enabled, seeded User/Admin personas       |
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

| ID   | Action                                                      | Expected result        | Evidence                      |
| ---- | ----------------------------------------------------------- | ---------------------- | ----------------------------- |
| HC-1 | Open `http://goodwill-ca.lvh.me:3000/api/health`            | healthy response       | screenshot or copied response |
| HC-2 | Open `http://goodwill-open.lvh.me:3000/auth/login`          | login page loads       | screenshot                    |
| HC-3 | Open `http://localhost:3002/accounts`                       | CP Accounts page loads | screenshot                    |
| HC-4 | Open `http://localhost:8025`                                | Mailpit loads          | screenshot                    |
| HC-5 | Log in as seeded User `member@example.com` on GoodWill Open | reaches `/app`         | screenshot                    |

Stop immediately if any health check fails.

---

## Role and Workspace Routing QA Cases

These cases close the current Admin / Agent / User frontend truth without claiming future Operational Access behavior is shipped.

| ID           | Scenario                                           | Persona                                                         | Expected result                                                                                                                                                                                                                         | Evidence                                  |
| ------------ | -------------------------------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| AUTH-ROLE-01 | Admin sign-in routes to admin surface              | `e2e-admin@example.com` after MFA                               | lands on `/admin`; `/app` is not used as the admin landing                                                                                                                                                                              | screenshot with URL bar                   |
| AUTH-ROLE-02 | User sign-in routes to workspace shell             | `member@example.com` fixture with canonical `USER` runtime role | lands on `/app`; no admin navigation or Settings navigation is visible                                                                                                                                                                  | screenshot with URL bar                   |
| AUTH-ROLE-03 | Agent sign-in routes to neutral workspace shell    | Agent persona prepared by developer or automated fixture        | lands on `/app`; shell does not show fake Tasks, Documents, Checklists, Operational Access, Access Grants, Responsible For, Assigned Areas, Oversight, Temporary Coverage, Special Access, Effective Access Resolver, or Permissions UI | screenshot with URL bar                   |
| AUTH-ROLE-04 | Agent cannot access admin surfaces                 | Agent persona prepared by developer or automated fixture        | typing `/admin`, `/admin/settings`, or `/admin/settings/access` redirects away from admin content                                                                                                                                       | screenshot of redirect                    |
| AUTH-ROLE-05 | User cannot access admin surfaces                  | `member@example.com` fixture with canonical `USER` runtime role | typing `/admin`, `/admin/settings`, or `/admin/settings/access` redirects away from admin content                                                                                                                                       | screenshot of redirect                    |
| AUTH-ROLE-06 | Invite level choices use current product language  | Admin invite page                                               | visible level choices are `User`, `Agent`, and `Admin`; `Member` is not selectable                                                                                                                                                      | screenshot of invite form                 |
| AUTH-ROLE-07 | Agent invite group assignment is provisioning-only | Admin invite page with active Agent group fixture               | Agent invite requires at least one active Agent group; User/Admin invite does not send Agent group IDs; copy must not claim group membership grants module access or visibility                                                         | screenshot and request trace if available |

Notes:

- `member@example.com` is a historical fixture email. It represents canonical `USER` behavior.
- Agent manual browser proof may require developer-prepared state until a stable seeded Agent persona is added.
- Operational module data differences remain future backend-resolved Operational Access work and are not manually executable yet.

---

## Execution Order

Run cases in this order unless a focused bug task explicitly needs a smaller subset.

1. Baseline login, logout, and Admin / Agent / User routing proof
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
5. Confirm `Operational Access` is not shown for the default disabled capability tenant.
6. Look for `Permissions`.

Expected results:

- Access and Modules/Personal are required setup paths.
- People & Teams is visible as a live, non-gating management surface.
- Communications is placeholder-only.
- Workspace Experience is overview-only placeholder.
- Operational Access is hidden by default unless `operational_access_enabled` is enabled for the tenant.
- Permissions is absent: no card, no CTA, no placeholder.

Evidence:

- screenshot of overview required sections
- screenshot of overview optional sections

### SET-02A — Operational Access shell is capability-gated

| Field         | Value                                                                             |
| ------------- | --------------------------------------------------------------------------------- |
| Environment   | Local host-run                                                                    |
| Persona       | authenticated admin                                                               |
| Fixture       | tenant with CP-owned `operational_access_enabled = true`; default disabled tenant |
| Preconditions | admin session established                                                         |

Steps:

1. Open `/admin/settings` on a tenant where `operational_access_enabled = false`.
2. Confirm no `Operational Access` card appears.
3. Open `/admin/settings/operational-access` on that disabled tenant.
4. Open `/admin/settings` on a tenant where `operational_access_enabled = true`.
5. Click the `Operational Access` card.
6. Read the shell content.
7. Sign in as Agent/User or use an Agent/User fixture and type `/admin/settings/operational-access` directly.

Expected results:

- Disabled tenants do not show the Operational Access card.
- Disabled tenants cannot access the shell route; the route returns not found or redirects through normal admin route handling.
- Enabled tenants show a live non-gating `Operational Access` card.
- Enabled admin users see the Operational Access configuration shell.
- The shell explicitly confirms that group grants, Responsible For, Oversight, Temporary Coverage, Special Access, and the backend people resolver proof are available, while Assigned Areas and broad module integrations remain deferred.
- Agent/User cannot access the admin shell.
- `/admin/settings/access` remains Access & Security and is unchanged.

Evidence:

- screenshot of disabled tenant overview without Operational Access card
- screenshot of enabled tenant overview with Operational Access card
- screenshot of Operational Access shell copy
- screenshot of Agent/User route denial or redirect

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
6. Add an active tenant user to the selected group.
7. Remove that user from the group.
8. Archive the group.
9. Confirm the archived group disappears from the normal active group list.
10. Confirm there is no restore action in the current foundation.
11. Confirm no Operational Access grants, Primary Where, Which Records, Additional Coverage, Special Access, Responsible For, Oversight, Temporary Coverage, `Can see`, or `Can do` UI appears.

Expected results:

- Admin can create, edit, archive, add member, and remove member.
- Archived groups disappear from the normal active group list.
- Restore is not shipped in the current foundation.
- Group membership management uses active tenant memberships only.
- The page remains a non-gating Settings management surface.
- Group membership does not change runtime role and does not grant module access.
- No Operational Access grant/configuration UI appears inside People & Teams.

Evidence:

- screenshot of People & Teams page after create
- screenshot after group member add/remove
- screenshot after archive showing the group is no longer in the active list
- screenshot or note confirming no restore action or Operational Access controls are visible

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
5. Confirm this case is separate from `/admin/settings/operational-access`, which is covered by SET-02A and is capability-gated.

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
3. Change a required Access setting from CP, such as the self-service MFA policy.
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

| Proof                                           | Command                                                                                                                                                                                                                                                                                                                                        | What it proves                                                                                                                                                                                                                                     |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Backend Settings proof suite                    | `yarn workspace @auth-lab/backend test -- settings-proof-closure.spec.ts settings-foundation.spec.ts settings-access.spec.ts settings-account.spec.ts settings-concurrency.spec.ts settings-cp-cascade.spec.ts settings-modules-personal.spec.ts settings-integrations.spec.ts settings-read-surfaces.spec.ts settings-readiness-gate.spec.ts` | migration/backfill and retired-scaffold removal, required/optional CP cascade, account/personal concurrency, conflicts, placeholder/absent behavior, account non-gating, personal completion                                                       |
| Backend People & Teams proof suite              | `yarn workspace @auth-lab/backend test -- people-teams-read.spec.ts people-teams-groups.spec.ts people-teams-members.spec.ts people-teams-migration.spec.ts`                                                                                                                                                                                   | tenant-scoped group reads/writes, membership management, admin-only protection, archived-group behavior, migration rollback safety, and audit coverage                                                                                             |
| Backend Operational Access foundation proof     | `yarn workspace @auth-lab/backend test -- operational-access-foundation.spec.ts operational-access-resolver.spec.ts operational-access-governance-hardening.spec.ts personal-cards-operational-access.spec.ts`                                                                                                                                 | capability gating, admin-only config, group membership grants nothing, grant + coverage behavior, direct detail bypass denial, oversight, temporary coverage, Special Access, masking, Why safety, scoped advanced saves, and audit hardening      |
| Backend role/invite provisioning proof          | `yarn workspace @auth-lab/backend test -- admin-invites.spec.ts invites-accept.spec.ts auth-sso-google-callback.spec.ts auth-sso-microsoft-callback.spec.ts backend-admin-guards.spec.ts`                                                                                                                                                      | canonical role outputs, legacy MEMBER-to-USER compatibility, public/SSO USER provisioning, Agent invite group validation, SSO Agent invite activation, token preservation on failed Agent group revalidation, and AGENT/USER admin-guard rejection |
| Frontend Settings and People & Teams unit proof | `yarn workspace frontend test:unit -- admin-settings people-teams`                                                                                                                                                                                                                                                                             | SSR page loaders and component rendering contract for Settings pages                                                                                                                                                                               |
| Frontend role/workspace proof                   | `yarn workspace frontend test:unit -- workspace-app-page admin-invite-management admin-settings`                                                                                                                                                                                                                                               | ADMIN / AGENT / USER routing, Agent/User admin Settings guard behavior, User/Agent invite UI language, Agent group selection rules, and neutral workspace shell without fake Operational Access surfaces                                           |
| Browser Settings proof                          | `yarn workspace frontend test:e2e test/e2e/settings.spec.ts`                                                                                                                                                                                                                                                                                   | real browser admin journey through `/admin`, Settings overview, People & Teams create/edit/archive/member management, archive disappearance/no-restore proof, Access acknowledge, Personal save, placeholders, and tenant isolation                |
| CP full-stack proof                             | `yarn workspace frontend test:e2e:cp`                                                                                                                                                                                                                                                                                                          | CP host create/publish/re-entry/status and tenant-host boundary in full-stack mode                                                                                                                                                                 |
| Proxy conformance                               | `./scripts/proxy-conformance.sh`                                                                                                                                                                                                                                                                                                               | Host preservation, `/api` stripping, cookie continuity, X-Forwarded headers, tenant isolation                                                                                                                                                      |

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

## Operational Access Step 4 QA notes

Operational Access QA is now executable for configuration foundation, advanced coverage, Special Access, the OA-owned runtime people proof surface, and the first real module proof surface at `/personal/cards`.

Executable now:

- Capability disabled tenants do not expose `/admin/settings/operational-access`.
- Capability enabled tenants expose the admin-only Operational Access settings page.
- Agent/User sessions cannot access admin-only Operational Access configuration routes or `/admin/settings/operational-access`.
- Runtime proof routes and Personal Cards module routes use backend-resolved access for Admin, Agent, and User actors.
- Active Agent groups can receive valid product-defined grants.
- Archived groups and non-Agent groups cannot receive Agent Operational Access grants.
- Invalid action keys, invalid Primary Where values, invalid Which Records values, and invalid action/where/record combinations are rejected.
- Oversight, Temporary Coverage, and Special Access are not accepted as Primary Where values.
- Responsible For coverage accepts only active Agent group members and active same-tenant target memberships.
- Cross-tenant group and membership IDs fail closed.
- Agent group membership alone still does not create runtime visibility.
- Agent with grant but no coverage receives a safe empty runtime people set.
- Agent with grant plus Responsible For sees only matching people.
- `/personal/cards` list is backend-filtered and never relies on frontend filtering.
- `/personal/cards/:membershipId` denies unauthorized direct detail bypass.
- User sees own/self-service Personal Card only.
- Admin sees by Admin level and the source path reports Admin-level truth.
- Oversight is directed, non-reciprocal, and single-hop.
- Oversight include-team false versus true behavior is proven.
- Temporary Coverage grants only during the active time window and expires automatically.
- Special Access requires reason, review date, expiry, and exact target/action.
- Special Access expiry fails closed.
- Advanced coverage saves are subject-scoped and must not wipe unrelated rows.
- Advanced coverage saves require the current `expectedVersion`; stale saves fail with 409 and do not overwrite current rows.
- Advanced coverage and Special Access success audit includes meaningful before/after detail.
- Rejected advanced coverage/Special Access mutations write failure audit where infrastructure supports it.
- Runtime people and Personal Cards output masks email for Agents, masks/hides sensitive proof fields for Agents, omits fields outside the proof card, and backend explanations avoid hidden field values.

Still not executable:

- Assigned Areas coverage, because stable employer/location pair IDs do not exist yet.
- Broad module integrations beyond the selected Personal Cards proof surface.
- Search/export/notification/PDF/generated-output visibility propagation.
- Full Personal Cards UI runtime flow; only backend module API proof is executable now.
