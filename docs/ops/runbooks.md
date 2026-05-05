# Hubins Auth-Lab — Operations Runbooks (Auth + Control Plane + Settings)

## Purpose

This document is the operator-facing runbook for the currently implemented Auth, Control Plane, and shipped Settings surfaces.

It exists to answer:

- how to confirm the local stack is healthy
- how to bootstrap and validate the current auth flows
- how to validate and recover the current Control Plane publish/status flows
- how to validate and recover the shipped Settings flows
- what operational notes matter for the current Personal full-replacement save contract

If a flow is not implemented, this runbook does not pretend it exists.

---

## 1. System dependencies and health checks

### Expected local services

- frontend
- backend
- Postgres
- Redis
- Mailpit
- local proxy
- Control Plane frontend

### Useful commands

- `yarn dev` — primary local startup path
- `yarn dev:stack` — full proxy-routed stack when boundary proof is needed
- `yarn status` — current service/status check
- `yarn reset-db` — wipe local data and rebuild from seed state
- `yarn stop` — stop local services

### Fast health checks

- tenant health: `http://goodwill-ca.lvh.me:3000/api/health`
- backend health: `http://localhost:3001/health`
- CP app, host-run: `http://localhost:3002/accounts`
- CP app, proxy topology proof: `http://cp.lvh.me:3000/accounts`
- CP host-run API shim: `http://localhost:3002/api/cp/accounts`
- Mailpit: `http://localhost:8025`

---

## 2. Control Plane operational notes

### Control Plane env contract

The Control Plane is a permanent internal product surface. Its no-auth access is not permanent.

- `CP_ENABLED=true` registers backend `/cp/*` routes.
- `CP_AUTH_MODE=none` is only for local development and CI while dedicated CP auth is deferred.
- `CP_AUTH_MODE=session` is the future production direction and currently fails closed until CP auth ships.
- `CP_NO_AUTH_ALLOWED` is deprecated compatibility only; do not add it to new env files.
- `yarn dev` injects `CP_ENABLED=true` and `CP_AUTH_MODE=none` for host-run local development so stale `backend/.env` files do not silently disable CP routes.

If `http://localhost:3002/api/cp/accounts` returns `404`, verify that the backend process was started with `CP_ENABLED=true`. If it returns `401`, CP routes exist but are running in a non-no-auth mode.

Current real CP operator path:

1. create draft account
2. save required Step 2 groups
3. save Personal CP sub-page when Personal is enabled
4. review Activation Ready
5. publish Active or Disabled
6. re-enter later through accounts list
7. toggle Active/Disabled after publish as needed

Important current truth:

- publish and status-only changes do not increment `cpRevision`
- meaningful allowance changes do increment `cpRevision`
- CP allowance truth remains separate from tenant Settings configuration truth

---

## 3. Settings operational notes

### Current shipped Settings routes

- `GET /settings/bootstrap`
- `GET /settings/overview`
- `GET /settings/access`
- `POST /settings/access/acknowledge`
- `GET /settings/account`
- `PUT /settings/account/branding`
- `PUT /settings/account/org-structure`
- `PUT /settings/account/calendar`
- `GET /settings/modules`
- `GET /settings/modules/personal`
- `PUT /settings/modules/personal`
- `GET /settings/integrations`
- `GET /settings/communications`

### Integrations readiness note

`GET /settings/integrations` is read-only and informational in v1.

Operational expectations:

- Settings reads must not make live outbound calls to Google, Microsoft, Stripe, HRIS providers, or marketplace systems.
- Google and Microsoft SSO readiness is based on cached auth/runtime readiness truth only.
- If the readiness snapshot is missing, stale, or invalid, the Settings page must show a degraded `BLOCKED` state with a warning.
- Do not treat a degraded Integrations card as proof that provider credentials are wrong by itself. First confirm whether the cached auth/runtime readiness snapshot exists and is fresh.
- HRIS providers and Stripe are deferred tenant-configuration cards; there is no tenant credential recovery or sync runbook for them in v1.

Operator triage for degraded SSO readiness:

1. Confirm the tenant CP setup allows the relevant SSO integration.
2. Confirm Access & Security has the matching login method enabled when the provider is expected to be in use.
3. Confirm auth/runtime SSO configuration is present in the active environment.
4. Refresh the Settings page and verify whether the cached readiness snapshot becomes fresh.
5. If the card remains degraded while real SSO login is expected to work, treat it as an auth/runtime readiness snapshot bug, not as a tenant Settings write issue.

### Personal save request-size note

`PUT /settings/modules/personal` is intentionally a full-replacement payload.
Each save sends:

- all family decisions
- all field decisions
- all section assignments

This is acceptable in the current v1 design, but operators should treat it as the heaviest Settings write path.

Operational expectations:

- do not proxy-truncate or aggressively rewrite request bodies for this route
- keep request-body limits comfortably above normal Personal payload size
- prefer normal admin interaction cadence; do not script rapid-fire repeated Personal saves
- investigate repeated `400` or `409` responses before retrying manually

### Personal conflict behavior

If a Personal save returns `409`:

- the frontend must keep the local draft
- the frontend refetches the latest server DTO
- the admin must reconcile intentionally
- there is no silent auto-merge and no silent retry

### Personal validation behavior

The backend rejects Personal saves when any of the following are true:

- empty section present
- included field missing from section assignments
- field assigned more than once
- excluded field still marked required or masked
- required-floor or system-managed field removed from the included required baseline
- payload no longer matches the tenant's current allowed Personal scope

---

## 4. Recovery guidance

### Reset local Settings state

When local Settings testing becomes unreliable:

1. run `yarn reset-db`
2. restart with `yarn dev`
3. reprovision or reload the tenant through Control Plane if needed
4. repeat the failing Settings flow from a clean browser state

### CP / Settings mismatch suspicion

If tenant runtime does not match recent CP allowance changes:

1. confirm the CP change actually saved
2. confirm the account publish/status state is what you expect
3. reload the tenant Settings surface
4. inspect whether the relevant Settings section is now `NEEDS_REVIEW`
5. if the mismatch persists after a clean reset, treat it as a bug in synchronous CP -> Settings cascade handling

---

## 5. Boundaries that remain intentional

The current repo still does **not** ship:

- tenant-facing Integrations write flows
- Integrations tenant credential entry, mapping editor, import rules UI, sync execution, or provider recovery flows
- Communications configuration
- Workspace Experience configuration
- Permissions configuration
- a giant all-settings publish action

Do not invent recovery steps for surfaces that are not implemented.

---

## 6. Settings proof and QA closure runbook

### Purpose

Use this runbook when validating the shipped Settings v1 proof pack or investigating a failed Settings QA run. This runbook is intentionally operational; product scope remains defined by the Settings docs and API contracts.

### Canonical reset before Settings proof

Use a clean local state for browser proof because the admin MFA setup flow mutates seeded state.

```bash
yarn reset-db
yarn dev
```

Wait until the frontend, backend, CP app, Mailpit, and local helper services are healthy. Then run the Green-Light Health Check in `docs/qa/qa-execution-pack.md`.

### Automated proof commands

Backend Settings proof:

```bash
yarn workspace @auth-lab/backend test -- settings-proof-closure.spec.ts settings-foundation.spec.ts settings-access.spec.ts settings-account.spec.ts settings-concurrency.spec.ts settings-cp-cascade.spec.ts settings-modules-personal.spec.ts settings-integrations.spec.ts settings-read-surfaces.spec.ts settings-readiness-gate.spec.ts
```

Browser Settings proof against the local tenant origin:

```bash
yarn workspace frontend test:e2e test/e2e/settings.spec.ts
```

Full-stack CP/proxy proof, when the stack is running in proxy mode:

```bash
yarn workspace frontend test:e2e:cp
./scripts/proxy-conformance.sh
```

### Deterministic Settings fixtures

The backend proof suite uses `backend/test/helpers/settings-fixtures.ts` to build deterministic tenant states through the same public test-facing HTTP paths used by the shipped product:

1. create a CP account
2. save CP integrations
3. save CP Access
4. save CP Account Settings
5. save CP Module Settings
6. save CP Personal catalog when Personal is enabled
7. publish the tenant as Active
8. create an authenticated admin session
9. drive Settings saves through `/settings/*`

Do not replace these fixtures with ad hoc SQL unless the test is specifically about migration/backfill mechanics. SQL-only setup hides the CP-to-Settings cascade and gives false confidence.

### Backfill and retired-scaffold proof expectations

Legacy scaffold backfill is conservative by design and is limited to migration/backfill behavior. The active auth acknowledgement route has been retired and must not act as a Settings writer.

Expected backfill behavior:

- native Settings state rows are created
- legacy Access acknowledgement may initialize Access as `COMPLETE` only during the explicit bridge/backfill path
- aggregate setup must not become `COMPLETE` from legacy acknowledgement alone
- other live sections remain `NOT_STARTED` unless real native configuration supports a stronger state

Expected active-route behavior:

- `POST /auth/workspace-setup-ack` returns normal route-miss behavior
- the retired route does not update `tenants.setup_completed_at`
- the retired route does not update `tenant_setup_state` or `tenant_setup_section_state`
- `/admin` and `/admin/settings` continue to use `/settings/*` truth only

If a legacy tenant becomes overall `COMPLETE` from scaffold acknowledgement alone, treat that as a P1 false-readiness bug. If the retired auth acknowledgement route can still mutate setup state, treat that as a P0 competing-truth regression.

### CP cascade proof expectations

Required CP changes must create review work when they affect a required Settings boundary.

Expected behavior:

- required Access changes set Access and aggregate to `NEEDS_REVIEW`
- required Personal target changes set Personal and aggregate to `NEEDS_REVIEW`
- optional Personal removals prune/hide the removed optional field without forcing review
- Account Settings remains non-gating and must not control banner lifecycle

If CP writes commit while the corresponding Settings cascade fails, treat it as a P0/P1 consistency issue depending on user impact.

### Conflict and concurrent-write proof expectations

Settings writes are optimistic-concurrency guarded.

Expected behavior:

- stale `expectedVersion` returns a version conflict
- stale `expectedCpRevision` is accepted only when the submitted payload is still valid under current CP truth
- invalid stale CP snapshot returns a CP revision conflict
- two concurrent Account card saves using the same card version produce exactly one success and one conflict
- two concurrent Personal full-replacement saves using the same section version produce exactly one success and one conflict
- the final persisted DTO must match the successful request, not whichever request happened to finish last
- frontend must never silently retry, discard, or hide conflict state

When this proof fails, treat it as a P1 data-loss risk. Do not debug it as a flaky UI issue first; inspect the repository write predicate, transaction boundary, and Settings section transition version check.

### Tenant and topology proof expectations

For browser proof:

- admin browser paths use the tenant origin and `/api/*` proxy path
- same-tenant `/api/settings/bootstrap` succeeds after login
- another tenant host returns 401 in the same browser context
- direct backend origin is not a valid authenticated browser Settings path

For full-stack proxy proof, use the proxy conformance script and CP smoke spec. Host preservation, cookie continuity, and `/api` prefix stripping are topology contracts and should not be debugged inside Settings code first.

### Evidence required for closure

A Settings closure run must retain:

- backend command output for Settings proof specs
- Playwright output or trace for `test/e2e/settings.spec.ts`
- proxy conformance output when full-stack topology is in scope
- screenshots for manual QA cases listed in `docs/qa/qa-execution-pack.md`
- bug report links for every failed or deferred case

CI green is necessary but not sufficient for closure.
