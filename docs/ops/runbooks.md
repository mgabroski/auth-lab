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
- CP app: `http://localhost:3002/accounts`
- Mailpit: `http://localhost:8025`

---

## 2. Control Plane operational notes

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
- Communications configuration
- Workspace Experience configuration
- Permissions configuration
- a giant all-settings publish action

Do not invent recovery steps for surfaces that are not implemented.
