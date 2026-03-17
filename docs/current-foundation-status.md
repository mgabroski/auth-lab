# Hubins Auth-Lab — Current Foundation Status

## Purpose

This document is the repo's practical truth snapshot.

It exists to keep four things aligned:

- what the repository actually implements now
- what the active documentation claims
- what future implementation sessions assume
- what is intentionally deferred to later hardening phases

If another active document disagrees with this file about shipped scope, this file wins until the lower document is repaired.

---

## 1. High-level status

The repository is no longer only a topology or backend-foundation sandbox.

Today the repo contains all of the following as real implemented surfaces:

- the locked single-origin topology and FE/BE wiring
- the backend Auth + User Provisioning module
- the frontend Auth + User Provisioning route and UI surface for the current module scope
- the current admin invite-management surface
- a repeatable local auth test environment contract with committed env examples and a canonical dev seed entry point

That does **not** mean the broader Hubins product UI is finished.
It means the **Auth + User Provisioning slice is implemented at feature-surface level**, while later phases still own confidence hardening, broader product expansion, and additional non-auth modules.

---

## 2. What is implemented now

### 2.1 Repository and infrastructure foundation

The following are real and load-bearing:

- monorepo/workspace structure
- backend application
- frontend application
- Docker-based local infrastructure
- Postgres + Redis integration
- host-run and full-stack local workflows
- proxy conformance tooling for topology validation
- committed local env templates for backend/frontend host-run mode
- canonical local dev seed fixtures for auth/provisioning testing

### 2.2 Topology and session foundation

The following are real and load-bearing:

- single public-origin browser model
- same-origin browser API model using `/api/*`
- SSR direct-backend model using forwarded request context
- host-derived tenant identity
- proxy-compatible routing model
- tenant-bound server-side sessions
- backend-owned continuation truth through `nextAction`

### 2.3 Backend Auth + User Provisioning surface

The backend currently implements:

- `GET /auth/config`
- `GET /auth/me`
- register
- login
- logout
- public signup
- invite acceptance
- forgot/reset password
- email verification + resend verification
- MFA setup / verify / recovery
- Google + Microsoft SSO start/callback
- admin invite create/list/resend/cancel
- admin audit event listing
- outbox-backed email delivery for auth/provisioning flows
- canonical local dev seed fixtures through `yarn workspace @auth-lab/backend db:seed:dev`

### 2.4 Frontend Auth + User Provisioning surface

The frontend currently implements the real route/UI surface for the current auth/provisioning scope.

#### Public and continuation routes

- `/`
- `/auth`
- `/auth/login`
- `/auth/signup`
- `/auth/register`
- `/auth/forgot-password`
- `/auth/reset-password`
- `/accept-invite`
- `/verify-email`
- `/auth/mfa/setup`
- `/auth/mfa/verify`
- `/auth/sso/done`
- `/auth/unavailable`
- `/auth/continue/[action]`
- `/topology-check`

#### Authenticated routes

- `/app`
- `/admin`
- `/admin/invites`
- `/dashboard` (compatibility handoff)

#### Implemented frontend capabilities

- root bootstrap handoff
- public auth entry routing
- login flow
- public signup flow
- invite registration flow
- forgot-password flow
- reset-password flow
- accept-invite flow
- verify-email continuation flow
- MFA setup flow
- MFA verify flow
- SSO completion landing
- authenticated member landing
- authenticated admin landing
- admin invite management UI
- logout flow
- legacy dashboard compatibility handoff

This means the frontend is **not** accurately described as "foundation only" anymore.

---

## 3. Scope boundary for the implemented module

The current repo should be described like this:

> The topology/foundation layer is implemented, and the Auth + User Provisioning slice is implemented across backend and frontend for its current scope.

The repo should **not** be described like either of these:

> The repo is still only backend/auth groundwork with no real frontend auth surface.

or

> The full Hubins product frontend is already implemented.

Both are incorrect.

What remains outside this completed module scope:

- broader member product modules beyond the authenticated landing surface
- broader admin product modules beyond current invite management
- non-auth business modules
- broader product navigation across future modules
- future management screens unrelated to the current auth/provisioning slice

---

## 4. Canonical documentation-home decision

The repo's documentation home is **scope-split, not single-folder-only**.

### 4.1 Repo-wide truth and operational documents

These live at repo root and under `/docs`:

- `README.md`
- `ARCHITECTURE.md`
- `docs/current-foundation-status.md`
- `docs/developer-guide.md`
- `docs/decision-log.md`
- `docs/implementation-session-charter.md`
- `docs/security-model.md`
- `docs/ops/runbooks.md`

These documents define repo-wide truth, architecture framing, operational setup/reset guidance, and session discipline.

### 4.2 Backend law and contract documents

These live under `backend/docs/`.

Use that folder for:

- backend implementation law
- backend module structure law
- backend API contract documents
- backend module guides
- backend prompt artifacts

### 4.3 Frontend scope documents

Frontend guidance remains close to the frontend code surface:

- `frontend/README.md`
- `frontend/src/shared/engineering-rules.md`

### 4.4 What this decision means in practice

Do **not** invent a second parallel home for the same truth.

When updating docs:

- update repo-wide truth and operational setup/reset guidance in root `/docs`
- update backend-specific law/contracts in `backend/docs`
- update frontend-specific usage/law where the frontend already keeps it

Historical uploaded sources that are **not** in the repo are reference material only until they are explicitly adopted into the repository.

---

## 5. Active authority chain for implementation sessions

For the current repo phase, the working truth chain is:

1. `Hubins User Provisioning.pdf` for locked business behavior and vocabulary
2. `hubins-topology-plan.docx` for locked topology and routing/session constraints
3. repo-root truth documents (`README.md`, `ARCHITECTURE.md`, this file, `docs/decision-log.md`, `docs/security-model.md`)
4. `docs/developer-guide.md` for truthful local environment, reset, seed, persona, and test-running guidance
5. repo engineering-law documents actually present in the codebase
6. `backend/docs/api/*.md`
7. adopted scope-specific guides such as `frontend/README.md`
8. derived execution prompts that remain aligned to the above

If a lower document disagrees with a higher one, the lower document must be corrected or retired.

---

## 6. Known limitations and intentionally deferred items

### 6.1 Deferred beyond the current implemented slice

The provisioning PDF explicitly names later capabilities that are **not** current shipped scope, including:

- HRIS import flow and admin controls
- SCIM
- SAML SSO
- suspend-users management surface beyond current foundations
- groups and teams
- session-control/device-management features
- enhanced MFA methods beyond the current TOTP/recovery implementation

These are not documentation omissions.
They are intentionally deferred beyond the current shipped slice.

### 6.2 Current confidence and regression protection status

Phase 3 added the current regression/confidence surface for the shipped auth/provisioning slice, including:

- backend nextAction contract coverage across login, signup, register, and `/auth/me` agreement
- continuation-flow contract coverage for invite acceptance outcomes (`SET_PASSWORD`, `SIGN_IN`, `MFA_SETUP_REQUIRED`)
- frontend unit coverage for route-state resolution, SSR bootstrap sequencing, and same-origin browser API discipline
- frontend auth-flow E2E coverage for member login/logout, admin MFA continuation, and signup-to-verify-email routing
- outbox worker lifecycle coverage for send, retry scheduling, non-retryable dead-lettering, and max-attempt dead-lettering

This improves confidence for the current shipped slice, but it does **not** mean all future hardening work is finished. Phase 4 still owns any broader cleanup, optional expansion, and non-scope redesign work.

### 6.3 Outbox observability / dead-letter visibility classification

Current outbox observability is **backend-internal / operator-visible only**.

What exists today:

- structured worker/event logs for claim, send, retry, dead-letter, and lost-claim paths
- durable outbox row state in `outbox_messages` (`status`, `attempts`, `last_error`, lease fields, availability timestamps)
- lifecycle regression tests that now prove those states and transitions

What does **not** exist today:

- admin-facing outbox viewer UI
- admin-facing dead-letter retry controls
- non-technical operator tooling for outbox inspection

That remains intentionally outside the current module scope.

---

## 7. Truthful current environment statement

As of this repo state:

- local host-run mode is the primary daily development path
- local full-stack Docker mode is the topology-validation path
- the repo now contains committed env examples for host-run setup
- the repo now contains a canonical dev seed command and canonical local auth fixtures
- shared staging/QA and production expectations are documented, but their full operator/bootstrap proof belongs to later roadmap phases

Any document claiming shared staging/QA or production bootstrap is already fully proven in this repo is overstating the current reality.
