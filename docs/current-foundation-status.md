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
- a repeatable local auth test environment contract with committed Mailpit-based local email capture and a canonical dev seed entry point
- an explicit operator-safe tenant bootstrap command that queues the first admin invite through the real outbox + SMTP path without raw token logging
- a documented manual bootstrap proof runbook for invite onboarding through session creation and MFA continuation
- a documented Phase 4 runbook for public signup, email verification, resend verification, and password recovery proof
- a real MFA setup page that now renders a scannable QR from the backend `otpauth://` URI plus issuer/account preview for manual Phase 5 proof
- a documented Phase 5 runbook for real authenticator-app setup, MFA login verification, and recovery-code single-use proof
- backend/frontend example env files now exist and document the Google + Microsoft SSO staging keys engineers must set before live-provider proof
- a documented Phase 6 runbook for real Google SSO staging proof, including redirect URI, JWKS reachability, expired-invite rejection, MFA continuation, and audit/session validation
- a documented Phase 7 runbook for real Microsoft SSO staging proof, including Azure portal app-registration steps, claim fallback and issuer resolution proof, expired-invite rejection, MFA continuation, and audit/session validation

That does **not** mean the broader Hubins product UI is finished.
It means the **Auth + User Provisioning slice is implemented at feature-surface level**, while later phases still own confidence hardening, broader product expansion, and additional non-auth modules.

---

## 2. What is implemented now

### 2.1 Repository and infrastructure foundation

The following are real and load-bearing:

- monorepo/workspace structure
- backend application
- frontend application
- proxy/container topology for full-stack local testing
- host-run development path using local backend + local frontend + infrastructure services
- Postgres and Redis infrastructure
- Mailpit local email capture for non-production-safe email proof

### 2.2 Locked topology and request model

The topology decisions remain unchanged:

- one public origin
- browser requests use same-origin `/api/*`
- SSR/server-side frontend access goes directly to backend via internal base URL and forwarded headers
- backend owns session/auth truth
- tenant identity is derived from host
- session cookies remain backend-owned and host-scoped
- SSO state handling remains separate from session-cookie handling

### 2.3 Backend auth/provisioning implementation

The backend currently implements the Auth + User Provisioning module foundation, including:

- login
- logout
- current-user/session bootstrap surface
- forgot-password / reset-password flow
- verify-email flow
- invite creation and acceptance flow
- role-aware continuation / next-action contract
- MFA setup / verify / recovery support already present in the module scope
- SSO initiation/callback surfaces currently present for Google and Microsoft under the existing locked topology
- outbox-backed email sending through the backend SMTP adapter
- SMTP classification behavior for retryable vs permanent provider failures
- a local dev seed that prepares bootstrap invite proof fixtures
- an explicit tenant-bootstrap CLI for shared QA/staging/production-style operator bootstrap

### 2.4 Frontend auth/provisioning implementation

The frontend currently contains the real UI surface for the implemented Auth + User Provisioning module scope, including:

- public auth entry routes
- continuation/bootstrap handling
- invite-email landing at `/accept-invite`
- invite-driven registration at `/auth/register`
- role-aware authenticated landing behavior
- current invite-management/admin UI surface already shipped in prior phases
- logout behavior wired to backend-owned session truth
- real browser-facing verify-email and reset-password continuation pages for email-delivered links
- a real MFA setup page that can render a scannable QR from the backend `qrCodeUri`

### 2.5 Current local developer contract

The repository now supports a repeatable local non-production email proof contract:

- Mailpit runs locally as the default SMTP sink
- backend host-run mode can send real SMTP messages to Mailpit
- frontend host-run mode can be used against backend host-run mode
- canonical seed data can enqueue a bootstrap invite email
- invite / verify-email / reset-password flows can be visually verified through Mailpit
- resend verification and reset-token failure behavior can be manually proven through the documented browser runbook
- tenant-based link construction can be verified using local hostnames
- MFA setup can be prepared with a visible QR code and expected issuer/account presentation before the real-device proof step

### 2.6 Current operator bootstrap contract

The repository now supports an explicit operator bootstrap flow for non-local environments:

- tenant bootstrap is an explicit command, not an automatic production startup side effect
- the bootstrap command creates or ensures the target tenant and a pending ADMIN invite only
- the bootstrap invite is queued into the outbox and delivered by the normal SMTP worker path
- raw invite tokens are not logged in operator mode
- the exact operator/browser validation sequence lives in `docs/ops/runbooks.md`

---

## 3. What Phase 2 added

Phase 2 added proof-oriented email delivery infrastructure and documentation, not a topology rewrite.

Specifically it added:

- Mailpit wiring in infra compose files
- canonical seed-driven invite email proof support
- local proof instructions for invite, verify-email, and password-reset mail arrival
- staging sandbox SMTP proof guidance in `docs/ops/runbooks.md`
- status/doc truth updates so the repository contract matches actual shipped local behavior

Phase 2 did **not** change:

- browser-to-backend request topology
- SSR/backend forwarding model
- tenant identity derivation
- auth/session ownership
- invite lifecycle semantics
- SSO architecture
- MFA architecture

---

## 4. What Phase 3 added

Phase 3 added bootstrap proof closure and operator-safe bootstrap behavior.

Specifically it added:

- a shared tenant-bootstrap helper separating local-dev convenience seeding from operator bootstrap
- a backend bootstrap command for staging/QA/production-style operator use
- local proof coverage for seed invite -> accept -> register -> authenticated session -> MFA continuation
- documented bootstrap/operator procedures in `docs/ops/runbooks.md`
- explicit runbook coverage for invite replay, expiry, and cancellation handling during onboarding

Phase 3 did **not** change:

- first-admin `/admin/settings` routing
- public signup proof scope
- password-reset proof scope
- real browser CI scope
- Google or Microsoft provider-live proof scope

## 5. What Phase 4 added

Phase 4 added public signup, email-verification, and password-recovery proof closure.

Specifically it added:

- a real frontend reset-password page that can consume email-delivered reset links in the browser
- mock-backed browser E2E coverage for signup verification, resend verification, blocked signup, forgot-password, reset-password, expired reset-token behavior, and reused reset-token behavior
- documented local proof procedures in `docs/ops/runbooks.md` for public signup + verification and forgot-password + reset-password
- explicit status truth that these flows are now proven at the repository/browser-proof level without claiming the later Phase 8 real-stack CI work is already done

Phase 4 did **not** change:

- MFA provider-live proof scope
- Google or Microsoft provider-live proof scope
- first-admin `/admin/settings` landing scope
- Phase 8 real-stack browser CI scope
- broader non-auth Hubins product scope

## 6. What Phase 5 added

Phase 5 adds the repository surfaces and proof procedure needed for real MFA validation.

Specifically it adds:

- a scannable QR on the real MFA setup page generated from the backend-provided `qrCodeUri`
- explicit issuer/account preview on the setup page so the expected authenticator-app presentation is visible before scan
- stronger recovery-code test coverage proving single-use enforcement across a fresh login session, not only within an already-elevated session
- a dedicated Phase 5 proof runbook in `docs/ops/runbooks.md` covering real authenticator enrollment, login verification, and recovery-code reuse rejection

Phase 5 does **not** automatically turn mocked/unit coverage into real-device proof by itself.
The final authenticator-app scan and reuse evidence remain a manual runbook execution step in the target environment.

## 7. What Phase 6 added

Phase 6 adds the repository-side readiness items for real Google live-provider validation.

Specifically it adds:

- committed backend/frontend `.env.example` files so the documented local/staging config contract now exists in the repo
- explicit Google SSO secrets/config checklist guidance in `docs/developer-guide.md`
- a dedicated Phase 6 runbook in `docs/ops/runbooks.md` covering configuration proof, active-member success proof, expired-invite rejection, MFA continuation, audit validation, and JWKS reachability
- stronger Google callback regression coverage for session payload correctness and the `MFA_REQUIRED` continuation when Google SSO is used by an admin who already has verified MFA

Phase 6 still requires a real staging execution with real Google credentials before it can be claimed as operationally proven.
The repository now contains the required proof procedure and regression coverage, but the live-provider round-trip itself remains an environment execution step.

## 8. What Phase 7 added

Phase 7 adds the repository-side readiness items for real Microsoft live-provider validation.

Specifically it adds:

- explicit Microsoft SSO secrets/config checklist guidance in `docs/developer-guide.md`, including exact env file/variable wiring and the note that this repo does not use a `MICROSOFT_TENANT_ID` env var
- a dedicated Phase 7 runbook in `docs/ops/runbooks.md` covering Azure portal app-registration steps, configuration proof, claim fallback proof, issuer resolution proof, active-member success proof, expired-invite rejection, MFA continuation, audit validation, and JWKS reachability
- stronger Microsoft callback regression coverage for session payload correctness, claim fallback resolution, and the `MFA_REQUIRED` continuation when Microsoft SSO is used by an admin who already has verified MFA

Phase 7 still requires a real staging execution with real Microsoft credentials before it can be claimed as operationally proven.
The repository now contains the required proof procedure and regression coverage, but the live-provider round-trip itself remains an environment execution step.

## 9. What Phase 8 added

Phase 8 adds real-stack browser E2E coverage and the CI job that proves it.

Specifically it adds:

- `backend/src/shared/db/seed/seed-e2e-fixtures.ts` — seeds a dedicated ADMIN persona (`e2e-admin@example.com`) in `goodwill-open` with no MFA configured, so the admin login continuation path returns `MFA_SETUP_REQUIRED` predictably in real-stack tests
- `backend/src/shared/db/seed/run-seed-e2e-fixtures.ts` — CLI runner: `yarn workspace @auth-lab/backend db:seed:e2e`
- `frontend/playwright.config.real-stack.mts` — Playwright config targeting the real Caddy proxy at `*.lvh.me:3000`; no mock backend, no `next dev` web server block
- `frontend/test/e2e/helpers/mailpit.ts` — Mailpit HTTP API helper (`purgeMailpit`, `waitForEmailToRecipient`, `extractLinkFromText`) for email-driven real-stack tests
- `frontend/test/e2e/real-stack-smoke.spec.ts` — 8 smoke tests covering all Phase 8 required journeys
- `.github/workflows/frontend-e2e-real-stack.yml` — CI job: builds Docker stack, seeds E2E fixtures, runs Playwright real-stack suite, uploads failure artifacts, tears down
- `scripts/seed-e2e-fixtures.sh` — local convenience wrapper for `docker compose exec` seed
- `frontend/package.json` and `backend/package.json` — `test:e2e:real-stack` and `db:seed:e2e` scripts added
- `docs/developer-guide.md` — updated frontend checks section with real-stack E2E instructions

**Drift fixed in this phase:**

- Mock (`acme` tenant) vs real stack (`goodwill-open`/`goodwill-ca`) tenant and persona mismatch now documented and resolved
- `frontend-tests.yml` stale "not yet" comment replaced with correct pointer to the new real-stack job
- Mailpit API helper created so real-stack tests never depend on mock backend `/__mail/messages` endpoint

**Boundary:**
Phase 8 proves the topology and session model in a real browser. Real OAuth round-trips (Google, Microsoft) remain Phase 6/7 operator proof — the SSO topology probe in Phase 8 stops at the 302 redirect + state cookie check without requiring live OAuth credentials.

Phase 8 does **not** change:

- backend auth flows or policies
- frontend auth forms or components
- session or cookie contracts
- proxy topology or Caddy/nginx configuration
- first-admin `/admin/settings` routing (Phase 9 scope)

---

## 10. Canonical local dev/test assumptions

### 10.1 Hostnames matter

Tenant-aware behavior must be tested using tenant hosts, not plain `localhost`, whenever host-derived tenant identity is part of the flow.

Current practical hosts:

- host-run frontend: `http://goodwill-ca.localhost:3000`
- host-run backend public-base-url pattern: `http://{tenantKey}.localhost:3000`
- full-stack proxy path may use the committed proxy host contract in infra/docs

### 10.2 Email is now part of the real local contract

Email-dependent auth flows are no longer “pretend only” in local development.

For local development, the repo expects:

- `EMAIL_PROVIDER=smtp`
- SMTP directed to Mailpit
- Mailpit UI/API available locally

This is intentionally convenience-first and **not production-safe**.
It exists only for local proof, developer feedback loops, and repeatable auth-flow verification.

### 10.3 Staging email remains sandboxed

The intended non-production staging behavior is sandbox SMTP delivery, not real end-user delivery.

The documented staging provider choice for this phase is Mailtrap Email Sandbox.
That choice exists to:

- prove email arrival outside local
- validate SMTP config shape with real credentials
- validate permanent-failure behavior without using real production mail delivery

### 10.4 Production-style bootstrap is explicit

Production-style tenant bootstrap is now treated as an explicit operator action.

That means:

- do **not** rely on `SEED_ON_START` in production-like environments
- use the explicit bootstrap command with tenant/admin parameters
- let the running backend worker deliver the invite via the real outbox + SMTP path
- validate the browser onboarding chain using the operator/bootstrap runbook

---

## 11. What is intentionally deferred or out of scope here

This file is not claiming completion of every future hardening concern.
The following remain outside the scope of this status snapshot unless separately marked shipped:

- production email-provider rollout
- real browser E2E coverage for all auth flows in CI
- broader non-auth Hubins product surfaces
- future settings/account-management modules not already shipped
- later operational hardening beyond the current documented runbooks and checks
- first-admin `/admin/settings` landing completion

---

## 12. Active truth-chain rule

The current truth-chain is:

1. repository code
2. active `/docs` truth/status documents
3. route/API/module docs
4. historical planning material

If an older planning document implies a behavior that the repository no longer follows, the code plus current `/docs` truth documents win.

---

## 13. Quick reality checklist

As of the current foundation state, all of the following should be true:

- backend starts with valid local or environment-specific config
- frontend starts with its current local config
- infra can run Postgres + Redis + Mailpit for local proof
- local invite email can be captured in Mailpit
- local verify-email can be captured in Mailpit
- local forgot-password/reset email can be captured in Mailpit
- public signup + verification can be manually proven through the documented browser runbook
- forgot-password + reset-password can be manually proven through the documented browser runbook
- MFA setup page can render a real scannable QR from the backend `otpauth://` URI
- Phase 5 real-device MFA proof can be executed through the documented runbook
- Google SSO staging config can be prepared from the committed `.env.example` files and the documented config checklist
- Microsoft SSO staging config can be prepared from the committed `.env.example` files and the documented config checklist
- Phase 6 live Google proof can be executed through the documented runbook once real staging credentials are available
- Phase 7 live Microsoft proof can be executed through the documented runbook once real staging credentials are available
- real-stack Playwright smoke tests pass against the full Docker Compose topology: `yarn workspace frontend test:e2e:real-stack`
- the Phase 8 CI job (`frontend-e2e-real-stack.yml`) runs the real-stack smoke suite on push/PR
- the E2E fixture seed (`yarn workspace @auth-lab/backend db:seed:e2e`) creates the required admin persona in `goodwill-open` with no MFA
- Mailpit HTTP API is reachable at port 8025 when running the full stack (used by real-stack E2E email-verification test)
- generated email links target the tenant-aware frontend host shape
- operator bootstrap can create a tenant-scoped pending ADMIN invite without logging a raw token
- invite acceptance can continue into registration, authenticated session creation, and MFA setup entry for a first admin bootstrap path
- current docs point to `/docs` as the repo truth home

If one of these statements stops being true, this file must be updated or the repo must be repaired.

---

## 14. Current foundation score intent

The repository should now be understood as:

- beyond topology-only
- beyond backend-foundation-only
- functionally implemented for the current Auth + User Provisioning slice
- supported by local and operator bootstrap proof procedures
- still subject to further hardening, operational proof expansion, and broader product work

That is the correct practical reading of the repo at this point.
