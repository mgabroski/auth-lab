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
- a repeatable local auth test environment contract with committed env examples, Mailpit-based local email capture, and a canonical dev seed entry point

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
- committed backend and frontend `.env.example` files for host-run setup

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

### 2.4 Frontend auth/provisioning implementation

The frontend currently contains the real UI surface for the implemented Auth + User Provisioning module scope, including:

- public auth entry routes
- continuation/bootstrap handling
- role-aware authenticated landing behavior
- current invite-management/admin UI surface already shipped in prior phases
- logout behavior wired to backend-owned session truth

### 2.5 Current local developer contract

The repository now supports a repeatable local non-production email proof contract:

- Mailpit runs locally as the default SMTP sink
- backend host-run mode can send real SMTP messages to Mailpit
- frontend host-run mode can be used against backend host-run mode
- canonical seed data can enqueue a bootstrap invite email
- invite / verify-email / reset-password flows can be visually verified through Mailpit
- tenant-based link construction can be verified using local hostnames

---

## 3. What Phase 2 added

Phase 2 added proof-oriented email delivery infrastructure and documentation, not a topology rewrite.

Specifically it added:

- Mailpit wiring in infra compose files
- committed backend/frontend environment examples
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

## 4. Canonical local dev/test assumptions

### 4.1 Hostnames matter

Tenant-aware behavior must be tested using tenant hosts, not plain `localhost`, whenever host-derived tenant identity is part of the flow.

Current practical hosts:

- host-run frontend: `http://goodwill-ca.localhost:3000`
- host-run backend public-base-url pattern: `http://{tenantKey}.localhost:3000`
- full-stack proxy path may use the committed proxy host contract in infra/docs

### 4.2 Email is now part of the real local contract

Email-dependent auth flows are no longer “pretend only” in local development.

For local development, the repo expects:

- `EMAIL_PROVIDER=smtp`
- SMTP directed to Mailpit
- Mailpit UI/API available locally

This is intentionally convenience-first and **not production-safe**.
It exists only for local proof, developer feedback loops, and repeatable auth-flow verification.

### 4.3 Staging email remains sandboxed

The intended non-production staging behavior is sandbox SMTP delivery, not real end-user delivery.

The documented staging provider choice for this phase is Mailtrap Email Sandbox.
That choice exists to:

- prove email arrival outside local
- validate SMTP config shape with real credentials
- validate permanent-failure behavior without using real production mail delivery

---

## 5. What is intentionally deferred or out of scope here

This file is not claiming completion of every future hardening concern.
The following remain outside the scope of this status snapshot unless separately marked shipped:

- production email-provider rollout
- real browser E2E coverage for all auth flows
- broader non-auth Hubins product surfaces
- future settings/account-management modules not already shipped
- later operational hardening beyond the current documented runbooks and checks

---

## 6. Active truth-chain rule

For current work on this repo, the practical truth chain is:

1. repository implementation
2. this status file
3. active operational/developer docs
4. older prompts or historical planning docs

If a lower artifact contradicts the repo or this file, repair the lower artifact instead of inventing new interpretation.

---

## 7. Quick reality checklist

As of the current foundation state, all of the following should be true:

- backend starts with committed example env adapted to local machine values
- frontend starts with committed example env
- infra can run Postgres + Redis + Mailpit
- local invite email can be captured in Mailpit
- local verify-email can be captured in Mailpit
- local forgot-password/reset email can be captured in Mailpit
- generated email links target the tenant-aware frontend host shape
- current docs point to `/docs` as the repo truth home

If one of these statements stops being true, this file must be updated or the repo must be repaired.

---

## 8. Current foundation score intent

The repository should now be understood as:

- beyond topology-only
- beyond backend-foundation-only
- functionally implemented for the current Auth + User Provisioning slice
- still subject to further hardening, operational proof expansion, and broader product work

That is the correct practical reading of the repo at this point.
