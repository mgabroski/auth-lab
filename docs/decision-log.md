# Decision Log

## Purpose

This file records locked architectural and cross-cutting decisions for the repository.

Use it when you need to know:

- what was decided
- why it was decided
- what it now constrains
- which older alternatives are no longer valid

This file is for real decisions only.
It is not a changelog.
It is not a backlog.
It is not a place to record ordinary implementation choices that already follow repo law.

If a change does not alter architecture, trust boundaries, cross-cutting behavior, documentation law, or module-spanning operating rules, it probably does not belong here.

---

## How To Read This File

### Fast path

1. check the ADR index below
2. open only the entries relevant to the task
3. do not load the full file unless the task truly needs decision history

### When to update this file

Add or update an entry only when a decision changes:

- repo architecture
- security or trust-boundary behavior
- topology or request model behavior
- module-spanning operating rules
- documentation system law
- cross-cutting product rules that affect implementation across more than one file or area

Do not write ADRs for:

- ordinary endpoint additions
- normal CRUD implementation choices
- local refactors that preserve existing repo law
- decisions already fully covered by code comments and skeleton rules

---

## ADR Index

| ID       | Title                                                                                                                       | Status | Scope                         |
| -------- | --------------------------------------------------------------------------------------------------------------------------- | ------ | ----------------------------- |
| ADR-0001 | Single Public Origin Through Reverse Proxy                                                                                  | LOCKED | topology                      |
| ADR-0002 | Host-Derived Tenant Resolution                                                                                              | LOCKED | topology / auth               |
| ADR-0003 | SSR Uses Internal Backend URL With Explicit Header Forwarding                                                               | LOCKED | frontend / backend / topology |
| ADR-0004 | Browser Uses Same-Origin `/api/*`; SSO Starts With Navigation, Not `fetch()`                                                | LOCKED | frontend / auth / topology    |
| ADR-0005 | Session Cookie And SSO State Cookie Are Separate Contracts                                                                  | LOCKED | auth / security               |
| ADR-0006 | Proxy Conformance Tests Are The Safety Net For Dev/Prod Proxy Drift                                                         | LOCKED | infra / topology              |
| ADR-0007 | Next.js App Router Is The Frontend Framework                                                                                | LOCKED | frontend                      |
| ADR-0008 | Workspace Setup Guidance Is Tenant-Scoped; No `FIRST_TIME_SETUP` NextAction                                                 | LOCKED | auth / settings boundary      |
| ADR-0009 | MFA TOTP Label Uses Verified Email, Not `userId`                                                                            | LOCKED | auth / MFA                    |
| ADR-0010 | Seed Bootstrap Delivery Differs By Environment                                                                              | LOCKED | auth / ops                    |
| ADR-0011 | Expired Invite Cannot Be Bypassed By SSO                                                                                    | LOCKED | auth / invites / SSO          |
| ADR-0012 | SSO Does Not Bypass App-Level MFA                                                                                           | LOCKED | auth / SSO / MFA              |
| ADR-0013 | Documentation System Uses Tiered Truth And One Active Prompt Pack                                                           | LOCKED | documentation system          |
| ADR-0014 | Control Plane Backend Lives Inside The Shared Backend; CP Provisioning And Tenant Configuration Truth Are Separate Tables   | LOCKED | CP / architecture             |
| ADR-0015 | Control Plane Remains Producer-Only Until The Real Settings State Engine Exists; Future Handoff Uses One Canonical Snapshot | LOCKED | CP / Settings boundary        |
| ADR-0016 | Control Plane Uses A Dedicated Host Surface Rather Than A Tenant-App Route Subtree                                          | LOCKED | CP / topology / security      |

---

## ADR-0001 — Single Public Origin Through Reverse Proxy

### Status

LOCKED

### Decision

The system is exposed to the browser through one public origin fronted by the reverse proxy.
The browser does not talk directly to backend service origins.

### Why

This keeps browser behavior same-origin, simplifies cookie handling, and keeps local behavior aligned with the intended production model.

### Consequences

- browser requests use proxy-routed paths
- proxy behavior becomes load-bearing
- cookie, session, and tenant behavior depend on correct proxy routing

### Supersedes

Any design that assumes the browser should call backend container or service origins directly.

---

## ADR-0002 — Host-Derived Tenant Resolution

### Status

LOCKED

### Decision

Tenant identity is derived from the host and treated as load-bearing request truth.

### Why

The platform is multi-tenant by host.
Tenant routing and access isolation must align with the incoming host context rather than a frontend-owned tenant switch.

### Consequences

- proxy must preserve host correctly
- backend request context must treat host-derived tenant resolution as authoritative
- tenant/session mismatches must fail closed

### Supersedes

Any design that makes tenant identity primarily frontend-selected or weakly inferred.

---

## ADR-0003 — SSR Uses Internal Backend URL With Explicit Header Forwarding

### Status

LOCKED

### Decision

SSR and server-side frontend calls use the internal backend URL and explicitly forward the host, cookie, and forwarded-header context needed by backend auth and tenant resolution.

### Why

SSR is not the browser.
Routing SSR through the public proxy as if it were a browser request adds avoidable indirection and weakens clarity.

### Consequences

- browser and SSR calls remain distinct by design
- SSR helpers must forward the correct headers explicitly
- SSR auth/bootstrap behavior must not be treated as generic browser fetch behavior

### Supersedes

Any design that treats SSR calls as interchangeable with browser `/api/*` calls.

---

## ADR-0004 — Browser Uses Same-Origin `/api/*`; SSO Starts With Navigation, Not `fetch()`

### Status

LOCKED

### Decision

Browser-side requests use same-origin `/api/*` routes.
SSO initiation uses browser navigation, not `fetch()`.

### Why

Same-origin browser API usage preserves the proxy model and cookie behavior.
SSO is a navigation flow, not a resource-fetch flow.

### Consequences

- browser API clients must remain relative-path clients
- frontend code must not hardcode backend origins for browser requests
- SSO start behavior must remain navigation-based

### Supersedes

Any design that starts SSO with `fetch()` or pushes browser traffic directly to backend origins.

---

## ADR-0005 — Session Cookie And SSO State Cookie Are Separate Contracts

### Status

LOCKED

### Decision

The session cookie and the SSO state cookie are separate cookies with separate purposes, lifecycle rules, and SameSite behavior.
They are host-only and must not use a parent-domain cookie model.

### Why

The session contract and the SSO callback protection contract solve different problems and require different browser behavior.

### Consequences

- session cookie and SSO state cookie must not be merged conceptually or technically
- host-only cookie behavior is mandatory for the intended isolation model
- cookie changes are security-sensitive and topology-sensitive

### Supersedes

Any design that mixes session and SSO callback state into one cookie model or weakens host-only behavior.

---

## ADR-0006 — Proxy Conformance Tests Are The Safety Net For Dev/Prod Proxy Drift

### Status

LOCKED

### Decision

Dev and prod may use different proxy families for now, but proxy conformance tests are required as the safety net for behavioral drift.

### Why

The request model is too important to leave to human memory or config review alone.

### Consequences

- proxy routing and forwarding behavior require executable proof
- proxy-sensitive changes require stronger validation than normal app changes
- a future single-proxy-family decision may still be made later if operational cost justifies it

### Supersedes

Any design that relies only on manual review to keep proxy behavior aligned across environments.

---

## ADR-0007 — Next.js App Router Is The Frontend Framework

### Status

LOCKED

### Decision

The frontend framework choice is Next.js App Router.

### Why

The repo’s frontend architecture, SSR model, and routing assumptions are built around this choice.

### Consequences

- route, SSR, and bootstrap patterns must remain compatible with App Router
- frontend guidance and tests assume this framework model

### Supersedes

Any unresolved framework-choice state for the current frontend.

---

## ADR-0008 — Workspace Setup Guidance Is Tenant-Scoped; No `FIRST_TIME_SETUP` NextAction

### Status

LOCKED

### Decision

Workspace setup state belongs to the tenant, not to an individual admin membership.
Admins land on `/admin` after full authentication, and workspace setup guidance is expressed through a non-blocking banner and `/admin/settings`, not through a `FIRST_TIME_SETUP` auth nextAction.

### Why

Workspace setup is shared tenant configuration, not a personal auth continuation state.

### Consequences

- `/admin` is the post-auth admin landing
- `/admin/settings` is the setup guidance/configuration surface
- auth nextAction contract must not grow a `FIRST_TIME_SETUP` branch
- workspace setup behavior must not become a per-admin dismissal state

### Supersedes

Any design that models workspace setup as a membership-scoped or auth-nextAction-only state.

---

## ADR-0009 — MFA TOTP Label Uses Verified Email, Not `userId`

### Status

LOCKED

### Decision

The MFA TOTP label uses the verified user email with issuer `Hubins`, not `userId`.

### Why

The authenticator-app presentation should reflect user-recognizable identity rather than an internal opaque identifier.

### Consequences

- MFA QR and label behavior must reflect verified email presentation
- tests and proof expectations should validate the visible label accordingly

### Supersedes

Any earlier behavior or assumption using `userId` as the intended MFA TOTP label.

---

## ADR-0010 — Seed Bootstrap Delivery Differs By Environment

### Status

LOCKED

### Decision

Seed/bootstrap delivery behavior is environment-specific:

- local dev may allow developer-friendly raw-token convenience
- shared staging/QA must use the real outbox + SMTP path
- production must not use raw-token convenience

### Why

Local convenience and operational realism are different concerns and should not be conflated.

### Consequences

- local behavior must not be described as the staging or production contract
- staging/QA bootstrap proof must validate real delivery behavior
- production bootstrap must follow an operator-safe runbook path

### Supersedes

Any design that treats local raw-token convenience as the general operational contract.

---

## ADR-0011 — Expired Invite Cannot Be Bypassed By SSO

### Status

LOCKED

### Decision

If a user’s only tenant-entry basis is an expired invite, Google SSO and Microsoft SSO must not activate that membership.

### Why

SSO must not become a bypass around invite expiration rules.

### Consequences

- invite expiry rules remain authoritative even in SSO continuation flows
- recovery path is admin resend or recreate invite

### Supersedes

Any design that allows SSO to reactivate or bypass an expired invite path.

---

## ADR-0012 — SSO Does Not Bypass App-Level MFA

### Status

LOCKED

### Decision

SSO authentication does not remove the application’s own MFA requirements.

### Why

Provider authentication and application-level MFA policy are not the same trust decision.

### Consequences

- users subject to app MFA must continue into MFA setup or verification as appropriate after SSO
- recovery code behavior remains valid after SSO exactly as after password login

### Supersedes

Any design that treats successful SSO as a blanket replacement for app-level MFA.

---

## ADR-0013 — Documentation System Uses Tiered Truth And One Active Prompt Pack

### Status

LOCKED

### Decision

The documentation system uses tiered truth:

- stable global law
- growing global contracts and operational docs
- opt-in module-local docs only for genuinely complex modules

The active prompt system is centralized under `docs/prompts/` rather than split across competing prompt packs.

### Why

This keeps the repo navigable for engineers and AI, reduces duplicate truth, and limits drift.

### Consequences

- module docs are opt-in, not mandatory
- API docs are domain-owned, not aggregated into one giant contract file
- prompts are execution infrastructure, not a second truth system
- support docs must not compete with higher-truth docs

### Supersedes

Any documentation model that duplicates truth widely, creates parallel prompt systems, or generates per-module docs by default.

---

---

## ADR-0014 — Control Plane Backend Lives Inside The Shared Backend; CP Provisioning And Tenant Configuration Truth Are Separate Tables

### Status

LOCKED

### Decision

The Control Plane backend is not a separate service. It lives inside the same Fastify backend process, under its own module boundary at `backend/src/modules/control-plane/`. All CP backend routes are prefixed `/cp/`.

CP provisioning truth (`cp_accounts` and future `cp_*_config` tables) is kept strictly separate from tenant configuration truth (`tenants` and future Settings tables). These must not be collapsed into a single mixed table model.

### Why

Splitting CP into a separate service would add deployment complexity with no benefit at this scale. The `/cp/` prefix provides clear routing separation without a process boundary.

Keeping CP provisioning truth and tenant configuration truth separate preserves the two-layer ownership model: CP controls what tenants are allowed to have; the tenant's own Settings control how they configure what they are allowed to have. Collapsing the two would make it impossible to change CP allowances without mutating tenant config, and would blur the Settings consumption contract.

### What This Constrains

- New CP domain tables must use the `cp_` prefix and must not share rows with tenant-facing tables.
- CP routes must be registered under the `control-plane` module boundary, not scattered under other modules.
- CP frontend must call backend through the same-origin `/api/*` proxy or `cpSsrFetch` — never via hardcoded backend origins.
- The CP → Settings cascade integration path is kept clean: CP writes produce `cpRevision` changes; the Settings state engine will consume those as a separate, explicit contract once it exists.

### Alternatives Considered

- Separate backend service for CP: rejected — premature complexity at this scale.
- Shared tables between CP and tenant Settings: rejected — blurs the ownership model and blocks clean Settings consumption.

---

## ADR-0015 — Control Plane Remains Producer-Only Until The Real Settings State Engine Exists; Future Handoff Uses One Canonical Snapshot

### Status

LOCKED

### Decision

Until the real Settings Step 10 Phase 2 state engine exists in this repository, Control Plane writes remain producer-only. They must not pretend to perform a live CP → Settings cascade.

During this blocked phase, the canonical handoff contract is a single internal `settingsHandoff` snapshot built from CP allowance truth, provisioning truth, and `cpRevision`. That snapshot may be returned on full CP account detail DTOs and may be consumed in-process by future Settings code, but it does not represent a live cascade success state.

Once the real Settings state engine exists, the future CP → Settings integration must use this same canonical contract and must execute synchronously in the same transaction boundary required by the locked Settings roadmap.

### Why

The prerequisite roadmap explicitly forbids fake CP → Settings integration before the real Settings engine exists. The Settings Step 10 roadmap also requires a synchronous, atomic, revision-based cascade once that engine is real.

Without a locked producer-side contract, CP could drift into ad hoc handoff shapes, fake webhook placeholders, or UI states that imply Settings synchronization has already happened. A single canonical snapshot keeps current behavior honest while preparing a clean future integration point.

### What This Constrains

- CP may expose a producer snapshot, but it must not claim live Settings synchronization while the Settings engine is absent.
- Producer snapshots must carry allowance truth and provisioning truth only — not CP Step 2 progress/configured flags as fake Settings truth.
- `cpRevision` remains the tenant-scoped revision signal for meaningful CP allowance mutations.
- Future Settings wiring must reuse the canonical handoff contract and must not invent a second cascade shape.
- No queue, webhook, fire-and-forget bridge, or placeholder success flag may be introduced as a substitute for the future synchronous cascade.

### Alternatives Considered

- Fake synchronous call into a non-existent Settings service: rejected — dishonest and incompatible with the locked dependency boundary.
- Async queue or webhook placeholder before Settings exists: rejected — violates the locked synchronous cascade model and creates drift.
- No handoff contract until Settings work starts: rejected — leaves CP without a stable producer shape and makes later integration noisier.

---

## ADR-0016 — Control Plane Uses A Dedicated Host Surface Rather Than A Tenant-App Route Subtree

### Status

LOCKED

### Decision

The Control Plane is exposed as its own host surface and application package. It must not be embedded as a route subtree inside the tenant-facing frontend.

In local development, the preferred proof path is the proxy-routed CP host (`cp.lvh.me:3000`). The direct Next.js dev server (`localhost:3002`) may still be used for local UI iteration, but it does not replace the dedicated-host topology contract.

### Why

The Control Plane serves a different audience, carries a different trust posture, and follows a different rollout sequence than the tenant-facing app. Keeping it on a dedicated host surface preserves a clean boundary for future CP authentication, avoids mixing operator routing with tenant routing, and keeps same-origin CP browser calls explicit.

This also prevents namespace confusion between CP routing and tenant/account-key routing. The repo already enforces reserved keys such as `cp`, `api`, `admin`, `app`, `auth`, and `www` to avoid host and path collisions.

### What This Constrains

- CP remains a separate `cp/` application package.
- CP must not be mounted under the tenant frontend route tree.
- CP browser calls still use same-origin `/api/*` on the CP host; server reads use the CP SSR helper.
- Proxy and runtime docs must describe CP as a dedicated host surface, not as a tenant-app sub-route.
- Reserved host/system namespaces must remain blocked from CP account-key use.

### Alternatives Considered

- Embed CP under the tenant app as `/admin` or `/control-plane`: rejected — blurs trust boundaries and couples operator routing to the tenant surface.
- Give CP its own backend service as part of this stage: rejected — unnecessary process split for the current repo scope.
- Rely only on the direct Next.js dev server with no dedicated host story: rejected — weakens topology truth and makes proxy-path verification less honest.

## Maintenance Rules

### 1. New entries must be real decisions

If the choice only affects a local implementation detail and does not alter repo law, cross-cutting behavior, or module-spanning rules, do not add an ADR.

### 2. Update in the same PR

If a real architectural or cross-cutting decision is made, the ADR belongs in that same PR.
Do not leave decision capture for later.

### 3. Keep entries short and sharp

Each entry should make scanning cheaper, not heavier.
If an ADR becomes long because it is re-explaining architecture or a module spec, move that material back to the correct canonical doc.

### 4. Do not duplicate module-local truth here

Module-specific implementation detail belongs in the module’s own highest-truth spec when one exists.
This file only records the cross-cutting or architectural decision itself.

---

## Final Position

Use this file to record what the repo has actually decided.

If you need current shipped truth, start with `docs/current-foundation-status.md`.
If you need architecture law, use `ARCHITECTURE.md`.
If you need security law, use `docs/security-model.md`.
If you need a real decision that constrains multiple areas, use this file.
