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
| ADR-0017 | CP → Settings Cascade Uses One Synchronous Revision-Based Contract Once The Settings Engine Exists                          | LOCKED | CP / Settings boundary        |
| ADR-0018 | Settings Bootstrap Semantics Move Out Of Auth Bootstrap Through A Controlled Rollout Bridge                                 | LOCKED | auth / settings boundary      |
| ADR-0019 | Settings Readiness Gate Retires Auth-Owned Setup Acknowledgement                                                            | LOCKED | auth / settings boundary      |
| ADR-0020 | Operational Access Target Levels Are Admin, Agent, And User With MEMBER Compatibility Alias                                 | LOCKED | access / auth migration       |
| ADR-0021 | Sensitive Field Conflicts Resolve To The Most Restrictive Effective Result                                                  | LOCKED | access / security             |
| ADR-0022 | Current Access & Security Route Must Not Be Confused With Future Operational Access                                         | LOCKED | settings / access routing     |
| ADR-0023 | Backend-Owned Effective Access Resolver Is Future Platform Authorization Truth                                              | LOCKED | authorization / architecture  |
| ADR-0024 | Reusable Groups Combine With Coverage Keys To Avoid Employer/Location-Specific Group Explosion                              | LOCKED | access / People & Teams       |
| ADR-0025 | Operational Access Provisioning Target Behavior Preserves Role Compatibility                                                | LOCKED | provisioning / access target  |
| ADR-0026 | Operational Access MVP Grants Use Agent Groups, Primary Where, Which Records, And Optional Coverage                         | LOCKED | access / People & Teams       |
| ADR-0027 | Personal Cards Are Reusable Field Groupings, Not Workflow Or Module State                                                   | LOCKED | Personal / access             |
| ADR-0028 | Special Access Is Rare, Reviewed, Audited, And Scope-Bound                                                                  | LOCKED | access / security             |
| ADR-0029 | Operational Access Runtime Proof Starts With Personal Cards, Then Published Documents                                       | LOCKED | access / rollout proof        |
| ADR-0030 | Operational Access 9.5 Source-of-Truth Model Replaces Older Operational Access Drafts                                       | LOCKED | access / documentation        |
| ADR-0031 | Operational Access Setup Splits Primary Where, Which Records, Additional Coverage, And Special Access                       | LOCKED | access / UX / architecture    |
| ADR-0032 | Oversight Is Directed, Single-Hop, And Dynamically Resolved                                                                 | LOCKED | access / hierarchy            |
| ADR-0033 | Operational Access Tenant Surface Is Guarded By `operational_access_enabled`                                                | LOCKED | CP / settings / access        |
| ADR-0034 | Search, Notifications, Exports, And High-Sensitivity Domains Must Consume Resolver Output                                   | LOCKED | access / security / modules   |
| ADR-0035 | Operational Access First Real Module Proof Is Personal Cards With Scoped Governance Saves                                   | LOCKED | access / Personal Cards       |

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
- When the Settings state engine is implemented, the live cascade must follow ADR-0017 and the bootstrap rollout must follow ADR-0018.

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

## ADR-0017 — CP → Settings Cascade Uses One Synchronous Revision-Based Contract Once The Settings Engine Exists

### Status

LOCKED

### Decision

When the real Settings state engine exists in this repository, any committed Control Plane mutation that changes tenant allowance truth must synchronously invoke the Settings cascade in the same transaction boundary.

This future live cascade uses one tenant-scoped monotonic `cpRevision` integer as the revision signal:

- one committed CP allowance mutation = one committed `cpRevision`
- one revision may contain multiple changed targets or boundaries
- replay/idempotency is evaluated at revision granularity, not event-key granularity

There is no asynchronous primary path for the live cascade:

- no queue
- no webhook
- no fire-and-forget background worker
- no split-commit design where CP writes commit first and Settings catches up later

If a revision has already been applied to the Settings side, replay is a no-op.
If reconciliation is ever needed, it is an explicit repair path with a dry-run mode — not a scheduled background sync loop.

### Why

The locked Settings Step 10 roadmap requires the CP → Settings path to be:

- synchronous
- atomic
- revision-based
- replay-safe
- honest about current and future boundaries

Without this decision, future implementation work could drift into an eventually-consistent primary path, duplicate revision models, or false "cascade succeeded" states that the repo has already rejected.

### Consequences

- CP allowance mutations remain the producer of `cpRevision`
- once the Settings engine exists, a qualifying CP mutation must not commit without the corresponding Settings cascade applying in the same transaction
- the current producer-only `settingsHandoff` snapshot remains the honest pre-engine boundary and does not become a substitute for the future live cascade
- reconciliation logic, when introduced later, must detect lagging revisions rather than inventing a second source of truth
- tests and docs for future Settings phases must validate atomicity, revision behavior, replay safety, and conflict handling

### Supersedes

Any future design that makes the primary CP → Settings cascade asynchronous, split-commit, event-key driven, or silently eventually consistent.

---

## ADR-0018 — Settings Bootstrap Semantics Move Out Of Auth Bootstrap Through A Controlled Rollout Bridge

### Status

LOCKED

### Decision

Final ownership for Settings bootstrap semantics belongs to the Settings module, not the auth bootstrap surface.

The future target contract is:

- auth bootstrap owns session, identity, membership, and role truth only
- `GET /settings/bootstrap` becomes the only source for Settings bootstrap semantics such as banner visibility, overall setup state, and next recommended action

The current auth-phase workspace-setup scaffold remains the honest shipped behavior until native Settings state exists.
That scaffold is temporary and must be retired through a controlled rollout bridge rather than left behind as a permanent second truth source.

The rollout bridge is locked as follows:

- if legacy workspace acknowledgement exists and native Settings rows do not, native Settings rows are created during backfill/bridge work
- legacy acknowledgement may only strengthen the Access boundary where the current acknowledge semantics still match; it must not by itself promote the tenant to overall `COMPLETE`
- all other live Settings sections default to `NOT_STARTED` unless real persisted section data justifies a stronger state
- `/admin` may temporarily consume both auth and Settings surfaces during rollout, but auth must stop mirroring Settings semantics once the native bootstrap surface is live
- after bridge completion, the legacy auth scaffold is removed from the Settings truth path

### Why

The current shipped repo needs a safe interim banner/acknowledgement behavior before the full Settings module exists.
But the locked Settings roadmap also forbids permanent duplicate bootstrap truth and requires backend-owned, persisted, Settings-native state.

Without a locked rollout bridge, future implementation work could either:

- keep auth as a permanent owner of Settings semantics, or
- perform an over-aggressive backfill that incorrectly marks tenants complete based only on the old acknowledgement timestamp

Both outcomes would violate the locked Settings model.

### Consequences

- the auth-phase workspace setup acknowledgement flow was temporary scaffolding, not the final Settings bootstrap contract
- Settings work introduced `GET /settings/bootstrap` as the authoritative Settings bootstrap surface
- rollout and backfill work is explicit, auditable, and conservative
- no tenant is backfilled to overall `COMPLETE` from legacy acknowledgement alone
- after bridge completion, auth bootstrap docs and code stop carrying live Settings semantics; `setupCompleted` remains only as compatibility metadata

### Supersedes

Any future design that leaves auth as the permanent owner of Settings bootstrap semantics, keeps two bootstrap truth sources indefinitely, or treats legacy acknowledgement as sufficient proof of full Settings completion.

## ADR-014 — Control Plane route existence is separate from no-auth access

LOCKED

### Decision

Control Plane is a permanent internal application surface in this repo. Its backend `/cp/*` route surface is controlled by `CP_ENABLED`, while its access policy is controlled separately by `CP_AUTH_MODE`.

The current allowed local/CI bridge is:

- `CP_ENABLED=true`
- `CP_AUTH_MODE=none`

`CP_AUTH_MODE=none` is allowed only for bounded local development and CI while dedicated CP authentication is deferred. Production must never run with `CP_AUTH_MODE=none`.

`CP_NO_AUTH_ALLOWED` is retained only as a deprecated compatibility alias for older local env files and must not be used in new environment templates.

### Why

The previous `CP_NO_AUTH_ALLOWED` flag overloaded two different concerns: whether CP routes existed at all, and whether those routes skipped authentication. That made stale local env files look like missing routes, because `/cp/*` was not registered and host-run CP requests returned 404.

Separating route registration from auth policy keeps CP as a first-class synchronized application surface while still keeping unauthenticated CP access explicitly temporary and non-production.

### Consequences

- backend route registration uses `CP_ENABLED`
- local/CI no-auth access uses `CP_AUTH_MODE=none`
- production startup fails if CP is enabled with `CP_AUTH_MODE=none`
- host-run `localhost:3002/api/*` remains a CP Next.js shim to the backend and requires backend CP routes to be enabled
- tenant hosts still receive generic 404s for `/api/cp/*`
- real production CP requires a dedicated CP auth mode before exposure

### Supersedes

Any interpretation that CP itself is temporary, or that no-auth access controls whether CP routes exist.

## ADR-0019 — Settings Readiness Gate Retires Auth-Owned Setup Acknowledgement

### Status

LOCKED

### Decision

The active repo no longer exposes auth-owned workspace setup acknowledgement as a Settings writer. The historical auth-phase acknowledgement route is retired from the live API surface, and Settings setup truth is owned by Settings-native persisted state.

Current authoritative setup consumers are:

- `/admin` reads `GET /settings/bootstrap` for banner visibility, aggregate status, and next recommended action
- `/admin/settings` reads `GET /settings/overview` for section cards, detailed status, and route treatment
- Settings section pages read and mutate only `/settings/*` APIs
- Control Plane allowance changes invoke the synchronous Settings cascade once a tenant is provisioned

`ConfigResponse.tenant.setupCompleted` and `tenants.setup_completed_at` remain as retired compatibility/backfill artifacts only. They must not be used by new Settings consumers for banner visibility, setup status, Needs Review state, or section progress.

### Why

The Settings v1 readiness gate requires one authoritative Settings bootstrap truth and no competing auth-phase Settings truth. Leaving an auth acknowledgement mutation active would allow a non-Settings route to mutate setup state outside the Settings state engine, bypassing section-level save semantics, audit expectations, and CP revision conflict handling.

### Consequences

- the retired auth acknowledgement route returns normal route-miss behavior and must not mutate `tenants.setup_completed_at` or Settings state
- Settings bootstrap and overview remain backend-authoritative and persisted
- legacy setup timestamps may still be used by migrations/backfill logic, but not by active Settings page consumers
- API docs, QA docs, runbooks, and readiness tests must describe the retired endpoint as compatibility history, not current behavior
- any future attempt to reintroduce auth-owned setup acknowledgement requires a new ADR because it would create a second Settings truth path

### Supersedes

Any interpretation of ADR-0003 or ADR-0018 that treats auth bootstrap or an auth acknowledgement route as current owner of Settings setup semantics.

## ADR-0020 — Operational Access Target Levels Are Admin, Agent, And User With MEMBER Compatibility Alias

### Status

LOCKED

### Decision

The future Operational Access model uses three tenant user levels: `Admin`, `Agent`, and `User`.

The current shipped backend runtime contract is `ADMIN | AGENT | USER`. Legacy `MEMBER` is treated as a compatibility alias for `USER` at controlled input/read boundaries during the backend compatibility window.

Future behavior target:

- `Admin` sees everything tenant-wide by level.
- `User` sees own/self-service data by default.
- `Agent` receives operational access through group toolbox + coverage keys, with rare Special Access for one-person extra capabilities.
- Public signup creates canonical `User`.
- HRIS/imported users map conceptually to future `User` unless explicitly promoted later.
- Current Agent invitations require at least one active Agent Group; that assignment is provisioning-only and does not grant runtime Operational Access.

### Why

The product needs a clear distinction between tenant administrators, operational workers, and self-service users without pretending Operational Access is shipped. The backend role foundation now carries the three runtime levels, while Agent operational access remains deferred.

### Consequences

- API docs must describe canonical `ADMIN | AGENT | USER` where backend responses/inputs now expose those values.
- Legacy `MEMBER` must remain documented only as a compatibility alias for `USER`.
- QA may test role parsing, session carrying, admin-only guards, and non-admin MFA policy for `AGENT`/`USER`.
- QA may test Agent invite group validation and group membership management as provisioning behavior.
- QA must not test Agent operational access, Agent Groups as operational grant subjects, Primary Where, Which Records, Additional Coverage, Special Access, Effective Access Resolver behavior, or module-level Agent/User data differences until those surfaces exist.

### Supersedes

Any wording that implies Agent operational access, Agent Group membership as a runtime grant, Primary Where, Which Records, Additional Coverage, Special Access, Effective Access Resolver behavior, or module-level Agent/User data differences are already shipped.

## ADR-0021 — Sensitive Field Conflicts Resolve To The Most Restrictive Effective Result

### Status

LOCKED

### Decision

Future Operational Access must treat sensitive-field visibility as intentional, explicit, auditable, and scope-bound.

When multiple group grants, scopes, or exceptions conflict for a sensitive field, the safer/more restrictive result wins by default unless there is an explicit sensitive-field visibility grant that applies to the target field and target scope.

Sensitive fields must not become visible merely because one broader group grants general access. Masked or hidden treatment must remain in effect when explicit sensitive visibility is absent, orphaned, expired, or outside scope.

### Why

Operational Access combines groups, scopes, cards, fields, and rare person-level exceptions. Additive access is useful for non-sensitive actions, but sensitive data needs a stricter default to avoid accidental exposure.

### Consequences

- Future Effective Access resolution must carry sensitive-field rules explicitly.
- Future module action catalogs must separate broad actions such as `Manage` from sensitive-field visibility.
- Future QA must prove conflict cases where a user belongs to multiple groups with different sensitive-field outcomes.
- Current Settings v1 Personal masking configuration is not a runtime Operational Access grant.

### Supersedes

Any interpretation that broad module access or broad card access automatically reveals sensitive fields.

## ADR-0022 — Current Access & Security Route Must Not Be Confused With Future Operational Access

### Status

LOCKED

### Decision

The current `/admin/settings/access` and backend `/settings/access` surface is **Access & Security** for Settings v1. It covers read-only / acknowledge-only tenant review of login methods, MFA policy, signup policy, invite policy, and SSO dependency readiness.

It is not the future Operational Access / People & Teams surface.

The future route strategy is a planned migration decision:

- current Access & Security should move toward clearer Security/Login & Security naming when a real migration is designed
- `/admin/settings/access` can later be reserved for tenant Operational Access only after a non-breaking route/content migration is planned, implemented, and tested
- no documentation-only change renames the live route, backend API, or current page semantics

### Why

The word “Access” is overloaded. The repo already ships Access & Security. The future roadmap needs Operational Access. Treating both as the same surface would cause product, QA, and implementation drift.

### Consequences

- Current API docs must state that `/settings/access` is Access & Security.
- Future Operational Access docs must not claim the current route already implements group/person/module access.
- QA must keep future Operational Access tests separate from executable Settings v1 Access & Security tests.
- Any route rename requires a real implementation task, not only docs.

### Supersedes

Any wording that treats the shipped Settings Access page as tenant Operational Access.

## ADR-0023 — Backend-Owned Effective Access Resolver Is Future Platform Authorization Truth

### Status

LOCKED

### Decision

Future Operational Access must be resolved by backend/service-layer Effective Access, not by React/frontend code and not by module-local permission systems.

The future resolver is the reusable platform authorization truth after tenant resolution, membership level, Agent Group membership, Primary Where, Which Records, Additional Coverage, Special Access, CP allowance, tenant configuration, target record context, Personal Card configuration, sensitive-field rules, orphan pruning, and fail-closed behavior are applied.

Primary Where and Which Records decisions must be target-record-aware. User/session context alone is not enough when the answer depends on the target person, employer, location, assigned area pair, Responsible For relationship, review queue, Personal Card, field, sensitivity class, document audience, task participant, or similar module-owned target context.

Frontend code may render backend-returned access outcomes, blockers, warnings, explanations, and resolved card/field states. It must not compute effective permission truth independently.

The future explanation view explains the backend decision that already happened. It is not a simulator, not a separate permission calculator, and not an alternate source of truth. Admin explanation may be simple: `Full tenant access by Admin level`. Agent and User explanations should show source group, Person Exception, scope, card, field, and fail-closed/orphan reason where applicable and safe to expose.

### Why

Operational access depends on tenant, actor, target record, target person placement, groups, exceptions, cards, fields, masking, and sensitivity. Computing that in each module or in the frontend would produce drift and security bugs.

### Consequences

- Future modules must define action catalogs, target objects, and resolver target-context requirements before implementation.
- Future QA must prove direct API denial, not only hidden buttons.
- Effective Access explanation views are explanations of backend decisions, not simulators that can create alternate truth.
- Current repo does not yet ship this resolver.

### Supersedes

Any module-specific visibility model that bypasses the shared future resolver.

## ADR-0024 — Reusable Groups Combine With Coverage Keys To Avoid Employer/Location-Specific Group Explosion

### Status

LOCKED

### Decision

Future People & Teams groups are reusable tenant-level teams/audiences. They define the **toolbox**: who commonly receives access and what kind of work they can do. They should not be employer/location-specific by default.

Operational Access combines:

```text
Group = toolbox
Coverage = keys
```

The tenant-admin setup model is:

```text
Who + What + Primary Where + Which Records + Optional Coverage + Why
```

Branch, regional, billing, reviewer, and manager patterns should use reusable groups plus coverage keys, not a new group for every employer/location combination.

Examples:

- `Billing Agents` group + Assigned Areas coverage per member.
- `Managers` group + Responsible For people per manager.
- `Document Reviewers` group + Assigned Areas plus Which Records = Documents requiring review.

Selected employer/location responsibility must use explicit pairs, not independent employer lists plus independent location lists, because independent lists can accidentally create unintended combinations.

### Why

Creating separate groups such as `IT Dallas`, `IT Chicago`, and `IT Miami` for every operational scope would explode group count, make access hard to audit, and confuse tenant admins. The 9.5 model keeps groups reusable and puts variance in coverage keys.

### Consequences

- Future module discovery must define supported Primary Where and Which Records choices.
- Future audience targeting must combine group + coverage and must limit Agent-created audiences to the Agent's own effective access scope.
- Group archive/delete must fail closed and retain orphan/remediation/audit references.
- Current repo does not yet implement People & Teams operational groups or runtime coverage keys.

### Supersedes

Any default model that solves access by requiring location-specific groups.

## ADR-0025 — Operational Access Provisioning Target Behavior Preserves Role Compatibility

### Status

LOCKED

### Decision

The future provisioning target for Operational Access is:

- Public signup creates `User` in the target model.
- HRIS import creates `User` only in the MVP target model.
- Admin invitation supports `Admin`, `Agent`, and `User`.
- Agent invitation requires at least one active Agent Group.
- Agent Group assignment created during invite flow is provisioning-only group membership until Operational Access grants, coverage, resolver, and module consumers ship.
- If every selected Agent Group is archived, deleted, orphaned, or otherwise inactive before invite acceptance, invite acceptance must fail closed and require an admin to update/resend the invitation.
- Backend invite and provisioning APIs recognize canonical runtime roles `ADMIN | AGENT | USER`; legacy `MEMBER` input is normalized to `USER` during compatibility.

### Why

Provisioning is the entry point into tenant access. The backend role foundation and invite flow now support the canonical runtime vocabulary and Agent Group assignment while still preventing documentation from pretending that group membership grants runtime Operational Access.

### Consequences

- Current API docs must describe canonical `ADMIN | AGENT | USER` where backend contracts changed, with `MEMBER` only as a legacy alias.
- Current invite design validates Agent Group selection at invitation creation and again at acceptance.
- Agent invite acceptance must not silently activate an Agent with ghost group membership from archived groups.
- People & Teams group membership remains provisioning-only until Operational Access grants, coverage, resolver, and module consumers ship.
- HRIS import planning must not create operational Agents in MVP without a later explicit promotion/admin action path.
- QA for Agent group invite behavior is executable for provisioning-only Agent group selection and invite acceptance. Operational Access QA remains future/not executable until Agent Groups become grant subjects, coverage, resolver contracts, and module consumers are implemented.

### Supersedes

Any design that treats public signup, HRIS import, or legacy `MEMBER`-style invitation as creating anything other than canonical `USER`, or any design that allows Agent activation without an active Agent Group.

## ADR-0026 — Operational Access MVP Grants Use Agent Groups, Primary Where, Which Records, And Optional Coverage

### Status

LOCKED

### Decision

Future Operational Access MVP subjects are limited and intentional:

- `Admin` receives full tenant access by level and does not need operational grants.
- Agent Groups are the primary subject for operational grants.
- `User` receives own/self-service behavior and does not receive cross-person operational grants in MVP.
- Special Access / Access Exceptions are rare direct-user paths for unusual one-person extra capability, not the normal grant path.
- Admin Groups may exist for organization/audience purposes, but they do not restrict or reduce Admin access.

The MVP setup split is:

```text
Primary Where — pick one normal operating model
Which Records — product-defined filter/queue inside that Where
Additional Coverage — optional Oversight or Temporary Coverage
Special Access — advanced, separate area
```

MVP Primary Where options are:

- Tenant-wide
- Assigned Areas
- Responsible For
- Review Queue

Which Records choices are module-defined, product-owned choices such as Documents requiring review, Open tasks, Billing records for assigned areas, Active checklist instances, or Benefits enrollment records requiring explicit high-sensitivity access.

Additional Coverage is optional and limited to:

- Oversight
- Temporary Coverage

Special Access is separate from Primary Where and Additional Coverage. It is an advanced review area for rare one-person extra capabilities.

Department, arbitrary group-as-target scope, reporting-tree expansion, and custom combinations are deferred unless a later module design proves they are needed and safe.

### Why

The platform needs enough access power for real Goodwill-style hierarchy, review queues, billing agents, temporary backup, and sensitive Personal/Benefits data without becoming an arbitrary policy builder. The Primary Where / Which Records / Additional Coverage split keeps the tenant-admin mental model understandable.

### Consequences

- New module discovery must define which Primary Where options and Which Records choices apply before technical planning starts.
- Future modules must not invent module-local visibility systems, location-specific default groups, or custom scope builders.
- Future resolver planning must include target-record context for every selected Primary Where and Which Records choice.
- Future User Groups must not become a stealth path for cross-person operational access in MVP.
- Any later Department, reporting-tree, or custom-scope implementation needs a separate design/ADR because it widens the platform access model.

### Supersedes

Any MVP design that gives operational grants to User Groups, treats Admin Groups as restrictions on Admins, collapses Oversight/Temporary Coverage into normal Primary Where, or models selected employer/location responsibility as independent lists that can create unintended combinations.

## ADR-0027 — Personal Cards Are Reusable Field Groupings, Not Workflow Or Module State

### Status

LOCKED

### Decision

Personal Cards are the future reusable grouping mechanism for allowed Personal fields.

Personal Cards:

- group Personal fields into tenant-admin-configured cards
- provide the runtime field/card layout consumed by modules
- carry card/field visibility, masking, editability, required/optional output after backend resolution
- are separate from workflow, approval, task, enrollment, document, or module lifecycle state

MVP rules:

- one field belongs to one active Personal Card
- a field not assigned to an active Personal Card is hidden at runtime
- consuming modules must request backend-resolved Personal Card output and must not raw-read Personal fields around Personal Cards
- if a consuming module needs a field that is unavailable through active Personal Cards, it must surface an admin-facing warning/blocker or fail closed safely; it must not silently expose the raw field or invent a module-local field layout

### Why

Personal data will be reused by many modules. Without a single resolved Personal Card contract, each module would recreate field layouts, masking, and sensitive-field behavior differently.

### Consequences

- Future module discovery must state whether the module consumes Personal Cards and which card/field output it needs.
- Future Personal Card resolver proof must happen before modules rely on Personal field visibility.
- Workflow state belongs to the consuming module, not to Personal Cards.
- Benefits, Documents, Tasks, Checklists, and similar modules must not bypass Personal Cards for Personal field display.
- Multiple-card field assignment is deferred beyond MVP because it creates conflict and explanation complexity.

### Supersedes

Any design that treats Personal Cards as a form builder, workflow engine, approval-state owner, or optional frontend-only layout while modules continue reading Personal fields directly.

## ADR-0028 — Special Access Is Rare, Reviewed, Audited, And Scope-Bound

### Status

LOCKED

### Decision

Future Special Access / Access Exceptions are rare direct user-specific access records used when normal group toolbox + coverage keys cannot model a legitimate operational need.

Special Access is not Primary Where and is not Additional Coverage. It lives in a separate advanced review area.

MVP Special Access rules:

- reason is required
- review date is required
- expiry is required for temporary extra access and sensitive-field access
- MVP mainly supports rare extra capability
- Special Access must be scope-bound, auditable, explainable, and fail closed when expired, orphaned, or outside scope
- Hubins does not automatically validate the reason category in MVP; accountability comes from the required reason, review/expiry discipline, explanation visibility, and audit trail

Examples:

- Mary can temporarily approve billing exports.
- John can temporarily manage documents tenant-wide.
- Lisa can temporarily run a sensitive report.

### Why

Real tenants need a narrow escape hatch for unusual one-person access. Without strict review, expiry, and audit rules, direct-user grants become an unmanageable shadow permission system.

### Consequences

- Future implementation must not use direct-user grants as the normal operational access path.
- Future admin UI must present Special Access as exception management, not as a second primary permission editor.
- Future Effective Access explanation must identify applicable Special Access sources where safe and useful.
- Future QA must cover expired, orphaned, sensitive, and out-of-scope Special Access.
- Sensitive-field Special Access must remain intentional and auditable.

### Supersedes

Any broad MVP design for direct-user grants, permanent unexplained exceptions, or general deny-style exceptions as a full policy feature.

## ADR-0029 — Operational Access Runtime Proof Starts With Personal Cards, Then Published Documents

### Status

LOCKED

### Decision

The first runtime proof of the future Operational Access model must be staged:

1. Personal Cards runtime resolver proof comes first.
2. Published Documents comes after as the first real operational module proof.

Personal Cards prove field/card resolution, masking, sensitive-field behavior, field-not-in-card fail-closed behavior, and backend-resolved card output.

Published Documents then prove that a real operational module consumes shared Operational Access rather than inventing module-local visibility.

### Why

Operational Access is cross-cutting and security-sensitive. Proving it first at the field/card resolution layer keeps the first proof narrow. Proving it next in Published Documents validates the module-consumer contract without letting every future module design its own resolver.

### Consequences

- Do not start broad Operational Access admin UI or multiple module integrations before the Personal Cards resolver proof is planned and implemented.
- Published Documents technical planning must consume the shared resolver contract and the module-discovery answers, not create a Documents-only permission system.
- QA sequencing must distinguish resolver proof from operational-module proof.
- Current repo docs must continue to say this is not implemented until code, tests, and QA evidence exist.

### Supersedes

Any rollout plan that starts with a giant permissions table, module-specific Documents access, or frontend-only visibility hiding before the backend resolver is proven.

## ADR-0030 — Operational Access 9.5 Source-of-Truth Model Replaces Older Operational Access Drafts

### Status

LOCKED

### Decision

`hubins-operational-access-9_5-source-of-truth-guide-final.md` is the active Operational Access product/architecture source for future planning.

Older Operational Access roadmap/model/UX drafts are superseded for active implementation planning. They may remain in history only if clearly marked as superseded.

This decision does not claim Operational Access is shipped. It only locks the planning source and anti-drift rule.

### Why

Operational Access had multiple overlapping drafts. The 9.5 guide resolves the final Admin/User/Agent model, group toolbox + coverage keys metaphor, Primary Where / Which Records / Additional Coverage split, Goodwill-style oversight behavior, and not-shipped boundaries.

### Consequences

- Future LLM implementation chats must load the 9.5 guide, not older Operational Access drafts.
- Current foundation status, module discovery, QA planning, and Account Settings Section 19 language must align to the 9.5 guide.
- If any older Operational Access document conflicts with the 9.5 guide, the 9.5 guide wins.

### Supersedes

Older Operational Access roadmap/model/UX drafts as active source-of-truth documents.

## ADR-0031 — Operational Access Setup Splits Primary Where, Which Records, Additional Coverage, And Special Access

### Status

LOCKED

### Decision

The future tenant-admin Operational Access setup must not present one confusing generic scope list. It must split access into these layers:

```text
Primary Where — pick one normal operating model
Which Records — product-defined filter/queue inside that Where
Additional Coverage — optional Oversight or Temporary Coverage
Special Access — advanced, separate area
```

Primary Where options are Tenant-wide, Assigned Areas, Responsible For, and Review Queue.

Which Records choices are published by each module and must remain product-defined.

Additional Coverage is optional and includes Oversight and Temporary Coverage.

Special Access is separate from group coverage setup and is reserved for rare one-person extra capabilities.

### Why

Tenant admins should not feel like they are operating a permission engine. The split maps to normal business questions: where does this group work, which records does it touch, and whether anyone needs extra coverage.

### Consequences

- Module discovery must answer Primary Where and Which Records separately.
- UX must not put Oversight, Temporary Coverage, or Special Access in the Primary Where list.
- Technical planning must preserve the distinction even if implementation uses shared internal tables/services later.
- QA must test the layers independently once shipped.

### Supersedes

Any seven-option or generic scope list that mixes normal operating model, review queues, oversight, temporary coverage, and special exceptions together.

## ADR-0032 — Oversight Is Directed, Single-Hop, And Dynamically Resolved

### Status

LOCKED

### Decision

Future Oversight is directed, not reciprocal, and single-hop in MVP.

If Manager A oversees Manager B and Manager C:

- B/C do not see A unless explicitly granted.
- A sees B/C as oversight targets.
- A sees B/C's responsible people/work only when `Includes their responsible people/work` is explicitly enabled.
- If enabled, the inclusion is dynamically resolved from B/C's current Responsible For coverage.
- If A oversees B and B oversees C, A does not automatically see C's team in MVP.

Sensitive fields remain governed by masking/unmasking rules and do not become visible merely because oversight exists.

### Why

Goodwill-style tenants need real manager/reviewer oversight without creating accidental reporting-tree expansion or reciprocal access. Single-hop directed resolution is powerful enough for MVP and easier to explain, audit, and test.

### Consequences

- Future resolver design must represent oversight direction and include-team behavior explicitly.
- Future UI must show the include-team decision clearly.
- Future QA must prove include-team yes/no, non-reciprocity, and single-hop behavior.
- Future implementation must not materialize broad static copies that drift from current Responsible For coverage.

### Supersedes

Any implicit reporting-tree expansion, reciprocal oversight, or multi-hop oversight behavior in MVP.

## ADR-0033 — Operational Access Tenant Surface Is Guarded By `operational_access_enabled`

### Status

LOCKED

### Decision

Advanced Operational Access setup is gated by a tenant capability:

```text
operational_access_enabled
```

When false, simple Admin/User tenants must not see advanced Operational Access setup.

When true, Agents, Agent Groups as operational grant subjects, Primary Where, Which Records, Additional Coverage, Special Access, and resolver-backed access can be made available according to implementation readiness.

This capability is shipped as a live fail-closed feature flag in this repo. It enables only the current Operational Access foundation and Personal Cards proof surface; it does not imply all-module Operational Access rollout.

### Why

Many tenants need only Admins and Users. Showing operational-grant setup to simple tenants would create confusion and unnecessary setup burden.

### Consequences

- CP owns enable/disable for the capability only; CP does not manage runtime Operational Access assignments.
- Settings/People & Teams UX must not expose advanced Operational Access controls for simple tenants.
- Docs and QA must distinguish the shipped foundation and Personal Cards proof from deferred all-module rollout, Assigned Areas, Review Queue enforcement, and search/export/notification/generated-output propagation.

### Supersedes

Any design that forces every tenant through advanced Agent/coverage setup.

## ADR-0034 — Search, Notifications, Exports, And High-Sensitivity Domains Must Consume Resolver Output

### Status

LOCKED

### Decision

Future modules must not apply Operational Access only to detail pages. The same backend-resolved visibility must govern:

- list pages
- search results
- autocomplete/suggestions
- notification titles and bodies
- email digests
- CSV exports
- PDF/generated documents
- report results
- background recipient selection

Sensitive and high-sensitivity domains, especially Benefits and Personal data, require explicit scope-bound access. Broad group membership or broad Manage actions do not imply unmasked sensitive export, notification, search, or generated-output access.

For sensitive-field conflicts, the safer/more restrictive result wins by default unless an explicit sensitive visibility grant applies to the field, target, channel, and scope.

### Why

Search, notifications, exports, generated PDFs, and emails are common data-leak paths. A module is not secure if only its UI detail page respects Effective Access.

### Consequences

- New module discovery must include search/export/notification leak checks.
- Future resolver planning must include set-shape decisions for list/search/export and decision-shape decisions for detail/action/field behavior.
- Benefits and similar high-sensitivity modules need explicit high-sensitivity access decisions before implementation.
- QA must prove that hidden records do not leak through counts, snippets, notifications, or exports.

### Supersedes

Any module design where search, notifications, exports, generated documents, or high-sensitivity records bypass backend Effective Access.

## ADR-0035 — Operational Access First Real Module Proof Is Personal Cards With Scoped Governance Saves

### Status

LOCKED

### Decision

The first real Operational Access module consumer is the backend Personal Cards read surface:

- `GET /personal/cards`
- `GET /personal/cards/:membershipId`

These endpoints consume the backend Operational Access resolver for `personal_cards.view`. They must server-filter list results, deny unauthorized direct detail access, return a module-owned Personal Card read model with server-decided field visibility/masking, include sensitive-field masking/hiding proof for `person.ssn` and `person.date_of_birth`, omit fields outside the shipped proof card, and expose only safe sourcePath / Why explanations. Frontend code may render this output but must not compute effective access or filter records into compliance.

Operational Access-owned runtime proof endpoints under `/operational-access/runtime/people` remain useful resolver proof surfaces, but closure proof must treat `/personal/cards` as the first normal module API integration.

Advanced coverage saves for Oversight, Temporary Coverage, and Special Access are versioned and subject-scoped. They may replace rows for the affected subject memberships only through `replaceForMembershipIds` plus subjects present in the payload. They require the current `expectedVersion` and must not use stale full-tenant replacement semantics that can wipe unrelated advanced access rows. Success audit records before/after detail; rejected sensitive mutations write failure audit where the shared audit infrastructure can persist the failure.

### Why

Operational Access needed proof that a real module API, not only an OA-owned diagnostic endpoint, can consume backend-resolved access safely. Advanced coverage also needed mutation hardening so a stale admin save cannot erase unrelated manager coverage, temporary backup, or one-person exception records. The tenant-scoped advanced coverage version provides a simple optimistic-concurrency boundary.

### Consequences

- The shipped runtime proof is narrow: `personal_cards.view` only.
- Assigned Areas, Review Queue enforcement, broad Which Records enforcement across all modules, search/export/notification/generated-output propagation, and a full Personal Cards UI remain not fully shipped.
- Group membership alone still grants no runtime visibility.
- CP still only enables/disables `operational_access_enabled`; CP does not manage runtime assignments.
- `/admin/settings/access` remains Access & Security.
- Future module integrations must follow the same pattern: backend-resolved set/detail decisions, server-side filtering, direct-bypass denial, masking, and safe Why output.

### Supersedes

Any interpretation that the Operational Access runtime proof is only an OA-owned route, or that advanced coverage saves may replace all tenant advanced access rows by default.

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

---
