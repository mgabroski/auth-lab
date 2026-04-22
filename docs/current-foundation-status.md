# Current Foundation Status

## Status

This document is the current shipped-truth snapshot for the repo.

It records what is implemented, what is locked, what remains open, and which active documents own which kinds of truth.

Documentation-system cleanup for the current repo state is closed.
Use the routing and tier rules in `AGENTS.md` as the canonical guide for documentation priority, AI read order, attachment rules, and tier assignment.

If this file conflicts with support docs, folder maps, prompt docs, or temporary planning notes, this file wins unless a module-specific higher-truth document explicitly outranks it for that module.

---

## Current Repo Phase

The repo is in the Auth / Provisioning foundation stage with topology, security model, current auth flows, and documentation routing substantially locked. The shipped Control Plane now includes create/setup/review/publish/re-entry/status-toggle behavior, producer-side Settings handoff output, dedicated route-level integrity coverage, and a real browser smoke in CI. The repo now also ships the current tenant-facing Settings slice for `/admin` and `/admin/settings`: real synchronous CP -> Settings cascade handling, `GET /settings/bootstrap`, `GET /settings/overview`, Settings-native banner consumption on `/admin`, a real Settings overview page at `/admin/settings`, a real Access page at `/admin/settings/access`, a real Account page at `/admin/settings/account` with per-card save boundaries, a real Modules hub page at `/admin/settings/modules`, a real Personal family-review + field-rule foundation page at `/admin/settings/modules/personal`, a placeholder-only Communications route, an honest SSR-gated Integrations shell, and continued absence of Permissions.

This repo already has:

- single public-origin local topology through the proxy
- host-derived tenant routing
- backend-owned auth/session/membership truth
- current auth and invite API surfaces
- current QA and developer execution documents
- a locked documentation routing model with explicit tiering
- a separate internal Control Plane frontend app with real create, setup, review, publish, re-entry, and status-toggle surfaces
- dedicated CP route-level integrity tests for create and edit / re-entry page surfaces
- a dedicated real-stack CP browser smoke in CI covering create → required-group saves → review → publish → re-enter → status toggle
- a real CP backend module (`backend/src/modules/control-plane/`) with create/read/list, group-save, review/publish, status-toggle, and producer-side handoff endpoints
- a real `cp_accounts` table (migration `0014_cp_accounts.ts`)
- real CP Step 2 persistence for setup groups and Personal field-catalog truth
- real CP Review & Publish backend composition, Activation Ready validation, publish action, and tenant provisioning truth
- real CP edit/re-entry surfaces, published-account status toggle, and practical accounts list actions
- real CP producer-side Settings handoff snapshot on full account detail DTOs and internal backend service composition
- CP frontend wired to real backend data for create basic-info submission, accounts list, Step 2 group saves, Step 2 progress state, required-group continuation gating, and Review & Publish

This repo does not yet claim that the full Auth / Provisioning closure roadmap is complete.
Roadmap closure still depends on the remaining real-environment, proof, QA, and production-readiness work tracked elsewhere.

## Settings Implementation Baseline (Current)

The locked Settings execution baseline for future repo work is now:

- `Account-Settings-Master-Context-v9_2.md` for product and ownership truth
- `Hubins-Settings-Step10-Roadmap-v4.docx` as the accepted implementation roadmap baseline
- `docs/decision-log.md` ADR-0017 and ADR-0018 for the now-locked Phase 0 contracts

What this means today:

- the repo still retains the auth-phase workspace-setup scaffold (`/auth/config` + `/auth/workspace-setup-ack`) as a backend compatibility bridge
- `/admin` now reads `GET /settings/bootstrap` as the only tenant-facing bootstrap-safe Settings source
- `/admin/settings` now reads `GET /settings/overview` as the real Settings overview source
- the repo now ships the real backend state engine foundation: persisted aggregate/section truth, aggregate recompute service, and synchronous CP cascade handling
- the current CP `settingsHandoff` snapshot remains producer-shaped, but it honestly reports that the Settings engine is present and synchronous cascade wiring is active
- the auth scaffold is no longer the tenant-facing truth path for banner or overview behavior, even though the bridge endpoint and compatibility field still exist in the backend
- no part of this baseline acceptance should be read as the full tenant Settings module already being shipped; the repo now holds the real read-side closure, the Access acknowledge path, the Account per-card save surface, the real Modules hub read surface, the real Personal family-review + field-rule read surface, and honest route treatment for later deferred pages

---

## Canonical Current-Truth Documents

These are the active current-truth docs for the repo as it exists today.
Use them before support docs.

1. `AGENTS.md` — canonical AI router, truth order, read order, attachment rules, and actual repo tier map
2. `ARCHITECTURE.md` — repo architecture law
3. `docs/security-model.md` — security, tenant, trust-boundary, and auth model law
4. `docs/decision-log.md` — locked architectural and cross-cutting decisions
5. `backend/docs/api/auth.md` — auth contract surface
6. `backend/docs/api/invites.md` — invite contract surface
7. `backend/docs/api/admin.md` — admin auth/provisioning contract surface
8. `backend/docs/api/cp-accounts.md` — CP accounts contract surface

### Supporting but non-canonical-by-default docs

These are active support docs, but they do not outrank the current-truth set above:

- `README.md`
- `docs/developer-guide.md`
- `docs/qa/qa-execution-pack.md`
- `docs/ops/*`
- `docs/prompts/catalog.md`
- other docs under `docs/prompts/`
- folder-map docs such as `backend/docs/README.md`, `frontend/README.md`, and `infra/README.md`

The support docs above now also carry explicit Control Plane execution/recovery guidance where that guidance is part of shipped repo truth.

### Historical and raw-input rule

Historical notes, raw inventories, cleanup inputs, and one-off planning materials are not active current-truth docs.
They must not be attached to continuation chats unless the task is explicitly historical analysis.

If a module-specific master context explicitly bans certain historical inputs, that ban must be respected.

---

## What Is Actually Shipped Now

The following foundations are treated as real in the repo now.

### Topology and routing

- browser traffic goes through one public origin
- proxy routes browser `/api/*` traffic to backend services
- frontend and backend are separated behind the proxy
- host-derived tenant identity is part of the runtime contract
- SSR uses the backend-aware path defined by repo architecture and topology law

### Auth and provisioning foundation

- password login exists
- invite-driven onboarding exists
- public signup exists where tenant policy allows it
- email verification and password reset flows exist in the product surface
- MFA setup and verification flows exist in the product surface
- admin vs member post-auth routing exists
- `/admin/settings` exists as a real admin route in current scope
- workspace-setup guidance exists as a real current surface, though broader Settings work remains open

### Documentation and execution surfaces

- root routing docs are tightened and active
- backend and frontend area routers are tightened and active
- one canonical developer execution surface exists: `docs/developer-guide.md`
- one canonical Auth / Provisioning QA execution surface exists: `docs/qa/qa-execution-pack.md`
- current prompt routing is centralized through `docs/prompts/catalog.md`

### Control Plane foundation (current)

- a separate Control Plane Next.js app exists at `cp/`
- the Control Plane is not part of the tenant frontend package
- root Control Plane entry redirects into the create-account flow
- **real backend module exists** at `backend/src/modules/control-plane/`
- **real `cp_accounts` table** created by migration `0014_cp_accounts.ts`
- **real CP Step 2 tables** created by migration `0015_cp_setup_groups.ts`
- **real CP provisioning table** created by migration `0016_cp_review_publish.ts`
- **real backend routes registered**:
  - `GET /cp/accounts`
  - `GET /cp/accounts/:accountKey`
  - `GET /cp/accounts/:accountKey/review`
  - `POST /cp/accounts`
  - `PUT /cp/accounts/:accountKey/access`
  - `PUT /cp/accounts/:accountKey/account-settings`
  - `PUT /cp/accounts/:accountKey/modules`
  - `PUT /cp/accounts/:accountKey/modules/personal`
  - `PUT /cp/accounts/:accountKey/integrations`
  - `POST /cp/accounts/:accountKey/publish`
  - `PATCH /cp/accounts/:accountKey/status`
- **real CP accounts API contract doc** exists at `backend/docs/api/cp-accounts.md`
- **real persisted Step 2 group state** now exists for:
  - Access, Identity & Security
  - Account Settings
  - Module Settings
  - Personal CP field configuration sub-page
  - Integrations & Marketplace
- **real Step 2 progress state** is persisted on `cp_accounts` and returned to the CP frontend
- **required-group continuation gating** is now real in the CP frontend overview and review shell
- **Review & Publish Step 3** is now real:
  - server-owned read-only review summary is returned by `GET /cp/accounts/:accountKey/review`
  - Activation Ready is evaluated server-side and returned to CP
  - publish action (`POST /cp/accounts/:accountKey/publish`) creates or updates a real `tenants` row and persists CP provisioning truth
- **Personal CP sub-page** exists under Module Settings and participates in Module Settings completion rules
- **CP same-origin API proxy** exists at `cp/src/app/api/[...path]/route.ts`
- **accounts list is now a practical re-entry surface**: edit/setup now re-enters at the real Step 2 setup overview, review/re-save remains available, and Active/Disabled toggle actions are all backend-backed
- **published-account status toggle is now real**:
  - `PATCH /cp/accounts/:accountKey/status` updates the real provisioned tenant row and `cp_accounts.cp_status`
  - Draft accounts still use Review & Publish for first publication
  - status changes do not increment `cpRevision` because they do not mutate CP allowance truth
- **canonical producer-side Settings handoff snapshot now exists** on full CP account detail DTOs as `settingsHandoff`
- **internal backend handoff contract now exists** through `CpAccountsService.getSettingsHandoff(accountKey)` for future in-process Settings consumption
- **current producer-side Settings handoff snapshot remains explicit and honest**:
  - `settingsHandoff.mode` remains `PRODUCER_ONLY` because the snapshot itself is still producer-shaped allowance/provisioning truth
  - `settingsHandoff.consumer.settingsEnginePresent` is now `true`
  - `settingsHandoff.consumer.cascadeStatus` is now `SYNC_ACTIVE`
  - unpublished accounts still report blocking reasons explaining that a tenant must be provisioned before live Settings consumption is eligible
  - published accounts no longer pretend the Settings engine is absent
- producer-side handoff snapshot carries allowance truth and provisioning truth only; it does **not** mirror CP Step 2 progress/configured flags as fake Settings truth
- CP backend remains bounded internal no-auth for the current non-public surface (local dev and CI only) — CP authentication is still deferred
- CP route registration is now disabled by default and enabled only when `CP_NO_AUTH_ALLOWED=true`
- tenant hosts reject `/api/cp/*`, backend CP routes return generic 404s on non-CP hosts, and the CP frontend returns 404 when `CP_NO_AUTH_ALLOWED` is not enabled for the current environment
- the locked 3-step CP flow (Basic Account Info → Account Setup → Review & Publish) remains unchanged
- the 4 locked setup groups remain unchanged
- `cpRevision` starts at 0 on account creation and increments only on meaningful Step 2 allowance mutations; publish and status-only changes do not increment it because they do not change allowance truth
- publish updates `cpStatus` and provisioning truth but does not increment `cpRevision` because it does not change CP allowance truth
- CP provisioning truth remains separate from tenant configuration truth
- meaningful Step 2 save routes now produce CP audit events for access, account settings, modules, personal, and integrations, with failure audit handling following the platform two-phase audit pattern

---

## What Is Locked

The following should be treated as locked unless reopened by an explicit architectural or product decision.

### Documentation-system rules

- one canonical truth order for the repo
- one canonical AI read order for the repo
- explicit Tier 1 / Tier 2 / Tier 3 mapping in `AGENTS.md`
- historical docs are demoted from active continuation context by default
- support docs do not outrank current-truth or law docs
- no two active docs should compete for the same job

### Architecture and trust-boundary rules

- frontend does not own auth truth
- backend owns session, membership, and next-action truth
- tenant identity is host-derived
- browser/backend topology is same-origin through the proxy
- SSR and browser request paths must not be treated as interchangeable
- auth, cookie, SSO, and forwarded-header behavior are boundary-sensitive and must be changed carefully

### Control Plane boundary rules

- Control Plane is a separate app, not a route subtree inside `frontend/`
- direct runtime imports from `frontend/` into `cp/` are not allowed
- CP API calls must go through the `/api/*` proxy or `cpSsrFetch` — never hardcoded backend origins
- CP provisioning truth and tenant configuration truth must not be collapsed into a single table model
- CP status vocabulary is locked: `Draft | Active | Disabled`
- account identity (name + key) is immutable after creation
- new accounts always start with `cpStatus = Draft` and `cpRevision = 0`

### QA/developer split

- developer execution and environment guidance lives in `docs/developer-guide.md`
- QA execution lives in `docs/qa/qa-execution-pack.md`
- neither doc should silently re-own the other's job

---

## What Is Still Open

The following remain open or incomplete at the repo level.

### Auth / Provisioning closure work

The full auth closure roadmap is still open in the areas already tracked by the roadmap, including:

- broader real-environment proof work
- final staging/provider proof for SSO and email delivery
- complete production-readiness closure
- final signoff that the full auth roadmap is closed

### Control Plane expansion

The Control Plane now ships its current internal create/setup/review/publish/re-entry/status-toggle surface plus producer-side Settings handoff output. Still open:

- CP authentication and operator RBAC
- CP audit trail UI
- later CP/Settings follow-up work such as explicit repair tooling and broader consumer wiring

### Settings expansion

The repo contains real `/admin/settings` groundwork and locked Settings design inputs, but the broader Settings implementation remains open.
Current shipped auth/settings surfaces must not be mistaken for full Settings completion.

Current truthful boundary:

- `/admin` now consumes `GET /settings/bootstrap` and no longer reads auth scaffold truth for banner semantics
- `/admin/settings` now consumes `GET /settings/overview` and no longer uses the one-shot auth acknowledgement placeholder as its main content model
- Step 10 foundation rows (`tenant_setup_state`, `tenant_setup_section_state`) are now consumed by live backend read surfaces and the synchronous CP cascade service
- `/admin/settings/access` now resolves to the first real Settings section page backed by `GET /settings/access` and the explicit `POST /settings/access/acknowledge` write path
- `/admin/settings/account` now resolves to the real Account Settings page backed by `GET /settings/account` plus the explicit per-card write routes for Branding, Organization Structure, and Company Calendar
- `/admin/settings/modules` now resolves to the real navigation-only Modules hub backed by `GET /settings/modules`
- `/admin/settings/modules/personal` now resolves to the real Personal family-review + field-rule foundation page backed by `GET /settings/modules/personal`
- `/admin/settings/integrations` still resolves as an honest SSR-gated shell; `/admin/settings/communications` remains placeholder-only; Permissions remains absent
- CP `settingsHandoff` remains producer-shaped but now honestly reports live Settings engine presence and active synchronous cascade wiring
- later Settings write phases beyond Access + Account remain intentionally unimplemented

### Future modules and later-scope surfaces

The repo does not claim closure for later product modules outside current auth/provisioning and currently locked design groundwork.

---

## Canonical QA and Developer Surfaces

### Developer execution surface

`docs/developer-guide.md`

Use this for:

- local setup
- commands
- environment execution
- reset/reseed workflow
- test-running instructions
- operational developer workflow

### QA execution surface

`docs/qa/qa-execution-pack.md`

Use this for:

- user-visible flow validation
- manual execution steps
- expected messages and outcomes
- evidence collection expectations
- scenario-by-scenario QA execution

Do not use `docs/developer-guide.md` as a second QA script.
Do not use the QA pack as a general developer setup guide.

---

## Actual Repo Tier Summary

This summary is informational only.
The canonical tier map lives in `AGENTS.md`.

### Tier 1

Canonical routing, current shipped truth, architecture law, security law, and area law.

### Tier 2

Canonical growing decision and API contract surfaces.

### Tier 3

Support docs, execution packs, prompt docs, folder maps, and tightly scoped module-local reference docs that do not compete with higher-tier truth.

---

## How To Use This File

Use this file when you need to answer any of the following:

- what is really shipped now
- what is locked vs still open
- which docs are canonical vs secondary
- whether a support doc is allowed to overrule a higher-truth source
