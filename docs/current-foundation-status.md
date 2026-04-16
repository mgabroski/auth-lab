# Current Foundation Status

## Status

This document is the current shipped-truth snapshot for the repo.

It records what is implemented, what is locked, what remains open, and which active documents own which kinds of truth.

Documentation-system cleanup for the current repo state is closed.
Use the routing and tier rules in `AGENTS.md` as the canonical guide for documentation priority, AI read order, attachment rules, and tier assignment.

If this file conflicts with support docs, folder maps, prompt docs, or temporary planning notes, this file wins unless a module-specific higher-truth document explicitly outranks it for that module.

---

## Current Repo Phase

The repo is in the Auth / Provisioning foundation stage with topology, security model, current auth flows, and documentation routing substantially locked. CP Phase 6 producer-side Settings handoff preparation is now shipped, while live CP → Settings cascade wiring remains correctly blocked until the real Settings state engine exists.

This repo already has:

- single public-origin local topology through the proxy
- host-derived tenant routing
- backend-owned auth/session/membership truth
- current auth and invite API surfaces
- current QA and developer execution documents
- a locked documentation routing model with explicit tiering
- a separate internal Control Plane frontend app with Phase 1 shell and routing
- a real CP backend module (`backend/src/modules/control-plane/`) with accounts create/read/list endpoints
- a real `cp_accounts` table (migration `0014_cp_accounts.ts`)
- real CP Phase 3 Step 2 persistence for setup groups and Personal field-catalog truth
- real CP Phase 4 Review & Publish backend composition, Activation Ready validation, publish action, and tenant provisioning truth
- real CP Phase 5 edit/re-entry surfaces, published-account status toggle, and practical accounts list actions
- real CP Phase 6 producer-side Settings handoff snapshot on full account detail DTOs and internal backend service composition
- CP frontend wired to real backend data for create basic-info submission, accounts list, Step 2 group saves, Step 2 progress state, required-group continuation gating, and Review & Publish

This repo does not yet claim that the full Auth / Provisioning closure roadmap is complete.
Roadmap closure still depends on the remaining real-environment, proof, QA, and production-readiness work tracked elsewhere.

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

### Control Plane foundation — Phase 6 producer-side handoff prep (current)

- a separate Control Plane Next.js app exists at `cp/`
- the Control Plane is not part of the tenant frontend package
- root Control Plane entry redirects into the create-account flow
- **real backend module exists** at `backend/src/modules/control-plane/`
- **real `cp_accounts` table** created by migration `0014_cp_accounts.ts`
- **real Phase 3 Step 2 tables** created by migration `0015_cp_setup_groups.ts`
- **real Phase 4 provisioning table** created by migration `0016_cp_review_publish.ts`
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
- **accounts list is now a practical re-entry surface**: edit/setup, review/re-save, and Active/Disabled toggle actions are all backend-backed
- **published-account status toggle is now real**:
  - `PATCH /cp/accounts/:accountKey/status` updates the real provisioned tenant row and `cp_accounts.cp_status`
  - Draft accounts still use Review & Publish for first publication
  - status changes do not increment `cpRevision` because they do not mutate CP allowance truth
- **canonical producer-side Settings handoff snapshot now exists** on full CP account detail DTOs as `settingsHandoff`
- **internal backend handoff contract now exists** through `CpAccountsService.getSettingsHandoff(accountKey)` for future in-process Settings consumption
- **State A stopping boundary is explicit and honest**:
  - `settingsHandoff.mode` is `PRODUCER_ONLY`
  - `settingsHandoff.consumer.settingsEnginePresent` is `false`
  - `settingsHandoff.consumer.cascadeStatus` is `NOT_WIRED`
  - blocking reasons explain why live CP → Settings cascade is not active yet
- producer-side handoff snapshot carries allowance truth and provisioning truth only; it does **not** mirror CP Step 2 progress/configured flags as fake Settings truth
- CP backend remains dev-only no-auth in this phase — CP authentication is a later phase
- the locked 3-step CP flow (Basic Account Info → Account Setup → Review & Publish) remains unchanged
- the 4 locked setup groups remain unchanged
- `cpRevision` starts at 0 on account creation and now increments on meaningful Step 2 allowance mutations
- publish updates `cpStatus` and provisioning truth but does not increment `cpRevision` because it does not change CP allowance truth
- CP provisioning truth remains separate from tenant configuration truth

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

### Control Plane expansion (remaining phases)

The Control Plane now ships Phase 6 producer-side Settings handoff preparation. Still open:

- CP authentication and operator RBAC
- CP audit trail UI
- CP → Settings cascade (blocked until Settings state engine exists)

### Settings expansion

The repo contains real `/admin/settings` groundwork and locked Settings design inputs, but the broader Settings implementation remains open.
Current shipped auth/settings surfaces must not be mistaken for full Settings completion.

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
