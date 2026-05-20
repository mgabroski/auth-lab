# Settings API

## Purpose

This document describes the currently shipped Settings-native backend surface.

Current live routes in this repo:

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

This is the real Settings-native tenant surface used by:

- `/admin`
- `/admin/settings`
- `/admin/settings/access`
- `/admin/settings/account`
- `/admin/settings/modules`
- `/admin/settings/modules/personal`
- `/admin/settings/integrations`
- `/admin/settings/operational-access` when the CP-owned `operational_access_enabled` capability is enabled
- `/admin/settings/communications`

It establishes:

- persisted aggregate and section setup truth
- real bootstrap and overview DTOs
- the real Access acknowledge path
- the real Account per-card save boundaries
- the real Modules hub read surface
- the final v1 Personal builder read surface
- the canonical Personal full-replacement save contract
- the real v1 Integrations informational read surface
- the Operational Access overview-card gate for tenants whose CP-owned `operational_access_enabled` capability is enabled
- the minimal Communications placeholder read route

It does **not** mean the full long-range Settings roadmap is complete.

## Access naming warning

`/settings/access` is the current **Access & Security** API surface.

It is not tenant Operational Access. It does not manage People & Teams, Agent Groups as Operational Access grant subjects, Primary Where, Which Records, Additional Coverage, Special Access / Access Exceptions, Responsible For person coverage, Assigned Areas, Oversight, Temporary Coverage, module action grants, Personal Card runtime visibility, or Effective Access explanations.

The separate Operational Access shell, when enabled by CP capability, is served by the frontend at `/admin/settings/operational-access` and is discovered through `GET /settings/overview`. There is no `/settings/operational-access` backend endpoint. Operational Access backend endpoints live under `/operational-access/*`.

## Authoritative bootstrap and route-treatment truth

`GET /settings/bootstrap` is the only active bootstrap source for Settings setup semantics. Auth bootstrap may expose compatibility metadata, but it must not be used for Settings banner visibility, aggregate setup state, section status, Needs Review state, or next recommended action.

Route treatment is locked as follows:

- Live v1 Settings surfaces: `/settings/bootstrap`, `/settings/overview`, `/settings/access`, `/settings/account`, `/settings/modules`, `/settings/modules/personal`, `/settings/integrations`, and the People & Teams management surface backed by `/people-teams/*`.
- Capability-gated Operational Access shell: `/admin/settings/operational-access` appears only when `GET /settings/overview` returns the `operationalAccess` card because the CP-owned `operational_access_enabled` capability is true. It has no backend `/settings/operational-access` endpoint; configuration and OA-owned resolver-proof endpoints are under `/operational-access/*`; the first real module proof endpoints are under `/personal/cards*`.
- Placeholder-only v1 surface: `/settings/communications`. It returns a minimal placeholder DTO and exposes no live configuration or mutation behavior.
- Overview-card-only v1 surface: Workspace Experience. It appears only as an overview card and has no backend route.
- Absent v1 surface: Permissions. It has no overview card, no backend route, and no tenant configuration API.

The retired auth-phase workspace setup acknowledgement route is not part of the active Settings API surface. Setup progress changes only through Settings-native mutations and CP-driven cascade handling.

---

## Guard model

All routes in this document require a fully authenticated admin session.

Controller guard:

- `role = ADMIN`
- `requireMfa = true`
- `requireEmailVerified = true`

Unauthenticated or under-qualified requests fail through the normal auth guard path.

---

## Shared rules

### Backend truth ownership

Settings setup truth is backend-authoritative.
It is persisted.
It is updated by explicit service-layer transitions.
It is not computed on read.

### Save model

- section-level save only
- no giant all-settings publish flow
- Personal has one authoritative page-level save in v1

### Versioning

Mutable Settings routes use:

- `expectedVersion`
- `expectedCpRevision`

Conflict rules:

- version drift returns `409`
- version checks are enforced at the mutation boundary, not only by pre-read comparison; stale concurrent writes must not overwrite newer persisted Settings truth
- stale `expectedCpRevision` returns `409` only when the submitted payload is no longer valid under current CP truth
- stale `expectedCpRevision` is accepted when the submitted payload is still valid under current CP truth

### Write rate limits

Settings write endpoints use the shared platform rate limiter before semantic validation and database work:

- Access acknowledge: light per-user/per-tenant limit
- Account card saves: moderate per-user/per-tenant limit
- Personal save: strict per-user/per-tenant limit because it is the heaviest full-replacement write path

Settings does not define a separate rate-limit subsystem.

### Audit payloads

Meaningful Settings writes use the shared audit infrastructure. Success audits are written inside the transaction. Failure audits are written outside the transaction so they survive rollback.

Settings audit metadata includes the source service, tenant, actor context from the request, target section/card, before/after summaries, versions, `cpRevision`, aggregate status, and conflict inputs where relevant.

### Shared mutation envelope

All shipped write routes return `SettingsMutationResultDto`:

- `section`
  - `key`
  - `status`
  - `version`
  - `cpRevision`
- `card` (Account writes only)
  - `key`
  - `status`
  - `version`
  - `cpRevision`
- `aggregate`
  - `status`
  - `version`
  - `cpRevision`
  - `nextAction`
- `warnings[]`

---

## Read routes

### `GET /settings/bootstrap`

Returns the bootstrap-safe Settings truth that `/admin` may consume.

Response shape:

- `overallStatus`
- `showSetupBanner`
- `nextAction`

This endpoint is intentionally minimal.
It is the Settings-native owner of banner semantics.

### `GET /settings/overview`

Returns the Settings overview DTO for `/admin/settings`.

Response shape:

- `overallStatus`
- `nextAction`
- `cards[]`

Each card reports:

- `key`
- `title`
- `description`
- `href`
- `classification`
- `status` (`NOT_STARTED`, `IN_PROGRESS`, `COMPLETE`, `NEEDS_REVIEW`, `PLACEHOLDER`, or `MANAGEMENT`)
- `warnings[]`
- `isRequired`
- `requiredReason`

`isRequired` is backend-owned. In v1, Access and Personal are required/gating when Personal is enabled; Account and Integrations remain live but non-gating setup cards; People & Teams is a live non-gating management card with `status = MANAGEMENT`; Operational Access is a capability-gated live non-gating configuration card with `status = MANAGEMENT` only when `operational_access_enabled` is true; Communications and Workspace Experience are placeholder-only; Permissions remains absent. People & Teams is group/membership management only and is not Operational Access.

### `GET /settings/access`

Returns the Access & Security review page DTO. This is not Operational Access.

Response shape:

- `sectionKey = "access"`
- `title`
- `description`
- `status`
- `version`
- `cpRevision`
- `canAcknowledge`
- `acknowledgeLabel`
- `groups[]`
- `blockers[]`
- `warnings[]`
- `nextAction`

### `GET /settings/account`

Returns the Account Settings DTO.

Response shape:

- `sectionKey = "account"`
- `title`
- `description`
- `status`
- `cards[]`
- `warnings[]`
- `nextAction`

Current card keys:

- `branding`
- `orgStructure`
- `calendar`

Each card reports:

- `version`
- `cpRevision`
- `visibility`
- `values`

### `GET /settings/modules`

Returns the navigation-only Modules hub DTO.

Response shape:

- `title`
- `description`
- `cards[]`
- `visibleModuleKeys[]`
- `nextAction`

Current truthful behavior:

- `personal` is the only live module card in v1
- `documents`, `benefits`, and `payments` may appear as placeholder cards when CP allows them
- the Modules hub itself has no independent Settings state row and no write endpoint

### `GET /settings/modules/personal`

Returns the final v1 Personal builder DTO.

Current truthful behavior:

- renders only CP-allowed families and fields
- hidden fields never appear in the DTO
- backend generates the default section model from reviewed and included families
- the read DTO carries the authoritative `version` and `cpRevision` used by the save contract
- completion remains save-driven only

Response shape:

- `sectionKey = "personal"`
- `title`
- `description`
- `status`
- `version`
- `cpRevision`
- `warnings[]`
- `blockers[]`
- `nextAction`
- `progress`
- `familyReview`
- `fieldConfiguration`
- `sectionBuilder`
- `conflictGuidance`
- `saveActionLabel = "Save Personal Configuration"`
- `stickySaveLabel = "Save Personal Configuration"`

#### `progress`

Reports:

- `reviewedFamiliesCount`
- `totalAllowedFamilies`
- `requiredFieldsReady`
- `sectionAssignmentsReady`
- `blockers[]`

#### `familyReview`

Reports:

- `key = "familyReview"`
- `title`
- `description`
- `summary`
- `status`
- `families[]`

Each family item reports:

- `familyKey`
- `label`
- `reviewDecision`
- `reviewStatus`
- `isAllowed`
- `canExclude`
- `lockedReason`
- `allowedFieldCount`
- `includedFieldCount`
- `requiredFieldKeys[]`
- `notes[]`
- `warnings[]`
- `blockers[]`

#### `fieldConfiguration`

Reports:

- `key = "fieldConfiguration"`
- `title`
- `description`
- `summary`
- `status`
- `hiddenVsExcluded`
- `families[]`

Each family reports:

- `familyKey`
- `label`
- `reviewDecision`
- `canExclude`
- `exclusionLockedReason`
- `visibleFieldCount`
- `includedFieldCount`
- `minimumRequiredFieldCount`
- `systemManagedFieldCount`
- `notes[]`
- `fields[]`

Each field row reports:

- `familyKey`
- `fieldKey`
- `label`
- `notes`
- `minimumRequired`
- `isSystemManaged`
- `included`
- `required`
- `masked`
- `includeRule`
- `requiredRule`
- `maskingRule`
- `canToggleInclude`
- `canToggleRequired`
- `canToggleMasking`
- `warnings[]`
- `blockers[]`

#### `sectionBuilder`

Reports:

- `key = "sectionBuilder"`
- `title`
- `description`
- `summary`
- `status`
- `sections[]`
- `emptySectionSaveBlocked = true`
- `removeOnlyWhenEmpty = true`

Each section reports:

- `sectionId`
- `name`
- `order`
- `fieldCount`
- `fields[]`

Each assigned field reports:

- `fieldKey`
- `familyKey`
- `label`
- `order`

#### `conflictGuidance`

Reports:

- `summary`
- `notes[]`

This is the read-side guidance for the Personal conflict contract.
The frontend must preserve the local draft on `409`, refetch the latest DTO, and let the admin reconcile explicitly.

### `GET /settings/communications`

Returns the minimal v1 Communications placeholder page DTO.

Current truthful behavior:

- Communications has an overview card and this read route only.
- The route has no setup, save, publish, template-library, notification-rule, or tenant-configuration behavior.
- The DTO explicitly reports that live configuration and mutation endpoints are unavailable.
- This route does not read or mutate setup state, version, `cpRevision`, or audit state.

Response shape:

- `key = "communications"`
- `title`
- `status = "PLACEHOLDER"`
- `treatment = "PLACEHOLDER_ROUTE_ONLY"`
- `description`
- `liveConfigurationAvailable = false`
- `mutationEndpointsAvailable = false`
- `notes[]`
- `backHref`

### `GET /settings/integrations`

Returns the v1 Integrations informational DTO.

Current truthful behavior:

- Google SSO Integration and Microsoft SSO Integration are the only live informational integration surfaces in v1.
- SSO status is derived from CP allowance truth, Access login-method dependency truth, and cached auth/runtime readiness truth.
- Settings GET routes do not make live outbound provider calls.
- Missing, stale, or invalid readiness snapshots are surfaced as `BLOCKED` with warnings instead of invented readiness.
- ADP, Hint, iStream, and Stripe are returned as deferred tenant-configuration cards.
- Marketplace is placeholder-only and intentionally not rendered as a tenant configuration card.
- No tenant credential entry, provider connection flow, mapping editor, import rules UI, sync execution flow, or fake connected status is exposed.

Response shape:

- `sectionKey = "integrations"`
- `title`
- `description`
- `status`
- `version`
- `cpRevision`
- `ssoIntegrations[]`
- `deferredIntegrations[]`
- `marketplace`
- `warnings[]`
- `nextAction`

Each SSO integration reports:

- `integrationKey`
- `providerKey`
- `displayStatus = HIDDEN | READY | NOT_IN_USE | BLOCKED`
- `visible`
- `cpAllowed`
- `loginMethodEnabled`
- `runtimeReadiness`
- `warnings[]`
- `resolutionHint`
- `accessDependency`
- `tenantConfigurationAvailable = false`
- `credentialEntryAvailable = false`
- `connectionFlowAvailable = false`

Each deferred integration reports:

- `integrationKey`
- `category = HRIS | PAYMENTS`
- `treatment = DEFERRED`
- `reason`
- `capabilities[]`
- `tenantConfigurationAvailable = false`
- `credentialEntryAvailable = false`
- `connectionFlowAvailable = false`
- `syncEngineAvailable = false`
- `mappingEditorAvailable = false`

---

## Write routes

### `POST /settings/access/acknowledge`

Used by `/admin/settings/access`.

Request body:

- `expectedVersion`
- `expectedCpRevision`

Returns the shared `SettingsMutationResultDto` envelope.

### `PUT /settings/account/branding`

Request body:

- `expectedVersion`
- `expectedCpRevision`
- `values`

Returns the shared `SettingsMutationResultDto` envelope.

### `PUT /settings/account/org-structure`

Request body:

- `expectedVersion`
- `expectedCpRevision`
- `values`

Returns the shared `SettingsMutationResultDto` envelope.

### `PUT /settings/account/calendar`

Request body:

- `expectedVersion`
- `expectedCpRevision`
- `values`

Returns the shared `SettingsMutationResultDto` envelope.

### `PUT /settings/modules/personal`

The canonical Personal write route.

Request body:

- `expectedVersion`
- `expectedCpRevision`
- `families[]`
  - `familyKey`
  - `reviewDecision`
- `fields[]`
  - `fieldKey`
  - `included`
  - `required`
  - `masked`
- `sections[]`
  - `sectionId`
  - `name`
  - `order`
  - `fields[]`
    - `fieldKey`
    - `order`

Contract rules:

- full replacement only
- no delta-patch semantics
- no silent auto-merge
- no silent retry
- no silent discard on conflict
- payload must cover the tenant's full current allowed Personal scope
- empty sections are rejected
- fields may be assigned only when included
- each included field must appear in exactly one section
- required-floor and system-managed fields must stay included and required
- stale `expectedCpRevision` is accepted only when the submitted full replacement is still valid under current CP truth

Returns the shared `SettingsMutationResultDto` envelope.

---

## Error behavior

### Validation failures

Request-shape validation errors return normal validation responses.

Semantic Personal validation failures return:

- `400`
- message: `Personal configuration could not be saved.`
- structured `blockers[]`

### Conflict failures

#### Personal version conflict

Returns `409` with message:

`Personal settings changed while you were editing them. Refresh the page and review the latest Personal configuration before saving again.`

#### Personal CP revision conflict

Returns `409` with message:

`Personal settings changed after this page was loaded. Refresh and review the latest allowed Personal scope before saving again.`

### Not found

If Personal is not allowed for the tenant, `GET /settings/modules/personal` and `PUT /settings/modules/personal` return a normal not-found response.

---

## Intentionally absent or deferred

The following remain intentionally unimplemented in the current repo state:

- tenant-facing Integrations write routes
- Integrations credential-entry routes
- Integrations provider connection/recovery routes
- Integrations sync or mapping routes
- Assigned Areas Operational Access routes
- broad Operational Access module-consumer routes beyond the selected Personal Cards proof surface
- Operational Access search/export/notification/PDF/generated-output integrations
- Permissions routes
- Communications write routes
- Communications template-library routes
- Communications notification-rule routes
- Workspace Experience routes
- Workspace Experience write or child routes
- any giant all-settings publish route

Their absence is intentional and must stay aligned with the locked roadmap.

## Operational Access settings surface after Step 4

When the CP-owned `operational_access_enabled` capability is true, `GET /settings/overview` includes the `operationalAccess` card linking to `/admin/settings/operational-access`.

That page renders backend-owned Operational Access configuration read models from `/operational-access/*`: product-defined actions, Primary Where choices, Which Records choices, active Agent groups, Responsible For coverage, and advanced coverage readiness. The first real module proof lives at `/personal/cards*`. Frontend code must not compute effective access.

The selected backend resolver proof surface is `/operational-access/runtime/people`, not a Settings API endpoint.

`/settings/access` and `/admin/settings/access` remain Access & Security. They are not Operational Access.
