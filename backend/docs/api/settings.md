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

This is the real Settings-native tenant surface used by:

- `/admin`
- `/admin/settings`
- `/admin/settings/access`
- `/admin/settings/account`
- `/admin/settings/modules`
- `/admin/settings/modules/personal`

It establishes:

- persisted aggregate and section setup truth
- real bootstrap and overview DTOs
- the real Access acknowledge path
- the real Account per-card save boundaries
- the real Modules hub read surface
- the final v1 Personal builder read surface
- the canonical Personal full-replacement save contract

It does **not** mean the full long-range Settings roadmap is complete.

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
- stale `expectedCpRevision` returns `409` only when the submitted payload is no longer valid under current CP truth
- stale `expectedCpRevision` is accepted when the submitted payload is still valid under current CP truth

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
- `status`
- `warnings[]`
- `isRequired`

### `GET /settings/access`

Returns the Access & Security review page DTO.

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
- Permissions routes
- Communications write routes
- Workspace Experience routes
- any giant all-settings publish route

Their absence is intentional and must stay aligned with the locked roadmap.
