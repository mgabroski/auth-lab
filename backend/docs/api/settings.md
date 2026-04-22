# Settings API

## Purpose

This document describes the currently shipped Settings-native backend read and write surface.

Current scope in this repo:

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

This is the currently shipped Settings-native tenant surface used by the frontend `/admin`, `/admin/settings`, the dedicated `/admin/settings/access` page, the dedicated `/admin/settings/account` page, the real Modules hub at `/admin/settings/modules`, and the real Personal read surface at `/admin/settings/modules/personal`.

It establishes:

- persisted Settings aggregate and section state
- real bootstrap and overview DTOs
- the real Access acknowledge path
- the real Account per-card save boundaries
- the real Modules hub read surface
- the Personal family-review plus field-rule foundation read surface

It does **not** mean the full tenant Settings write surface is already shipped.

---

## Guard model

All endpoints in this document require a fully authenticated admin session.

Controller guard:

- `role = ADMIN`
- `requireMfa = true`
- `requireEmailVerified = true`

Unauthenticated or under-qualified requests fail through the normal auth guard path.

---

## Read surfaces

### `GET /settings/bootstrap`

Returns the bootstrap-safe Settings truth that `/admin` may consume.

Response shape:

- `overallStatus`
- `showSetupBanner`
- `nextAction`

This endpoint is intentionally minimal. It is the Settings-native owner of banner semantics and must not fall back to the old auth-phase acknowledgement scaffold.

### `GET /settings/overview`

Returns the settings overview DTO for `/admin/settings`.

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

Card keys currently shipped:

- `branding`
- `orgStructure`
- `calendar`

Each mutable card reports its own:

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

Returns the current Personal read model.

Current truthful behavior:

- renders only CP-allowed families and fields
- hidden fields never appear in the DTO
- family review is visible but still unsaved in the current repo state
- field configuration now exposes required-floor, system-managed, and hidden-vs-excluded rule foundations
- section builder and the final Personal save contract are still deferred

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
- `moduleEnabled`
- `familyReview`
- `fieldConfiguration`
- `sectionBuilder`

#### `familyReview`

Reports:

- `title`
- `description`
- `summary`
- `families[]`

Each family item reports:

- `familyKey`
- `label`
- `reviewDecision`
- `reviewStatus`
- `allowedFieldCount`
- `defaultSelectedFieldCount`
- `containsLockedRequiredFields`
- `canExclude`
- `requiredFieldKeys[]`
- `systemManagedFieldKeys[]`
- `notes[]`

#### `fieldConfiguration`

Reports:

- `key = "fieldConfiguration"`
- `title`
- `description`
- `summary`
- `status = "CURRENT_FOUNDATION"`
- `isLiveInCurrentRepo = true`
- `hiddenVsExcluded`
- `conflictGuidance`
- `families[]`

`hiddenVsExcluded` is explicit and honest:

- hidden = not CP-allowed, never rendered
- excluded = CP-allowed but tenant-disabled later; that tenant-owned state is not yet persisted because the final Personal save contract is not shipped in this phase

`conflictGuidance` reports:

- `version`
- `cpRevision`
- `summary`
- `notes[]`

This is the read-side groundwork for later Personal conflict handling. The current repo still has no Personal mutation route, so there is no fake retry, fake success, or silent discard path.

Each field-configuration family reports:

- `familyKey`
- `label`
- `canExclude`
- `exclusionLockedReason`
- `visibleFieldCount`
- `defaultSelectedFieldCount`
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
- `presentationState`
- `readiness`
- `requiredRule`
- `maskingRule`
- `canBeExcludedLater`
- `canToggleRequiredLater`
- `canToggleMaskingLater`
- `warnings[]`
- `blockers[]`

Interpretation rules:

- required-floor fields report `requiredRule = LOCKED_REQUIRED`
- system-managed fields report read-only presentation and locked masking behavior
- allowed fields that are not default-selected are still visible because they are available for later tenant inclusion
- hidden fields are absent entirely

#### `sectionBuilder`

Still reports a future-phase panel only:

- `key = "sectionBuilder"`
- `title`
- `description`
- `status = "FUTURE_PHASE"`
- `isLiveInCurrentRepo = false`
- `summary`

---

## Write surfaces

### `POST /settings/access/acknowledge`

Current shipped write used by `/admin/settings/access`.

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

---

## Not shipped yet

The following remain intentionally unimplemented in the current repo state:

- `PUT /settings/modules/personal`
- final Personal full-replacement save semantics
- default section generation and section-builder writes
- tenant-side Personal conflict resolution UX beyond the read-side groundwork in the DTO
- live Integrations write surfaces
- Permissions routes

The absence of these routes is intentional and must stay aligned with the locked roadmap.
