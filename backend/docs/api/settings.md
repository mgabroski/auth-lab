# Settings API

## Purpose

This document describes the currently shipped Settings-native backend read surface.

Current scope in this repo:

- `GET /settings/bootstrap`
- `GET /settings/overview`

This is the currently shipped Settings read surface used by the frontend `/admin` and `/admin/settings` routes.
It establishes the persisted Settings state engine and the first real tenant-facing read DTOs.
It does **not** mean the full tenant Settings write surface is already shipped.

---

## Guard model

Both endpoints require a fully authenticated admin session.

Controller guard:

- `role = ADMIN`
- `requireMfa = true`
- `requireEmailVerified = true`

Unauthenticated or under-qualified requests fail through the normal auth guard path.

---

## GET `/settings/bootstrap`

### Purpose

Returns the bootstrap-safe Settings truth that `/admin` may consume.

This endpoint is intentionally minimal.
It is the Settings-native replacement foundation for using auth scaffolding as the long-term owner of setup semantics.

### Response

```json
{
  "overallStatus": "IN_PROGRESS",
  "showSetupBanner": true,
  "nextAction": {
    "key": "modules",
    "label": "Continue Personal setup",
    "href": "/admin/settings/modules/personal"
  }
}
```

### Field rules

- `overallStatus`
  - one of: `NOT_STARTED`, `IN_PROGRESS`, `COMPLETE`, `NEEDS_REVIEW`
  - read from persisted Settings state
  - never frontend-derived
- `showSetupBanner`
  - `true` when `overallStatus !== COMPLETE`
- `nextAction`
  - `null` when no required action remains
  - currently points only to required/gating v1 boundaries
  - current keys:
    - `access`
    - `modules` (used when Personal is the next required child)

### Important contract rule

`/admin` may consume this endpoint.
`/admin` now consumes this endpoint as its only bootstrap-safe Settings source. It must not consume detailed section-resolution truth from elsewhere.

---

## GET `/settings/overview`

### Purpose

Returns the first real Settings overview read model.

This endpoint is for `/admin/settings` and the current SSR-gated Settings section route shells. It includes top-level card treatment, persisted statuses, placeholder handling, and a next-action pointer.

### Response

```json
{
  "overallStatus": "NOT_STARTED",
  "nextAction": {
    "key": "access",
    "label": "Review Access & Security",
    "href": "/admin/settings/access"
  },
  "cards": [
    {
      "key": "access",
      "title": "Access & Security",
      "description": "Review the platform-managed access envelope for this workspace.",
      "href": "/admin/settings/access",
      "classification": "REQUIRED_GATING",
      "status": "NOT_STARTED",
      "warnings": [],
      "isRequired": true
    },
    {
      "key": "account",
      "title": "Account Settings",
      "description": "Configure branding, organization structure, and company calendar values.",
      "href": "/admin/settings/account",
      "classification": "LIVE_NON_GATING",
      "status": "NOT_STARTED",
      "warnings": [],
      "isRequired": false
    },
    {
      "key": "modules",
      "title": "Modules",
      "description": "Open the modules hub. Personal is the only live configurable child in v1.",
      "href": "/admin/settings/modules",
      "classification": "NAVIGATION_ONLY",
      "status": "NOT_STARTED",
      "warnings": [],
      "isRequired": false
    },
    {
      "key": "integrations",
      "title": "Integrations",
      "description": "View informational SSO integration readiness and deferred integration cards.",
      "href": "/admin/settings/integrations",
      "classification": "LIVE_NON_GATING",
      "status": "NOT_STARTED",
      "warnings": [
        "Google SSO runtime readiness is unavailable from the cached auth/runtime snapshot. Settings GET routes do not make live provider calls."
      ],
      "isRequired": false
    },
    {
      "key": "communications",
      "title": "Communications",
      "description": "Placeholder only in v1. Email templates and notification rules are not live yet.",
      "href": "/admin/settings/communications",
      "classification": "PLACEHOLDER_ONLY",
      "status": "PLACEHOLDER",
      "warnings": [],
      "isRequired": false
    },
    {
      "key": "workspaceExperience",
      "title": "Workspace Experience",
      "description": "Placeholder only in v1. Workspace Experience configuration remains deferred.",
      "href": null,
      "classification": "PLACEHOLDER_ONLY",
      "status": "PLACEHOLDER",
      "warnings": [],
      "isRequired": false
    }
  ]
}
```

### Classification rules

- `REQUIRED_GATING`
  - v1: `access`
- `LIVE_NON_GATING`
  - v1: `account`, `integrations`
- `NAVIGATION_ONLY`
  - v1: `modules`
  - no independent persisted state row exists for the hub itself
  - current status is read-composed from the Personal child state
- `PLACEHOLDER_ONLY`
  - v1: `communications`, `workspaceExperience`
- absent surfaces do not appear
  - v1: `permissions`

### Important rules

- Account remains explicitly non-gating
- Permissions remains absent
- Communications remains placeholder-only
- Workspace Experience remains overview-card-only
- Integrations warnings are allowed to surface cached readiness-unavailable truth
- Settings GET routes never make live outbound provider calls

---

## Persistence boundary

These routes read persisted state from:

- `tenant_setup_state`
- `tenant_setup_section_state`

They may compose allowance/readiness metadata around that persisted state, but they do not compute aggregate completion truth as a substitute for persisted ownership.

---

## CP cascade relationship

This repo now ships the real synchronous CP -> Settings cascade foundation.
That means:

- published CP tenants keep `tenant_setup_state` and `tenant_setup_section_state` aligned to the latest applied `cpRevision`
- required CP changes can move surviving required boundaries into `NEEDS_REVIEW`
- non-gating changes do not fake aggregate regression

This document does **not** describe CP routes themselves.
See `backend/docs/api/cp-accounts.md` for the CP surface.
