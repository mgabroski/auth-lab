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

This is the currently shipped Settings-native tenant surface used by the frontend `/admin`, `/admin/settings`, the dedicated `/admin/settings/access` page, and the dedicated `/admin/settings/account` page.
It establishes the persisted Settings state engine, the real overview DTOs, the real Access acknowledge path, and the real Account per-card save boundaries.
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

## GET `/settings/access`

### Purpose

Returns the real Access & Security page DTO for `/admin/settings/access`.

This is the first real Settings section page in the current repo.
It is read-only in v1 and truthfully separates:

- CP mismatch blockers that fail closed
- operational readiness warnings that point tenant admins to Integrations
- explicit acknowledge semantics for completing the Access boundary

### Response

```json
{
  "sectionKey": "access",
  "title": "Access & Security",
  "description": "Review the platform-managed access envelope for this workspace.",
  "status": "NOT_STARTED",
  "version": 1,
  "cpRevision": 3,
  "canAcknowledge": true,
  "acknowledgeLabel": "Acknowledge & Mark Reviewed",
  "groups": [
    {
      "key": "loginMethods",
      "title": "Login Methods",
      "description": "These login methods are platform-managed in v1.",
      "rows": [
        {
          "key": "password",
          "label": "Username & Password",
          "value": "Enabled",
          "readOnly": true,
          "managedBy": "CONTROL_PLANE",
          "status": "READY",
          "warning": null,
          "blocker": null,
          "resolutionHref": null
        },
        {
          "key": "google",
          "label": "Google SSO",
          "value": "Enabled",
          "readOnly": true,
          "managedBy": "CONTROL_PLANE",
          "status": "WARNING",
          "warning": "Google SSO runtime readiness is unavailable from the cached auth/runtime snapshot. Settings GET routes do not make live provider calls.",
          "blocker": null,
          "resolutionHref": "/admin/settings/integrations"
        }
      ]
    }
  ],
  "blockers": [],
  "warnings": [
    "Google SSO runtime readiness is unavailable from the cached auth/runtime snapshot. Settings GET routes do not make live provider calls."
  ],
  "nextAction": {
    "key": "access",
    "label": "Review Access & Security",
    "href": "/admin/settings/access"
  }
}
```

### Important rules

- Access is shown only for the real shipped v1 route
- all visible rows are read-only in v1
- completion is not page visit
- completion is not generic save
- `canAcknowledge` is `false` when CP mismatch blockers exist
- operational readiness warnings do not fake success and do not become blockers by themselves
- readiness warnings may point to `/admin/settings/integrations`, but Integrations remains a separate surface

## POST `/settings/access/acknowledge`

### Purpose

Marks the Access boundary reviewed under the current persisted Settings state and current CP revision.

This is the only completion action for Access in v1.
It updates only the Access section plus aggregate recompute. It does not mutate unrelated sections.

### Request

```json
{
  "expectedVersion": 1,
  "expectedCpRevision": 3
}
```

### Response

```json
{
  "section": {
    "key": "access",
    "status": "COMPLETE",
    "version": 2,
    "cpRevision": 3
  },
  "aggregate": {
    "status": "IN_PROGRESS",
    "version": 2,
    "cpRevision": 3,
    "nextAction": {
      "key": "modules",
      "label": "Continue Personal setup",
      "href": "/admin/settings/modules/personal"
    }
  },
  "warnings": []
}
```

### Mutation rules

- requires a fully authenticated admin session
- fails with `409 CONFLICT` when `expectedVersion` is stale
- fails with `409 CONFLICT` when `expectedCpRevision` is stale
- fails with `409 CONFLICT` when platform-managed blockers remain unresolved
- writes success audit inside the transaction
- writes failure audit outside the transaction so it survives rollback

### Current shipped audit actions

- `settings.access.acknowledged`
- `settings.access.acknowledge.failed`

## GET `/settings/account`

### Purpose

Returns the real Account Settings page DTO for `/admin/settings/account`.

This route is the shipped v1 Account surface. It is live, tenant-configurable, and explicitly non-gating. It only covers the locked v1 Account cards:

- Branding
- Organization Structure
- Company Calendar

### Response

```json
{
  "sectionKey": "account",
  "title": "Account Settings",
  "description": "Configure the allowed branding, organization structure, and company calendar values for this workspace. Account Settings is live in v1 but remains non-gating.",
  "status": "NOT_STARTED",
  "cards": [
    {
      "key": "branding",
      "title": "Branding",
      "description": "Manage the allowed branding values for this workspace.",
      "status": "NOT_STARTED",
      "version": 1,
      "cpRevision": 4,
      "visibility": {
        "logo": true,
        "menuColor": true,
        "fontColor": true,
        "welcomeMessage": true
      },
      "values": {
        "logoUrl": null,
        "menuColor": null,
        "fontColor": null,
        "welcomeMessage": null
      }
    },
    {
      "key": "orgStructure",
      "title": "Organization Structure",
      "description": "Manage the allowed employer and location lists for this workspace.",
      "status": "NOT_STARTED",
      "version": 1,
      "cpRevision": 4,
      "visibility": {
        "employers": true,
        "locations": true
      },
      "values": {
        "employers": [],
        "locations": []
      }
    },
    {
      "key": "calendar",
      "title": "Company Calendar",
      "description": "Maintain the observed company dates used by this workspace.",
      "status": "NOT_STARTED",
      "version": 1,
      "cpRevision": 4,
      "visibility": {
        "allowed": true
      },
      "values": {
        "observedDates": []
      }
    }
  ],
  "warnings": [],
  "nextAction": {
    "key": "access",
    "label": "Review Access & Security",
    "href": "/admin/settings/access"
  }
}
```

### Read rules

- hidden if the tenant has no CP-allowed Account cards at all
- only CP-allowed cards appear
- no read-only Account mode is invented in v1
- card `version` and `cpRevision` are the authoritative mutation preconditions for each card save
- Account remains live but non-gating in aggregate setup behavior

## PUT `/settings/account/branding`

### Purpose

Saves the Branding card only.

### Request

```json
{
  "expectedVersion": 1,
  "expectedCpRevision": 4,
  "values": {
    "logoUrl": "https://cdn.example.com/logo.svg",
    "menuColor": "#0f172a",
    "fontColor": "#ffffff",
    "welcomeMessage": "Welcome to the workspace"
  }
}
```

## PUT `/settings/account/org-structure`

### Purpose

Saves the Organization Structure card only.

### Request

```json
{
  "expectedVersion": 1,
  "expectedCpRevision": 4,
  "values": {
    "employers": ["Acme"],
    "locations": ["Skopje"]
  }
}
```

## PUT `/settings/account/calendar`

### Purpose

Saves the Company Calendar card only.

### Request

```json
{
  "expectedVersion": 1,
  "expectedCpRevision": 4,
  "values": {
    "observedDates": ["2026-01-01", "2026-12-25"]
  }
}
```

### Shared Account mutation response

All three Account card writes return the same envelope:

```json
{
  "section": {
    "key": "account",
    "status": "IN_PROGRESS",
    "version": 2,
    "cpRevision": 4
  },
  "card": {
    "key": "branding",
    "status": "COMPLETE",
    "version": 2,
    "cpRevision": 4
  },
  "aggregate": {
    "status": "IN_PROGRESS",
    "version": 2,
    "cpRevision": 4,
    "nextAction": {
      "key": "access",
      "label": "Review Access & Security",
      "href": "/admin/settings/access"
    }
  },
  "warnings": []
}
```

### Shared Account mutation rules

- requires a fully authenticated admin session
- each card is an explicit save boundary; there is no page-level save-all flow
- fails with `404 NOT FOUND` when the whole Account section or the specific card is not CP-allowed for that tenant
- fails with `409 CONFLICT` when `expectedVersion` is stale for that card
- fails with `409 CONFLICT` when `expectedCpRevision` is stale **and** the submitted payload no longer fits the latest CP allowance truth for that card
- a stale `expectedCpRevision` is still accepted when the payload remains valid under the current allowance truth
- writes success audit inside the transaction
- writes failure audit outside the transaction so it survives rollback
- Account saves do not block overall completion and do not control the setup banner lifecycle

### Current shipped Account audit actions

- `settings.account.branding.saved`
- `settings.account.branding.save.failed`
- `settings.account.org_structure.saved`
- `settings.account.org_structure.save.failed`
- `settings.account.calendar.saved`
- `settings.account.calendar.save.failed`

## Persistence boundary

These routes read persisted state from:

- `tenant_setup_state`
- `tenant_setup_section_state`
- `tenant_account_settings`

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
