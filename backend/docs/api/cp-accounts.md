# CP Accounts API Contract

This document describes the backend CP accounts contract implemented in this repository.

It is a contract document, not a product brief. It describes what the backend actually exposes now. It must stay aligned with `backend/src/modules/control-plane/accounts/cp-accounts.routes.ts`.

Read this after:

1. `docs/current-foundation-status.md`
2. `ARCHITECTURE.md`
3. `docs/decision-log.md`
4. `backend/docs/engineering-rules.md`

---

## 1. Scope

This file covers the CP accounts endpoints registered in:

- `backend/src/modules/control-plane/accounts/cp-accounts.routes.ts`

Current route surface:

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

---

## 2. Topology

CP routes are on the same backend process as all other routes. They are prefixed with `/cp/` to keep them distinct from tenant-facing routes.

**Dev-only no-auth**: CP routes carry no authentication in this phase. This is a deliberate development-phase shortcut. CP authentication will be added in a later phase.

---

## 3. Shared response shapes

### 3.1 Account list row

`GET /cp/accounts` returns:

```json
{
  "accounts": [
    {
      "id": "uuid",
      "accountName": "GoodWill CA",
      "accountKey": "goodwill-ca",
      "cpStatus": "Draft",
      "cpRevision": 2,
      "step2Progress": {
        "configuredCount": 3,
        "totalCount": 4,
        "requiredConfiguredCount": 3,
        "requiredTotalCount": 3,
        "canContinueToReview": true,
        "groups": [
          {
            "slug": "access-identity-security",
            "title": "Access, Identity & Security",
            "isRequired": true,
            "configured": true
          }
        ]
      }
    }
  ]
}
```

### 3.2 Full account detail

All read and write endpoints except `GET /cp/accounts`, `GET /cp/accounts/:accountKey/review`, and `POST /cp/accounts/:accountKey/publish` return the full CP account detail shape.

```json
{
  "id": "uuid",
  "accountName": "GoodWill CA",
  "accountKey": "goodwill-ca",
  "cpStatus": "Draft",
  "cpRevision": 2,
  "createdAt": "2026-01-01T00:00:00.000Z",
  "updatedAt": "2026-01-01T00:00:00.000Z",
  "step2Progress": {
    "configuredCount": 3,
    "totalCount": 4,
    "requiredConfiguredCount": 3,
    "requiredTotalCount": 3,
    "canContinueToReview": true,
    "groups": [
      {
        "slug": "access-identity-security",
        "title": "Access, Identity & Security",
        "isRequired": true,
        "configured": true
      },
      {
        "slug": "account-settings",
        "title": "Account Settings",
        "isRequired": true,
        "configured": true
      },
      {
        "slug": "module-settings",
        "title": "Module Settings",
        "isRequired": true,
        "configured": true
      },
      {
        "slug": "integrations-marketplace",
        "title": "Integrations & Marketplace",
        "isRequired": false,
        "configured": false
      }
    ]
  },
  "access": {
    "configured": true,
    "loginMethods": {
      "password": true,
      "google": false,
      "microsoft": false
    },
    "mfaPolicy": {
      "adminRequired": true,
      "memberRequired": false
    },
    "signupPolicy": {
      "publicSignup": false,
      "adminInvitationsAllowed": true,
      "allowedDomains": []
    }
  },
  "accountSettings": {
    "configured": true,
    "branding": {
      "logo": true,
      "menuColor": true,
      "fontColor": true,
      "welcomeMessage": true
    },
    "organizationStructure": {
      "employers": true,
      "locations": true
    },
    "companyCalendar": {
      "allowed": true
    }
  },
  "moduleSettings": {
    "configured": false,
    "moduleDecisionsSaved": true,
    "personalSubpageSaved": false,
    "modules": {
      "personal": true,
      "documents": false,
      "benefits": false,
      "payments": false
    }
  },
  "personal": {
    "saved": false,
    "families": [
      {
        "familyKey": "identity",
        "label": "Identity",
        "isAllowed": true,
        "allowedLocked": true,
        "fields": ["..."]
      }
    ]
  },
  "integrations": {
    "configured": false,
    "integrations": [
      {
        "integrationKey": "integration.sso.google",
        "label": "Google SSO Integration",
        "isAllowed": false,
        "capabilities": []
      }
    ]
  },
  "settingsHandoff": {
    "contractVersion": 1,
    "producedAt": "2026-01-01T00:00:00.000Z",
    "mode": "PRODUCER_ONLY",
    "eligibility": "BLOCKED_UNPUBLISHED_ACCOUNT",
    "consumer": {
      "settingsEnginePresent": false,
      "cascadeStatus": "NOT_WIRED",
      "blockingReasons": [
        "Settings Step 10 Phase 2 is not implemented in this repo yet. The Control Plane remains a producer-only source of allowance truth.",
        "Account \"goodwill-ca\" is not provisioned to a tenant yet. Publish the account before any future Settings cascade can become eligible."
      ]
    },
    "account": {
      "accountId": "uuid",
      "accountKey": "goodwill-ca",
      "accountName": "GoodWill CA",
      "cpStatus": "Draft",
      "cpRevision": 2
    },
    "provisioning": {
      "isProvisioned": false,
      "tenantId": null,
      "tenantKey": null,
      "tenantName": null,
      "tenantState": "NOT_PROVISIONED",
      "publishedAt": null
    },
    "allowances": {
      "access": {
        "loginMethods": {
          "password": true,
          "google": false,
          "microsoft": false
        },
        "mfaPolicy": {
          "adminRequired": true,
          "memberRequired": false
        },
        "signupPolicy": {
          "publicSignup": false,
          "adminInvitationsAllowed": true,
          "allowedDomains": []
        }
      },
      "account": {
        "branding": {
          "logo": true,
          "menuColor": true,
          "fontColor": true,
          "welcomeMessage": true
        },
        "organizationStructure": {
          "employers": true,
          "locations": true
        },
        "companyCalendar": {
          "allowed": true
        }
      },
      "modules": {
        "modules": {
          "personal": true,
          "documents": false,
          "benefits": false,
          "payments": false
        }
      },
      "personal": {
        "families": [
          {
            "familyKey": "identity",
            "isAllowed": true
          }
        ],
        "fields": [
          {
            "familyKey": "identity",
            "fieldKey": "person.first_name",
            "isAllowed": true,
            "defaultSelected": true,
            "minimumRequired": "required",
            "isSystemManaged": false
          }
        ]
      },
      "integrations": {
        "integrations": [
          {
            "integrationKey": "integration.sso.google",
            "isAllowed": false,
            "capabilities": []
          }
        ]
      }
    }
  }
}
```

### 3.3 Producer-side Settings handoff snapshot

Every full account detail now includes `settingsHandoff`.

This is **not** a live Settings integration status. It is the canonical producer snapshot that the future Settings state engine will consume once Settings Step 10 Phase 2 exists.

Current truthful behavior:

- `mode` is always `PRODUCER_ONLY`
- `consumer.settingsEnginePresent` is always `false`
- `consumer.cascadeStatus` is always `NOT_WIRED`
- `blockingReasons` explain why live cascade wiring is not active yet
- `allowances` carries allowance truth only — not CP Step 2 progress/configured flags
- unpublished accounts remain `BLOCKED_UNPUBLISHED_ACCOUNT`
- published accounts become `READY_FOR_FUTURE_SETTINGS_CONSUMER`, but still remain producer-only until the real Settings state engine ships

There is no separate HTTP route for this contract in the current repo. It is included on the full account detail DTO and is also available through the internal `CpAccountsService` handoff method for future in-process Settings consumption.

### 3.4 Review response

`GET /cp/accounts/:accountKey/review` and `POST /cp/accounts/:accountKey/publish` return a backend-owned Review DTO:

- includes full `account` detail
- includes server-composed read-only summary sections (frontend renders without recomputing)
- includes backend-authoritative Activation Ready evaluation
- includes provisioning result (the real tenant row identity/state)

```json
{
  "account": { "...": "Full account detail" },
  "sections": [
    {
      "key": "identity",
      "title": "Account Identity",
      "lines": [{ "label": "Account Name", "value": "GoodWill CA" }]
    }
  ],
  "activationReadiness": {
    "isReady": false,
    "checks": [
      {
        "code": "ACCESS_DECISIONS_MADE",
        "label": "Access, Identity & Security decisions made",
        "passed": false,
        "detail": "Save the Access, Identity & Security group first."
      }
    ],
    "blockingReasons": ["Save the Access, Identity & Security group first."]
  },
  "provisioning": {
    "isProvisioned": true,
    "tenantId": "uuid",
    "tenantKey": "goodwill-ca",
    "tenantName": "GoodWill CA",
    "tenantState": "DISABLED",
    "publishedAt": "2026-01-01T00:00:00.000Z"
  }
}
```

---

## 4. Endpoints

### 4.1 `GET /cp/accounts`

Returns all CP accounts as list rows suitable for the CP accounts list page. Rows are ordered by most recently updated first so QA and engineering can re-enter the latest accounts quickly.

**Response — 200 OK**

See shared account list row shape above.

---

### 4.2 `GET /cp/accounts/:accountKey`

Returns the full CP account record for the given `accountKey`.

**Path param**: `accountKey` — the unique account key (lowercase, hyphens).

**Response — 200 OK**

See shared full account detail shape above.

**Response — 404 Not Found**

```json
{
  "code": "NOT_FOUND",
  "message": "CP account not found: <accountKey>"
}
```

---

### 4.3 `GET /cp/accounts/:accountKey/review`

Returns the backend-owned Review DTO for the given `accountKey`.

**Important rules**

- Summary sections are composed server-side.
- Activation Ready is evaluated server-side.
- The provisioning result is based on real persisted provisioning records (`cp_account_provisioning` + `tenants`).

**Response — 200 OK**

See Review response shape above.

**Response — 404 Not Found**

Same as `GET /cp/accounts/:accountKey`.

---

### 4.4 `POST /cp/accounts`

Creates a new Draft CP account.

**Request body**

```json
{
  "accountName": "GoodWill CA",
  "accountKey": "goodwill-ca"
}
```

**Validation rules**

| Field         | Rule                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------ |
| `accountName` | Required. Non-empty string. Max 255 characters.                                            |
| `accountKey`  | Required. Non-empty string. Max 100 characters. Must match `^[a-z0-9-]+$`. Must be unique. |

**Response — 201 Created**

Returns the full created account detail.

**Response — 409 Conflict**

```json
{
  "code": "CONFLICT",
  "message": "Account key is already taken: <accountKey>",
  "meta": { "accountKey": "<accountKey>" }
}
```

---

### 4.5 `PUT /cp/accounts/:accountKey/access`

Persists the Access, Identity & Security group and marks it configured.

**Request body**

```json
{
  "loginMethods": {
    "password": true,
    "google": false,
    "microsoft": false
  },
  "mfaPolicy": {
    "adminRequired": true,
    "memberRequired": false
  },
  "signupPolicy": {
    "publicSignup": false,
    "adminInvitationsAllowed": true,
    "allowedDomains": ["@goodwill.org"]
  }
}
```

**Important rules**

- Google login method cannot be saved unless Google SSO Integration is already allowed.
- Microsoft login method cannot be saved unless Microsoft SSO Integration is already allowed.
- `adminRequired` is persisted as `true` in this phase.
- Allowed domains are normalized to trimmed lowercase unique values on save.

**Response — 200 OK**

Returns the full account detail with updated `access`, `step2Progress`, and `cpRevision`.

---

### 4.6 `PUT /cp/accounts/:accountKey/account-settings`

Persists the Account Settings group and marks it configured.

**Request body**

```json
{
  "branding": {
    "logo": true,
    "menuColor": true,
    "fontColor": true,
    "welcomeMessage": true
  },
  "organizationStructure": {
    "employers": true,
    "locations": true
  },
  "companyCalendar": {
    "allowed": true
  }
}
```

**Important rules**

- Any explicit allow/deny combination is valid.
- Explicit save is enough to mark this group configured.

**Response — 200 OK**

Returns the full account detail with updated `accountSettings`, `step2Progress`, and `cpRevision`.

---

### 4.7 `PUT /cp/accounts/:accountKey/modules`

Persists the Module Settings group decisions.

**Request body**

```json
{
  "modules": {
    "personal": true,
    "documents": false,
    "benefits": false,
    "payments": false
  }
}
```

**Important rules**

- Explicit module save marks `moduleDecisionsSaved = true`.
- If `personal` is enabled, Module Settings is not treated as configured until the Personal CP sub-page is explicitly saved.
- If `personal` is disabled, Module Settings becomes configured immediately on save.

**Response — 200 OK**

Returns the full account detail with updated `moduleSettings`, `step2Progress`, and `cpRevision`.

---

### 4.8 `PUT /cp/accounts/:accountKey/modules/personal`

Persists the Personal CP field-catalog sub-page.

**Request body**

```json
{
  "families": [
    {
      "familyKey": "identity",
      "isAllowed": true
    }
  ],
  "fields": [
    {
      "fieldKey": "person.first_name",
      "isAllowed": true,
      "defaultSelected": true
    }
  ]
}
```

**Important rules**

- Full replacement contract: request must include the full current family set and the full editable field set.
- `Default Selected` is valid only when `Allowed` is `true`.
- Unchecking `Allowed` clears `Default Selected`.
- Required baseline fields remain allowed even if the payload attempts to disable them.
- System-managed `System ID` is not an editable payload field.
- Successful Personal save sets `personalSubpageSaved = true` and may complete Module Settings if module decisions were already saved.

**Response — 200 OK**

Returns the full account detail with updated `personal`, `moduleSettings`, `step2Progress`, and `cpRevision`.

---

### 4.9 `PUT /cp/accounts/:accountKey/integrations`

Persists the Integrations & Marketplace group and marks it configured.

**Request body**

```json
{
  "integrations": [
    {
      "integrationKey": "integration.sso.google",
      "isAllowed": true,
      "capabilities": []
    }
  ]
}
```

**Important rules**

- Full replacement contract: request must include the full current integration set.
- Explicit save is enough to mark this group configured even if all integrations remain disabled.
- Google SSO Integration cannot be disabled while Google login method remains enabled in Access.
- Microsoft SSO Integration cannot be disabled while Microsoft login method remains enabled in Access.

**Response — 200 OK**

Returns the full account detail with updated `integrations`, `step2Progress`, and `cpRevision`.

---

### 4.10 `POST /cp/accounts/:accountKey/publish`

Publishes a tenant from Control Plane.

This endpoint:

- evaluates Activation Ready server-side
- blocks `Active` when Activation Ready fails
- allows `Disabled` even when Activation Ready fails
- creates or updates a real `tenants` row for QA use
- records the CP-side provisioning result in `cp_account_provisioning`
- updates `cp_accounts.cp_status` to `Active` or `Disabled`

**Request body**

```json
{
  "targetStatus": "Active"
}
```

**Response — 200 OK**

Returns the Review response shape.

**Response — 409 Conflict**

When `targetStatus = Active` and Activation Ready fails:

```json
{
  "code": "CONFLICT",
  "message": "Active publish is blocked until Activation Ready passes.",
  "meta": {
    "blockingReasons": ["Save the Access, Identity & Security group first."]
  }
}
```

If the account key matches an existing tenant created outside Control Plane:

```json
{
  "code": "CONFLICT",
  "message": "Cannot publish account because tenant key is already provisioned outside Control Plane: <accountKey>",
  "meta": { "accountKey": "<accountKey>" }
}
```

---

### 4.11 `PATCH /cp/accounts/:accountKey/status`

Toggles an already-published account between `Active` and `Disabled` without reopening Step 1 identity editing.

This endpoint:

- is intended for quick status changes from the accounts list and edit/re-entry flows
- updates the real provisioned tenant row
- updates `cp_accounts.cp_status`
- does **not** increment `cpRevision` because status changes do not mutate CP allowance truth
- rejects Draft accounts because first publication still belongs to Review & Publish

**Request body**

```json
{
  "targetStatus": "Active"
}
```

**Response — 200 OK**

Returns the full account detail shape.

**Response — 409 Conflict**

When the account is still Draft / not yet provisioned:

```json
{
  "code": "CONFLICT",
  "message": "Status toggle is available only after the account has been published once: <accountKey>",
  "meta": { "accountKey": "<accountKey>" }
}
```

When `targetStatus = Active` and Activation Ready fails:

```json
{
  "code": "CONFLICT",
  "message": "Active publish is blocked until Activation Ready passes.",
  "meta": {
    "blockingReasons": ["Save the Access, Identity & Security group first."]
  }
}
```

---

## 5. Status vocabulary

| Value      | Meaning                            |
| ---------- | ---------------------------------- |
| `Draft`    | Created but not yet published      |
| `Active`   | Published and reachable by tenants |
| `Disabled` | Published but access is suspended  |

New accounts are always created with `cpStatus: "Draft"`.

---

## 6. cpRevision

- `cpRevision` starts at `0` for every new account.
- It increments on meaningful persisted CP allowance mutations.
- It does **not** increment when a save is accepted but the resulting allowance truth is unchanged.
- Publish updates `cpStatus` and provisioning truth but does **not** increment `cpRevision` because it does not change CP allowance truth.
- `PATCH /cp/accounts/:accountKey/status` also does **not** increment `cpRevision` for the same reason.

---

## 7. CP → Settings producer boundary (current repo state)

The current repo is still in **State A** for the Control Plane prerequisite roadmap:

- the real Settings Step 10 Phase 2 state engine does not exist yet
- there is no `SettingsStateService`
- there is no `SettingsCpCascadeService`
- CP does **not** fake a synchronous cascade, webhook, queue handoff, or success flag

What is shipped now:

- CP persists real allowance truth in `cp_*` tables
- CP maintains honest `cpRevision` behavior for allowance mutations
- CP returns the canonical `settingsHandoff` producer snapshot on full account detail DTOs
- CP exposes the same producer snapshot through an internal backend service contract for the future Settings module to consume in-process

What is intentionally not shipped yet:

- no live cascade call from CP writes into Settings
- no fake “synced to Settings” UI or API field
- no Settings-side tables, section state, aggregate state, or reconciliation behavior

---

## 8. Module location

```text
backend/src/modules/control-plane/
  control-plane.module.ts
  accounts/
    cp-accounts.catalog.ts
    cp-accounts.controller.ts
    cp-accounts.errors.ts
    cp-accounts.module.ts
    cp-accounts.routes.ts
    cp-accounts.schemas.ts
    cp-accounts.service.ts
    cp-accounts.types.ts
    handoff/
      cp-settings-handoff.builder.ts
      cp-settings-handoff.types.ts
    dal/
      cp-accounts.query-sql.ts
      cp-accounts.repo.ts
```
