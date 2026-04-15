# CP Accounts API Contract

This document describes the backend CP accounts API contract implemented in this repository.

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
- `POST /cp/accounts`
- `PUT /cp/accounts/:accountKey/access`
- `PUT /cp/accounts/:accountKey/account-settings`
- `PUT /cp/accounts/:accountKey/modules`
- `PUT /cp/accounts/:accountKey/modules/personal`
- `PUT /cp/accounts/:accountKey/integrations`

Publish and status endpoints remain deferred.

---

## 2. Topology

CP routes are on the same backend process as all other routes. They are prefixed with `/cp/` to keep them distinct from tenant-facing routes.

**Dev-only no-auth**: CP routes carry no authentication in this phase. This is a deliberate development-phase shortcut. CP authentication will be added in a later phase.

---

## 3. Shared response shape

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

All read and write endpoints except `GET /cp/accounts` return the full CP account detail shape.

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
        "fields": [ ... ]
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
  }
}
```

---

## 4. Endpoints

### 4.1 `GET /cp/accounts`

Returns all CP accounts as list rows suitable for the CP accounts list page.

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

### 4.3 `POST /cp/accounts`

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

### 4.4 `PUT /cp/accounts/:accountKey/access`

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

### 4.5 `PUT /cp/accounts/:accountKey/account-settings`

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

### 4.6 `PUT /cp/accounts/:accountKey/modules`

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

### 4.7 `PUT /cp/accounts/:accountKey/modules/personal`

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

### 4.8 `PUT /cp/accounts/:accountKey/integrations`

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
- Publish and status-toggle increments remain deferred until their endpoints ship.

---

## 7. Deferred endpoints (later phases)

The following endpoints remain deferred:

- `POST /cp/accounts/:accountKey/publish`
- `PATCH /cp/accounts/:accountKey/status`

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
    dal/
      cp-accounts.query-sql.ts
      cp-accounts.repo.ts
```
