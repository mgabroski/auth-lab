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

---

## 2. Topology

CP routes are on the same backend process as all other routes. They are prefixed with `/cp/` to keep them distinct from tenant-facing routes.

**Dev-only no-auth**: CP routes carry no authentication in this phase. This is a deliberate development-phase shortcut. CP authentication will be added in a later phase.

---

## 3. Endpoints

### 3.1 `GET /cp/accounts`

Returns all CP accounts as a list.

**Response — 200 OK**

```json
{
  "accounts": [
    {
      "id": "uuid",
      "accountName": "Goodwill CA",
      "accountKey": "goodwill-ca",
      "cpStatus": "Draft",
      "cpRevision": 0
    }
  ]
}
```

`accounts` is an empty array `[]` when no accounts exist.

---

### 3.2 `GET /cp/accounts/:accountKey`

Returns the full CP account record for the given `accountKey`.

**Path param**: `accountKey` — the unique account key (lowercase, hyphens).

**Response — 200 OK**

```json
{
  "id": "uuid",
  "accountName": "Goodwill CA",
  "accountKey": "goodwill-ca",
  "cpStatus": "Draft",
  "cpRevision": 0,
  "createdAt": "2026-01-01T00:00:00.000Z",
  "updatedAt": "2026-01-01T00:00:00.000Z"
}
```

**Response — 404 Not Found**

```json
{
  "code": "NOT_FOUND",
  "message": "CP account not found: <accountKey>"
}
```

---

### 3.3 `POST /cp/accounts`

Creates a new Draft CP account.

**Request body**

```json
{
  "accountName": "Goodwill CA",
  "accountKey": "goodwill-ca"
}
```

**Validation rules**:

| Field         | Rule                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------ |
| `accountName` | Required. Non-empty string. Max 255 characters.                                            |
| `accountKey`  | Required. Non-empty string. Max 100 characters. Must match `^[a-z0-9-]+$`. Must be unique. |

**Response — 201 Created**

Returns the full created account object (same shape as `GET /cp/accounts/:accountKey`).

```json
{
  "id": "uuid",
  "accountName": "Goodwill CA",
  "accountKey": "goodwill-ca",
  "cpStatus": "Draft",
  "cpRevision": 0,
  "createdAt": "2026-01-01T00:00:00.000Z",
  "updatedAt": "2026-01-01T00:00:00.000Z"
}
```

**Response — 409 Conflict** (accountKey already taken)

```json
{
  "code": "CONFLICT",
  "message": "Account key is already taken: <accountKey>",
  "meta": { "accountKey": "<accountKey>" }
}
```

**Response — 422 Validation Error**

```json
{
  "code": "VALIDATION_ERROR",
  "message": "Invalid request body",
  "meta": { "issues": [ ... ] }
}
```

---

## 4. Status vocabulary

| Value      | Meaning                            |
| ---------- | ---------------------------------- |
| `Draft`    | Created but not yet published      |
| `Active`   | Published and reachable by tenants |
| `Disabled` | Published but access is suspended  |

New accounts are always created with `cpStatus: "Draft"`.

---

## 5. cpRevision

`cpRevision` starts at `0` for every new account. It is incremented on meaningful CP mutations (group saves, publish). Group saves and publish are deferred to later phases.

---

## 6. Deferred endpoints (later phases)

The following endpoints are defined in the CP prerequisite roadmap but not yet implemented:

- `PUT /cp/accounts/:accountKey/access`
- `PUT /cp/accounts/:accountKey/account-settings`
- `PUT /cp/accounts/:accountKey/modules`
- `PUT /cp/accounts/:accountKey/modules/personal`
- `PUT /cp/accounts/:accountKey/integrations`
- `POST /cp/accounts/:accountKey/publish`
- `PATCH /cp/accounts/:accountKey/status`

---

## 7. Module location

```
backend/src/modules/control-plane/
  control-plane.module.ts
  accounts/
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
